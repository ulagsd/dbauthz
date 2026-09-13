package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
	"github.com/ulagsd/db-iam/internal/secret"
)

func testCaps() core.Capabilities {
	caps, err := classify(basePostgres())
	if err != nil {
		panic(err)
	}
	return caps
}

func planFor(t *testing.T, spec provider.RoleSpec) *provider.Plan {
	t.Helper()
	p, err := New().PlanCreateRole(spec, testCaps())
	if err != nil {
		t.Fatalf("PlanCreateRole: %v", err)
	}
	return p
}

// The property this whole path exists for: a password reaches PostgreSQL as a
// verifier, and never appears in anything a human or a log will see.
func TestPlanCreateRoleNeverExposesThePassword(t *testing.T) {
	const password = "correct-horse-battery-staple"

	plan := planFor(t, provider.RoleSpec{
		Name: "alice", Login: true, Inherit: true,
		Password: secret.Text(password), ConnectionLimit: -1,
	})

	create := plan.Statements[0]

	if strings.Contains(create.SQL, password) {
		t.Fatal("the plaintext password reached the executable statement; " +
			"it would land in pg_stat_activity and the server log")
	}
	if !strings.Contains(create.SQL, "SCRAM-SHA-256$") {
		t.Error("the executable statement should carry a SCRAM verifier")
	}

	// The reviewable form must show that a password is set without showing
	// the verifier, which is enough to mount an offline attack.
	if strings.Contains(create.Redacted(), "SCRAM-SHA-256$") {
		t.Error("the verifier leaked into the reviewable form of the statement")
	}
	if strings.Contains(create.Redacted(), password) {
		t.Error("the plaintext leaked into the reviewable form")
	}
	if !strings.Contains(create.Redacted(), "PASSWORD") {
		t.Error("a reviewer must still be able to see that a password is being set")
	}
}

func TestPlanCreateRoleStatements(t *testing.T) {
	plan := planFor(t, provider.RoleSpec{
		Name: "alice", Login: true, Inherit: true, ConnectionLimit: 5,
		MemberOf:   []string{"app_ro", "analyst"},
		ValidUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	// create + comment + two memberships
	if len(plan.Statements) != 4 {
		t.Fatalf("got %d statements:\n%s", len(plan.Statements), plan.Render())
	}

	create := plan.Statements[0].SQL
	for _, want := range []string{
		`CREATE ROLE "alice"`, "LOGIN", "INHERIT",
		// Every attribute that could let a role escape being managed is stated
		// explicitly rather than left to a server default.
		"NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION", "NOBYPASSRLS",
		"CONNECTION LIMIT 5", "VALID UNTIL '2027-01-01T00:00:00Z'",
	} {
		if !strings.Contains(create, want) {
			t.Errorf("CREATE ROLE is missing %q:\n  %s", want, create)
		}
	}

	if !strings.Contains(plan.Statements[1].SQL, "COMMENT ON ROLE") {
		t.Errorf("expected the role to be marked as managed: %s", plan.Statements[1].SQL)
	}
	if got := plan.Statements[2].SQL; got != `GRANT "app_ro" TO "alice"` {
		t.Errorf("membership statement = %q", got)
	}

	if plan.MaxRisk() != provider.RiskGrant {
		t.Errorf("MaxRisk = %v, want grant: creating a principal widens access", plan.MaxRisk())
	}
	if len(plan.CreatedRoles) != 1 || plan.CreatedRoles[0] != "alice" {
		t.Errorf("CreatedRoles = %v, want [alice] so Verify can check it", plan.CreatedRoles)
	}
	if plan.Hash == "" {
		t.Error("the plan must be content-addressed")
	}
}

func TestPlanCreateRoleNoLoginTakesNoPassword(t *testing.T) {
	plan := planFor(t, provider.RoleSpec{Name: "app_ro", Login: false, Inherit: true, ConnectionLimit: -1})

	create := plan.Statements[0].SQL
	if !strings.Contains(create, "NOLOGIN") {
		t.Errorf("expected NOLOGIN: %s", create)
	}
	if strings.Contains(create, "PASSWORD") {
		t.Errorf("a group role must not be given a password: %s", create)
	}
}

func TestPlanCreateRoleRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec provider.RoleSpec
		want string
	}{
		{
			name: "injection in the role name is caught before quoting matters",
			spec: provider.RoleSpec{Name: "x\x00y", Login: true},
			want: "null byte",
		},
		{
			name: "reserved prefix",
			spec: provider.RoleSpec{Name: "pg_evil", Login: true},
			want: "reserved",
		},
		{
			name: "bad parent role",
			spec: provider.RoleSpec{Name: "alice", Login: true, MemberOf: []string{" bad"}},
			want: "whitespace",
		},
		{
			name: "password on a role that cannot log in",
			spec: provider.RoleSpec{Name: "grp", Login: false, Password: "a-long-enough-password"},
			want: "must not have a password",
		},
		{
			name: "short password",
			spec: provider.RoleSpec{Name: "alice", Login: true, Password: "short"},
			want: "at least",
		},
		{
			name: "password equal to the username",
			spec: provider.RoleSpec{Name: "averylongusername", Login: true, Password: "averylongusername"},
			want: "must not be the username",
		},
		{
			name: "nonsense connection limit",
			spec: provider.RoleSpec{Name: "alice", Login: true, ConnectionLimit: -7},
			want: "connection limit",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New().PlanCreateRole(tc.spec, testCaps())
			if err == nil {
				t.Fatalf("spec was accepted, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// An identifier that survives validation must still be quoted, not interpolated.
func TestPlanCreateRoleQuotesAwkwardNames(t *testing.T) {
	plan := planFor(t, provider.RoleSpec{
		Name: `we"ird; DROP ROLE admin; --`, Login: false, ConnectionLimit: -1,
	})
	want := `CREATE ROLE "we""ird; DROP ROLE admin; --"`
	if !strings.Contains(plan.Statements[0].SQL, want) {
		t.Errorf("name was not safely quoted:\n  %s", plan.Statements[0].SQL)
	}
}

func TestPlanCreateRoleWarnsWhenNotAdmin(t *testing.T) {
	p := basePostgres()
	p.isSuperuser = false
	caps, err := classify(p)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := New().PlanCreateRole(
		provider.RoleSpec{Name: "alice", Login: false, ConnectionLimit: -1}, caps)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Statements[0].Reason, "not an admin") {
		t.Errorf("expected the plan to say this may be refused: %q", plan.Statements[0].Reason)
	}
}
