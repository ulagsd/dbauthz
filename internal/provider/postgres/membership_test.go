package postgres

import (
	"strings"
	"testing"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
)

func membershipPlan(t *testing.T, c provider.MembershipChange, caps core.Capabilities) *provider.Plan {
	t.Helper()
	p, err := New().PlanMembership(c, caps)
	if err != nil {
		t.Fatalf("PlanMembership: %v", err)
	}
	return p
}

// The ordering is the fail-safe property from ARCHITECTURE S2: no intermediate
// state during a reassignment grants more than either endpoint.
func TestPlanMembershipRevokesBeforeGranting(t *testing.T) {
	plan := membershipPlan(t, provider.MembershipChange{
		Member: "alice",
		Grant:  []string{"app_rw", "analyst"},
		Revoke: []string{"app_ro", "support"},
	}, testCaps())

	if len(plan.Statements) != 4 {
		t.Fatalf("got %d statements:\n%s", len(plan.Statements), plan.Render())
	}
	for i, st := range plan.Statements {
		isRevoke := strings.HasPrefix(st.SQL, "REVOKE")
		if i < 2 && !isRevoke {
			t.Errorf("statement %d should be a revoke: %s", i, st.SQL)
		}
		if i >= 2 && isRevoke {
			t.Errorf("statement %d should be a grant: %s", i, st.SQL)
		}
	}
	if plan.MaxRisk() != provider.RiskRevoke {
		t.Errorf("MaxRisk = %v, want revoke", plan.MaxRisk())
	}
}

func TestPlanMembershipQuotesNames(t *testing.T) {
	plan := membershipPlan(t, provider.MembershipChange{
		Member: `we"ird`, Grant: []string{`ro"le`},
	}, testCaps())

	if got := plan.Statements[0].SQL; got != `GRANT "ro""le" TO "we""ird"` {
		t.Errorf("statement = %q", got)
	}
}

func TestPlanMembershipCallsOutBroadRoles(t *testing.T) {
	plan := membershipPlan(t, provider.MembershipChange{
		Member: "alice", Grant: []string{"pg_read_all_data"},
	}, testCaps())

	if !strings.Contains(plan.Statements[0].Reason, "bypassing table privileges") {
		t.Errorf("reason = %q, want it to explain the role's reach", plan.Statements[0].Reason)
	}
}

func TestPlanMembershipRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change provider.MembershipChange
		want   string
	}{
		{"nothing to do", provider.MembershipChange{Member: "alice"}, "no roles"},
		{
			"contradiction",
			provider.MembershipChange{Member: "alice", Grant: []string{"app_ro"}, Revoke: []string{"app_ro"}},
			"both grant and revoke",
		},
		{
			"contradiction ignoring case",
			provider.MembershipChange{Member: "alice", Grant: []string{"App_RO"}, Revoke: []string{"app_ro"}},
			"both grant and revoke",
		},
		{
			"bad member",
			provider.MembershipChange{Member: "al ice ", Grant: []string{"app_ro"}},
			"whitespace",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New().PlanMembership(tc.change, testCaps())
			if err == nil {
				t.Fatalf("accepted, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// There is no way back if db-iam locks itself out: the change takes effect,
// the next connection fails, and nothing here can undo it.
func TestConnectedRoleIsProtected(t *testing.T) {
	caps := testCaps()
	caps.ConnectedRole = "dbiam_admin"

	t.Run("membership", func(t *testing.T) {
		_, err := New().PlanMembership(provider.MembershipChange{
			Member: "DBIAM_ADMIN", Revoke: []string{"app_ro"}, // case must not evade it
		}, caps)
		if err == nil || !strings.Contains(err.Error(), "connects as") {
			t.Errorf("err = %v, want a refusal naming the connected role", err)
		}
	})

	t.Run("creation", func(t *testing.T) {
		_, err := New().PlanCreateRole(provider.RoleSpec{
			Name: "dbiam_admin", Login: true, ConnectionLimit: -1,
		}, caps)
		if err == nil || !strings.Contains(err.Error(), "connects as") {
			t.Errorf("err = %v, want a refusal naming the connected role", err)
		}
	})

	t.Run("other principals are unaffected", func(t *testing.T) {
		if _, err := New().PlanMembership(provider.MembershipChange{
			Member: "alice", Grant: []string{"app_ro"},
		}, caps); err != nil {
			t.Errorf("unrelated principal was refused: %v", err)
		}
	})
}
