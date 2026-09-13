package postgres

import (
	"strings"
	"testing"

	"github.com/ulagsd/db-iam/internal/core"
)

func basePostgres() probe {
	return probe{versionNum: 160004, version: "16.4", currentRole: "dbiam", isSuperuser: true}
}

func TestClassifyVanillaPostgres(t *testing.T) {
	caps, err := classify(basePostgres())
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if caps.Engine != Engine || caps.Version != "16.4" {
		t.Errorf("engine/version = %q/%q", caps.Engine, caps.Version)
	}
	if caps.Flavor != "" {
		t.Errorf("Flavor = %q, want empty for vanilla", caps.Flavor)
	}
	if !caps.Superuser {
		t.Error("Superuser should be true")
	}
	for _, l := range []core.Level{
		core.LevelTarget, core.LevelDatabase, core.LevelSchema,
		core.LevelObject, core.LevelAttribute,
	} {
		if !caps.Supports(l) {
			t.Errorf("postgres must support the %s level", l)
		}
	}
	if caps.ColumnGrants != core.SupportNative {
		t.Errorf("ColumnGrants = %v, want native", caps.ColumnGrants)
	}
	if caps.RowFilters != core.SupportNative {
		t.Errorf("RowFilters = %v, want native", caps.RowFilters)
	}
	if caps.Masking != core.SupportSubstitute {
		t.Errorf("Masking = %v, want substitute: postgres has no masking primitive", caps.Masking)
	}
	if caps.NativeDeny {
		t.Error("postgres privileges are additive; NativeDeny must be false")
	}
	if !caps.FutureGrants || !caps.TransactionalDDL {
		t.Error("postgres has ALTER DEFAULT PRIVILEGES and transactional DDL")
	}
}

func TestClassifyRejectsUnsupportedVersion(t *testing.T) {
	p := basePostgres()
	p.versionNum, p.version = 130012, "13.12"
	if _, err := classify(p); err == nil {
		t.Fatal("classify accepted postgres 13, want an error")
	}
}

func TestClassifyFlavors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(*probe)
		wantFlavor string
		wantNote   string
	}{
		{
			name:       "rds",
			mutate:     func(p *probe) { p.hasRDSSuperuser = true },
			wantFlavor: "rds",
			wantNote:   "no true superuser",
		},
		{
			name:       "aurora reports rdsadmin too",
			mutate:     func(p *probe) { p.hasRDSSuperuser, p.hasRDSAdmin = true, true },
			wantFlavor: "rds",
			wantNote:   "event triggers are unavailable",
		},
		{
			name:       "cloudsql",
			mutate:     func(p *probe) { p.hasCloudSQLSuperuser = true },
			wantFlavor: "cloudsql",
			wantNote:   "cloudsqlsuperuser",
		},
		{
			name:       "azure",
			mutate:     func(p *probe) { p.hasAzureSuperuser = true },
			wantFlavor: "azure",
			wantNote:   "azure_pg_admin",
		},
		{
			name:       "neon",
			mutate:     func(p *probe) { p.hasNeonSuperuser = true },
			wantFlavor: "neon",
			wantNote:   "branch operations",
		},
		{
			name:       "supabase",
			mutate:     func(p *probe) { p.hasSupabaseAdmin = true },
			wantFlavor: "supabase",
			wantNote:   "service_role",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := basePostgres()
			tc.mutate(&p)
			caps, err := classify(p)
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			if caps.Flavor != tc.wantFlavor {
				t.Errorf("Flavor = %q, want %q", caps.Flavor, tc.wantFlavor)
			}
			if !containsSubstring(caps.Notes, tc.wantNote) {
				t.Errorf("Notes = %v, want one mentioning %q", caps.Notes, tc.wantNote)
			}
		})
	}
}

// On a managed provider the connected role is not rolsuper, but membership in
// the platform's admin role is enough to manage privileges. Missing this would
// make db-iam refuse to work on RDS, which is most of the real installs.
func TestClassifyManagedMembershipCountsAsSuperuser(t *testing.T) {
	p := basePostgres()
	p.isSuperuser = false
	p.hasRDSSuperuser = true
	p.memberOf = []string{"rds_superuser"}

	caps, err := classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if !caps.Superuser {
		t.Error("membership of rds_superuser should count as superuser")
	}
	if containsSubstring(caps.Notes, "is not a superuser") {
		t.Error("should not warn about privileges when the role has admin membership")
	}
}

func TestClassifyWarnsOnUnprivilegedRole(t *testing.T) {
	p := basePostgres()
	p.isSuperuser = false

	caps, err := classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if caps.Superuser {
		t.Error("Superuser should be false")
	}
	if !containsSubstring(caps.Notes, "is not a superuser") {
		t.Errorf("Notes = %v, want a warning about limited privileges", caps.Notes)
	}
}

func TestClassifyNotesTimescale(t *testing.T) {
	p := basePostgres()
	p.hasTimescale = true

	caps, err := classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if !containsSubstring(caps.Notes, "TimescaleDB") {
		t.Errorf("Notes = %v, want a TimescaleDB caveat", caps.Notes)
	}
}

// CanExpress is the gate that stands between a policy and silent
// under-enforcement, so exercise it against a real capability profile.
func TestCapabilitiesCanExpress(t *testing.T) {
	caps, err := classify(basePostgres())
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	table := core.MustParseResourcePath("dbi:postgres:target/t:db/app:schema/public:table/orders")

	t.Run("plain select is native", func(t *testing.T) {
		g := core.Grant{Action: core.ActionSelect, Resource: table}
		if s, what := caps.CanExpress(g); s != core.SupportNative {
			t.Errorf("got %v (%s), want native", s, what)
		}
	})

	t.Run("column-scoped select is native", func(t *testing.T) {
		g := core.Grant{Action: core.ActionSelect, Resource: table, Columns: core.NamedColumns("id", "total")}
		if s, what := caps.CanExpress(g); s != core.SupportNative {
			t.Errorf("got %v (%s), want native", s, what)
		}
	})

	t.Run("column-scoped delete is impossible", func(t *testing.T) {
		// DELETE removes whole rows, so narrowing it to columns is meaningless
		// on every engine. This must be caught, not emitted as a table grant.
		g := core.Grant{Action: core.ActionDelete, Resource: table, Columns: core.NamedColumns("id")}
		s, what := caps.CanExpress(g)
		if s != core.SupportNone {
			t.Errorf("got %v, want none", s)
		}
		if !strings.Contains(what, string(core.ActionDelete)) {
			t.Errorf("limitation = %q, want it to name the action", what)
		}
	})

	t.Run("row filter is native", func(t *testing.T) {
		g := core.Grant{
			Action:    core.ActionSelect,
			Resource:  table,
			RowFilter: core.MustParsePredicate("tenant_id = ${session.tenant}"),
		}
		if s, what := caps.CanExpress(g); s != core.SupportNative {
			t.Errorf("got %v (%s), want native", s, what)
		}
	})

	t.Run("masking degrades to substitution", func(t *testing.T) {
		g := core.Grant{
			Action:   core.ActionSelect,
			Resource: table,
			Mask:     &core.MaskSpec{Kind: "partial", Columns: []string{"ssn"}},
		}
		s, what := caps.CanExpress(g)
		if s != core.SupportSubstitute {
			t.Errorf("got %v, want substitute", s)
		}
		if what != "masking" {
			t.Errorf("limitation = %q, want %q", what, "masking")
		}
	})

	t.Run("the weakest capability wins", func(t *testing.T) {
		// A grant needing both a native row filter and a substituted mask is
		// only as good as its weakest part.
		g := core.Grant{
			Action:    core.ActionSelect,
			Resource:  table,
			RowFilter: core.MustParsePredicate("a = 1"),
			Mask:      &core.MaskSpec{Kind: "null", Columns: []string{"ssn"}},
		}
		if s, _ := caps.CanExpress(g); s != core.SupportSubstitute {
			t.Errorf("got %v, want substitute", s)
		}
	})

	t.Run("action invalid at this level is rejected", func(t *testing.T) {
		// USAGE is a schema-level privilege; asking for it on a table is a
		// policy error and must surface as one.
		g := core.Grant{Action: core.ActionUsage, Resource: table}
		if s, _ := caps.CanExpress(g); s != core.SupportNone {
			t.Errorf("got %v, want none", s)
		}
	})
}

func containsSubstring(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}
