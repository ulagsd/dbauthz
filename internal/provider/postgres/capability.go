// Package postgres implements the db-iam provider for PostgreSQL and its
// managed variants.
package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
)

// Engine is the canonical engine id used in resource paths.
const Engine = "postgres"

// Minimum server we support. Below this the predefined roles (pg_read_all_data
// and friends) do not exist and role membership semantics differ enough that
// the emitter would need a second code path for very little benefit.
const minServerVersionNum = 140000

// probe is the raw result of asking a server about itself. Separating it from
// classification keeps the interesting logic testable without a database,
// which matters because the variants that break things — RDS, Cloud SQL,
// Neon — are exactly the ones hardest to spin up in CI.
type probe struct {
	versionNum  int    // server_version_num, e.g. 160004
	version     string // server_version, e.g. "16.4"
	currentRole string
	isSuperuser bool

	// roles present on the server that identify a managed variant
	hasRDSSuperuser      bool
	hasRDSAdmin          bool
	hasCloudSQLSuperuser bool
	hasAzureSuperuser    bool
	hasNeonSuperuser     bool
	hasSupabaseAdmin     bool

	// membership of the connected role, used when it is not a true superuser
	memberOf []string

	// presence of the TimescaleDB extension, which restricts some DDL
	hasTimescale bool
}

// classify turns a probe into a capability profile.
//
// Every field here is derived from something the server actually said. The
// temptation is to shortcut this with a version check and be done, but the
// managed variants diverge in precisely the areas that matter for a privilege
// tool — who may alter whom — so the flavour detection earns its keep.
func classify(p probe) (core.Capabilities, error) {
	if p.versionNum > 0 && p.versionNum < minServerVersionNum {
		return core.Capabilities{}, fmt.Errorf(
			"postgres %s is below the minimum supported version 14", p.version)
	}

	caps := core.Capabilities{
		Engine:  Engine,
		Version: p.version,
		// PostgreSQL implements the full hierarchy, which is why it is the
		// reference provider: a policy that works here exercises every level.
		Levels: core.NewLevelSet(
			core.LevelTarget, core.LevelDatabase, core.LevelSchema,
			core.LevelObject, core.LevelAttribute,
		),
		ColumnGrants: core.SupportNative,
		RowFilters:   core.SupportNative, // CREATE POLICY, since 9.5
		// No native masking primitive. A managed security-barrier view can
		// stand in, but that is a substitution and is always declared as one.
		Masking:          core.SupportSubstitute,
		NativeDeny:       false, // privileges are purely additive
		FutureGrants:     true,  // ALTER DEFAULT PRIVILEGES
		TransactionalDDL: true,  // the property that makes apply recoverable
	}

	caps.Flavor, caps.Notes = detectFlavor(p)
	caps.Superuser = p.isSuperuser || hasAny(p.memberOf,
		"rds_superuser", "cloudsqlsuperuser", "azure_pg_admin", "neon_superuser")

	if !caps.Superuser {
		caps.Notes = append(caps.Notes,
			"connected role is not a superuser: roles it does not own, and objects "+
				"owned by other roles, cannot be managed")
	}
	if p.hasTimescale {
		caps.Notes = append(caps.Notes,
			"TimescaleDB present: privileges on hypertable chunks are managed by the "+
				"extension and are not reconciled here")
	}
	return caps, nil
}

// detectFlavor identifies the managed variant and the restrictions it brings.
// Order matters: Aurora also has rds_superuser, so the more specific marker is
// checked first.
func detectFlavor(p probe) (string, []string) {
	switch {
	case p.hasRDSAdmin && p.hasRDSSuperuser:
		return "rds", []string{
			"Amazon RDS/Aurora: no true superuser. The rds_superuser role cannot " +
				"alter roles it does not own, and event triggers are unavailable.",
		}
	case p.hasRDSSuperuser:
		return "rds", []string{
			"Amazon RDS: no true superuser; rds_superuser is the ceiling.",
		}
	case p.hasCloudSQLSuperuser:
		return "cloudsql", []string{
			"Cloud SQL: cloudsqlsuperuser is the ceiling; some catalog objects are " +
				"not visible and event triggers are unavailable.",
		}
	case p.hasAzureSuperuser:
		return "azure", []string{
			"Azure Database for PostgreSQL: azure_pg_admin is the ceiling.",
		}
	case p.hasNeonSuperuser:
		return "neon", []string{
			"Neon: roles are managed by the control plane and may be recreated on " +
				"branch operations.",
		}
	case p.hasSupabaseAdmin:
		return "supabase", []string{
			"Supabase: the anon, authenticated and service_role roles are managed by " +
				"the platform and are excluded from authoritative mode.",
		}
	}
	return "", nil
}

func hasAny(have []string, want ...string) bool {
	for _, h := range have {
		for _, w := range want {
			if strings.EqualFold(h, w) {
				return true
			}
		}
	}
	return false
}

// Capabilities probes a live server.
func (pr *Provider) Capabilities(ctx context.Context, q provider.Querier) (core.Capabilities, error) {
	p, err := runProbe(ctx, q)
	if err != nil {
		return core.Capabilities{}, fmt.Errorf("probing postgres target: %w", err)
	}
	return classify(p)
}

// probeSQL asks for everything classify needs in one round trip. Role presence
// is read from pg_roles rather than assumed, because the same managed provider
// changes its role names between versions.
const probeSQL = `
SELECT
  current_setting('server_version_num')::int              AS version_num,
  current_setting('server_version')                       AS version,
  current_user                                            AS current_role,
  (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser,
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_superuser')      AS has_rds_superuser,
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rdsadmin')           AS has_rds_admin,
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cloudsqlsuperuser')  AS has_cloudsql,
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'azure_pg_admin')     AS has_azure,
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'neon_superuser')     AS has_neon,
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'supabase_admin')     AS has_supabase,
  EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')    AS has_timescale,
  COALESCE(
    (SELECT array_agg(g.rolname)
       FROM pg_auth_members m
       JOIN pg_roles g ON g.oid = m.roleid
       JOIN pg_roles r ON r.oid = m.member
      WHERE r.rolname = current_user),
    '{}'
  )                                                       AS member_of
`

func runProbe(ctx context.Context, q provider.Querier) (probe, error) {
	var p probe
	rows, err := q.Query(ctx, probeSQL)
	if err != nil {
		return p, err
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return p, err
		}
		return p, fmt.Errorf("probe returned no rows")
	}
	err = rows.Scan(
		&p.versionNum, &p.version, &p.currentRole, &p.isSuperuser,
		&p.hasRDSSuperuser, &p.hasRDSAdmin, &p.hasCloudSQLSuperuser,
		&p.hasAzureSuperuser, &p.hasNeonSuperuser, &p.hasSupabaseAdmin,
		&p.hasTimescale, &p.memberOf,
	)
	if err != nil {
		return p, err
	}
	return p, rows.Err()
}
