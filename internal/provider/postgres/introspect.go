package postgres

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
)

// Introspect reads the observed state of the connected database.
//
// Scope is currently one database per call — the one the connection is
// attached to — because PostgreSQL will not let a session read another
// database's catalog. Covering a whole cluster means one connection per
// database, which the caller arranges.
//
// The since cursor is accepted but not yet honoured: every call is a full
// read. Incremental introspection matters at 10^5 objects and is tracked
// separately; correctness first.
func (pr *Provider) Introspect(
	ctx context.Context, q provider.Querier, scope provider.Scope, _ provider.Cursor,
) (*provider.Snapshot, error) {
	dbName, err := currentDatabase(ctx, q)
	if err != nil {
		return nil, err
	}

	snap := &provider.Snapshot{
		Target:  scope.Target,
		TakenAt: time.Now().UTC(),
		Version: time.Now().UnixNano(),
	}

	base := core.ResourcePath{
		Engine: Engine,
		Segments: []core.Segment{
			core.LiteralSegment(core.KindTarget, scope.Target.ID),
			core.LiteralSegment(core.KindDatabase, dbName),
		},
	}

	if snap.Principals, err = readPrincipals(ctx, q); err != nil {
		return nil, fmt.Errorf("reading roles: %w", err)
	}
	if snap.Objects, err = readObjects(ctx, q, base); err != nil {
		return nil, fmt.Errorf("reading objects: %w", err)
	}
	if snap.Grants, err = readGrants(ctx, q, base); err != nil {
		return nil, fmt.Errorf("reading grants: %w", err)
	}
	markOwnerGrants(snap)
	return snap, nil
}

// markOwnerGrants flags privileges a role holds because it owns the object.
//
// PostgreSQL materialises the owner's implicit ALL into the ACL as soon as any
// grant is made on an object, so these appear as ordinary grants. They are not:
// revoking them breaks the owner, and authoritative mode must leave them alone.
func markOwnerGrants(snap *provider.Snapshot) {
	owners := make(map[string]string, len(snap.Objects))
	for _, o := range snap.Objects {
		owners[o.Path.String()] = o.Owner
	}
	for i, g := range snap.Grants {
		snap.Grants[i].Implicit = owners[g.Path.String()] == g.Grantee
	}
}

func currentDatabase(ctx context.Context, q provider.Querier) (string, error) {
	rows, err := q.Query(ctx, `SELECT current_database()`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("current_database() returned no rows")
	}
	var name string
	if err := rows.Scan(&name); err != nil {
		return "", err
	}
	return name, rows.Err()
}

// pg_roles carries every role in the cluster. The pg_ prefixed ones are the
// server's own predefined roles and are never managed here.
const principalsSQL = `
SELECT
  r.rolname,
  r.rolcanlogin,
  r.rolinherit,
  COALESCE((
    SELECT array_agg(g.rolname ORDER BY g.rolname)
      FROM pg_auth_members m
      JOIN pg_roles g ON g.oid = m.roleid
     WHERE m.member = r.oid
  ), '{}') AS member_of,
  -- The comment is how db-iam tells what it created from what was already
  -- there. It travels with the role and survives dump and restore, which a
  -- side table on the target would not.
  COALESCE(shobj_description(r.oid, 'pg_authid'), '') AS comment
FROM pg_roles r
WHERE r.rolname NOT LIKE 'pg\_%'
ORDER BY r.rolname
`

func readPrincipals(ctx context.Context, q provider.Querier) ([]provider.ObservedPrincipal, error) {
	rows, err := q.Query(ctx, principalsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []provider.ObservedPrincipal
	for rows.Next() {
		var (
			p       provider.ObservedPrincipal
			comment string
		)
		if err := rows.Scan(&p.Name, &p.Login, &p.Inherit, &p.MemberOf, &comment); err != nil {
			return nil, err
		}
		p.Managed = comment == ManagedComment
		out = append(out, p)
	}
	return out, rows.Err()
}

// relkind: r ordinary table, p partitioned table, v view, m materialised view,
// S sequence. Toast and temp schemas are the server's business, not ours.
const objectsSQL = `
SELECT
  n.nspname,
  c.relname,
  c.relkind,
  pg_get_userbyid(c.relowner) AS owner,
  c.relrowsecurity,
  COALESCE((
    SELECT array_agg(a.attname ORDER BY a.attnum)
      FROM pg_attribute a
     WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
  ), '{}') AS columns
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_toast%'
  AND n.nspname NOT LIKE 'pg\_temp%'
ORDER BY n.nspname, c.relname
`

func readObjects(ctx context.Context, q provider.Querier, base core.ResourcePath) ([]provider.ObservedObject, error) {
	rows, err := q.Query(ctx, objectsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []provider.ObservedObject
	for rows.Next() {
		var (
			schema, name, relkind, owner string
			rls                          bool
			columns                      []string
		)
		if err := rows.Scan(&schema, &name, &relkind, &owner, &rls, &columns); err != nil {
			return nil, err
		}
		out = append(out, provider.ObservedObject{
			Path:    objectPath(base, schema, name, relkind),
			Owner:   owner,
			Columns: columns,
			RLS:     rls,
		})
	}
	return out, rows.Err()
}

// kindForRelkind maps PostgreSQL's relkind to a portable segment kind. A
// materialised view is a view for privilege purposes; a partitioned table is a
// table.
func kindForRelkind(relkind string) core.SegmentKind {
	switch relkind {
	case "v", "m":
		return core.KindView
	case "S":
		return core.KindSequence
	default:
		return core.KindTable
	}
}

func objectPath(base core.ResourcePath, schema, name, relkind string) core.ResourcePath {
	p := core.ResourcePath{Engine: base.Engine}
	p.Segments = append(p.Segments, base.Segments...)
	p.Segments = append(p.Segments,
		core.LiteralSegment(core.KindSchema, schema),
		core.LiteralSegment(kindForRelkind(relkind), name),
	)
	return p
}

// aclexplode unpacks the ACL arrays the catalog stores. Reading the catalog
// directly rather than information_schema matters: the information_schema
// views filter to privileges the caller is involved in, which would silently
// hide grants and make a diff propose changes that are already in place.
//
// A NULL acl means "no explicit grants, owner defaults apply" and is reported
// as no grants; the object's Owner carries that information instead.
//
// Grantee 0 is the PUBLIC pseudo-role, which is an implicit grantee on new
// objects and the first thing authoritative mode has to revoke.
const grantsSQL = `
SELECT
  n.nspname,
  c.relname,
  c.relkind,
  CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
  a.privilege_type,
  NULL::text AS column_name
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(c.relacl) a
WHERE c.relacl IS NOT NULL
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_toast%'

UNION ALL

SELECT
  n.nspname,
  c.relname,
  c.relkind,
  CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
  a.privilege_type,
  att.attname AS column_name
FROM pg_attribute att
JOIN pg_class c ON c.oid = att.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(att.attacl) a
WHERE att.attacl IS NOT NULL
  AND att.attnum > 0 AND NOT att.attisdropped
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')

ORDER BY 1, 2, 4, 5
`

func readGrants(ctx context.Context, q provider.Querier, base core.ResourcePath) ([]provider.ObservedGrant, error) {
	rows, err := q.Query(ctx, grantsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Column privileges arrive one row per column; collapse them onto the
	// object so a grant of SELECT(a, b) reads as one grant rather than two.
	type key struct {
		path, grantee string
		action        core.Action
	}
	index := map[key]int{}
	var out []provider.ObservedGrant

	for rows.Next() {
		var (
			schema, name, relkind, grantee, privilege string
			column                                    *string
		)
		if err := rows.Scan(&schema, &name, &relkind, &grantee, &privilege, &column); err != nil {
			return nil, err
		}
		action, ok := actionForPrivilege(privilege)
		if !ok {
			continue // an engine privilege with no portable meaning
		}
		path := objectPath(base, schema, name, relkind)
		k := key{path: path.String(), grantee: grantee, action: action}

		idx, seen := index[k]
		if !seen {
			out = append(out, provider.ObservedGrant{
				Grantee: grantee, Action: action, Path: path,
			})
			idx = len(out) - 1
			index[k] = idx
		}
		if column != nil {
			out[idx].Columns = append(out[idx].Columns, *column)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// aclexplode returns columns in catalog order, which is not stable across
	// servers. Plan hashes and golden files both depend on this being sorted.
	for i := range out {
		sort.Strings(out[i].Columns)
	}
	return out, nil
}

// actionForPrivilege maps a PostgreSQL privilege name onto the portable
// vocabulary. Privileges with no portable equivalent are skipped rather than
// approximated, so they never appear in a diff as something db-iam claims to
// manage.
func actionForPrivilege(p string) (core.Action, bool) {
	switch p {
	case "SELECT":
		return core.ActionSelect, true
	case "INSERT":
		return core.ActionInsert, true
	case "UPDATE":
		return core.ActionUpdate, true
	case "DELETE":
		return core.ActionDelete, true
	case "TRUNCATE":
		return core.ActionTruncate, true
	case "REFERENCES":
		return core.ActionReference, true
	case "TRIGGER":
		return core.ActionTrigger, true
	case "USAGE":
		return core.ActionUsage, true
	case "CREATE":
		return core.ActionCreate, true
	case "CONNECT":
		return core.ActionConnect, true
	case "TEMPORARY", "TEMP":
		return core.ActionTemporary, true
	case "EXECUTE":
		return core.ActionExecute, true
	}
	return "", false
}
