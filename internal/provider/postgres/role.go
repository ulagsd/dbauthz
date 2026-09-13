package postgres

import (
	"fmt"
	"strings"
	"time"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
	"github.com/ulagsd/db-iam/internal/secret"
)

// ManagedComment marks a role as created by db-iam.
//
// PostgreSQL has nowhere else to record this: there is no role metadata table
// to annotate, and a side table on the target would be state db-iam has to
// keep in sync with the thing it describes. A comment travels with the role,
// survives dump and restore, and is visible to a DBA reading \du+ — which is
// the point, since the alternative is a role nobody can account for.
const ManagedComment = "managed by db-iam"

// PlanCreateRole builds the statements that create a role.
//
// No I/O happens here. The result is a plan to be reviewed and then applied,
// which is what makes it possible to show an operator exactly what will run
// before anything runs.
func (pr *Provider) PlanCreateRole(spec provider.RoleSpec, caps core.Capabilities) (*provider.Plan, error) {
	if err := ValidateIdentifier(spec.Name); err != nil {
		return nil, fmt.Errorf("role name: %w", err)
	}
	if err := guardConnectedRole(spec.Name, caps); err != nil {
		return nil, err
	}
	for _, parent := range spec.MemberOf {
		// A reference, not a creation: granting a predefined pg_ role here is
		// legitimate and must not be refused.
		if err := ValidateIdentifierRef(parent); err != nil {
			return nil, fmt.Errorf("member of %q: %w", parent, err)
		}
	}
	if !spec.Login && !spec.Password.Empty() {
		return nil, fmt.Errorf("a role that cannot log in must not have a password")
	}
	if !spec.Password.Empty() {
		if err := secret.ValidatePassword(spec.Password, spec.Name); err != nil {
			return nil, err
		}
	}
	if spec.ConnectionLimit < -1 {
		return nil, fmt.Errorf("connection limit must be -1 (unlimited) or a count")
	}

	create, display, err := renderCreateRole(spec)
	if err != nil {
		return nil, err
	}

	plan := &provider.Plan{
		Target:    core.TargetRef{Engine: Engine},
		CreatedAt: time.Now().UTC(),
	}

	plan.Statements = append(plan.Statements, provider.Statement{
		SQL:     create,
		Display: display,
		// Creating a principal widens the reachable surface even before it is
		// granted anything, because it is a new thing that can authenticate.
		Risk:   provider.RiskGrant,
		Reason: describeRole(spec),
	})

	comment := spec.Comment
	if comment == "" {
		comment = ManagedComment
	}
	plan.Statements = append(plan.Statements, provider.Statement{
		SQL: fmt.Sprintf("COMMENT ON ROLE %s IS %s",
			QuoteIdentifier(spec.Name), QuoteLiteral(comment)),
		Risk:   provider.RiskSafe,
		Reason: "mark the role as managed, so a later reconcile can tell it apart",
	})

	for _, parent := range spec.MemberOf {
		plan.Statements = append(plan.Statements, provider.Statement{
			SQL: fmt.Sprintf("GRANT %s TO %s",
				QuoteIdentifier(parent), QuoteIdentifier(spec.Name)),
			Risk: provider.RiskGrant,
			Reason: fmt.Sprintf(
				"%s joins %s and receives everything that role holds", spec.Name, parent),
		})
	}

	if !caps.Superuser {
		plan.Statements[0].Reason += " (the connected role is not an admin; " +
			"PostgreSQL may refuse this)"
	}

	plan.CreatedRoles = []string{spec.Name}
	plan.ComputeHash()
	return plan, nil
}

// renderCreateRole returns the executable statement and its reviewable twin.
//
// The two differ in exactly one place: the password verifier. A reviewer needs
// to see that a password is being set, not what it hashes to — the verifier is
// enough to mount an offline attack, so it has no business in a plan view, an
// API response or an audit record.
func renderCreateRole(spec provider.RoleSpec) (sql, display string, err error) {
	var opts []string

	if spec.Login {
		opts = append(opts, "LOGIN")
	} else {
		opts = append(opts, "NOLOGIN")
	}
	if spec.Inherit {
		opts = append(opts, "INHERIT")
	} else {
		opts = append(opts, "NOINHERIT")
	}

	// Everything a role could use to escape being managed is spelled out
	// rather than left to the server's defaults, so reading the statement
	// tells you the whole story.
	opts = append(opts, "NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION", "NOBYPASSRLS")

	if spec.ConnectionLimit >= 0 {
		opts = append(opts, fmt.Sprintf("CONNECTION LIMIT %d", spec.ConnectionLimit))
	}
	if !spec.ValidUntil.IsZero() {
		opts = append(opts, "VALID UNTIL "+QuoteLiteral(spec.ValidUntil.UTC().Format(time.RFC3339)))
	}

	base := fmt.Sprintf("CREATE ROLE %s WITH %s", QuoteIdentifier(spec.Name), strings.Join(opts, " "))
	if spec.Password.Empty() {
		return base, "", nil
	}

	verifier, err := SCRAMVerifier(spec.Password, 0)
	if err != nil {
		return "", "", err
	}
	return base + " PASSWORD " + QuoteLiteral(verifier),
		base + " PASSWORD '[SCRAM-SHA-256 verifier]'",
		nil
}

func describeRole(spec provider.RoleSpec) string {
	kind := "group role, carries privilege but cannot connect"
	if spec.Login {
		kind = "login role"
		if spec.Password.Empty() {
			kind += " with no password; it can only authenticate by certificate, " +
				"cloud IAM or peer"
		} else {
			// Worth stating plainly, because it is the non-obvious property of
			// this whole path.
			kind += "; the password is sent as a precomputed SCRAM verifier, so " +
				"the plaintext never reaches the server, its logs or pg_stat_activity"
		}
	}
	return "create " + kind
}

var _ provider.RoleManager = (*Provider)(nil)
