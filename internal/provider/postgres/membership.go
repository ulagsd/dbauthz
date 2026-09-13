package postgres

import (
	"fmt"
	"strings"
	"time"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
)

// broadPredefinedRoles are PostgreSQL's own roles that hand out access to
// everything at once. Granting one is legitimate and occasionally necessary,
// but it defeats every table-level privilege the rest of this tool exists to
// manage, so the plan says so rather than letting it read like any other grant.
var broadPredefinedRoles = map[string]string{
	"pg_read_all_data":          "reads every table in every database, bypassing table privileges",
	"pg_write_all_data":         "writes every table in every database, bypassing table privileges",
	"pg_execute_server_program": "runs programs on the database host as the server's OS user",
	"pg_read_server_files":      "reads any file the server process can read",
	"pg_write_server_files":     "writes any file the server process can write",
}

// PlanMembership builds the statements that change a principal's roles.
//
// Revokes are ordered before grants. On a reassignment that ordering is the
// difference between a moment where the principal holds nothing extra and a
// moment where it holds both its old and its new access at once.
func (pr *Provider) PlanMembership(
	change provider.MembershipChange, caps core.Capabilities,
) (*provider.Plan, error) {
	if err := ValidateIdentifier(change.Member); err != nil {
		return nil, fmt.Errorf("member: %w", err)
	}
	if err := guardConnectedRole(change.Member, caps); err != nil {
		return nil, err
	}
	if len(change.Grant) == 0 && len(change.Revoke) == 0 {
		return nil, fmt.Errorf("no roles to grant or revoke")
	}

	// A role appearing on both sides is a contradiction, not an intent worth
	// guessing at. Whichever way it were resolved, half the request would be
	// silently ignored.
	both := intersect(change.Grant, change.Revoke)
	if len(both) > 0 {
		return nil, fmt.Errorf("%s appears in both grant and revoke", strings.Join(both, ", "))
	}

	plan := &provider.Plan{
		Target:    core.TargetRef{Engine: Engine},
		CreatedAt: time.Now().UTC(),
	}

	for _, role := range change.Revoke {
		if err := ValidateIdentifierRef(role); err != nil {
			return nil, fmt.Errorf("revoke %q: %w", role, err)
		}
		plan.Statements = append(plan.Statements, provider.Statement{
			SQL: fmt.Sprintf("REVOKE %s FROM %s",
				QuoteIdentifier(role), QuoteIdentifier(change.Member)),
			Risk: provider.RiskRevoke,
			Reason: fmt.Sprintf(
				"%s loses everything %s holds; anything relying on that access stops working",
				change.Member, role),
		})
	}

	for _, role := range change.Grant {
		if err := ValidateIdentifierRef(role); err != nil {
			return nil, fmt.Errorf("grant %q: %w", role, err)
		}
		reason := fmt.Sprintf("%s joins %s and receives everything that role holds",
			change.Member, role)
		if warning, broad := broadPredefinedRoles[strings.ToLower(role)]; broad {
			reason = fmt.Sprintf("%s joins %s, which %s", change.Member, role, warning)
		}
		plan.Statements = append(plan.Statements, provider.Statement{
			SQL: fmt.Sprintf("GRANT %s TO %s",
				QuoteIdentifier(role), QuoteIdentifier(change.Member)),
			Risk:   provider.RiskGrant,
			Reason: reason,
		})
	}

	plan.ComputeHash()
	return plan, nil
}

// guardConnectedRole refuses to touch the principal db-iam authenticates as.
//
// There is no recovery path if this goes wrong: the change takes effect, the
// next connection fails, and db-iam can no longer reach the database to undo
// it. An operator with a psql session can still do it deliberately.
func guardConnectedRole(name string, caps core.Capabilities) error {
	if caps.ConnectedRole != "" && strings.EqualFold(name, caps.ConnectedRole) {
		return fmt.Errorf(
			"refusing to modify %q: it is the role db-iam connects as, and a change "+
				"that locked it out could not be undone from here", name)
	}
	return nil
}

func intersect(a, b []string) []string {
	inB := make(map[string]struct{}, len(b))
	for _, s := range b {
		inB[strings.ToLower(s)] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := inB[strings.ToLower(s)]; ok {
			out = append(out, s)
		}
	}
	return out
}
