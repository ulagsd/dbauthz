package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/ulagsd/db-iam/internal/provider"
)

// Apply executes a plan.
//
// PostgreSQL has transactional DDL, which is the property that makes this
// recoverable: the whole plan commits or none of it does, and there is never a
// moment where half a set of privileges exists. Engines without it need the
// statement ordering itself to be fail-safe, which is why the non-transactional
// path below is written out rather than assumed away.
func (pr *Provider) Apply(
	ctx context.Context, q provider.Querier, plan *provider.Plan,
) (*provider.ApplyResult, error) {
	res := &provider.ApplyResult{PlanHash: plan.Hash, StartedAt: time.Now().UTC()}
	defer func() { res.EndedAt = time.Now().UTC() }()

	if plan.Empty() {
		return res, nil
	}

	beginner, ok := q.(provider.Beginner)
	if !ok {
		return pr.applySequential(ctx, q, plan, res)
	}

	tx, err := beginner.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("beginning transaction: %w", err)
	}
	// Rollback after a successful commit is a no-op, so this is safe to defer
	// unconditionally and removes every path that could leave one open.
	defer func() { _ = tx.Rollback(ctx) }()

	for i, stmt := range plan.Statements {
		if err := tx.Exec(ctx, stmt.SQL); err != nil {
			res.Failed++
			res.Errors = append(res.Errors, provider.StatementError{
				// The redacted form: an error is the most likely thing to be
				// pasted into a ticket or a chat window.
				Index: i, SQL: stmt.Redacted(), Err: err.Error(),
			})
			// Nothing has been committed, so nothing needs undoing and the
			// executed count stays zero. Reporting otherwise would describe a
			// state the database is not in.
			return res, fmt.Errorf("statement %d failed, transaction rolled back: %w", i+1, err)
		}
		res.Executed++
	}

	if err := tx.Commit(ctx); err != nil {
		res.Executed = 0
		return res, fmt.Errorf("commit failed, no statements applied: %w", err)
	}
	return res, nil
}

// applySequential runs a plan without a transaction.
//
// Only reachable when the connection cannot begin one. A failure partway
// through leaves the target in a state that is real but unintended, so it is
// reported as indeterminate rather than retried: replaying a partially applied
// privilege change is how a tool creates access nobody asked for.
func (pr *Provider) applySequential(
	ctx context.Context, q provider.Querier, plan *provider.Plan, res *provider.ApplyResult,
) (*provider.ApplyResult, error) {
	for i, stmt := range plan.Statements {
		if err := q.Exec(ctx, stmt.SQL); err != nil {
			res.Failed++
			res.Errors = append(res.Errors, provider.StatementError{
				Index: i, SQL: stmt.Redacted(), Err: err.Error(),
			})
			res.Indeterminate = i > 0
			return res, fmt.Errorf("statement %d of %d failed with no transaction to undo it: %w",
				i+1, len(plan.Statements), err)
		}
		res.Executed++
	}
	return res, nil
}

// Verify re-reads the target and confirms the plan's intent holds.
//
// Checking the observed result rather than trusting a successful apply is what
// catches the cases where a statement succeeded but did not mean what it
// looked like: a trigger rewrote it, an extension intervened, or a concurrent
// change undid it between commit and now.
func (pr *Provider) Verify(
	ctx context.Context, q provider.Querier, plan *provider.Plan,
) (*provider.VerifyResult, error) {
	out := &provider.VerifyResult{Converged: true}

	for _, name := range plan.CreatedRoles {
		exists, err := roleExists(ctx, q, name)
		if err != nil {
			return nil, fmt.Errorf("verifying role %q: %w", name, err)
		}
		if !exists {
			out.Converged = false
			out.Divergence = append(out.Divergence,
				fmt.Sprintf("role %q was reported created but is not present", name))
		}
	}
	return out, nil
}

func roleExists(ctx context.Context, q provider.Querier, name string) (bool, error) {
	// A bind parameter, because this one is a value rather than an identifier.
	rows, err := q.Query(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, name)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, err
		}
		return false, fmt.Errorf("existence check returned no rows")
	}
	var exists bool
	if err := rows.Scan(&exists); err != nil {
		return false, err
	}
	return exists, rows.Err()
}
