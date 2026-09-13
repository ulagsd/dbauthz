package provider

import (
	"context"
	"time"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/secret"
)

// RoleSpec describes a database principal to create.
//
// Deliberately absent: SUPERUSER, and any other attribute that would let a
// created role escape db-iam's own control. A tool whose API can mint an
// unconstrained superuser is a privilege escalation path wearing a form, so
// that capability stays outside it — an operator who needs one has a psql
// session and an audit trail of their own.
type RoleSpec struct {
	Name string

	// Login separates a principal that authenticates from a group role that
	// only carries privilege. Group roles take no password.
	Login bool

	// Password is optional. When Login is set and this is empty, the caller is
	// expected to have generated one; a login role with no password can only
	// authenticate by another method (certificate, cloud IAM, peer).
	Password secret.Text

	// Inherit controls whether membership privileges apply automatically or
	// only after SET ROLE. NOINHERIT changes what a principal effectively
	// holds at connection time, which the solver has to model.
	Inherit bool

	// ConnectionLimit caps concurrent connections. -1 means unlimited.
	ConnectionLimit int

	// ValidUntil expires the role's password. Zero means no expiry.
	ValidUntil time.Time

	// MemberOf lists existing roles this one joins.
	MemberOf []string

	// Comment is recorded on the role so a later reconcile can tell what
	// db-iam created from what it must not touch.
	Comment string
}

// RoleManager is implemented by providers that can create principals.
//
// It is separate from Provider because the core contract is about compiling
// permissions, and not every engine manages identity the same way — some
// delegate it to the platform entirely. Keeping it optional means those
// providers implement Provider without a pile of unsupported stubs.
type RoleManager interface {
	// PlanCreateRole produces the statements that would create the role. It
	// performs no I/O: the result is reviewed, then handed to Apply.
	PlanCreateRole(spec RoleSpec, caps core.Capabilities) (*Plan, error)
}

// Tx is a transaction over a target.
type Tx interface {
	Querier
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Beginner is implemented by connections that support transactions.
//
// Apply checks for it rather than requiring it, because whether DDL can roll
// back is an engine property, not a connection one: PostgreSQL can, MySQL and
// Snowflake cannot, and the apply path has to be correct either way.
type Beginner interface {
	Begin(ctx context.Context) (Tx, error)
}
