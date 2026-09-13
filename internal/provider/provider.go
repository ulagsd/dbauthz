// Package provider defines the contract every database engine implements.
//
// The split this package enforces is the one the whole system rests on:
// everything above it is engine-neutral, everything below it is engine
// specific, and core.EffectivePermissionSet is the only vocabulary that
// crosses the line. A provider never resolves identity, never expands a glob,
// and never reasons about deny — the solver has already done all three.
package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/ulagsd/db-iam/internal/core"
)

// Provider compiles portable permissions into one engine's own primitives.
type Provider interface {
	// Engine is the canonical engine id used in resource paths.
	Engine() string

	// Capabilities probes a live connection. Implementations must read the
	// server, not assume from the engine name: version, edition and managed
	// flavour all change what can be expressed.
	Capabilities(ctx context.Context, q Querier) (core.Capabilities, error)

	// Introspect reads observed state. since carries an opaque cursor so a
	// large cluster need not be re-read in full every cycle; a zero cursor
	// means a complete read.
	Introspect(ctx context.Context, q Querier, scope Scope, since Cursor) (*Snapshot, error)

	// Compile lowers the portable permission set into engine statements.
	// It returns *UnsupportedError when the set cannot be faithfully
	// expressed and the policy does not permit substitution.
	Compile(eps *core.EffectivePermissionSet, caps core.Capabilities, opts CompileOptions) (*StatementSet, error)

	// Diff turns desired statements plus observed state into an ordered plan.
	// The ordering must satisfy the fail-safe property: no intermediate state
	// during apply may grant more privilege than either endpoint.
	Diff(desired *StatementSet, live *Snapshot) (*Plan, error)

	// Apply executes a plan.
	Apply(ctx context.Context, q Querier, plan *Plan) (*ApplyResult, error)

	// Verify re-reads the target and asserts the plan's intent now holds.
	Verify(ctx context.Context, q Querier, plan *Plan) (*VerifyResult, error)
}

// Querier is the narrow database surface a provider needs. Keeping it an
// interface lets the golden-file tests exercise compilation with no server,
// and keeps driver choice out of the SPI.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	Exec(ctx context.Context, sql string, args ...any) error
}

// Rows is a minimal forward-only result set.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// Cursor is an opaque incremental-introspection marker.
type Cursor string

// Scope bounds an introspection to part of a target, and names the target the
// resulting resource paths belong to.
type Scope struct {
	Target    core.TargetRef
	Databases []string // empty means every database the connection can reach
	Schemas   []string // empty means every schema except the engine's own
}

// OnUnsupported is the policy author's instruction for what to do when the
// target cannot express a grant. It defaults to Refuse, and that default is
// the load-bearing part: a tool that quietly downgrades an access control is
// worse than no tool, because it is believed.
type OnUnsupported int

const (
	// Refuse rejects the plan rather than weakening the control.
	Refuse OnUnsupported = iota
	// Substitute permits a documented stand-in construct, recorded in the plan.
	Substitute
)

func (o OnUnsupported) String() string {
	if o == Substitute {
		return "substitute"
	}
	return "refuse"
}

// CompileOptions carries per-apply settings.
type CompileOptions struct {
	OnUnsupported OnUnsupported

	// Mode decides what happens to privileges the policy does not mention.
	Mode ReconcileMode

	// IdentityStrategy decides how a principal becomes a native database
	// object, and with it whether a Deny is expressible at all.
	IdentityStrategy IdentityStrategy

	// ManagedPrefix namespaces every object db-iam creates, so adopt mode can
	// tell what it owns from what it must not touch.
	ManagedPrefix string
}

// ReconcileMode decides the treatment of undeclared state.
type ReconcileMode int

const (
	// ModeAdopt manages only what the policy declares and leaves everything
	// else alone. The default, because authoritative mode is unadoptable on
	// an existing cluster.
	ModeAdopt ReconcileMode = iota
	// ModeAdditive grants but never revokes.
	ModeAdditive
	// ModeAuthoritative revokes undeclared grants and drops undeclared
	// managed roles.
	ModeAuthoritative
)

func (m ReconcileMode) String() string {
	switch m {
	case ModeAdditive:
		return "additive"
	case ModeAuthoritative:
		return "authoritative"
	}
	return "adopt"
}

// IdentityStrategy decides how a db-iam principal is materialised in the
// database. See docs/ARCHITECTURE.md §8: this choice determines whether a
// column- or object-level Deny can be honoured, because no SQL engine has a
// persistent deny to fall back on.
type IdentityStrategy int

const (
	// StrategyPerPrincipalRole gives each principal its own role carrying a
	// computed grant set. Deny is always satisfiable. Default for humans.
	StrategyPerPrincipalRole IdentityStrategy = iota
	// StrategySharedRole maps principals onto roles shared per permission set.
	// Fewer objects, but a Deny that contradicts an inherited grant cannot be
	// expressed and is reported as a conflict instead.
	StrategySharedRole
	// StrategyEphemeral mints a role per session with a TTL. Zero standing
	// privilege; requires the access-request workflow.
	StrategyEphemeral
)

func (s IdentityStrategy) String() string {
	switch s {
	case StrategySharedRole:
		return "shared-role"
	case StrategyEphemeral:
		return "ephemeral"
	}
	return "per-principal-role"
}

// UnsupportedError reports that a grant cannot be faithfully expressed.
//
// It names the statement to fix rather than just the missing feature, because
// the operator's next action is to edit a policy, not to read a capability
// table.
type UnsupportedError struct {
	Engine     string
	Capability string   // the capability that falls short
	Origin     []string // policy statement ids responsible
	Grant      string   // the grant, rendered
	Remedy     string   // what the operator can do about it
}

func (e *UnsupportedError) Error() string {
	msg := fmt.Sprintf("%s cannot express %s", e.Engine, e.Capability)
	if len(e.Origin) > 0 {
		msg += fmt.Sprintf(" required by statement %v", e.Origin)
	}
	if e.Grant != "" {
		msg += ": " + e.Grant
	}
	if e.Remedy != "" {
		msg += " (" + e.Remedy + ")"
	}
	return msg
}

// ErrUnsupported matches any UnsupportedError via errors.Is.
var ErrUnsupported = errors.New("unsupported by target engine")

// Is reports whether target is the ErrUnsupported sentinel.
func (e *UnsupportedError) Is(target error) bool { return target == ErrUnsupported }

// Registry maps engine ids to providers.
type Registry struct{ byEngine map[string]Provider }

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{byEngine: map[string]Provider{}} }

// Register adds a provider, panicking on a duplicate engine id since that can
// only be a programming error at wire-up time.
func (r *Registry) Register(p Provider) {
	if _, dup := r.byEngine[p.Engine()]; dup {
		panic("provider: duplicate registration for engine " + p.Engine())
	}
	r.byEngine[p.Engine()] = p
}

// Get returns the provider for an engine.
func (r *Registry) Get(engine string) (Provider, error) {
	p, ok := r.byEngine[engine]
	if !ok {
		return nil, fmt.Errorf("no provider registered for engine %q", engine)
	}
	return p, nil
}

// Engines lists registered engine ids.
func (r *Registry) Engines() []string {
	out := make([]string, 0, len(r.byEngine))
	for e := range r.byEngine {
		out = append(out, e)
	}
	return out
}
