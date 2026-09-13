package postgres

import (
	"context"
	"fmt"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
)

// Provider is the PostgreSQL implementation of provider.Provider.
type Provider struct{}

// New returns the PostgreSQL provider.
func New() *Provider { return &Provider{} }

// Engine returns the canonical engine id.
func (pr *Provider) Engine() string { return Engine }

var errNotImplemented = fmt.Errorf("postgres provider: not implemented yet")

// Introspect reads observed state from the target.
func (pr *Provider) Introspect(context.Context, provider.Querier, provider.Scope, provider.Cursor) (*provider.Snapshot, error) {
	return nil, errNotImplemented
}

// Compile lowers a portable permission set into PostgreSQL statements.
func (pr *Provider) Compile(*core.EffectivePermissionSet, core.Capabilities, provider.CompileOptions) (*provider.StatementSet, error) {
	return nil, errNotImplemented
}

// Diff produces an ordered plan from desired statements and observed state.
func (pr *Provider) Diff(*provider.StatementSet, *provider.Snapshot) (*provider.Plan, error) {
	return nil, errNotImplemented
}

// Apply executes a plan against the target.
func (pr *Provider) Apply(context.Context, provider.Querier, *provider.Plan) (*provider.ApplyResult, error) {
	return nil, errNotImplemented
}

// Verify re-reads the target and asserts the plan's intent holds.
func (pr *Provider) Verify(context.Context, provider.Querier, *provider.Plan) (*provider.VerifyResult, error) {
	return nil, errNotImplemented
}

// Compile-time assertion that the provider satisfies the SPI.
var _ provider.Provider = (*Provider)(nil)
