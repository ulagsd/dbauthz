// Package pgconn adapts pgx to the narrow provider.Querier surface.
//
// Keeping the driver behind provider.Querier is what lets the compiler and its
// golden-file tests run with no database at all; only introspection and apply
// need a real server.
package pgconn

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ulagsd/db-iam/internal/provider"
)

// Pool is a pgx connection pool exposed as a provider.Querier.
type Pool struct{ pool *pgxpool.Pool }

// Open dials the target and verifies the connection.
//
// The pool is deliberately small: db-iam issues DDL in short bursts, not
// sustained query traffic, and a privileged connection is something to hold as
// few of as possible.
func Open(ctx context.Context, dsn string) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing connection string: %w", err)
	}
	cfg.MaxConns = 4
	cfg.MinConns = 0
	cfg.MaxConnIdleTime = 2 * time.Minute
	cfg.MaxConnLifetime = 30 * time.Minute

	// Statements are built once and vary little, so the default prepared
	// statement cache is fine; what matters is that identifiers are always
	// quoted by the emitter rather than interpolated blindly.
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connecting: %w", err)
	}
	return &Pool{pool: pool}, nil
}

// Close releases the pool.
func (p *Pool) Close() { p.pool.Close() }

// Query runs a query.
func (p *Pool) Query(ctx context.Context, sql string, args ...any) (provider.Rows, error) {
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return &pgxRows{rows: rows}, nil
}

// Exec runs a statement, discarding the command tag.
func (p *Pool) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := p.pool.Exec(ctx, sql, args...)
	return err
}

type pgxRows struct{ rows pgx.Rows }

func (r *pgxRows) Next() bool             { return r.rows.Next() }
func (r *pgxRows) Scan(dest ...any) error { return r.rows.Scan(dest...) }
func (r *pgxRows) Err() error             { return r.rows.Err() }
func (r *pgxRows) Close()                 { r.rows.Close() }

var _ provider.Querier = (*Pool)(nil)

// Begin starts a transaction.
//
// PostgreSQL can roll back DDL, which is what lets an apply be all-or-nothing.
func (p *Pool) Begin(ctx context.Context) (provider.Tx, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &pgxTx{tx: tx}, nil
}

type pgxTx struct{ tx pgx.Tx }

func (t *pgxTx) Query(ctx context.Context, sql string, args ...any) (provider.Rows, error) {
	rows, err := t.tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return &pgxRows{rows: rows}, nil
}

func (t *pgxTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return err
}

func (t *pgxTx) Commit(ctx context.Context) error   { return t.tx.Commit(ctx) }
func (t *pgxTx) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }

var _ provider.Beginner = (*Pool)(nil)
