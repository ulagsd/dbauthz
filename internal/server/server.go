// Package server exposes db-iam over HTTP and serves the console.
//
// This is the evaluation server. It has no authentication, no tenancy and no
// authorization, and it must not be exposed beyond localhost: the API reaches
// a privileged database connection, so anything that can call it can read the
// shape of every managed database. The control-plane design in
// docs/ARCHITECTURE.md §12 is what replaces this.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ulagsd/db-iam/internal/audit"
	"github.com/ulagsd/db-iam/internal/config"
	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/pgconn"
	"github.com/ulagsd/db-iam/internal/provider"
)

// TargetConn is a live connection to one managed database.
type TargetConn interface {
	provider.Querier
	Close()
}

// DialFunc opens a connection to a target. It is a field on Server rather than
// a direct call so the API can be tested against a stub, which matters: these
// handlers are the layer most likely to leak a credential, and that is worth
// asserting without standing up a database.
type DialFunc func(ctx context.Context, dsn string) (TargetConn, error)

// Server holds the wiring for the evaluation API.
type Server struct {
	cfg      config.Config
	registry *provider.Registry
	log      *slog.Logger
	dial     DialFunc
	audit    *audit.Log

	mu    sync.Mutex
	conns map[string]TargetConn // lazily opened, keyed by target id
}

// New builds a server that connects to targets with pgx.
func New(cfg config.Config, reg *provider.Registry, log *slog.Logger) *Server {
	return NewWithDialer(cfg, reg, log, func(ctx context.Context, dsn string) (TargetConn, error) {
		return pgconn.Open(ctx, dsn)
	})
}

// NewWithDialer builds a server with a custom connection opener.
func NewWithDialer(cfg config.Config, reg *provider.Registry, log *slog.Logger, dial DialFunc) *Server {
	return &Server{
		cfg: cfg, registry: reg, log: log, dial: dial,
		audit: audit.New(),
		conns: map[string]TargetConn{},
	}
}

// Close releases every open target connection.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.conns {
		c.Close()
		delete(s.conns, id)
	}
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /api/v1/actions", s.handleActions)
	mux.HandleFunc("GET /api/v1/targets", s.handleTargets)
	mux.HandleFunc("GET /api/v1/targets/{id}/capabilities", s.handleCapabilities)
	mux.HandleFunc("GET /api/v1/targets/{id}/snapshot", s.handleSnapshot)
	mux.HandleFunc("POST /api/v1/targets/{id}/users", s.handleCreateUser)
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	mux.Handle("/", consoleHandler())

	return s.withLogging(mux)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Debug("request",
			"method", r.Method, "path", r.URL.Path,
			"status", rec.status, "duration", time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// --- handlers ---

type targetView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Engine     string `json:"engine"`
	Connection string `json:"connection"` // always redacted
}

func (s *Server) handleTargets(w http.ResponseWriter, _ *http.Request) {
	out := make([]targetView, 0, len(s.cfg.Targets))
	for _, t := range s.cfg.Targets {
		out = append(out, targetView{
			ID: t.ID, Name: t.Name, Engine: t.Engine,
			// Redacted, always: a connection string is a credential and this
			// response reaches a browser.
			Connection: t.Redacted(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": out})
}

type actionView struct {
	Name         string `json:"name"`
	ColumnScoped bool   `json:"column_scoped"`
	Mutating     bool   `json:"mutating"`
}

func (s *Server) handleActions(w http.ResponseWriter, _ *http.Request) {
	actions := core.AllActions()
	out := make([]actionView, 0, len(actions))
	for _, a := range actions {
		out = append(out, actionView{
			Name: string(a), ColumnScoped: a.ColumnScoped(), Mutating: a.Mutating(),
		})
	}
	sets := map[string][]string{}
	for name, set := range core.BuiltinPermissionSets {
		for _, a := range set.Sorted() {
			sets[name] = append(sets[name], string(a))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": out, "permission_sets": sets})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	target, prov, conn, err := s.resolve(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ProbeTimeout)
	defer cancel()

	caps, err := prov.Capabilities(ctx, conn)
	if err != nil {
		writeError(w, fmt.Errorf("probing %s: %w", target.ID, err))
		return
	}
	writeJSON(w, http.StatusOK, caps)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	target, prov, conn, err := s.resolve(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	scope := provider.Scope{Target: core.TargetRef{
		ID: target.ID, Name: target.Name, Engine: target.Engine,
	}}
	snap, err := prov.Introspect(ctx, conn, scope, "")
	if err != nil {
		writeError(w, fmt.Errorf("introspecting %s: %w", target.ID, err))
		return
	}
	writeJSON(w, http.StatusOK, snapshotView(snap))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ProbeTimeout)
	defer cancel()

	for _, t := range s.cfg.Targets {
		if _, _, _, err := s.resolve(ctx, t.ID); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ready": false, "target": t.ID, "error": err.Error(),
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true})
}

// --- helpers ---

var errNoSuchTarget = errors.New("no such target")

func (s *Server) resolve(ctx context.Context, id string) (config.Target, provider.Provider, TargetConn, error) {
	var target config.Target
	found := false
	for _, t := range s.cfg.Targets {
		if t.ID == id {
			target, found = t, true
			break
		}
	}
	if !found {
		return target, nil, nil, fmt.Errorf("%w: %q", errNoSuchTarget, id)
	}

	prov, err := s.registry.Get(target.Engine)
	if err != nil {
		return target, nil, nil, err
	}

	conn, err := s.connFor(ctx, target)
	if err != nil {
		return target, nil, nil, err
	}
	return target, prov, conn, nil
}

func (s *Server) connFor(ctx context.Context, t config.Target) (TargetConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c, ok := s.conns[t.ID]; ok {
		return c, nil
	}
	c, err := s.dial(ctx, t.DSN)
	if err != nil {
		// Only the redacted form may appear here. A driver error often echoes
		// the connection string back, so the message is rebuilt rather than
		// wrapped verbatim.
		return nil, fmt.Errorf("connecting to %s (%s): %s", t.ID, t.Redacted(), redactErr(err, t))
	}
	s.conns[t.ID] = c
	return c, nil
}

// redactErr strips a target's connection string out of a driver error, since
// pgx includes the DSN in several of its messages and this text reaches the
// browser.
func redactErr(err error, t config.Target) string {
	return strings.ReplaceAll(err.Error(), t.DSN, t.Redacted())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// contextWithTimeout bounds a handler's work against the request's own context.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, errNoSuchTarget) {
		status = http.StatusNotFound
	}
	writeJSON(w, status, map[string]any{"error": err.Error()})
}
