package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ulagsd/db-iam/internal/config"
	"github.com/ulagsd/db-iam/internal/provider"
	"github.com/ulagsd/db-iam/internal/provider/postgres"
)

const testDSN = "postgres://dbiam_admin:hunter2@db:5432/app?sslmode=disable"

// stubConn answers the provider's catalog queries with canned rows, so the
// handlers, the view layer and the redaction can be exercised with no server.
type stubConn struct{ failOn string }

func (c *stubConn) Close() {}

func (c *stubConn) Exec(context.Context, string, ...any) error { return nil }

func (c *stubConn) Query(_ context.Context, sql string, _ ...any) (provider.Rows, error) {
	if c.failOn != "" && strings.Contains(sql, c.failOn) {
		return nil, fmt.Errorf("boom")
	}
	switch {
	case strings.Contains(sql, "server_version_num"):
		return &stubRows{data: [][]any{{
			160004, "16.4", "dbiam_admin", true,
			false, false, false, false, false, false, false,
			[]string{},
		}}}, nil

	case strings.Contains(sql, "current_database()"):
		return &stubRows{data: [][]any{{"app"}}}, nil

	case strings.Contains(sql, "FROM pg_roles r"):
		return &stubRows{data: [][]any{
			{"alice", true, true, []string{"analyst"}},
			{"analyst", false, true, []string{"app_ro"}},
			{"bob", true, false, []string{"support"}},
		}}, nil

	case strings.Contains(sql, "c.relrowsecurity"):
		return &stubRows{data: [][]any{
			{"public", "orders", "r", "dbiam_admin", true, []string{"id", "tenant_id"}},
			{"public", "users", "r", "dbiam_admin", false, []string{"id", "email", "ssn"}},
			{"analytics", "v_active_users", "v", "analyst", false, []string{"id", "email"}},
		}}, nil

	case strings.Contains(sql, "aclexplode"):
		col := "email"
		return &stubRows{data: [][]any{
			{"public", "orders", "r", "support", "SELECT", (*string)(nil)},
			{"public", "users", "r", "support", "SELECT", &col},
			{"analytics", "v_active_users", "v", "PUBLIC", "SELECT", (*string)(nil)},
			// A privilege with no portable meaning must be skipped, not guessed at.
			{"public", "orders", "r", "alice", "MAINTAIN", (*string)(nil)},
		}}, nil
	}
	return &stubRows{}, nil
}

type stubRows struct {
	data [][]any
	i    int
}

func (r *stubRows) Next() bool { r.i++; return r.i <= len(r.data) }
func (r *stubRows) Err() error { return nil }
func (r *stubRows) Close()     {}

func (r *stubRows) Scan(dest ...any) error {
	row := r.data[r.i-1]
	if len(row) != len(dest) {
		return fmt.Errorf("stub: row has %d columns, scan wants %d", len(row), len(dest))
	}
	for i, v := range row {
		switch d := dest[i].(type) {
		case *string:
			*d = v.(string)
		case *bool:
			*d = v.(bool)
		case *int:
			*d = v.(int)
		case *[]string:
			*d = v.([]string)
		case **string:
			*d = v.(*string)
		default:
			return fmt.Errorf("stub: unsupported scan target %T at column %d", dest[i], i)
		}
	}
	return nil
}

func newTestServer(t *testing.T, conn TargetConn) *httptest.Server {
	t.Helper()
	reg := provider.NewRegistry()
	reg.Register(postgres.New())

	cfg := config.Config{
		Targets: []config.Target{{ID: "demo-pg", Name: "demo-pg", Engine: "postgres", DSN: testDSN}},
	}
	s := NewWithDialer(cfg, reg, slog.New(slog.DiscardHandler),
		func(context.Context, string) (TargetConn, error) { return conn, nil })

	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close() })
	return ts
}

func getJSON(t *testing.T, ts *httptest.Server, path string, want int) map[string]any {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("GET %s: status %d, want %d: %s", path, resp.StatusCode, want, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("GET %s: bad JSON: %v: %s", path, err, body)
	}
	return out
}

// The single most important assertion in this package: a connection string is
// a credential, and these responses reach a browser.
func TestTargetsRedactsThePassword(t *testing.T) {
	ts := newTestServer(t, &stubConn{})

	resp, err := http.Get(ts.URL + "/api/v1/targets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "hunter2") {
		t.Fatalf("the password leaked into the API response: %s", body)
	}
	if !strings.Contains(string(body), "xxxxx") {
		t.Errorf("expected a redacted connection string, got: %s", body)
	}
}

func TestConnectionErrorDoesNotLeakTheDSN(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register(postgres.New())
	cfg := config.Config{
		Targets: []config.Target{{ID: "demo-pg", Name: "demo-pg", Engine: "postgres", DSN: testDSN}},
	}
	// A driver error that echoes the connection string back, which pgx does.
	s := NewWithDialer(cfg, reg, slog.New(slog.DiscardHandler),
		func(context.Context, string) (TargetConn, error) {
			return nil, fmt.Errorf("failed to connect to `%s`: refused", testDSN)
		})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/targets/demo-pg/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "hunter2") {
		t.Fatalf("the password leaked through a driver error: %s", body)
	}
}

func TestCapabilitiesEndpoint(t *testing.T) {
	ts := newTestServer(t, &stubConn{})
	got := getJSON(t, ts, "/api/v1/targets/demo-pg/capabilities", http.StatusOK)

	if got["Engine"] != "postgres" || got["Version"] != "16.4" {
		t.Errorf("engine/version = %v/%v", got["Engine"], got["Version"])
	}
	// Rendered as names, not integers, or the console shows "2".
	if got["RowFilters"] != "native" {
		t.Errorf("RowFilters = %v, want \"native\"", got["RowFilters"])
	}
	if got["Masking"] != "substitute" {
		t.Errorf("Masking = %v, want \"substitute\"", got["Masking"])
	}
	if got["NativeDeny"] != false {
		t.Errorf("NativeDeny = %v, want false", got["NativeDeny"])
	}
	levels, ok := got["Levels"].([]any)
	if !ok || len(levels) != 5 {
		t.Errorf("Levels = %v, want five level names", got["Levels"])
	}
}

func TestSnapshotEndpoint(t *testing.T) {
	ts := newTestServer(t, &stubConn{})
	got := getJSON(t, ts, "/api/v1/targets/demo-pg/snapshot", http.StatusOK)

	summary := got["summary"].(map[string]any)
	if summary["principals"].(float64) != 3 {
		t.Errorf("principals = %v, want 3", summary["principals"])
	}
	if summary["objects"].(float64) != 3 {
		t.Errorf("objects = %v, want 3", summary["objects"])
	}
	// MAINTAIN has no portable meaning and must be dropped, not approximated.
	if summary["grants"].(float64) != 3 {
		t.Errorf("grants = %v, want 3 (the unmappable privilege must be skipped)", summary["grants"])
	}
	if summary["public_grants"].(float64) != 1 {
		t.Errorf("public_grants = %v, want 1", summary["public_grants"])
	}

	grants := got["grants"].([]any)
	var columnScoped map[string]any
	for _, g := range grants {
		gm := g.(map[string]any)
		if cols := gm["columns"].([]any); len(cols) > 0 {
			columnScoped = gm
		}
	}
	if columnScoped == nil {
		t.Fatal("expected one column-scoped grant")
	}
	if columnScoped["object"] != "users" || columnScoped["columns"].([]any)[0] != "email" {
		t.Errorf("column grant = %v", columnScoped)
	}

	// A view must keep its kind: table/x and view/x are different resources.
	var sawView bool
	for _, o := range got["objects"].([]any) {
		if om := o.(map[string]any); om["kind"] == "view" && om["name"] == "v_active_users" {
			sawView = true
			if om["owner"] != "analyst" {
				t.Errorf("view owner = %v, want analyst", om["owner"])
			}
		}
	}
	if !sawView {
		t.Error("the view was not reported as kind=view")
	}
}

func TestUnknownTargetIs404(t *testing.T) {
	ts := newTestServer(t, &stubConn{})
	getJSON(t, ts, "/api/v1/targets/nope/capabilities", http.StatusNotFound)
}

func TestIntrospectFailurePropagates(t *testing.T) {
	ts := newTestServer(t, &stubConn{failOn: "aclexplode"})
	got := getJSON(t, ts, "/api/v1/targets/demo-pg/snapshot", http.StatusInternalServerError)
	if !strings.Contains(got["error"].(string), "grants") {
		t.Errorf("error = %v, want it to name the failing stage", got["error"])
	}
}

func TestActionsEndpoint(t *testing.T) {
	ts := newTestServer(t, &stubConn{})
	got := getJSON(t, ts, "/api/v1/actions", http.StatusOK)

	actions := got["actions"].([]any)
	if len(actions) == 0 {
		t.Fatal("no actions returned")
	}
	sets := got["permission_sets"].(map[string]any)
	if _, ok := sets["reader"]; !ok {
		t.Errorf("permission_sets = %v, want a reader set", sets)
	}
}

func TestConsoleIsServedWithHardeningHeaders(t *testing.T) {
	ts := newTestServer(t, &stubConn{})

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "db-iam") {
		t.Error("console did not render")
	}
	for header, want := range map[string]string{
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "frame-ancestors 'none'",
	} {
		if got := resp.Header.Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", header, got, want)
		}
	}
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t, &stubConn{})
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d", resp.StatusCode)
	}
}
