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

	// Verify's existence check, after a role is created.
	case strings.Contains(sql, "EXISTS (SELECT 1 FROM pg_roles"):
		return &stubRows{data: [][]any{{true}}}, nil

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

// --- create user -----------------------------------------------------------

func postJSON(t *testing.T, ts *httptest.Server, path, body string, want int) map[string]any {
	t.Helper()
	resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("POST %s: status %d, want %d: %s", path, resp.StatusCode, want, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("POST %s: bad JSON: %v: %s", path, err, raw)
	}
	return out
}

// execConn records the statements it is asked to run, so a test can assert on
// what would reach the database.
type execConn struct {
	stubConn
	executed []string
	failAt   int // 1-based; 0 never fails
}

func (c *execConn) Exec(_ context.Context, sql string, _ ...any) error {
	c.executed = append(c.executed, sql)
	if c.failAt > 0 && len(c.executed) == c.failAt {
		return fmt.Errorf("simulated failure")
	}
	return nil
}

// Begin is deliberately absent: without it the server exercises the
// non-transactional path, which is the one with the interesting failure mode.

func TestCreateUserDryRunAppliesNothing(t *testing.T) {
	conn := &execConn{}
	ts := newTestServer(t, conn)

	got := postJSON(t, ts, "/api/v1/targets/demo-pg/users",
		`{"name":"dana","login":true,"dry_run":true}`, http.StatusOK)

	if got["applied"] != false {
		t.Errorf("applied = %v, want false", got["applied"])
	}
	if len(conn.executed) != 0 {
		t.Errorf("a dry run executed %d statements: %v", len(conn.executed), conn.executed)
	}
	if plan := got["plan"].(map[string]any); plan["hash"] == "" {
		t.Error("a dry run should still return a plan")
	}
}

// The property the whole password path exists for, asserted at the API edge.
func TestCreateUserNeverReturnsOrExecutesThePlaintext(t *testing.T) {
	const password = "correct-horse-battery-staple"
	conn := &execConn{}
	ts := newTestServer(t, conn)

	resp, err := http.Post(ts.URL+"/api/v1/targets/demo-pg/users", "application/json",
		strings.NewReader(`{"name":"dana","login":true,"password":"`+password+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), password) {
		t.Fatalf("the plaintext password came back in the response: %s", body)
	}
	if strings.Contains(string(body), "SCRAM-SHA-256$") {
		t.Fatalf("the verifier leaked into the response, which is enough for an "+
			"offline attack: %s", body)
	}

	create := conn.executed[0]
	if strings.Contains(create, password) {
		t.Fatal("the plaintext reached the database statement")
	}
	if !strings.Contains(create, "SCRAM-SHA-256$") {
		t.Errorf("expected a precomputed verifier in the statement: %s", create)
	}
}

func TestCreateUserGeneratesAPasswordWhenNoneIsGiven(t *testing.T) {
	ts := newTestServer(t, &execConn{})

	got := postJSON(t, ts, "/api/v1/targets/demo-pg/users",
		`{"name":"dana","login":true}`, http.StatusCreated)

	pw, _ := got["generated_password"].(string)
	if len(pw) < 12 {
		t.Fatalf("generated_password = %q, want a strong generated password", pw)
	}
	if got["password_shown_once"] != true {
		t.Error("the response should say the password cannot be retrieved again")
	}
	if got["verified"] != true {
		t.Error("the created role should be verified against the database")
	}
}

// A group role has nothing to authenticate with, so generating a password for
// it would be noise the operator has to ignore.
func TestCreateGroupRoleGeneratesNoPassword(t *testing.T) {
	conn := &execConn{}
	ts := newTestServer(t, conn)

	got := postJSON(t, ts, "/api/v1/targets/demo-pg/users",
		`{"name":"app_ro","login":false}`, http.StatusCreated)

	if _, present := got["generated_password"]; present {
		t.Error("a role that cannot log in must not be given a password")
	}
	if !strings.Contains(conn.executed[0], "NOLOGIN") {
		t.Errorf("expected NOLOGIN: %s", conn.executed[0])
	}
}

// An unknown field must not be ignored. Silently dropping "superuser": true
// would let a caller believe they asked for something they did not get.
func TestCreateUserRejectsUnknownFields(t *testing.T) {
	ts := newTestServer(t, &execConn{})
	got := postJSON(t, ts, "/api/v1/targets/demo-pg/users",
		`{"name":"dana","superuser":true}`, http.StatusBadRequest)

	if !strings.Contains(got["error"].(string), "superuser") {
		t.Errorf("error = %v, want it to name the rejected field", got["error"])
	}
}

func TestCreateUserValidationRejections(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"reserved prefix", `{"name":"pg_evil"}`, "reserved"},
		{"empty name", `{"name":""}`, "empty"},
		{"weak password", `{"name":"dana","login":true,"password":"short"}`, "at least"},
		{"password on a group role", `{"name":"grp","login":false,"password":"a-long-enough-one"}`, "must not have a password"},
		{"bad valid_until", `{"name":"dana","valid_until":"next tuesday"}`, "RFC 3339"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &execConn{}
			ts := newTestServer(t, conn)
			got := postJSON(t, ts, "/api/v1/targets/demo-pg/users", tc.body, http.StatusBadRequest)
			if !strings.Contains(got["error"].(string), tc.want) {
				t.Errorf("error = %v, want it to mention %q", got["error"], tc.want)
			}
			if len(conn.executed) != 0 {
				t.Errorf("a rejected request still executed %v", conn.executed)
			}
		})
	}
}

// Without a transaction, a failure after the first statement leaves the target
// in a state nobody asked for. That has to be reported, not retried.
func TestCreateUserReportsIndeterminateStateOnPartialApply(t *testing.T) {
	conn := &execConn{failAt: 2} // CREATE ROLE succeeds, COMMENT fails
	ts := newTestServer(t, conn)

	got := postJSON(t, ts, "/api/v1/targets/demo-pg/users",
		`{"name":"dana","login":true}`, http.StatusInternalServerError)

	if got["indeterminate"] != true {
		t.Errorf("indeterminate = %v, want true: one statement ran and cannot be undone",
			got["indeterminate"])
	}
}

func TestAuditRecordsEveryAttemptAndChains(t *testing.T) {
	ts := newTestServer(t, &execConn{})

	postJSON(t, ts, "/api/v1/targets/demo-pg/users", `{"name":"dana","login":true,"dry_run":true}`, http.StatusOK)
	postJSON(t, ts, "/api/v1/targets/demo-pg/users", `{"name":"dana","login":true}`, http.StatusCreated)
	postJSON(t, ts, "/api/v1/targets/demo-pg/users", `{"name":"pg_evil"}`, http.StatusBadRequest)

	got := getJSON(t, ts, "/api/v1/audit", http.StatusOK)
	if got["chain_valid"] != true {
		t.Errorf("chain_valid = %v", got["chain_valid"])
	}
	// The rejected request never reached a plan, so it is not an audited
	// change; the dry run and the apply both are.
	if got["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", got["count"])
	}

	records := got["records"].([]any)
	newest := records[0].(map[string]any)
	if newest["action"] != "role.create" {
		t.Errorf("newest action = %v", newest["action"])
	}
	// The audit must not become the place the secret finally leaks.
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "SCRAM-SHA-256$") {
		t.Error("a verifier leaked into the audit record")
	}
	if newest["intent"].(map[string]any)["password_generated"] != true {
		t.Error("the audit should record that a password was generated")
	}
}
