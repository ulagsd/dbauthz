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
			{"alice", true, true, []string{"analyst"}, "managed by db-iam"},
			{"analyst", false, true, []string{"app_ro"}, ""},
			{"bob", true, false, []string{"support"}, ""},
			{"dbiam_admin", true, true, []string{}, ""},
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
	if summary["principals"].(float64) != 4 {
		t.Errorf("principals = %v, want 4", summary["principals"])
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
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := resp.Header.Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", header, got, want)
		}
	}

	// The policy must name script-src and style-src explicitly. Leaving them
	// to fall back to default-src is what blocked the console's own script
	// while the page still rendered, so the absence of a directive is the bug
	// worth testing for.
	csp := resp.Header.Get("Content-Security-Policy")
	for _, directive := range []string{"script-src 'self'", "style-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("Content-Security-Policy is missing %q: %s", directive, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("the console needs no inline script or style; the policy should not allow it: %s", csp)
	}
}

// The console is only served if every file it asks for is actually there. An
// embed that quietly lost app.js would leave the same dead page as the CSP bug.
func TestConsoleServesItsAssets(t *testing.T) {
	ts := newTestServer(t, &stubConn{})

	for path, wantType := range map[string]string{
		"/app.js":  "javascript",
		"/app.css": "css",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d", path, resp.StatusCode)
			continue
		}
		if len(body) == 0 {
			t.Errorf("GET %s: empty", path)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, wantType) {
			t.Errorf("GET %s: Content-Type = %q, want %s", path, ct, wantType)
		}
	}
}

// The page must reference the external files, or splitting them achieved
// nothing and the CSP will block whatever is left inline.
func TestConsoleHasNoInlineScriptOrStyle(t *testing.T) {
	ts := newTestServer(t, &stubConn{})

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	page := string(body)

	if strings.Contains(page, "<script>") {
		t.Error("the page has an inline <script>, which the CSP blocks")
	}
	if strings.Contains(page, "<style>") {
		t.Error("the page has an inline <style>, which the CSP blocks")
	}
	for _, want := range []string{`src="app.js"`, `href="app.css"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not load %s", want)
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

// --- principals ------------------------------------------------------------

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
// what would reach the database. It deliberately has no Begin, which puts the
// server on the non-transactional path — the one with the interesting failure
// mode.
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

const (
	usersPath = "/api/v1/targets/demo-pg/users"
	rolesPath = "/api/v1/targets/demo-pg/roles"
)

// The split is the point: the endpoint decides whether the principal can
// authenticate, so a group role can never accidentally become a login.
func TestRoleAndUserEndpointsDecideLogin(t *testing.T) {
	t.Run("a role cannot log in", func(t *testing.T) {
		conn := &execConn{}
		ts := newTestServer(t, conn)

		got := postJSON(t, ts, rolesPath, `{"name":"reporting"}`, http.StatusCreated)

		if _, present := got["generated_password"]; present {
			t.Error("a role must not be given a password")
		}
		if !strings.Contains(conn.executed[0], "NOLOGIN") {
			t.Errorf("expected NOLOGIN: %s", conn.executed[0])
		}
		if strings.Contains(conn.executed[0], "PASSWORD") {
			t.Errorf("a role must not be given a password: %s", conn.executed[0])
		}
	})

	t.Run("a user can", func(t *testing.T) {
		conn := &execConn{}
		ts := newTestServer(t, conn)

		got := postJSON(t, ts, usersPath, `{"name":"dana"}`, http.StatusCreated)

		if pw, _ := got["generated_password"].(string); len(pw) < 12 {
			t.Errorf("generated_password = %q, want a strong generated password", pw)
		}
		if got["password_shown_once"] != true {
			t.Error("the response should say the password cannot be retrieved again")
		}
		if !strings.Contains(conn.executed[0], "LOGIN") ||
			strings.Contains(conn.executed[0], "NOLOGIN") {
			t.Errorf("expected LOGIN: %s", conn.executed[0])
		}
	})

	// The old shape carried a login flag. Rejecting it rather than ignoring it
	// means a caller upgrading from it finds out.
	t.Run("a login flag is refused on either endpoint", func(t *testing.T) {
		for _, path := range []string{usersPath, rolesPath} {
			ts := newTestServer(t, &execConn{})
			got := postJSON(t, ts, path, `{"name":"x","login":true}`, http.StatusBadRequest)
			if !strings.Contains(got["error"].(string), "login") {
				t.Errorf("%s: error = %v, want it to name the rejected field", path, got["error"])
			}
		}
	})
}

func TestCreateUserDryRunAppliesNothing(t *testing.T) {
	conn := &execConn{}
	ts := newTestServer(t, conn)

	got := postJSON(t, ts, usersPath, `{"name":"dana","dry_run":true}`, http.StatusOK)

	if got["applied"] != false {
		t.Errorf("applied = %v, want false", got["applied"])
	}
	if len(conn.executed) != 0 {
		t.Errorf("a dry run executed %d statements: %v", len(conn.executed), conn.executed)
	}
	if plan := got["plan"].(map[string]any); plan["hash"] == "" {
		t.Error("a dry run should still return a plan")
	}
	// A password that will never be used must not be handed out.
	if _, present := got["generated_password"]; present {
		t.Error("a dry run revealed a password for a user it did not create")
	}
}

// The property the whole password path exists for, asserted at the API edge.
func TestCreateUserNeverReturnsOrExecutesThePlaintext(t *testing.T) {
	const password = "correct-horse-battery-staple"
	conn := &execConn{}
	ts := newTestServer(t, conn)

	resp, err := http.Post(ts.URL+usersPath, "application/json",
		strings.NewReader(`{"name":"dana","password":"`+password+`"}`))
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
	if strings.Contains(conn.executed[0], password) {
		t.Fatal("the plaintext reached the database statement")
	}
	if !strings.Contains(conn.executed[0], "SCRAM-SHA-256$") {
		t.Errorf("expected a precomputed verifier in the statement: %s", conn.executed[0])
	}
}

func TestCreateUserWithRolesGrantsThemInTheSamePlan(t *testing.T) {
	conn := &execConn{}
	ts := newTestServer(t, conn)

	postJSON(t, ts, usersPath, `{"name":"dana","roles":["app_ro","analyst"]}`, http.StatusCreated)

	joined := strings.Join(conn.executed, "\n")
	for _, want := range []string{`GRANT "app_ro" TO "dana"`, `GRANT "analyst" TO "dana"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestCreateRejectsUnknownFields(t *testing.T) {
	ts := newTestServer(t, &execConn{})
	got := postJSON(t, ts, usersPath, `{"name":"dana","superuser":true}`, http.StatusBadRequest)

	if !strings.Contains(got["error"].(string), "superuser") {
		t.Errorf("error = %v, want it to name the rejected field", got["error"])
	}
}

func TestCreateValidationRejections(t *testing.T) {
	for _, tc := range []struct{ name, path, body, want string }{
		{"reserved prefix", usersPath, `{"name":"pg_evil"}`, "reserved"},
		{"empty name", usersPath, `{"name":""}`, "empty"},
		{"weak password", usersPath, `{"name":"dana","password":"short"}`, "at least"},
		{"bad valid_until", usersPath, `{"name":"dana","valid_until":"next tuesday"}`, "RFC 3339"},
		{"role with a bad parent", rolesPath, `{"name":"grp","roles":[" bad"]}`, "whitespace"},
		// Locking out the role db-iam connects as cannot be undone from here.
		{"the connected role", usersPath, `{"name":"dbiam_admin"}`, "connects as"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &execConn{}
			ts := newTestServer(t, conn)
			got := postJSON(t, ts, tc.path, tc.body, http.StatusBadRequest)
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
func TestCreateReportsIndeterminateStateOnPartialApply(t *testing.T) {
	conn := &execConn{failAt: 2} // CREATE ROLE succeeds, COMMENT fails
	ts := newTestServer(t, conn)

	got := postJSON(t, ts, usersPath, `{"name":"dana"}`, http.StatusInternalServerError)

	if got["indeterminate"] != true {
		t.Errorf("indeterminate = %v, want true: one statement ran and cannot be undone",
			got["indeterminate"])
	}
}

// --- membership ------------------------------------------------------------

func TestMembershipRevokesBeforeGranting(t *testing.T) {
	conn := &execConn{}
	ts := newTestServer(t, conn)

	postJSON(t, ts, usersPath+"/alice/roles",
		`{"grant":["app_rw"],"revoke":["app_ro"]}`, http.StatusOK)

	if len(conn.executed) != 2 {
		t.Fatalf("got %d statements: %v", len(conn.executed), conn.executed)
	}
	// The ordering is the fail-safe property: at no point does alice hold both
	// her old and her new access.
	if !strings.HasPrefix(conn.executed[0], "REVOKE") {
		t.Errorf("first statement should revoke, got: %s", conn.executed[0])
	}
	if !strings.HasPrefix(conn.executed[1], "GRANT") {
		t.Errorf("second statement should grant, got: %s", conn.executed[1])
	}
}

func TestMembershipRisk(t *testing.T) {
	ts := newTestServer(t, &execConn{})

	got := postJSON(t, ts, usersPath+"/alice/roles",
		`{"revoke":["app_ro"],"dry_run":true}`, http.StatusOK)

	plan := got["plan"].(map[string]any)
	if plan["max_risk"] != "revoke" {
		t.Errorf("max_risk = %v, want revoke: taking access away can break things",
			plan["max_risk"])
	}
}

// Granting pg_read_all_data is legitimate but defeats every table privilege
// db-iam manages, so the plan must say that rather than read like any grant.
func TestMembershipCallsOutBroadPredefinedRoles(t *testing.T) {
	ts := newTestServer(t, &execConn{})

	got := postJSON(t, ts, usersPath+"/alice/roles",
		`{"grant":["pg_read_all_data"],"dry_run":true}`, http.StatusOK)

	stmts := got["plan"].(map[string]any)["statements"].([]any)
	reason := stmts[0].(map[string]any)["reason"].(string)
	if !strings.Contains(reason, "bypassing table privileges") {
		t.Errorf("reason = %q, want it to explain how broad the role is", reason)
	}
}

func TestMembershipRejections(t *testing.T) {
	for _, tc := range []struct{ name, member, body, want string }{
		{"nothing to do", "alice", `{}`, "no roles"},
		{"contradiction", "alice", `{"grant":["app_ro"],"revoke":["app_ro"]}`, "both grant and revoke"},
		{"bad role name", "alice", `{"grant":["pg_evil "]}`, "whitespace"},
		{"the connected role", "dbiam_admin", `{"grant":["app_ro"]}`, "connects as"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &execConn{}
			ts := newTestServer(t, conn)
			got := postJSON(t, ts, usersPath+"/"+tc.member+"/roles", tc.body, http.StatusBadRequest)
			if !strings.Contains(got["error"].(string), tc.want) {
				t.Errorf("error = %v, want it to mention %q", got["error"], tc.want)
			}
			if len(conn.executed) != 0 {
				t.Errorf("a rejected request still executed %v", conn.executed)
			}
		})
	}
}

// --- listing ---------------------------------------------------------------

func TestListUsersAndRolesAreDisjoint(t *testing.T) {
	ts := newTestServer(t, &execConn{})

	users := getJSON(t, ts, usersPath, http.StatusOK)["principals"].([]any)
	roles := getJSON(t, ts, rolesPath, http.StatusOK)["principals"].([]any)

	for _, u := range users {
		if u.(map[string]any)["login"] != true {
			t.Errorf("a non-login principal appeared under users: %v", u)
		}
	}
	for _, r := range roles {
		if r.(map[string]any)["login"] != false {
			t.Errorf("a login principal appeared under roles: %v", r)
		}
	}
	if len(users) == 0 || len(roles) == 0 {
		t.Fatalf("expected both lists to be populated: %d users, %d roles", len(users), len(roles))
	}
}

func TestListMarksManagedAndSelf(t *testing.T) {
	ts := newTestServer(t, &execConn{})
	users := getJSON(t, ts, usersPath, http.StatusOK)["principals"].([]any)

	byName := map[string]map[string]any{}
	for _, u := range users {
		m := u.(map[string]any)
		byName[m["name"].(string)] = m
	}

	if byName["alice"]["managed"] != true {
		t.Error("alice carries the db-iam comment and should be marked managed")
	}
	if byName["bob"]["managed"] != false {
		t.Error("bob has no comment and must not be marked managed")
	}
	// The console needs this to stop an operator locking db-iam out of itself.
	if byName["dbiam_admin"]["self"] != true {
		t.Error("the connected role should be marked so the console can protect it")
	}
}

func TestAuditRecordsEveryAttemptAndChains(t *testing.T) {
	ts := newTestServer(t, &execConn{})

	postJSON(t, ts, usersPath, `{"name":"dana","dry_run":true}`, http.StatusOK)
	postJSON(t, ts, usersPath, `{"name":"dana"}`, http.StatusCreated)
	postJSON(t, ts, usersPath+"/dana/roles", `{"grant":["app_ro"]}`, http.StatusOK)
	postJSON(t, ts, usersPath, `{"name":"pg_evil"}`, http.StatusBadRequest)

	got := getJSON(t, ts, "/api/v1/audit", http.StatusOK)
	if got["chain_valid"] != true {
		t.Errorf("chain_valid = %v", got["chain_valid"])
	}
	// The rejected request never reached a plan, so it is not an audited
	// change; the dry run, the create and the membership change all are.
	if got["count"].(float64) != 3 {
		t.Errorf("count = %v, want 3", got["count"])
	}

	records := got["records"].([]any)
	if newest := records[0].(map[string]any); newest["action"] != "membership.change" {
		t.Errorf("newest action = %v", newest["action"])
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "SCRAM-SHA-256$") {
		t.Error("a verifier leaked into the audit record")
	}
}
