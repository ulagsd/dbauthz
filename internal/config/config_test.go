package config

import (
	"strings"
	"testing"
)

func TestRedacted(t *testing.T) {
	for _, tc := range []struct{ name, dsn, wantGone, wantKept string }{
		{
			name:     "password is replaced",
			dsn:      "postgres://admin:hunter2@db:5432/app?sslmode=disable",
			wantGone: "hunter2",
			wantKept: "admin",
		},
		{
			name:     "query string is dropped",
			dsn:      "postgres://admin:hunter2@db:5432/app?password=alsosecret",
			wantGone: "alsosecret",
			wantKept: "db:5432",
		},
		{
			name:     "no password is fine",
			dsn:      "postgres://admin@db:5432/app",
			wantGone: "xxxxx",
			wantKept: "admin",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Target{DSN: tc.dsn}.Redacted()
			if strings.Contains(got, tc.wantGone) {
				t.Errorf("Redacted() = %q, must not contain %q", got, tc.wantGone)
			}
			if !strings.Contains(got, tc.wantKept) {
				t.Errorf("Redacted() = %q, want it to keep %q", got, tc.wantKept)
			}
		})
	}
}

// An unparseable DSN must not fall through to printing the original.
func TestRedactedFailsClosed(t *testing.T) {
	got := Target{DSN: "://not a url:hunter2@"}.Redacted()
	if strings.Contains(got, "hunter2") {
		t.Errorf("Redacted() leaked on a malformed DSN: %q", got)
	}
}

func TestLoadTargets(t *testing.T) {
	t.Setenv("DBIAM_TARGETS", "a=postgres://x@h/a, b=postgres://y@h/b")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Targets) != 2 || cfg.Targets[0].ID != "a" || cfg.Targets[1].ID != "b" {
		t.Fatalf("targets = %+v", cfg.Targets)
	}
	if cfg.Addr != ":8080" {
		t.Errorf("Addr = %q, want the default", cfg.Addr)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ name, val string }{
		{"empty", ""},
		{"no separator", "just-an-id"},
		{"missing id", "=postgres://h/db"},
		{"missing dsn", "a="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DBIAM_TARGETS", tc.val)
			if _, err := Load(); err == nil {
				t.Errorf("Load() accepted %q", tc.val)
			}
		})
	}
}
