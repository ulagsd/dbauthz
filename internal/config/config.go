// Package config loads db-iam server configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config is the server's runtime configuration.
type Config struct {
	Addr         string
	Targets      []Target
	ProbeTimeout time.Duration
}

// Target is one managed database, as configured at startup.
//
// DSN holds a connection string only because this is the evaluation path. The
// architecture calls for a secretRef resolved at use time from Vault, a K8s
// Secret or a cloud secret manager, and nothing here should be taken as the
// shape of that: a production deployment must not carry credentials in its
// environment.
type Target struct {
	ID     string
	Name   string
	Engine string
	DSN    string
}

// Redacted returns the DSN with any password removed, for display and logs.
// Every path that shows a connection string goes through this.
func (t Target) Redacted() string {
	u, err := url.Parse(t.DSN)
	if err != nil {
		return "(unparseable connection string)"
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	u.RawQuery = ""
	return u.String()
}

// Load reads configuration from the environment.
func Load() (Config, error) {
	c := Config{
		Addr:         envOr("DBIAM_ADDR", ":8080"),
		ProbeTimeout: 10 * time.Second,
	}

	// DBIAM_TARGETS is a comma-separated list of id=dsn pairs. One target is
	// the common case for the quickstart; the real control plane reads these
	// from its own database.
	raw := os.Getenv("DBIAM_TARGETS")
	if raw == "" {
		return c, fmt.Errorf("DBIAM_TARGETS is not set")
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, dsn, ok := strings.Cut(entry, "=")
		if !ok || id == "" || dsn == "" {
			return c, fmt.Errorf("DBIAM_TARGETS entry %q: want <id>=<connection string>", entry)
		}
		c.Targets = append(c.Targets, Target{
			ID: id, Name: id, Engine: "postgres", DSN: dsn,
		})
	}
	if len(c.Targets) == 0 {
		return c, fmt.Errorf("DBIAM_TARGETS contained no usable entries")
	}
	return c, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
