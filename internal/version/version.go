// SPDX-License-Identifier: Apache-2.0

// Package version reports build information for the dbauthz binary.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set at link time by the release build, for example:
//
//	-ldflags "-X github.com/ulagsd/dbauthz/internal/version.version=v0.1.0"
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// Info describes the running build.
type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit,omitempty"`
	Date     string `json:"date,omitempty"`
	Modified bool   `json:"modified,omitempty"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

// Get returns the build information. Values not set at link time fall back to
// the VCS metadata the Go toolchain embeds in the binary.
func Get() Info {
	info := Info{
		Version:  version,
		Commit:   commit,
		Date:     date,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		case "vcs.modified":
			info.Modified = s.Value == "true"
		}
	}
	return info
}

// String renders the build information on one line.
func (i Info) String() string {
	commit := i.Commit
	if commit == "" {
		commit = "unknown"
	}
	if i.Modified {
		commit += "-dirty"
	}
	return fmt.Sprintf("dbauthz %s (commit %s, %s, %s)", i.Version, commit, i.Go, i.Platform)
}
