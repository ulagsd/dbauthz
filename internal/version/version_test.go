// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	info := Get()
	if info.Version == "" {
		t.Fatal("version is empty")
	}
	if info.Go != runtime.Version() {
		t.Errorf("Go = %q, want %q", info.Go, runtime.Version())
	}
	if want := runtime.GOOS + "/" + runtime.GOARCH; info.Platform != want {
		t.Errorf("Platform = %q, want %q", info.Platform, want)
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		{
			name: "release build",
			info: Info{Version: "v0.1.0", Commit: "abc123", Go: "go1.26.5", Platform: "linux/amd64"},
			want: "dbauthz v0.1.0 (commit abc123, go1.26.5, linux/amd64)",
		},
		{
			name: "dirty tree",
			info: Info{Version: "dev", Commit: "abc123", Modified: true, Go: "go1.26.5", Platform: "darwin/arm64"},
			want: "commit abc123-dirty",
		},
		{
			name: "no commit",
			info: Info{Version: "dev", Go: "go1.26.5", Platform: "darwin/arm64"},
			want: "commit unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.String(); !strings.Contains(got, tt.want) {
				t.Errorf("String() = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}
