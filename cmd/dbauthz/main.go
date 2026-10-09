// SPDX-License-Identifier: Apache-2.0

// Command dbauthz is the dbauthz CLI and server binary.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ulagsd/dbauthz/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
