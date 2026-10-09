// SPDX-License-Identifier: Apache-2.0

// Package cli implements the dbauthz command-line interface.
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// NewRootCommand builds the dbauthz command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "dbauthz",
		Short: "Policy-driven access control for databases",
		Long: "dbauthz compiles access policy into each database's native roles and grants,\n" +
			"shows the plan, and applies it with an audit record.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCommand())
	return root
}

// Execute runs the CLI with the given arguments and returns the process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := NewRootCommand()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(stderr, "Error:", err)
		return 1
	}
	return 0
}
