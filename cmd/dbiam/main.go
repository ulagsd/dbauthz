// Command dbiam is the db-iam command line interface.
package main

import (
	"fmt"
	"os"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
	"github.com/ulagsd/db-iam/internal/provider/postgres"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dbiam:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	reg := provider.NewRegistry()
	reg.Register(postgres.New())

	if len(args) == 0 {
		usage(reg)
		return nil
	}

	switch args[0] {
	case "version":
		fmt.Printf("dbiam %s\n", version)
		return nil
	case "actions":
		// The canonical vocabulary, so a policy author can see what exists
		// without reading the source.
		for _, a := range core.AllActions() {
			fmt.Printf("%-16s column-scoped=%-5t mutating=%t\n", a, a.ColumnScoped(), a.Mutating())
		}
		return nil
	case "engines":
		for _, e := range reg.Engines() {
			fmt.Println(e)
		}
		return nil
	default:
		usage(reg)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(reg *provider.Registry) {
	fmt.Fprintf(os.Stderr, `dbiam %s

Usage:
  dbiam <command>

Commands:
  version    Print the version
  actions    List the canonical action vocabulary
  engines    List registered database engines

Engines: %v
`, version, reg.Engines())
}
