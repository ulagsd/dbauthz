# db-iam

Database-agnostic, IAM-style fine-grained access management for databases.

One declarative policy, compiled into each engine's own native privilege
primitives — so enforcement holds no matter how a client connects: `psql`, an
ORM, a BI tool, or an AI agent.

> **Status: early.** The engine-neutral core, the provider contract and
> PostgreSQL introspection work. The solver, the compiler and apply do not
> exist yet. There is no authentication. Do not point this at a production
> database.

## Quickstart

```bash
make up            # postgres + db-iam + console on 127.0.0.1:8080
open http://127.0.0.1:8080
make down-clean    # stop and delete the demo database
```

The stack seeds a deliberately messy demo estate — a grant to `PUBLIC`, a
column-level grant that withholds `ssn`, a table with row-level security
already enabled, and a `NOINHERIT` role — because every one of those is
something the solver will have to reason about.

The console is embedded in the server binary, so the stack is two containers,
not three: one image, one process, one origin, and no CORS. `make up-dev`
serves it from the working tree instead, for editing without a rebuild.

## What works today

| | |
|---|---|
| `internal/core` | Resource paths, action vocabulary, capability model, row-filter predicate AST. Engine-neutral; may not import a driver. |
| `internal/provider` | The contract every engine implements. |
| `internal/provider/postgres` | Capability probe (RDS, Aurora, Cloud SQL, Azure, Neon, Supabase, Timescale) and catalog introspection. |
| `internal/server` | Evaluation HTTP API and the embedded console. |

Not yet: the solver, `Compile`, `Diff`, `Apply`, `Verify`, policy documents,
authentication, tenancy, audit.

## Development

```bash
make check   # fmt, vet, lint, race tests
make build   # bin/dbiam
```

## Documents

- [docs/RESEARCH.md](docs/RESEARCH.md) — competitive landscape, engine capability matrix, technology strategy
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — architecture and high-level design

## Licence

Apache-2.0.
