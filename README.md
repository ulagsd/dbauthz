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
make up
open http://127.0.0.1:8080
make down-clean    # stop and delete the demo database
```

Three containers:

| | | |
|---|---|---|
| `console` | `127.0.0.1:8080` | nginx: serves the console, reverse-proxies `/api` to the API |
| `dbiam` | `127.0.0.1:8081` | the API, for `curl` |
| `postgres` | `127.0.0.1:15432` | the database being managed |

Every port is loopback-bound, and Postgres deliberately avoids 5432 since a
developer is likely to have one there already. Override with
`DBIAM_CONSOLE_PORT`, `DBIAM_API_PORT`, `DBIAM_PG_PORT`.

The console reaches the API through the nginx proxy rather than directly, so
the browser sees one origin and there is no CORS policy to maintain. The
server binary *also* embeds the same console — that stays the right answer for
a single-binary deployment, and the separate container is for stacks that want
the front end released or scaled on its own. Both read the same files, so
there is one source of truth.

`make up-dev` serves the console from the working tree in both containers, for
editing without a rebuild.

The stack seeds a deliberately messy demo estate — a grant to `PUBLIC`, a
column-level grant that withholds `ssn`, a table with row-level security
already enabled, a `NOINHERIT` role, and an object owned by another role —
because every one of those is something the solver will have to reason about.

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
