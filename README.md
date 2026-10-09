# dbauthz

**Policy-driven access control for databases.**

dbauthz compiles one access policy into each database's native roles and
grants. It shows you the plan, applies it, and records every change in a
tamper-evident audit log.

> **Status: pre-alpha.** Nothing here is ready for production use.

## What it targets

| Engines | Support |
|---|---|
| PostgreSQL | First provider, in progress |
| MySQL / MariaDB | Second provider, planned |
| SQL Server, Oracle, Cassandra/ScyllaDB, ClickHouse, Snowflake, Redshift, MongoDB, Trino | Planned. These have native roles and grants |
| Apache Pinot, Elasticsearch/OpenSearch, Kafka, Druid | Planned. These control access through an admin API |

### Not supported, by design

**SQLite, DuckDB, RocksDB and LMDB will never be supported.** They have no
users, roles or grants. Anything that can open the file can read all of it, so
there is nothing for dbauthz to manage. dbauthz reports a clear error for these
engines rather than half-working.

## Build

Requires Go 1.26 or later.

```bash
make build
./bin/dbauthz version
```

## Documentation

- [Technology stack](docs/STACK.md): frozen decisions and their reasons
- [Engine reference](docs/reference.md): vendor documentation for every engine's
  permission model
- [Engineering workflow](docs/WORKFLOW.md): commits, branching, versioning and releases
- [Architecture decisions](docs/adr/README.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## Licence

[Apache-2.0](LICENSE)
