# db-iam — Technology Stack Freeze

> **v0.1 · 2026-09-22 · FOR REVIEW, NOT YET FROZEN**
>
> Scope: languages, libraries, tools, services, packaging and licence.
> Out of scope: architecture diagrams, HLD, API shapes, data models. Those come
> after this document is agreed.
>
> Every decision carries a status — **FROZEN**, **PROPOSED** or **OPEN** — and
> what it would cost to reverse. Nothing here is settled until you say so.

---

## 0. Read this first

One finding from the research changes the shape of the product, and it has to
be resolved before a stack can be frozen, because one of the answers adds a
whole delivery surface.

**The engines you listed do not share an identity model. They fall into three
classes, and only two of them are the same product.**

| Class | Engines | Identity model | What db-iam can do |
|---|---|---|---|
| **A — native privilege system** | PostgreSQL, MySQL/MariaDB, SQL Server, Oracle, Cassandra/ScyllaDB, ClickHouse, Snowflake, Redshift, MongoDB, Trino | Roles + GRANT, or equivalent | Compile policy into native statements. **This is the product.** |
| **B — access control, but not via SQL** | Apache Pinot, Elasticsearch/OpenSearch, Kafka, Druid | Admin API / config-driven ACLs | Same pipeline, different emitter: compile to their API instead of SQL |
| **C — no identity model at all** | **SQLite, DuckDB, RocksDB, LMDB** | None. There are no users. | **Nothing.** |

Class C is not a gap to fill later. It is a category error:

- [SQLite has no `GRANT`/`REVOKE`](https://flaviocopes.com/sqlite-user-permissions/). The database is one file, and anything that can open the file can read all of it. The security boundary is the filesystem.
- **RocksDB** is a library linked into your process. There is no connection, no session and no principal — only your application's own code.
- **DuckDB** is embedded and OLAP-focused, with the same property.

So "IAM for RocksDB" cannot mean what "IAM for Postgres" means. There are only
three coherent answers, and they are different products:

1. **Out of scope.** Say so plainly in the README. The capability model still
   needs to *express* "this engine has no identity system" so the answer is a
   clear refusal rather than a half-working provider.
2. **A policy decision API** the embedding application calls before it reads
   (a PDP, plus client SDKs). This is a genuinely useful product — it is what
   Cedar is for — but it is a **library integration**, not an agent, and it
   would add SDKs in Go, Python, Java, Node and Rust to the stack.
3. **A proxy in front of the file.** For RocksDB that means replacing the
   library. Not viable.

> **Recommendation: Class A and B in scope. Class C explicitly out of scope for
> v1.** Revisit only if you decide to build (2), which is a separate product
> decision, not a driver.

Everything below assumes that recommendation. **If you want Class C in, say so
now** — it adds a multi-language SDK surface and changes §2.4 and §2.9.

---

## 1. Core language

### FROZEN — **Go 1.26+** for control plane, agent, CLI, operator and providers

The deciding factor is not taste. It is that **every in-scope engine has a
pure-Go driver, and the only engines that need cgo are the ones with no
identity model anyway.**

| Engine | Driver | Pure Go | Notes |
|---|---|---|---|
| PostgreSQL | `jackc/pgx` v5 | ✅ | Best Postgres client in any language; also exposes the wire protocol |
| MySQL / MariaDB | `go-sql-driver/mysql` | ✅ | |
| SQL Server | `microsoft/go-mssqldb` | ✅ | First-party |
| Cassandra / ScyllaDB | `apache/cassandra-gocql-driver` | ✅ | Now an ASF project |
| ClickHouse | `ClickHouse/clickhouse-go` | ✅ | First-party |
| Snowflake | `snowflakedb/gosnowflake` | ✅ | First-party |
| MongoDB | `mongodb/mongo-go-driver` | ✅ | First-party |
| Trino | `trinodb/trino-go-client` | ✅ | |
| Apache Pinot | plain HTTP to the controller | ✅ | Admin API; no driver needed |
| SQLite | `modernc.org/sqlite` | ✅ | Pure Go exists — but Class C |
| **DuckDB** | `duckdb/duckdb-go` | ❌ **cgo** | [Requires `CGO_ENABLED=1`](https://github.com/marcboeker/go-duckdb) |
| **RocksDB** | `linxGnu/grocksdb` | ❌ **cgo** | C++ bindings |

That split is unusually clean, and it is load-bearing: **the entire in-scope
engine list builds with `CGO_ENABLED=0`.** That one fact is what buys the
single static binary, free cross-compilation to six targets, `distroless/static`
images, and no glibc/musl divergence. Drivers needing cgo cannot ship without
giving that up, and cross-compilation turns cgo off by itself.

**Alternatives considered and rejected:**

- **Rust** — the strongest runner-up, and correct if a high-throughput wire
  proxy were core to v1. Cedar's reference implementation is Rust. Rejected
  because driver coverage outside Postgres/MySQL is materially thinner, the
  operator and Terraform ecosystems are Go, and the contributor pool for
  infrastructure OSS is smaller. Revisit only for a future data-path proxy.
- **Java** — Apache Ranger's lineage, and the only place with first-party SDKs
  for every warehouse. Rejected on JVM footprint and the absence of any
  single-binary story, which is a stated requirement.
- **TypeScript / Node** — fine for the console, not for a privileged agent
  binary. Driver quality is uneven and the distribution story is poor.
- **Python** — pgbedrock and Permifrost both chose it and both stalled. Packaging
  a privileged tool with a Python runtime is a recurring support cost.

**Reversal cost: very high.** This is the one decision everything else assumes.

---

## 2. Extensibility — how engines get added

This is the "flexible and dynamic for drivers to be added later" requirement,
and it is the most important design decision in this document.

### 2.1 Mechanism

Three options were researched:

| Option | How | Verdict |
|---|---|---|
| **In-tree Go interface** | Providers compiled into the binary | **FROZEN as primary** |
| [`hashicorp/go-plugin`](https://pkg.go.dev/github.com/hashicorp/go-plugin) | Subprocess over gRPC; plugins in any language | **PROPOSED as escape hatch, deferred to v2** |
| WASM ([wazero](https://wazero.io) / Extism) | Sandboxed, in-process | **Rejected** |

**Why WASM is rejected** despite being the fashionable answer: a WASM module
cannot touch the network unless the host hands it that capability, and WASI
sockets remain immature. A database provider's entire job is to open a
connection to a database. A sandbox that cannot do network I/O is the wrong
sandbox for this workload. wazero is excellent — this is not its use case.

**Why go-plugin is not the primary mechanism**: it buys language independence
we do not need, since every in-scope driver is already Go. The price is process
supervision, version skew between host and plugin, and a much harder debugging
story. HashiCorp uses it because Terraform providers are written by strangers;
db-iam's providers will be written by contributors to db-iam.

**Why go-plugin stays on the roadmap**: it is the answer when someone needs an
engine whose only usable SDK is Java or Python, or a cgo driver they do not
want linked into the main binary. Deferred, not discarded.

### 2.2 The rule that keeps the option open

> **The provider interface exchanges only serialisable values.**
> No `*sql.DB`, no open handles, no callbacks, no `any` crossing the boundary.

That single constraint means the in-tree interface can be lifted onto gRPC
later without redesigning it. It costs almost nothing now and is expensive to
retrofit. It is the concrete meaning of "flexible for drivers to be added
later."

### 2.3 Provider conformance tiers

Adding an engine is a contribution, so the bar has to be legible:

| Tier | Meaning |
|---|---|
| **Full** | Every capability expressed natively; complete golden-file corpus |
| **Partial** | Some capabilities only via documented substitutes |
| **Experimental** | Compiles, not production-validated |

A shared fixture corpus with per-provider expected output is what makes "does
MySQL handle column denies correctly?" a diff rather than an argument. **Build
it before the second provider exists.**

---

## 3. Policy engine

### FROZEN — **[Cedar](https://www.cedarpolicy.com/), embedded via `cedar-policy/cedar-go`**

- Apache-2.0, **CNCF Sandbox**, v4.x, ~1.17M downloads
- [Cedar Analysis](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/) gives **formal verification of policy properties in CI** — you can prove "no policy grants write on `payments` to a non-finance principal" rather than test samples. Nothing else in this space offers it, and it is a genuine differentiator to lead with.
- SDKs in Go, Rust, Java, Python, TypeScript — matters if Class C ever pulls in an SDK surface
- Reads like AWS IAM, which is the mental model you asked for
- Embedded, so no sidecar and no network hop on the hot path

**Rejected:**
- **OPA / Rego** — very flexible, but Rego is a well-known adoption tax and does more work per evaluation than a purpose-built evaluator.
- **OpenFGA / SpiceDB** — Zanzibar ReBAC is the wrong shape. This problem is `principal × action × resource × condition`, not a relationship graph.
- **Casbin** — simple, but weak on schemas and validation.
- **Oso / Polar** — what `sqlauthz` used; Oso has deprecated that path.
- **Cerbos** — good, but service-shaped where we want embedded.

**OPEN:** whether the *user-facing* format is Cedar directly or an IAM-shaped
JSON that lowers to Cedar. Recommendation: the latter as the surface, Cedar as
the canonical internal representation. Decide next iteration.

---

## 4. API layer

### PROPOSED — Protobuf + [Connect RPC](https://connectrpc.com) + [buf](https://buf.build)

This is the decision I would most like a second pass on, because the research
cuts against it in one important way.

**The case against:** a 2025 Postman survey put REST adoption at 93% versus
14% for gRPC, and the current best-practice advice for small teams shipping new
products is REST + OpenAPI, for debuggability and universal tooling.

**The case for, which I think wins here:** there are four consumers of one
contract — the console, the CLI, the Kubernetes operator and (later) the
Terraform provider. Hand-maintaining four clients against a REST spec is the
cost REST does not advertise. Connect gives:

- One `.proto` → gRPC, gRPC-Web, **and plain JSON over HTTP POST**, so `curl`
  works without `grpcurl` — the usual objection to gRPC does not apply
- `buf` lint and **breaking-change detection in CI**, which matters a lot for a
  tool people automate against
- A generated TypeScript client for the console, free

**Rejected:** raw gRPC (needs grpc-gateway for JSON, and gRPC-Web for browsers),
plain REST + `huma`/`chi` + OpenAPI (simpler, but four hand-written clients).

**Reversal cost: high.** Looks reversible, is not. Worth one iteration.

---

## 5. Control-plane storage

### FROZEN — **PostgreSQL 15+, as the only supported store**

| Concern | Choice | Why |
|---|---|---|
| Store | PostgreSQL 15+ | Dogfooding; the control plane holds audit data and runs multiple replicas |
| Queries | [`sqlc`](https://sqlc.dev) | Compile-time-checked SQL, generated types, no ORM |
| Migrations | `goose` | Plain, ordered, reversible |
| Job queue | [River](https://riverqueue.com/) | Postgres-backed. Reconcile loops, credential expiry, drift scans |

**Explicitly rejected — SQLite as an alternative store.** The "zero
dependencies" appeal is real, but it doubles the test matrix permanently and
the control plane wants a real database. Single-node evaluation ships a
Postgres container, not a second backend.

**Explicitly rejected — Redis.** Every additional required service is an
install barrier, and a Postgres-backed queue covers the need.

---

## 6. Console

### PROPOSED — React 19 + TypeScript + Vite + TanStack Router/Query + Tailwind + shadcn/ui, `go:embed`ed into the binary

Embedding means one image, one process, one origin and **no CORS**. A separate
nginx container stays available for teams who want the front end released or
scaled independently, but it is not the default.

**OPEN:** whether the console ships in v1 at all, or whether v1 is API + CLI
and the console follows. A console is a large and permanent cost, and it is the
part most likely to slow the first release.

---

## 7. Identity, secrets and authorization

| Concern | Choice | Status |
|---|---|---|
| Human authentication | **OIDC** — Keycloak, Zitadel, Okta, Entra, Google, Authentik | FROZEN |
| Machine authentication | OIDC client credentials, short-lived tokens; SPIFFE/SPIRE optional later | FROZEN |
| db-iam's own authorization | **Cedar** — dogfood the engine | FROZEN |
| User provisioning | SCIM | Deferred |
| Secret storage | Pluggable `SecretProvider`: env, file, K8s Secret, Vault, AWS SM, GCP SM, Azure KV | FROZEN |
| Local encryption | Envelope encryption via KMS / Vault Transit / `age` | FROZEN |

**Never build an identity provider.** db-iam consumes identity; it does not
issue it.

**db-iam stores no target credential values.** Targets carry a reference
resolved at use time. This is what lets the control plane hold zero secrets in
its own database, and it is not retrofittable.

---

## 8. Observability and audit

| Concern | Choice |
|---|---|
| Traces, metrics, logs | OpenTelemetry |
| Metrics scrape | Prometheus `/metrics` |
| Application logging | `log/slog`, structured |
| **Audit** | **Separate from logging.** Append-only, hash-chained, exported to SIEM / object storage |

Audit is not logging and must not share a pipeline with it. Application logs
are lossy and rotate; audit does neither. The property to hold from day one is
**no privilege change without a record**, failures included — far harder to
retrofit than to start with.

---

## 9. Packaging and distribution

Your requirement: *Kubernetes, EC2, Docker Compose, Rancher, binary — wherever
they want.* Here is the full matrix, and the observation that Rancher and EC2
need nothing special because they are already covered.

| Target | Tooling | Status |
|---|---|---|
| **Single binary** | `goreleaser` → Homebrew, apt/rpm/apk, Scoop, `go install` | FROZEN |
| **VM / EC2 / bare metal** | Binary + systemd unit + `/etc/dbiam/config.yaml` | FROZEN |
| **Container** | Multi-stage → `distroless/static`, non-root, read-only root, multi-arch via buildx | FROZEN |
| **Docker Compose** | Committed quickstart, one command | FROZEN |
| **Kubernetes — Helm** | OCI chart published to GHCR | FROZEN |
| **Kubernetes — Operator** | `kubebuilder` / `controller-runtime`, CRDs, GitOps with Argo/Flux | FROZEN |
| **Rancher / OpenShift / EKS / GKE** | Nothing extra — Helm chart plus a `SecurityContext` that assumes no root | FROZEN |
| **Terraform** | `terraform-plugin-framework` | FROZEN, v2 |
| **Air-gapped** | Binary + local Postgres + file/KMS secrets. **Nothing may require an internet call at runtime** | FROZEN |
| **Supply chain** | `syft` SBOM, `cosign` signing, SLSA provenance, OpenSSF Scorecard | FROZEN |

**Connectivity model:** an optional outbound-dialling agent per network
segment, over mTLS, so the control plane never needs inbound reach into a
production network. This is the single thing that makes the product deployable
in regulated environments, and it is the topology Teleport and hoop.dev both
use.

**The constraint that makes all of this work is `CGO_ENABLED=0`.** It is why
cross-compilation is free, why `distroless/static` works, why there is no
glibc/musl split, and why the cgo-only engines are a real architectural
boundary rather than a preference.

---

## 10. Development and CI toolchain

| Concern | Choice | Status |
|---|---|---|
| CI | GitHub Actions, matrix across Go versions and engine versions | FROZEN |
| Lint | `golangci-lint` v2 | FROZEN |
| Schema / API lint | `buf lint`, `buf breaking` | PROPOSED, with §4 |
| Integration tests | `testcontainers-go`, one container per engine per major version | FROZEN |
| Compiler correctness | Golden-file corpus, shared fixtures, per-provider expected output | FROZEN |
| Dependency updates | Renovate | FROZEN |
| Release | `goreleaser`, conventional commits, semantic versioning | FROZEN |
| Contribution | DCO sign-off (lighter than a CLA, sufficient for Apache-2.0) | PROPOSED |

---

## 11. External services — what an operator must run

**Required:**

| Service | Why | Notes |
|---|---|---|
| PostgreSQL 15+ | Control-plane state | One instance; can be RDS/Cloud SQL |
| An OIDC provider | Human authentication | Any conformant one |

**Optional:**

| Service | Why |
|---|---|
| Vault / AWS SM / GCP SM / Azure KV | Target credential storage |
| KMS | Envelope encryption when using the local secret store |
| SIEM or object storage | Audit export |
| Prometheus / OTel collector | Metrics and traces |

Two required services is the number to defend. Every addition is an install
barrier, and this is the main reason Redis and a second storage backend were
rejected.

---

## 12. Licence

### PROPOSED — **Apache-2.0**

- Matches Cedar and the CNCF ecosystem
- The **patent grant** matters for a tool enterprises run with privileged
  database credentials, and is why CNCF, ASF and the Linux Foundation prefer it
- Lowest friction for both adoption and contribution

**Alternatives and what they cost:**

- **AGPL-3.0** — defends against SaaS re-hosting; [several major projects have moved back to it](https://redmonk.com/sogrady/2026/03/25/open-source-licensing-2026/). Costs you corporate users whose legal policy bans AGPL, which for an infrastructure tool is a meaningful slice.
- **BUSL-1.1** — source-available, **not open source by the OSI definition**, converting to an OSI licence after four years. Cockroach, HashiCorp, Sentry precedent. **This would contradict your stated "open source" requirement**, so it is listed only for completeness.

**Decide before v1.0.** Relicensing an established open-source core is the most
reliable way to lose a community. If a commercial path matters later, keep the
core Apache-2.0 and put enterprise features in a **separate repository**;
never retrofit a licence onto the core.

---

## 13. The freeze at a glance

| Layer | Choice | Status |
|---|---|---|
| Language | Go 1.26+ | **FROZEN** |
| Build constraint | `CGO_ENABLED=0`, pure-Go drivers only | **FROZEN** |
| Extensibility | In-tree Go SPI, serialisable-only boundary | **FROZEN** |
| Future plugins | `hashicorp/go-plugin` over gRPC | Deferred to v2 |
| Policy engine | Cedar, embedded (`cedar-go`) | **FROZEN** |
| Policy surface | IAM-shaped JSON → Cedar | **OPEN** |
| API | Protobuf + Connect RPC + buf | **PROPOSED** |
| Control-plane store | PostgreSQL 15+, `sqlc`, `goose`, River | **FROZEN** |
| Console | React 19 + Vite + TanStack + Tailwind, `go:embed` | **PROPOSED** |
| Human auth | OIDC | **FROZEN** |
| Self-authz | Cedar | **FROZEN** |
| Secrets | Pluggable provider + envelope encryption | **FROZEN** |
| Observability | OpenTelemetry + Prometheus + `slog` | **FROZEN** |
| Audit | Hash-chained, separate from logs | **FROZEN** |
| CLI | `cobra` + `goreleaser` | **FROZEN** |
| Containers | distroless/static, multi-arch, cosign, SBOM | **FROZEN** |
| Kubernetes | Helm (OCI) + `kubebuilder` operator | **FROZEN** |
| IaC | `terraform-plugin-framework` | **FROZEN**, v2 |
| Licence | Apache-2.0 | **PROPOSED** |
| Engine scope | Class A + B; Class C out | **OPEN — blocks everything** |

---

## 14. Open questions, in the order they block work

1. **Class C engines — in or out?** (§0) Changes whether a policy-decision API
   and multi-language SDKs exist at all. **Blocks the API and packaging
   decisions.**
2. **API protocol** — Connect RPC or plain REST + OpenAPI? (§4)
3. **Console in v1** — ship it, or API + CLI first? (§6)
4. **Policy surface** — Cedar directly, or IAM-shaped JSON lowering to Cedar? (§3)
5. **Licence** — Apache-2.0 or AGPL-3.0? (§12)
6. **Engine order after PostgreSQL.** MySQL is the useful second because it
   *lacks* row-level security and forces the capability-negotiation machinery
   early, while the cost of getting it wrong is still low. Cassandra is the
   more interesting third: it proves the model survives a non-relational
   hierarchy.
7. **Project name.** `db-iam` is descriptive and available-looking, but check
   for trademark and package-registry collisions before the first public
   release.

---

## Appendix — what the prototype already established

The working spike is being set aside as you asked, but four of its results are
evidence for decisions above rather than throwaway:

- `pgx` + `CGO_ENABLED=0` produced a **22.7 MB** `distroless/static` image that
  cross-compiles to linux/amd64 and linux/arm64 with no toolchain
- PostgreSQL's **transactional DDL** makes an all-or-nothing apply real; the
  non-transactional path that MySQL and Snowflake will need is a genuinely
  different code path, not a fallback
- Computing the **SCRAM-SHA-256 verifier client-side** works and keeps
  plaintext out of `pg_stat_activity` and the server log — verified by logging
  in as a created role
- Capability probing must be **read from the server, never inferred from the
  engine name**: RDS, Cloud SQL, Neon and Supabase each cap what the connected
  role may do, and those are most of the real installs

---

## Sources

- [SQLite user permissions](https://flaviocopes.com/sqlite-user-permissions/) · [Choosing SQLite, DuckDB, RocksDB or LMDB](https://oneuptime.com/blog/post/2026-09-08-choose-sqlite-duckdb-rocksdb-lmdb/view)
- [go-duckdb requires CGO](https://github.com/marcboeker/go-duckdb) · [duckdb/duckdb-go](https://github.com/duckdb/duckdb-go)
- [Cassandra CQL role-based access control](https://axonops.com/docs/data-platforms/cassandra/cql/security/rbac/) · [Apache Pinot access control](https://docs.pinot.apache.org/operators/operating-pinot/access-control) · [Pinot authentication and ACLs](https://docs.pinot.apache.org/operate-pinot/security/authentication)
- [hashicorp/go-plugin](https://pkg.go.dev/github.com/hashicorp/go-plugin) · [Go plugin patterns that ship](https://dev.to/gabrielanhaia/building-a-plugin-system-in-go-without-plugin-3-patterns-that-actually-ship-133d) · [go-plugin over WebAssembly](https://github.com/knqyf263/go-plugin)
- [Connect: a better gRPC](https://buf.build/blog/connect-a-better-grpc) · [ConnectRPC and proto-first API design](https://zylos.ai/research/2026-05-13-connectrpc-proto-first-api-design-agent-native-backends/)
- [Cedar](https://www.cedarpolicy.com/) · [cedar-go](https://github.com/cedar-policy/cedar-go) · [Cedar Analysis](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)
- [The state of open source licensing in 2026 — RedMonk](https://redmonk.com/sogrady/2026/03/25/open-source-licensing-2026/)
- [jackc/pgx](https://github.com/jackc/pgx) · [cgo and cross-compilation](https://ecostack.dev/posts/go-and-cgo-cross-compilation/)
- Landscape research: [docs/RESEARCH.md](./RESEARCH.md)
