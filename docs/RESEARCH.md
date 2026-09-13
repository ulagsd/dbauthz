# db-iam — Landscape Research & Technology Strategy

> Status: research spike, revised 2026-09-13 for a database-agnostic scope.
> Audience: project founders / early contributors.
> Goal: decide whether "IAM-style fine-grained database access management, open source, with a console" is an unoccupied niche, and pick a stack that installs anywhere and speaks to any engine.

---

## 1. Executive summary

**The niche is real, but narrow and specific.** Four product categories already touch this problem, and each solves a different slice:

| Category | Solves | Does NOT solve |
|---|---|---|
| Permissions-as-code CLIs (pgbedrock, pgroles, sqlauthz, Permifrost, Terraform) | Declarative GRANT/REVOKE convergence | No console, no identity, no approvals, no audit, no multi-cluster; each is single-engine |
| DB access platforms (Bytebase, Teleport, hoop.dev, StrongDM) | Identity, JIT access, session audit, console | Enforcement lives in *their* proxy/credential path, not in native DB privileges |
| Policy engines (Cedar, OPA, OpenFGA, Casbin) | Policy evaluation | No DB awareness, no grant compilation |
| Cloud IAM for DBs (RDS IAM auth, Cloud SQL IAM, Entra) | Authentication | Stops at the connection — inside the DB it is still plain `GRANT` |

**Nobody owns the intersection**: *one IAM-shaped policy document that compiles into each engine's own native privilege primitives, with a console, approvals, drift detection and a tamper-evident audit trail, self-hostable and open source.*

**Four findings that shape the design:**

1. **Do not invent a policy language.** Adopt [Cedar](https://github.com/cedar-policy/cedar) — Apache-2.0, CNCF Sandbox, Rust core with Go/TS/Python/Java SDKs, plus formal verification tooling. It already *looks* like IAM. Ship an optional IAM-shaped JSON front-end that lowers to Cedar.
2. **The critical architectural fork is enforcement location.** Compile policies down to native privileges (no component in the data path) **or** intercept queries in a wire proxy (arbitrary granularity, masking, but a new failure domain per engine). Recommendation: ship (1) first, add (2) as an optional per-engine component later.
3. **No mainstream SQL engine has a persistent `Deny`.** Privileges are additive everywhere — Postgres, MySQL, ClickHouse, Snowflake, Redshift. An IAM-style "explicit deny wins" must be resolved at *compile time* by subtracting from the computed grant set. This is universal, which is good news: one solver serves every provider.
4. **Going DB-agnostic is the right call, and it raises the bar.** The abstraction that matters is not "run SQL against N engines" — it is a **capability model**. Engines differ in hierarchy depth (MySQL has no schema level), and in whether they can express row filters or masking at all. The planner must either compile a policy natively, degrade *explicitly*, or **refuse** — never silently under-enforce.

---

## 2. Competitive landscape

### 2.1 Layer A — Permissions-as-code (closest functional overlap, weakest products)

| Tool | Engine | Lang | Policy format | Console | Status |
|---|---|---|---|---|---|
| [pgbedrock](https://github.com/Squarespace/pgbedrock) | Postgres | Python | YAML | No | Effectively unmaintained |
| [pgroles](https://github.com/thepartly/pgroles) | Postgres | Rust | YAML profiles/bundles | No | New, ~21★, active — **already ships a K8s operator + Helm chart** |
| [sqlauthz](https://github.com/cfeenstra67/sqlauthz) | Postgres | TypeScript | Oso **Polar** DSL | No | ~93★, early; row- *and* column-level; depends on deprecated `oso` |
| [posgra](https://github.com/codenize-tools/posgra) | Postgres | Ruby | Ruby DSL | No | Dormant |
| [Permifrost](https://gitlab.com/gitlab-data/permifrost) | Snowflake | Python | YAML | No | GitLab Data team; permissions only |
| [Titan Core](https://pypi.org/project/titan-core/) | Snowflake | Python | YAML | No | Full Snowflake IaC, supersedes Permifrost |
| Terraform `cyrilgdn/postgresql`, `mysql`, `snowflakedb/snowflake` | Per-engine | Go | HCL | No | De facto incumbent by install count; painful state, no drift console, no approvals |
| [Atlas](https://atlasgo.io/) (Ariga) | ~15 engines | Go | HCL/SQL | Cloud UI | **The most credible competitor now that you're multi-engine.** Extended beyond schema into roles, grants and RLS as code. Commercial-backed. |

**Key observations:**
- pgbedrock is the canonical prior art — [Squarespace's write-up](https://engineering.squarespace.com/blog/2018/building-on-solid-ground-getting-postgres-foundations-right-with-pgbedrock) is still the best articulation of the problem. It deliberately simplified to "read vs. write per object" because raw Postgres privileges are too subtle for most users. That simplification instinct is right and should carry into db-iam's UX.
- pgroles' three reconcile modes — **authoritative / additive / adopt** — are a design worth copying outright.
- **Every one of these is single-engine and none has a console.** That, plus the fact that Permifrost/Titan are just pgbedrock reinvented for Snowflake, is the clearest possible evidence that a shared multi-engine core is the missing piece.

### 2.2 Layer B — Database access platforms (strongest products, different enforcement model)

**[Bytebase](https://docs.bytebase.com/security/database-permission/overview/) — the closest overall competitor, and already multi-engine** (Postgres, MySQL, Aurora, SQL Server, Oracle, MariaDB, Snowflake…).
- Its own user/role model, SSO-integrated, decoupled from DB users. Per-user audit trails even behind a shared DB user.
- Built-in roles plus custom roles composed from atomic permissions (`bb.sql.select`, `bb.sql.explain`).
- **Statement-level enforcement**: classifies each SQL statement and validates before execution — but only inside Bytebase's own SQL Editor / change workflow.
- Access grants: temporary elevated privilege, approval-gated, auto-expiring, with optional unmask/export. Column-level masking.
- **The structural weakness to attack**: a developer who connects with `psql` or `mysql` bypasses Bytebase entirely. Enforcement is advisory unless native grants are *also* locked down — which Bytebase does not manage for you. Source-available with paid tiers.

**[Teleport](https://goteleport.com/)** — replaces static secrets with short-lived, identity-bound X.509 certificates; RBAC maps identities to DB users/roles; full session recording. Authorises *at connection time*, then gets out of the way. Excellent at "who may connect as which DB role"; does nothing about what that role can touch.

**HashiCorp Vault DB secrets engine** — dynamic short-lived credentials generated from operator-supplied creation statements. You still hand-write the `CREATE ROLE ... GRANT ...` SQL per engine. No console for object permissions, no policy model over tables.

**[hoop.dev](https://hoop.dev/)** — MIT-licensed L7 gateway, OIDC/SAML-driven, sole enforcement point for DB/K8s/SSH/RDP. Session recording, field masking, JIT approval, short-lived per-session credentials. Deploys as Docker Compose or a K8s DaemonSet with an agent beside each resource. **Copy this deployment topology.**

**Commercial / closed:** StrongDM, Cyral (**acquired by Varonis**), Satori, Immuta, Apono, ConductorOne, Indent, Opal, Entitle (BeyondTrust). A well-funded, consolidating market — which validates demand and argues for the open-source, self-hosted, no-data-path-dependency angle.

**[Apache Ranger](https://ranger.apache.org/blogs/policy_model.html) — the architectural precedent to study hardest, and now your closest structural analogue.** Central policy admin console + REST API, with per-engine **plugins** that pull policies and enforce locally. [Row-filter and column-masking policies](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=65868896), plus ABAC conditions on user/group/resource attributes. Exactly the shape db-iam should grow into.

**Ranger's limits are your opening:** its world is Hive/HDFS/Trino/Kafka/HBase — the Hadoop lineage. There is **no Postgres plugin, no MySQL plugin, no Snowflake plugin.** It enforces via in-process plugins inside JVM data engines, which is why it can't reach a plain OLTP database. db-iam compiling to *native* privileges reaches exactly the engines Ranger cannot.

### 2.3 Layer C — Policy engines (build on, don't compete with)

| Engine | Model | Fit |
|---|---|---|
| **[Cedar](https://docs.cedarpolicy.com/)** | ABAC/RBAC, `permit`/`forbid`, entities + schema | **Recommended.** Rust core (sub-ms eval), Apache-2.0, **CNCF Sandbox**, v4.x. SDKs in Rust, Java, Python, JS/TS, Go. Reads like IAM. [Cedar Analysis](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/) gives *formal verification* of policy properties in CI — nothing else in this space offers that. AWS Verified Permissions is hosted Cedar, so the mental model is already familiar. |
| OPA / Rego | Datalog-ish, general purpose | Very flexible, heavier per-eval, Rego is a known adoption tax. |
| OpenFGA / SpiceDB | Zanzibar ReBAC | Great for relationship graphs, wrong shape for "principal + action + resource + condition" over DB objects. |
| Cerbos / Casbin / Oso | RBAC/ABAC | Casbin is simple but weak on schemas; Oso's Polar is what sqlauthz used, and Oso has deprecated that path. |

Cedar's entity model is a particularly good fit for multi-engine work: entity **types** are yours to define, so one schema can express a hierarchy that each provider projects differently.

### 2.4 Layer D — Cloud-native DB IAM (what users will compare you to)

RDS IAM authentication, [Cloud SQL IAM authentication and IAM groups](https://cloud.google.com/sql/docs/postgres/iam-authentication), and Entra ID for Azure Database all map cloud identities to DB logins. **They authenticate; they do not authorise inside the database.** Once connected, everything is still `GRANT`.

Positioning line: *"Cloud IAM gets you to the door. db-iam decides which rooms you can enter — on every database you run."*

---

## 3. The engine capability matrix — the heart of a DB-agnostic design

This table is the real specification. Every provider must declare which of these it supports, and the planner must react to the answer.

| Capability | PostgreSQL | MySQL 8 | ClickHouse | Snowflake | Redshift | SQL Server | MongoDB |
|---|---|---|---|---|---|---|---|
| Hierarchy depth | cluster › db › **schema** › table › column | server › **db(=schema)** › table › column | cluster › db › table › column | account › db › schema › table › column | cluster › db › schema › table › column | server › db › schema › table › column | cluster › db › collection › field |
| Roles / groups | ✅ roles, nestable | ✅ roles (8.0+) | ✅ roles | ✅ roles, hierarchical | ✅ roles | ✅ roles | ✅ roles |
| Column-level grant | ✅ `SELECT/INSERT/UPDATE/REFERENCES` | ✅ column grants | ✅ `GRANT SELECT(col)` | ⚠️ via masking policy | ✅ | ✅ | ❌ (views only) |
| Row-level filtering | ✅ `CREATE POLICY` (RLS) | ❌ views only | ✅ `CREATE ROW POLICY` | ✅ row access policy | ✅ RLS policy | ✅ security policy + predicate fn | ❌ views only |
| Native masking | ❌ (use views) | ❌ (Enterprise plugin only) | ❌ | ✅ masking policy *(Enterprise+ edition)* | ✅ dynamic data masking, with priorities | ✅ dynamic data masking | ❌ |
| Persistent `DENY` | ❌ additive only | ❌ | ❌ | ❌ | ❌ | ⚠️ `DENY` exists, and wins | ❌ |
| Default/future grants | ✅ `ALTER DEFAULT PRIVILEGES` | ❌ | ❌ | ✅ future grants | ✅ | ❌ | ❌ |

**Consequences for the design:**

1. **Hierarchy depth is not uniform.** MySQL's "database" *is* the schema level. A naive five-level model will produce nonsense on MySQL and MongoDB. Model the canonical hierarchy as a **path of typed segments** and let each provider declare which segments it uses and how a wildcard expands.

2. **Capability negotiation, with refusal as a first-class outcome.** When a policy asks for something the target cannot express, the planner has exactly three legal responses, and the choice is the policy author's, not the tool's:
   - **Compile natively** (row filter → `CREATE POLICY` on Postgres, `CREATE ROW POLICY` on ClickHouse).
   - **Compile via a documented substitute**, recorded in the plan (row filter → a managed security-barrier view on MySQL, with the base table revoked).
   - **Refuse the apply** with a precise error naming the policy, the engine and the missing capability.
   Silent under-enforcement is the one unacceptable outcome — it turns a security tool into a liability. Make `onUnsupported: refuse | substitute` an explicit field, defaulting to `refuse`.

3. **SQL Server is the one engine with real `DENY`**, and there it takes precedence. Your compile-time deny solver still produces the correct grant set everywhere; on SQL Server you *may* additionally emit `DENY` for defence in depth. Don't let that one exception leak into the core model.

4. **Edition gates are real.** Snowflake Dynamic Data Masking and tag-based masking require Enterprise Edition or higher. Probe capabilities at connect time rather than assuming from the engine name — the same product has different capability sets by tier and by managed provider.

5. **Snowflake evaluates row access policies before masking policies.** Where an engine defines an evaluation order, mirror it in the planner's semantics so the modelled effective permissions match reality.

---

## 4. Per-engine reality checks

### PostgreSQL (first provider)
- **No deny.** `REVOKE` removes a grant; there is no persistent deny object. `Effect: Deny` must be reflected as *absence* of a grant, and must also block inherited role memberships that would reintroduce it. Plan for a full effective-permission solver.
- `PUBLIC` is an implicit grantee on every new object and on `CREATE` in the `public` schema (tightened in PG 15). Authoritative mode must revoke from `PUBLIC`.
- `INHERIT` vs `NOINHERIT` + `SET ROLE` changes effective permissions at runtime — the solver must model both.
- `ALTER DEFAULT PRIVILEGES` is per-grantor-per-schema: the classic reason grants "don't stick" on new tables.
- Predefined roles (`pg_read_all_data`, `pg_write_all_data`, `pg_monitor`, PG 14+) are a convenient compile target for coarse policies.
- PG 16+ changed role-membership semantics (`ADMIN`/`INHERIT`/`SET` grant options) — version-gate the emitter.
- Table owners bypass RLS unless `ALTER TABLE ... FORCE ROW LEVEL SECURITY`.
- Managed providers restrict you: RDS has no true superuser (`rds_superuser`), Cloud SQL has `cloudsqlsuperuser`; Aurora, Neon, Supabase and Timescale each differ. pgroles' own docs flag "managed PostgreSQL support varies by provider" — a real, recurring support cost. Maintain a compatibility matrix plus a runtime capability probe.

### MySQL / MariaDB
- Roles exist from 8.0 but are not enabled by default per session (`SET DEFAULT ROLE` / `activate_all_roles_on_login`) — a genuine footgun.
- **No RLS.** Row filtering means a managed view plus revoking the base table, or a proxy. This is the first place `onUnsupported` matters.
- No masking in Community Edition.
- Two-level hierarchy: `db.table`, no schema layer.

### ClickHouse
- [Solid RBAC](https://clickhouse.com/docs/knowledgebase/row-column-policy): roles, `GRANT SELECT(col)` column grants (a user without the grant cannot read the column, *not even via `SELECT *`*), and `CREATE ROW POLICY`. Row policies and column grants compose cleanly — rows matching the policy AND columns granted.
- Wildcard grants across databases/tables have historically been limited; check the target version.

### Snowflake
- Richest natively: hierarchical roles, row access policies, masking policies, future grants, tag-based policies.
- [Row access policies are evaluated first, then masking policies.](https://docs.snowflake.com/en/user-guide/security-row-intro)
- Masking is **Enterprise Edition or higher**; masking policies cannot reference other tables; row access policies add per-query overhead.
- Permifrost and Titan Core already own the permissions-as-code niche here — differentiate on console, approvals and cross-engine policy, not on the compiler.

### Redshift
- Dynamic data masking obfuscates at query time without transforming stored data; supports **conditional/cell-level** masking and **multiple policies on one column with explicit priorities** to resolve role conflicts. That priority model is a good reference for your own conflict resolution.

### Later candidates
SQL Server (has real `DENY`, RLS via security policies, native DDM), Oracle (VPD, Label Security, redaction), BigQuery (IAM + policy tags + row access policies), Databricks Unity Catalog ([row filters and column masks as SQL UDFs, plus ABAC policies at catalog/schema level](https://docs.databricks.com/aws/en/data-governance/unity-catalog/filters-and-masks/)), MongoDB (role-based; field-level only via views).

> Unity Catalog's split — table-level filters/masks vs. **tag-driven ABAC policies that auto-cover newly tagged tables** — is worth stealing. Tag-based policy is how you solve "new tables appear between reconciles" at the *policy* layer rather than the plumbing layer.

---

## 5. Gap analysis — where db-iam wins

1. **Native-privilege compiler + console + audit + approvals, across engines, in one Apache-2.0 binary.** Nobody ships all five. pgbedrock/Permifrost have the compiler per-engine and no UI; Bytebase has the console but enforces out-of-band; Ranger has the console and plugin model but cannot reach OLTP databases; Teleport/Vault do credentials, not object privileges.
2. **One policy, many engines.** "Analysts may read `analytics.*` everywhere" expressed once and compiled correctly into Postgres RLS, ClickHouse row policies and Snowflake row access policies is a capability that does not currently exist in open source.
3. **Enforcement that survives a raw client.** Because policies become real privileges, the guarantee holds for `psql`, `mysql`, BI tools, ORMs, Metabase and AI agents alike. No data-path component required. This is the sharpest wedge against Bytebase.
4. **Formal verification of access policy.** Cedar Analysis lets you *prove* "no policy grants write on `payments` to a non-`finance` principal" in CI, rather than testing samples. No competitor offers this. Lead with it.
5. **Access review evidence as a first-class artifact.** "Everyone with write access to `payments.*` across all six clusters as of 2026-06-30" is a SOC 2 / ISO 27001 deliverable currently produced by hand. Exportable, signed, point-in-time.

### Deliberately *not* in v1
- No wire proxy. It's a data-path failure domain, a performance liability, and a per-engine support burden.
- No IdP. Consume OIDC.
- No SQL editor. That's Bytebase/DBeaver's game and it drags you into a different product.
- No more than two engines. Ship Postgres, then MySQL, and only then generalise — two providers is the minimum to prove the abstraction, and three is how you get a bad one.

---

## 6. Security architecture (non-negotiables)

db-iam's control plane will hold the most dangerous credential set in the organisation.

**Credential handling**
- No long-lived privileged credentials in plaintext, ever. Envelope encryption with a KMS-backed DEK (AWS KMS / GCP KMS / Azure KV / Vault Transit / `age` for self-hosted).
- First-class `secretRef` indirection — K8s Secret, Vault, AWS SM, GCP SM, Azure KV — behind a pluggable provider interface, so the control plane can hold *zero* secrets in its own database.
- Pull-based agent per network segment (hoop.dev / Teleport topology): the agent dials out over mTLS; the control plane never needs inbound reach to a production database. This is what makes the product deployable in regulated environments.

**Authorization of the tool itself**
- Every API call resolves: authenticated identity → tenant membership → permission → resource ownership → audit record. Never trust a client-supplied tenant id, an `Origin` header, a subdomain, or anything the frontend asserts.
- Dogfood Cedar for db-iam's own RBAC. Same engine, same tests, and it's a live demo of the policy model.
- Enforce tenant scoping in the repository layer (make an unscoped query unconstructable), plus RLS on the control-plane database as defence in depth.

**Change safety**
- `plan` before `apply`, always. Render the exact per-engine statements. Never apply an unreviewed plan.
- Classify destructive operations (role drop, revoke-all, ownership transfer) and gate them behind approval / dual control.
- Apply transactionally per target where the engine allows it — and note that several engines (MySQL DDL, Snowflake) give **no transactional DDL**, so the provider must declare whether rollback is possible and the planner must order statements to fail safe (revoke before grant, never leave a window of excess privilege).
- Record the emitted statements and the before/after effective-permission snapshot.
- Break-glass path that is loud: requires a reason, fires an alert, time-boxed.

**Audit**
- Append-only, hash-chained (each record includes the previous record's hash) so tampering is detectable. Export to SIEM / S3 / Loki.
- Record both *intent* (policy change, who approved) and *effect* (statements emitted, resulting effective permissions).
- Point-in-time access review export — the SOC 2 evidence artifact, and a genuine adoption driver.

**Supply chain** — SBOM (syft), signed images and provenance (cosign + SLSA), pinned dependencies, OpenSSF Scorecard. Enterprises will ask before deploying a privileged tool.

> These are engineering recommendations, not a compliance opinion. SOC 2 / ISO scoping decisions need your auditor.

---

## 7. Recommended technology stack

### 7.1 Core language: **Go**

Rust is defensible (pgroles chose it; Cedar's reference implementation is Rust) and is the right call *if* a high-throughput wire proxy is core to v1. Otherwise Go wins decisively, and the multi-engine scope strengthens the case:

- **Driver coverage is the deciding factor.** Go has first-rate, actively maintained drivers for every target: `jackc/pgx`, `go-sql-driver/mysql`, `ClickHouse/clickhouse-go`, `snowflakedb/gosnowflake`, `microsoft/go-mssqldb`, `mongodb/mongo-go-driver`. Rust's coverage outside Postgres is thinner.
- Single static binary, trivial cross-compilation (linux/darwin/windows × amd64/arm64) — "installs anywhere" falls out for free.
- The entire Kubernetes operator ecosystem (controller-runtime, kubebuilder) is Go. So is the Terraform plugin framework. Both are on the roadmap.
- Largest contributor pool for infrastructure OSS. For a project whose success depends on outside contributors, this is first-order.
- `pgx/pgproto3` keeps a wire-protocol path open if you *do* build the proxy later.

**Decision: Go for the control plane, CLI, agent, providers and operator.**

### 7.2 The provider interface (design this in Phase 0, even with one implementation)

The abstraction is *not* "execute SQL". It is introspect → declare capabilities → compile → order → apply.

```go
type Provider interface {
    // Identity and negotiated capabilities of this specific target,
    // probed at connect time — not inferred from the engine name.
    // Edition, version and managed-provider restrictions all land here.
    Capabilities(ctx context.Context) (Capabilities, error)

    // Read live principals, objects and effective privileges.
    Introspect(ctx context.Context, scope Scope) (*CatalogSnapshot, error)

    // Lower a resolved, deny-subtracted permission set into engine
    // statements. Returns ErrUnsupported naming the capability when the
    // policy cannot be expressed and substitution is not permitted.
    Compile(desired *EffectivePermissions, live *CatalogSnapshot, opts CompileOpts) (*Plan, error)

    // Apply, declaring up front whether rollback is available so the
    // planner can order statements to fail safe.
    Apply(ctx context.Context, plan *Plan) (*ApplyResult, error)
}

type Capabilities struct {
    Hierarchy        []SegmentKind // e.g. {Cluster, Database, Schema, Table, Column}
    ColumnGrants     bool
    RowFilters       RowFilterSupport // Native | ViaView | None
    Masking          MaskingSupport   // Native | ViaView | None
    NativeDeny       bool
    FutureGrants     bool
    TransactionalDDL bool
}
```

Two rules keep this honest: **capabilities are probed, never assumed**, and **`Compile` returning `ErrUnsupported` is a normal, expected outcome** that surfaces to the user as a refusal rather than a silent downgrade.

### 7.3 Component stack

| Concern | Choice | Why |
|---|---|---|
| **Policy engine** | [`cedar-policy/cedar-go`](https://github.com/cedar-policy/cedar-go), embedded | No network hop, no sidecar. Cedar schema defines engine-neutral entity types; providers project them. Ship an IAM-shaped JSON document format that lowers to Cedar so the AWS mental model is preserved. |
| **Policy verification** | Cedar Analysis in CI | Prove properties rather than test samples. Unique differentiator. |
| **API** | Protobuf + [Connect RPC](https://connectrpc.com) | One definition → gRPC, gRPC-Web and plain JSON/HTTP. `buf` for codegen, lint and breaking-change detection. Generate OpenAPI for `curl` users, TS client for the console. |
| **Metadata store** | PostgreSQL 15+ only | Dogfooding. Resist SQLite — dual-store support doubles the test matrix for little gain. `sqlc` for type-safe queries, `goose` for migrations. |
| **Background work** | Postgres-backed queue — [River](https://riverqueue.com/) or `FOR UPDATE SKIP LOCKED` + outbox | Reconcile loops, credential expiry, drift scans. **No Redis dependency** — every extra required service costs installs. |
| **Console** | React 19 + TypeScript + Vite + TanStack Router/Query + Tailwind + shadcn/ui | Conventional, fast, contributor-friendly. Monaco for the policy editor with Cedar validation client-side via **Cedar's WASM build** — instant feedback, no round trip. |
| **Console packaging** | `go:embed` the built SPA into the binary | One image, one process, no nginx sidecar, no CORS. Critical for "one command install". |
| **AuthN (humans)** | OIDC (Keycloak, Zitadel, Okta, Entra, Google, Authentik) | Never build an IdP. SCIM in phase 2. |
| **AuthN (machines)** | Short-lived tokens, OIDC client credentials, optional SPIFFE/SPIRE | Agents and CI need first-class non-human identity. |
| **Secrets** | Pluggable `SecretProvider`: env, file, K8s Secret, Vault, AWS SM, GCP SM, Azure KV | Plus envelope encryption for anything stored locally. |
| **Observability** | OpenTelemetry + Prometheus `/metrics` + structured `slog` | Standard, no lock-in. Audit exported separately from application logs. |
| **CLI** | `cobra` + `goreleaser`, binary named `dbiam` | `dbiam plan`, `apply`, `diff`, `whoami`, `review export`. Homebrew, apt/rpm/apk, Scoop, `go install`, `krew` plugin. |
| **Testing** | `testcontainers-go` per engine; golden-file tests for statement emission; property tests for policy→effective-permission equivalence | The golden-file suite per provider is what makes the compiler trustworthy, and it's how a contributor adds an engine safely. Add a managed-provider matrix (RDS, Cloud SQL, Aurora, Neon, Supabase, CNPG, PlanetScale) where feasible. |

### 7.4 Deployment matrix — "installable anywhere"

Ship all of it, in this order:

1. **Docker** — multi-stage onto `gcr.io/distroless/static`, non-root UID, read-only rootfs, multi-arch via `buildx` (amd64 + arm64). Signed with `cosign`, SBOM attached, SLSA provenance.
2. **Docker Compose quickstart** — `docker compose up` gives control plane + Postgres + a seeded demo target + console on `:8080`. This is the README's first code block and it disproportionately drives stars.
3. **Helm chart**, published as an OCI artifact to GHCR. Values for HA replicas, external Postgres, ingress, OIDC, secret providers, resource limits, PodSecurityContext, NetworkPolicy.
4. **Kubernetes Operator + CRDs** (kubebuilder / controller-runtime) — the GitOps story:
   - `DatabaseTarget` — engine, connection, credential reference, capability profile
   - `AccessPolicy` — the Cedar/IAM document
   - `RoleBinding` — principal → policy → scope
   - `AccessRequest` — JIT request with TTL and approval status
   Reconciled continuously; works with Argo CD and Flux. Drift correction becomes a controller loop, which is the natural framing.
5. **Terraform provider** (`terraform-plugin-framework`) — meets the largest existing user base (people on `cyrilgdn/postgresql` and `snowflakedb/snowflake`) where they already are. High-leverage migration path.
6. **Bare metal / VM** — single binary + systemd unit + `/etc/dbiam/config.yaml`. Plenty of regulated database estates are not on Kubernetes.
7. **Agent mode** — outbound-only, mTLS to the control plane, one per network segment. Removes the inbound-access objection entirely.

### 7.5 Licensing

- **Apache-2.0 for the core.** Matches Cedar and the CNCF ecosystem; lowest-friction for enterprise adoption of a privileged tool, and most likely to attract contributors.
- If a commercial path matters later: keep the core Apache-2.0 and put enterprise features in a **separate** repository/licence rather than retrofitting BUSL. Relicensing an existing OSS core is the most reliable way to lose a community.
- AGPL is the alternative if defending against SaaS re-hosting matters more than enterprise adoption. It will cost you corporate users. Decide before v1.0.

---

## 8. Proposed architecture

```
                    ┌─────────────────────────────────────────┐
  OIDC IdP ────────▶│           db-iam control plane          │
                    │  (single Go binary, embedded React SPA)  │
  Console (browser)─┤                                         │
  CLI / Terraform ──┤  Connect RPC API  │  Policy store (PG)   │
  K8s Operator ─────┤  Cedar engine     │  Audit (hash chain)  │
                    │  Planner + solver │  Job queue (PG)      │
                    └──────────┬──────────────────────────────┘
                               │ mTLS, outbound-dialed
                    ┌──────────▼──────────┐
                    │     db-iam agent    │  (one per network segment)
                    │  ┌───────────────┐  │
                    │  │   providers   │  │  capability-probed per target
                    │  └───────────────┘  │
                    └──────────┬──────────┘
              ┌────────┬───────┴────┬───────────┬──────────┐
              ▼        ▼            ▼           ▼          ▼
         Postgres   MySQL      ClickHouse   Snowflake   (SQL Server,
         (RDS/CNPG) (Aurora)                            Mongo, BigQuery…)
```

**Request flow for a policy change**

```
author policy ──▶ Cedar validate (schema + Analysis)
              ──▶ probe target capabilities
              ──▶ resolve principals/resources against live catalog
              ──▶ solve effective permissions (Deny subtracted, membership expanded)
              ──▶ per-provider Compile  ──▶ ErrUnsupported? refuse or substitute
              ──▶ diff vs. live catalog state
              ──▶ emit statement plan  ──▶ approval gate (if destructive)
              ──▶ apply (fail-safe ordering; transactional where supported)
              ──▶ audit record (intent + statements + resulting snapshot)
```

**Example policy document** (IAM-shaped front-end, lowered to Cedar). Note the engine-qualified resource path and the explicit `onUnsupported`:

```json
{
  "version": "2026-09-01",
  "statements": [
    {
      "sid": "AnalystsReadAnalytics",
      "effect": "Allow",
      "principals": ["group:analysts"],
      "actions": ["db:Select"],
      "resources": ["dbi:*:target/*:db/app:schema/analytics:table/*"]
    },
    {
      "sid": "NeverReadPII",
      "effect": "Deny",
      "principals": ["*"],
      "actions": ["db:Select"],
      "resources": ["dbi:postgres:target/prod:db/app:schema/public:table/users:column/ssn"],
      "condition": { "NotInGroup": { "principal.groups": "compliance" } }
    },
    {
      "sid": "TenantRowScope",
      "effect": "Allow",
      "principals": ["group:support"],
      "actions": ["db:Select"],
      "resources": ["dbi:*:target/prod:db/app:schema/*:table/orders"],
      "rowFilter": { "expr": "tenant_id = ${session.tenant}" },
      "onUnsupported": "refuse"
    }
  ]
}
```

How the planner lowers these:

| Statement | PostgreSQL | ClickHouse | MySQL 8 |
|---|---|---|---|
| `AnalystsReadAnalytics` | role membership + `GRANT SELECT ON ALL TABLES IN SCHEMA analytics` + `ALTER DEFAULT PRIVILEGES` | `GRANT SELECT ON analytics.*` + periodic reconcile (no future grants) | maps to `GRANT SELECT ON analytics.*` (db == schema) |
| `NeverReadPII` | column-scoped grants **omitting** `ssn` (no deny exists) | `GRANT SELECT(col, …)` omitting `ssn` | column grants omitting `ssn` |
| `TenantRowScope` | `CREATE POLICY` + `ENABLE ROW LEVEL SECURITY` + `FORCE` | `CREATE ROW POLICY` | **`ErrUnsupported`** → refused, because `onUnsupported: refuse` |

The `${session.tenant}` placeholder is deliberately engine-neutral: Postgres renders it as `current_setting('dbiam.tenant')`, ClickHouse as `currentUser()`-derived context, Snowflake via `CURRENT_ROLE()`/session tags. Keep the policy portable; let the provider render.

---

## 9. Suggested roadmap

| Phase | Scope | Proves |
|---|---|---|
| **0 — MVP (6–10 wks)** | `Provider` interface + **Postgres provider only**. Policy doc → `plan`/`apply` of roles, memberships, grants, default privileges. Deny solver. Drift detection. CLI. Read-only console. PG 14–18. | The compiler is correct and the diff is trustworthy. The foundation of everything. |
| **1 — Second engine** | **MySQL provider.** Capability negotiation, `onUnsupported`, fail-safe statement ordering for non-transactional DDL. | The abstraction is real, not aspirational. Do this *early* — an abstraction validated by one implementation is a guess. |
| **2 — Platform** | OIDC login, db-iam's own RBAC (Cedar), hash-chained audit, multi-target, Helm chart, K8s operator + CRDs, agent mode. | It's deployable and safe in a real org. |
| **3 — Workflow** | JIT access requests, approval chains, auto-expiry, ephemeral credential minting, Slack/Teams approval, access review export. | It replaces the spreadsheet + Jira ticket process. Where the commercial pull is. |
| **4 — Fine-grained** | Column-scoped grants everywhere, managed row filters, masking via managed views, Cedar Analysis in CI, Terraform provider. | The "fine-grained" claim holds across engines. |
| **5 — Expansion** | ClickHouse, Snowflake, SQL Server providers. Optional wire proxy for per-query enforcement and dynamic masking on engines that lack native support. | It's a platform. |

**The one sequencing opinion worth arguing about:** resist shipping six providers early. Two well-tested engines with an honest capability model beats six that each work in the demo. Ranger's plugin sprawl is a cautionary tale.

---

## 10. Open questions to resolve before writing code

1. **Enforcement model** — confirm native-privilege compilation for v1 (recommended) over a proxy. Everything downstream depends on this.
2. **Policy surface** — pure Cedar, or IAM-shaped JSON lowering to Cedar? (Recommended: the latter as the user-facing format, Cedar as the canonical internal representation.)
3. **Authoritative vs. additive default** — pgroles offers three modes. Authoritative is safer but frightening to adopt on an existing cluster. Recommended: `adopt` by default, opt in to authoritative.
4. **Identity mapping** — does db-iam create native DB roles per human, map humans to shared functional roles, or mint ephemeral roles per session? Each gives different audit granularity and blast radius, and the answer differs per engine.
5. **Second engine: MySQL or ClickHouse?** MySQL has the larger user base but *lacks* RLS, which forces the `onUnsupported` machinery early — arguably a feature. ClickHouse has richer native primitives and an easier compile. Recommended: MySQL, precisely because it's the harder case.
6. **Licence** — Apache-2.0 vs AGPL. Decide before v1.0.

---

## Sources

- [Squarespace/pgbedrock](https://github.com/Squarespace/pgbedrock) · [docs](https://pgbedrock.readthedocs.io/en/latest/) · [engineering blog](https://engineering.squarespace.com/blog/2018/building-on-solid-ground-getting-postgres-foundations-right-with-pgbedrock)
- [thepartly/pgroles](https://github.com/thepartly/pgroles) · [cfeenstra67/sqlauthz](https://github.com/cfeenstra67/sqlauthz) · [codenize-tools/posgra](https://github.com/codenize-tools/posgra) · [netwo-io/lib_iam](https://github.com/netwo-io/lib_iam)
- [CloudNativePG — PostgreSQL Role Management](https://cloudnative-pg.io/docs/1.28/declarative_role_management/)
- [Bytebase — database permission overview](https://docs.bytebase.com/security/database-permission/overview/) · [JIT database access tutorial](https://docs.bytebase.com/tutorials/just-in-time-database-access-amazon-aurora)
- [Teleport vs StrongDM](https://goteleport.com/compare/strongdm-alternative/) · [Benchmarking policy languages](https://goteleport.com/blog/benchmarking-policy-languages/)
- [hoop.dev — JIT access for Postgres](https://hoop.dev/blog/configuring-ai-agents-access-to-postgres-with-just-in-time-access)
- [Varonis acquires Cyral](https://www.varonis.com/blog/varonis-to-acquire-cyral-database-activity-monitoring) · [Satori vs Cyral](https://satoricyber.com/satori-vs-cyral/)
- [Apache Ranger policy model](https://ranger.apache.org/blogs/policy_model.html) · [row filtering & column masking](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=65868896)
- [Cedar docs](https://docs.cedarpolicy.com/) · [cedar-policy/cedar](https://github.com/cedar-policy/cedar) · [cedar-go](https://github.com/cedar-policy/cedar-go) · [Cedar Analysis](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/) · [Cedar joins CNCF Sandbox](https://infoq.com/news/2026/01/cedar-joins-cncf-sandbox/)
- [Permit.io — OPA vs OpenFGA vs Cedar](https://www.permit.io/blog/policy-engine-showdown-opa-vs-openfga-vs-cedar)
- [Atlas — schema as code](https://atlasgo.io/docs) · [GitLab Permifrost](https://gitlab.com/gitlab-data/permifrost) · [Titan Core](https://pypi.org/project/titan-core/)
- [ClickHouse — row and column level security](https://clickhouse.com/docs/knowledgebase/row-column-policy)
- [Snowflake — understanding row access policies](https://docs.snowflake.com/en/user-guide/security-row-intro)
- [Databricks Unity Catalog — row filters and column masks](https://docs.databricks.com/aws/en/data-governance/unity-catalog/filters-and-masks/) · [ABAC vs row filters/column masks](https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/abac-vs-rls-cm)
- [Amazon Redshift — dynamic data masking](https://docs.aws.amazon.com/redshift/latest/dg/t_ddm.html)
- [Cloud SQL IAM authentication](https://cloud.google.com/sql/docs/postgres/iam-authentication) · [AWS — managing PostgreSQL users and roles](https://aws.amazon.com/blogs/database/managing-postgresql-users-and-roles/)
- [jackc/pgx](https://github.com/jackc/pgx) · [pgproto3](https://pkg.go.dev/github.com/jackc/pgx/v5/pgproto3)
