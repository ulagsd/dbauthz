# db-iam — Foundations to Get Solid On

> Companion to [STACK.md](./STACK.md) v0.3. Everything here exists because
> something in that document depends on it.
>
> This is deliberately **ruthless about priority**. A list of forty
> technologies is useless. Roughly 70% of the value is in Tier 0, and if you
> only ever do Tier 0 you will be able to hold your own in every design
> conversation we have next.

---

## How to use this

Each area has a **depth** and a **stopping condition** — a question you should
be able to answer without looking it up. The stopping condition matters more
than the reading list: it tells you when to move on instead of studying
forever.

| Depth | Means |
|---|---|
| **Working** | You can write it, debug it, and argue about design in it |
| **Reading** | You can review someone else's and spot a bad decision |
| **Conceptual** | You know what it is, why it is there, and when it bites |
| **Awareness** | You can recognise the word and look it up when you touch it |

**Assumption I am making:** you are comfortable with SQL, Docker, and at least
one programming language. If any of that is wrong, tell me and I will reshuffle.

---

## Tier 0 — Learn these before our next conversation

Two things. Everything we discuss about the policy document, the solver and the
provider interface is downstream of them, and a gap here is the kind that stays
invisible while you nod along to a design that is subtly wrong.

### 0.1 PostgreSQL's privilege model — depth: **working**

**This is the single highest-leverage thing on the page.** The whole product is
a compiler that targets it. You cannot evaluate a solver design without it.

What to cover, in order:

1. **Roles are one thing.** There is no separate "user" — a user is a role with
   `LOGIN`. Read `CREATE ROLE` fully.
2. **`GRANT` and `REVOKE`** — the privilege types (`SELECT`, `INSERT`,
   `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, `USAGE`, `CREATE`,
   `CONNECT`, `TEMPORARY`, `EXECUTE`) and which object kinds each applies to.
3. **Privileges are additive. There is no `DENY`.** Sit with this one — it is
   the reason the solver exists at all.
4. **Role membership** — `GRANT role TO role`, and the difference between
   `INHERIT` and `NOINHERIT` plus `SET ROLE`. This changes what a principal
   actually holds at connection time.
5. **`PUBLIC`** — the implicit grantee on every new object. Where it bites, and
   what changed in PostgreSQL 15.
6. **`ALTER DEFAULT PRIVILEGES`** — per-grantor, per-schema. The reason grants
   "don't stick" on tables created tomorrow.
7. **Column-level grants** — which privileges accept a column list, and what
   `SELECT *` does when you only hold some columns.
8. **Row-level security** — `CREATE POLICY`, `ENABLE`/`FORCE ROW LEVEL
   SECURITY`, and who bypasses it.
9. **Ownership** — what the owner implicitly holds, and why revoking from an
   owner is a mistake.
10. **Predefined roles** — `pg_read_all_data` and friends, and why `pg_` is
    reserved.
11. **Reading the catalog** — `pg_roles`, `pg_authid`, `pg_auth_members`,
    `pg_class.relacl`, `aclexplode()`, `information_schema` and why the
    catalog is the truthful source and `information_schema` is not.

**Source:** the PostgreSQL manual, chapters *Database Roles*, *Privileges*
(5.8), *Row Security Policies* (5.9), and the `GRANT` / `REVOKE` /
`CREATE ROLE` / `ALTER DEFAULT PRIVILEGES` reference pages. It is genuinely
well written; you do not need a book.

**Do it hands-on.** Spin up a Postgres container, create roles, grant things,
then try to answer the questions below by experiment.

> **Stopping condition.** Answer these without looking anything up:
> 1. Alice is a member of role `analyst`, which holds `SELECT` on everything in
>    `public`. Write SQL that leaves Alice unable to read `public.salaries`
>    while she stays in `analyst`. *(You can't. Understanding **why** is the
>    point — it is the single most important constraint in the product.)*
> 2. You `GRANT SELECT ON ALL TABLES IN SCHEMA app TO reader`. A migration
>    creates `app.orders` tomorrow. Can `reader` read it? What would make it
>    able to?
> 3. What does `GRANT SELECT (id, email) ON users TO support` do to
>    `SELECT * FROM users` run by `support`?
> 4. Bob is `NOINHERIT` and a member of `writer`. What can Bob do immediately
>    after connecting, and what must he do first?
> 5. Who can read a table that has RLS enabled but no policy? Who can read it
>    despite a restrictive policy?

### 0.2 The AWS IAM policy evaluation model — depth: **working**

Our policy format is IAM-shaped, so the mental model has to be exact. You have
AWS SAA material in flight already, which covers most of this — but the
**evaluation logic** specifically is what matters here, not the console.

Cover: `Effect` / `Principal` / `Action` / `Resource` / `Condition`; the
difference between an **implicit deny** (nothing allowed it) and an **explicit
deny** (something forbade it); why **explicit deny always wins** regardless of
order; wildcards in ARNs; and condition operators.

**Source:** the AWS documentation page *Policy evaluation logic* in the IAM
User Guide. Read the decision flowchart until it is boring.

> **Stopping condition.**
> 1. Explain the difference between implicit and explicit deny, and why the
>    distinction matters when you are *compiling* rather than *deciding*.
> 2. A policy allows `s3:*` on `*`, another denies `s3:DeleteObject` on one
>    bucket. What happens, and why does evaluation order not matter?
> 3. Why can an IAM-style `Deny` not be translated directly into a PostgreSQL
>    statement? *(Combine this with 0.1 — it is the crux of the whole solver.)*

---

## Tier 1 — Needed to participate in the architecture and HLD

### 1.1 Go — depth: **reading**, moving to **working**

You do not need mastery. You need to review a pull request and tell whether a
design is right.

Cover: structs and methods; **interfaces and implicit satisfaction** (this is
the whole provider SPI); errors as values, wrapping, `errors.Is`/`As`;
`context.Context` for cancellation and deadlines; slices and maps, including
the nil-vs-empty distinction; goroutines and channels at a basic level; and
the `testing` package including table-driven tests.

**Source:** *A Tour of Go*, then *Effective Go*, then read a real codebase.

> **Stopping condition.** Given an interface with five methods, explain what it
> would take for a new type to satisfy it and why Go does not need an
> `implements` keyword. Explain why our provider interface must not pass
> `*sql.DB` across its boundary.

### 1.2 Concurrency and transactions in databases — depth: **conceptual**

Cover: ACID; isolation levels and what each actually prevents; **transactional
DDL** — PostgreSQL has it, MySQL does not, and this is why our apply path has
two shapes; advisory locks; and `SELECT ... FOR UPDATE SKIP LOCKED`, which is
how the job queue works without Redis.

> **Stopping condition.** Explain why a failed multi-statement apply is safe on
> PostgreSQL and dangerous on MySQL, and what the code must do differently.

### 1.3 Protocol Buffers and RPC — depth: **conceptual**, moving to **reading**

Cover: what an IDL is and why schema-first matters; protobuf syntax, field
numbers, and **why you never reuse a field number**; what backward and forward
compatibility mean; gRPC's four call types; what Connect adds (plain JSON over
HTTP POST, browser support without a proxy); and what `buf` does — lint,
generate, and breaking-change detection.

**Source:** the Protocol Buffers language guide (proto3), then the Connect
documentation.

> **Stopping condition.** You add a field to a request message. Is that a
> breaking change? What if you rename one? What if you renumber one?

### 1.4 OAuth 2.0 and OIDC — depth: **conceptual**

This is how every human authenticates to db-iam.

Cover: **authentication versus authorization** (OIDC does the first, OAuth the
second); ID token versus access token; JWT structure and how signature
validation works; the authorization code flow with PKCE; the client credentials
flow for machines; claims, scopes, and group claims; and discovery via
`/.well-known/openid-configuration`.

> **Stopping condition.** Explain why db-iam should never see a user's password,
> and what it actually receives instead. Explain why validating a JWT means more
> than checking the signature.

### 1.5 MySQL's privilege model — depth: **conceptual**

Only the **differences** from PostgreSQL matter — they are the reason MySQL is
our second engine.

Cover: roles arrived in 8.0 and are **not active by default per session**
(`SET DEFAULT ROLE`, `activate_all_roles_on_login`); there is **no row-level
security**; there is no schema level — a "database" *is* the schema; and DDL is
not transactional.

> **Stopping condition.** A policy says "support may read only their own
> tenant's rows in `orders`". What do we do on PostgreSQL, and what are the
> three possible answers on MySQL?

---

## Tier 2 — Needed to build and operate it

### 2.1 Security fundamentals — depth: **working** on the first three

This is a security product. These are not optional.

| Topic | What to know |
|---|---|
| **Password storage** | Salts, work factors, why a hash is not encryption. **SCRAM-SHA-256** specifically: what a *verifier* is and why sending one beats sending a password |
| **SQL injection and identifier quoting** | Why identifiers cannot be bind parameters, and what quoting does and does not fix |
| **Least privilege and blast radius** | What a compromised control plane can reach, and how to shrink it |
| **TLS and mTLS** | Certificate validation, why `sslmode=verify-full` is the only correct setting for a real target |
| **Envelope encryption** | DEK versus KEK, what a KMS actually does, why you store a reference and not a secret |
| **Audit integrity** | Hash chains, why append-only matters, why audit is not logging |

> **Stopping condition.** Explain why computing a SCRAM verifier client-side is
> better than `CREATE ROLE ... PASSWORD 'literal'`, naming three specific places
> the plaintext would otherwise appear.

### 2.2 PostgreSQL as an application database — depth: **working**

Different from 0.1 — this is Postgres as *our own* store, not as a target.

Cover: schema migrations and why they must be ordered and forward-only in
practice; connection pooling and why a pool is small for a DDL tool; `JSONB`
and when to use it instead of columns; indexing basics; and row-level security
again, this time as *our* defence-in-depth for multi-tenancy.

### 2.3 Docker and container fundamentals — depth: **working**

Cover: images, layers, and the build cache; multi-stage builds; **distroless
and static images**, and why they have no shell; running as non-root with a
read-only root filesystem; multi-architecture builds with buildx; and why
`CGO_ENABLED=0` is what makes all of this simple for us.

> **Stopping condition.** Explain why our API image has no shell, and what that
> costs you when debugging.

### 2.4 Kubernetes and the operator pattern — depth: **conceptual**, later **working**

Cover: Pod / Deployment / Service / Secret / ConfigMap; **the reconciliation
loop** — desired state versus observed state, which is the same idea as our
drift detection; CRDs and what a controller does; Helm charts and values; and
`SecurityContext` and `NetworkPolicy`.

> **Stopping condition.** Explain how a Kubernetes controller and db-iam's
> drift reconciler are the same pattern, and where the analogy stops.

### 2.5 Observability — depth: **conceptual**

Cover: metrics versus traces versus logs and when each is the right tool;
OpenTelemetry as a vendor-neutral standard; Prometheus scraping and metric
types; and structured logging.

---

## Tier 3 — Learn when you touch it

Awareness is enough now. None of these will block a design conversation.

| Topic | Why it is on the list |
|---|---|
| **Cedar** — the *model*, not the syntax | We borrowed `permit`/`forbid`, deny-wins and typed entities. One hour on the docs is plenty |
| **Supply chain**: SBOM, `cosign`, SLSA | Enterprises ask before deploying a privileged tool |
| **`goreleaser`** | How the binary reaches Homebrew, apt and Scoop |
| **Terraform provider development** | v2 work |
| **`sqlc`, `goose`, River** | Straightforward once Go and SQL are solid |
| **SCIM, SPIFFE/SPIRE** | Deferred features |
| **Property-based testing** | Worth an hour before we write the solver tests |

---

## What you can safely ignore

Time is the scarce resource, so here is what the freeze removed from your
reading list:

| Skip | Because |
|---|---|
| **Rust** | Considered and rejected in §1 |
| **Rego / OPA** | Rejected in §3 |
| **WebAssembly, wazero, Extism** | Rejected in §2.1 |
| **Cedar's syntax and SDK** | We borrow the model, not the dependency |
| **React, Tailwind, TanStack** | Console is deferred past v1 |
| **GraphQL** | Never in the picture |
| **Redis, Kafka, message brokers** | Deliberately excluded to keep required services at two |
| **SQLite, DuckDB, RocksDB internals** | Out of scope entirely |
| **ORMs** | We use `sqlc`, which is the opposite of an ORM |

---

## A suggested sequence

Rough, and assumes limited hours a week rather than full time. Adjust freely —
the order matters more than the durations.

| When | Focus | Outcome |
|---|---|---|
| **Week 1** | 0.1 PostgreSQL privileges, hands-on | You can answer all five stopping-condition questions |
| **Week 2** | 0.2 IAM evaluation model, plus 1.1 Go to reading depth | You can explain why an IAM `Deny` has no direct SQL translation |
| **Week 3** | 1.3 protobuf/Connect, 1.4 OIDC, 1.2 transactions | You can review the API design |
| **Week 4** | 2.1 security fundamentals, 1.5 MySQL differences | You can review the apply path and the credential handling |
| **Ongoing** | Tier 2 as we build each piece | — |

**After week 1 you can already hold the policy-document conversation.** After
week 2 you can hold the solver conversation, which is the hard one. Everything
else can happen alongside the build.

---

## The five ideas that matter most

If you remember nothing else from this page:

1. **No SQL engine has a persistent `DENY`.** Privileges are additive. An
   IAM-style deny must be resolved when the plan is built, by withholding a
   grant — never at runtime.
2. **A column-level deny narrows a grant rather than removing it.** That makes
   it a set operation on the output, not an authorization decision, and it is
   why no off-the-shelf policy engine solves our core problem.
3. **Role membership can make a deny unsatisfiable.** If Alice inherits a grant
   from a shared role, no arrangement of `GRANT` statements can take it from
   her alone. The tool must *report* that rather than silently ignore it.
4. **Capabilities are probed, never inferred.** The same engine differs by
   version, by edition, and by managed provider. Assuming from a name is how a
   security tool silently under-enforces.
5. **Refusing is a feature.** When a target cannot express a policy faithfully,
   the correct behaviour is to stop and say so. A tool that quietly grants
   something weaker than what was written is worse than no tool, because it is
   believed.
