# dbauthz — Engine Reference

> Primary sources for every engine dbauthz targets: roles, privileges, grants,
> ownership, row security and authentication.
>
> **The rule:** before changing a provider, the solver, the action vocabulary or
> the capability model, read the relevant section below first. Link the page you
> relied on in the PR or ADR. If an engine's behaviour is not covered here, add
> the link in the same PR.
>
> Order follows the frozen engine order in [STACK.md](STACK.md): PostgreSQL,
> then MySQL, then Cassandra, then the rest of Class A and B.
>
> Links point at each vendor's "current" or latest-stable docs unless a version
> is named. Behaviour changes between versions, so check the version notes for
> anything version-sensitive.

---

## 1. PostgreSQL — first engine

### 1.1 Concepts

| Topic | Link | Why dbauthz cares |
|---|---|---|
| Database roles (chapter) | [user-manag](https://www.postgresql.org/docs/current/user-manag.html) | Entry point for the identity model |
| Roles | [database-roles](https://www.postgresql.org/docs/current/database-roles.html) | Users and groups are both roles |
| Role attributes | [role-attributes](https://www.postgresql.org/docs/current/role-attributes.html) | `LOGIN`, `SUPERUSER`, `CREATEROLE`, `BYPASSRLS` and others |
| Role membership | [role-membership](https://www.postgresql.org/docs/current/role-membership.html) | `INHERIT`, `SET`, `ADMIN` options; membership closure in the solver |
| Dropping roles | [role-removal](https://www.postgresql.org/docs/current/role-removal.html) | Ownership must be reassigned before a role can go |
| Predefined roles | [predefined-roles](https://www.postgresql.org/docs/current/predefined-roles.html) | `pg_read_all_data`, `pg_monitor`, `pg_maintain` and others |
| Privileges | [ddl-priv](https://www.postgresql.org/docs/current/ddl-priv.html) | Privilege-to-object table and ACL abbreviations |
| Row security policies | [ddl-rowsecurity](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) | Row-level capability; permissive vs restrictive |
| Schemas and search path | [ddl-schemas](https://www.postgresql.org/docs/current/ddl-schemas.html) | Secure schema usage patterns; `public` schema defaults |
| Function security | [perm-functions](https://www.postgresql.org/docs/current/perm-functions.html) | `SECURITY DEFINER` is a privilege-escalation path |

### 1.2 Statements

| Statement | Link |
|---|---|
| `GRANT` | [sql-grant](https://www.postgresql.org/docs/current/sql-grant.html) |
| `REVOKE` | [sql-revoke](https://www.postgresql.org/docs/current/sql-revoke.html) |
| `CREATE ROLE` | [sql-createrole](https://www.postgresql.org/docs/current/sql-createrole.html) |
| `ALTER ROLE` | [sql-alterrole](https://www.postgresql.org/docs/current/sql-alterrole.html) |
| `DROP ROLE` | [sql-droprole](https://www.postgresql.org/docs/current/sql-droprole.html) |
| `ALTER DEFAULT PRIVILEGES` | [sql-alterdefaultprivileges](https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html) |
| `CREATE POLICY` | [sql-createpolicy](https://www.postgresql.org/docs/current/sql-createpolicy.html) |
| `ALTER POLICY` | [sql-alterpolicy](https://www.postgresql.org/docs/current/sql-alterpolicy.html) |
| `DROP POLICY` | [sql-droppolicy](https://www.postgresql.org/docs/current/sql-droppolicy.html) |
| `ALTER TABLE` (`ENABLE` / `FORCE ROW LEVEL SECURITY`, `OWNER TO`) | [sql-altertable](https://www.postgresql.org/docs/current/sql-altertable.html) |
| `REASSIGN OWNED` | [sql-reassign-owned](https://www.postgresql.org/docs/current/sql-reassign-owned.html) |
| `DROP OWNED` | [sql-drop-owned](https://www.postgresql.org/docs/current/sql-drop-owned.html) |
| `SET ROLE` | [sql-set-role](https://www.postgresql.org/docs/current/sql-set-role.html) |
| `SET SESSION AUTHORIZATION` | [sql-set-session-authorization](https://www.postgresql.org/docs/current/sql-set-session-authorization.html) |

### 1.3 Introspection — reading actual state

The planner diffs desired state against these. Read them from the server; never
infer capability from the engine name.

| Source | Link | Holds |
|---|---|---|
| `pg_authid` | [catalog-pg-authid](https://www.postgresql.org/docs/current/catalog-pg-authid.html) | Roles and attributes (superuser-only) |
| `pg_roles` | [view-pg-roles](https://www.postgresql.org/docs/current/view-pg-roles.html) | Readable view of `pg_authid` without passwords |
| `pg_auth_members` | [catalog-pg-auth-members](https://www.postgresql.org/docs/current/catalog-pg-auth-members.html) | Membership edges and their options |
| `pg_class` | [catalog-pg-class](https://www.postgresql.org/docs/current/catalog-pg-class.html) | `relacl` for tables, views and sequences |
| `pg_attribute` | [catalog-pg-attribute](https://www.postgresql.org/docs/current/catalog-pg-attribute.html) | `attacl` for column privileges |
| `pg_default_acl` | [catalog-pg-default-acl](https://www.postgresql.org/docs/current/catalog-pg-default-acl.html) | Default privileges |
| `pg_init_privs` | [catalog-pg-init-privs](https://www.postgresql.org/docs/current/catalog-pg-init-privs.html) | Initial privileges from `initdb` and extensions |
| `pg_policy` / `pg_policies` | [catalog-pg-policy](https://www.postgresql.org/docs/current/catalog-pg-policy.html) · [view-pg-policies](https://www.postgresql.org/docs/current/view-pg-policies.html) | Row security policies |
| Access privilege functions | [functions-info](https://www.postgresql.org/docs/current/functions-info.html) | `has_*_privilege`, `pg_has_role`, `aclexplode` |
| `information_schema` | [table_privileges](https://www.postgresql.org/docs/current/infoschema-table-privileges.html) · [column_privileges](https://www.postgresql.org/docs/current/infoschema-column-privileges.html) · [applicable_roles](https://www.postgresql.org/docs/current/infoschema-applicable-roles.html) · [enabled_roles](https://www.postgresql.org/docs/current/infoschema-enabled-roles.html) | SQL-standard views; less complete than the catalogs |

### 1.4 Authentication and credentials

| Topic | Link |
|---|---|
| Client authentication (chapter) | [client-authentication](https://www.postgresql.org/docs/current/client-authentication.html) |
| `pg_hba.conf` | [auth-pg-hba-conf](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html) |
| Password authentication and SCRAM | [auth-password](https://www.postgresql.org/docs/current/auth-password.html) |
| Session defaults, including `row_security` | [runtime-config-client](https://www.postgresql.org/docs/current/runtime-config-client.html) |
| Protocol message flow | [protocol-flow](https://www.postgresql.org/docs/current/protocol-flow.html) |

### 1.5 Version notes

| Version | Change that affects dbauthz | Link |
|---|---|---|
| 15 | `PUBLIC` no longer has `CREATE` on the `public` schema by default | [Release 15](https://www.postgresql.org/docs/release/15.0/) |
| 16 | `CREATEROLE` is restricted; membership gains separate `INHERIT` and `SET` options | [Release 16](https://www.postgresql.org/docs/release/16.0/) |
| 17 | New `MAINTAIN` privilege and `pg_maintain` predefined role | [Release 17](https://www.postgresql.org/docs/release/17.0/) |
| 18 | MD5 password authentication is deprecated | [Release 18](https://www.postgresql.org/docs/release/18.0/) |
| — | Supported-version policy | [Versioning](https://www.postgresql.org/support/versioning/) |

### 1.6 Managed PostgreSQL

Managed services cap what the connected role can do. Most real installs are one
of these.

| Service | Link |
|---|---|
| Amazon RDS / Aurora | [Roles and permissions](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.PostgreSQL.CommonDBATasks.Roles.html) |
| Google Cloud SQL | [Users](https://cloud.google.com/sql/docs/postgres/users) |
| Azure Flexible Server | [Create users](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-create-users) |
| Supabase | [Postgres roles](https://supabase.com/docs/guides/database/postgres/roles) |
| Neon | [Manage roles](https://neon.com/docs/manage/roles) |

---

## 2. MySQL and MariaDB — second engine

MySQL has no row-level security and no transactional DDL. `GRANT`, `REVOKE`
and `CREATE USER` commit implicitly. Read the implicit-commit page before
designing apply ordering.

### 2.1 MySQL 8.4

| Topic | Link |
|---|---|
| Access control and account management (chapter) | [access-control](https://dev.mysql.com/doc/refman/8.4/en/access-control.html) |
| Privileges provided | [privileges-provided](https://dev.mysql.com/doc/refman/8.4/en/privileges-provided.html) |
| Grant tables | [grant-tables](https://dev.mysql.com/doc/refman/8.4/en/grant-tables.html) |
| Roles | [roles](https://dev.mysql.com/doc/refman/8.4/en/roles.html) |
| Partial revokes | [partial-revokes](https://dev.mysql.com/doc/refman/8.4/en/partial-revokes.html) |
| Account categories (`SYSTEM_USER`) | [account-categories](https://dev.mysql.com/doc/refman/8.4/en/account-categories.html) |
| Account names (`user@host`) | [account-names](https://dev.mysql.com/doc/refman/8.4/en/account-names.html) |
| When privilege changes take effect | [privilege-changes](https://dev.mysql.com/doc/refman/8.4/en/privilege-changes.html) |
| Statements causing implicit commit | [implicit-commit](https://dev.mysql.com/doc/refman/8.4/en/implicit-commit.html) |
| `GRANT` · `REVOKE` | [grant](https://dev.mysql.com/doc/refman/8.4/en/grant.html) · [revoke](https://dev.mysql.com/doc/refman/8.4/en/revoke.html) |
| `CREATE USER` · `CREATE ROLE` · `SET DEFAULT ROLE` | [create-user](https://dev.mysql.com/doc/refman/8.4/en/create-user.html) · [create-role](https://dev.mysql.com/doc/refman/8.4/en/create-role.html) · [set-default-role](https://dev.mysql.com/doc/refman/8.4/en/set-default-role.html) |
| `SHOW GRANTS` | [show-grants](https://dev.mysql.com/doc/refman/8.4/en/show-grants.html) |
| `caching_sha2_password` | [caching-sha2-pluggable-authentication](https://dev.mysql.com/doc/refman/8.4/en/caching-sha2-pluggable-authentication.html) |

### 2.2 MariaDB

MariaDB's role model differs from MySQL's. Treat it as a separate capability
profile, not an alias.

| Topic | Link |
|---|---|
| `GRANT` | [grant](https://mariadb.com/kb/en/grant/) |
| Roles overview | [roles_overview](https://mariadb.com/kb/en/roles_overview/) |
| `CREATE USER` | [create-user](https://mariadb.com/kb/en/create-user/) |

---

## 3. Cassandra and ScyllaDB — third engine

| Topic | Link |
|---|---|
| CQL security: roles, permissions, `GRANT` | [Cassandra CQL security](https://cassandra.apache.org/doc/latest/cassandra/developing/cql/security.html) |
| Operating security: authenticator, authorizer | [Cassandra operating security](https://cassandra.apache.org/doc/latest/cassandra/managing/operating/security.html) |
| ScyllaDB RBAC | [ScyllaDB RBAC use case](https://opensource.docs.scylladb.com/stable/operating-scylla/security/rbac-usecase.html) |

---

## 4. Later engines

Starting points only. Expand an engine into its own section, in the shape of
section 1, when its provider work begins.

### 4.1 Class A — native privilege system

| Engine | Links |
|---|---|
| SQL Server | [Permissions](https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine) · [GRANT](https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-transact-sql) |
| Oracle | [Privilege and role authorization](https://docs.oracle.com/en/database/oracle/oracle-database/23/dbseg/configuring-privilege-and-role-authorization.html) |
| ClickHouse | [Access rights](https://clickhouse.com/docs/operations/access-rights) · [GRANT](https://clickhouse.com/docs/sql-reference/statements/grant) |
| Snowflake | [Access control overview](https://docs.snowflake.com/en/user-guide/security-access-control-overview) · [Privileges](https://docs.snowflake.com/en/user-guide/security-access-control-privileges) |
| Redshift | [GRANT](https://docs.aws.amazon.com/redshift/latest/dg/r_GRANT.html) · [Role-based access control](https://docs.aws.amazon.com/redshift/latest/dg/t_Roles.html) |
| MongoDB | [Role-based access control](https://www.mongodb.com/docs/manual/core/authorization/) · [Built-in roles](https://www.mongodb.com/docs/manual/reference/built-in-roles/) |
| Trino | [System access control](https://trino.io/docs/current/security/built-in-system-access-control.html) · [GRANT](https://trino.io/docs/current/sql/grant.html) |

### 4.2 Class B — access control through an admin API

| Engine | Links |
|---|---|
| Apache Pinot | [Access control](https://docs.pinot.apache.org/operators/operating-pinot/access-control) |
| Elasticsearch | [Defining roles](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/defining-roles) |
| OpenSearch | [Access control](https://docs.opensearch.org/latest/security/access-control/index/) |
| Apache Kafka | [Authorization and ACLs](https://kafka.apache.org/documentation/#security_authz) |
| Apache Druid | [User authentication and authorization](https://druid.apache.org/docs/latest/operations/security-user-auth) |

### 4.3 Class C — out of scope

SQLite, DuckDB, RocksDB and LMDB have no identity model. They are not providers.
See [STACK.md §0](STACK.md).

---

## Maintaining this file

- Links were checked on 2026-10-09. dev.mysql.com blocks scripted link checkers,
  so check those links in a browser.
- Prefer the vendor's own documentation. Third-party posts go in an ADR, not here.
- When a provider pins engine versions, pin the links for those versions too.
