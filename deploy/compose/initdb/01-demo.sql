-- Demo estate for the db-iam quickstart.
--
-- Deliberately messy in instructive ways. Every oddity below is something the
-- solver and the Postgres provider will have to reason about:
--
--   * a grant to PUBLIC, the implicit grantee on new objects
--   * a column-level grant, which is how a column Deny gets expressed
--   * a table with row-level security already enabled
--   * a role hierarchy with one NOINHERIT member, which changes what a
--     principal effectively holds
--   * an object owned by someone other than the connecting role

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------- schemas --
CREATE SCHEMA IF NOT EXISTS analytics;
CREATE SCHEMA IF NOT EXISTS billing;

-- ------------------------------------------------------------------ roles --
-- Group roles carrying privilege.
CREATE ROLE app_ro   NOLOGIN;
CREATE ROLE app_rw   NOLOGIN;
CREATE ROLE analyst  NOLOGIN;
CREATE ROLE support  NOLOGIN;

-- Login roles. bi_tool is a service account; the rest stand in for people.
CREATE ROLE bi_tool  LOGIN PASSWORD 'demo-not-a-real-secret';
CREATE ROLE alice    LOGIN PASSWORD 'demo-not-a-real-secret';
CREATE ROLE bob      LOGIN PASSWORD 'demo-not-a-real-secret' NOINHERIT;
CREATE ROLE app_svc  LOGIN PASSWORD 'demo-not-a-real-secret';

GRANT analyst TO alice;
GRANT app_ro  TO analyst;
-- bob holds support only after SET ROLE, because he is NOINHERIT. A solver
-- that ignores this reports privileges bob does not actually have at connect.
GRANT support TO bob;
GRANT app_rw  TO app_svc;
GRANT app_ro  TO bi_tool;

-- ----------------------------------------------------------------- tables --
CREATE TABLE public.users (
  id          bigserial PRIMARY KEY,
  email       text NOT NULL UNIQUE,
  full_name   text NOT NULL,
  ssn         text,                     -- the column a Deny will carve out
  tenant_id   uuid NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.orders (
  id          bigserial PRIMARY KEY,
  user_id     bigint NOT NULL REFERENCES public.users(id),
  tenant_id   uuid NOT NULL,
  total_cents bigint NOT NULL,
  status      text NOT NULL DEFAULT 'pending',
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE billing.invoices (
  id          bigserial PRIMARY KEY,
  order_id    bigint NOT NULL REFERENCES public.orders(id),
  amount_cents bigint NOT NULL,
  card_last4  text,
  issued_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE analytics.daily_revenue (
  day          date NOT NULL,
  tenant_id    uuid NOT NULL,
  total_cents  bigint NOT NULL,
  PRIMARY KEY (day, tenant_id)
);

CREATE VIEW analytics.v_active_users AS
  SELECT id, email, tenant_id FROM public.users WHERE created_at > now() - interval '30 days';

-- An object owned by another role, to exercise the "cannot manage what you do
-- not own" path on managed providers.
ALTER TABLE analytics.daily_revenue OWNER TO analyst;

-- ------------------------------------------------------------------- data --
INSERT INTO public.users (email, full_name, ssn, tenant_id) VALUES
  ('ada@example.com',   'Ada Lovelace',  '111-11-1111', '11111111-1111-1111-1111-111111111111'),
  ('grace@example.com', 'Grace Hopper',  '222-22-2222', '11111111-1111-1111-1111-111111111111'),
  ('alan@example.com',  'Alan Turing',   '333-33-3333', '22222222-2222-2222-2222-222222222222');

INSERT INTO public.orders (user_id, tenant_id, total_cents, status) VALUES
  (1, '11111111-1111-1111-1111-111111111111',  4200, 'paid'),
  (2, '11111111-1111-1111-1111-111111111111', 15000, 'pending'),
  (3, '22222222-2222-2222-2222-222222222222',   990, 'paid');

INSERT INTO analytics.daily_revenue (day, tenant_id, total_cents) VALUES
  (current_date - 1, '11111111-1111-1111-1111-111111111111', 19200),
  (current_date - 1, '22222222-2222-2222-2222-222222222222',   990);

-- ----------------------------------------------------------------- grants --
GRANT USAGE ON SCHEMA public, analytics, billing TO app_ro;
GRANT USAGE ON SCHEMA public                     TO app_rw;
GRANT USAGE ON SCHEMA analytics                  TO analyst;

GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO analyst;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.orders, public.users TO app_rw;
GRANT SELECT ON public.orders TO support;

-- Column-level grant: support may read users, but never the ssn column. This
-- is exactly the shape a column-level Deny compiles into, since PostgreSQL
-- privileges are additive and there is nothing to deny with.
GRANT SELECT (id, email, full_name, tenant_id, created_at) ON public.users TO support;

-- A grant to PUBLIC. Easy to make by accident, invisible in most tooling, and
-- the first thing authoritative mode has to revoke.
GRANT SELECT ON analytics.daily_revenue TO PUBLIC;

-- ------------------------------------------------------- row-level security --
-- Already enabled by hand, so introspection has pre-existing RLS to adopt
-- rather than a clean slate.
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_tenant_isolation ON public.orders
  FOR SELECT TO support
  USING (tenant_id = NULLIF(current_setting('dbiam.tenant', true), '')::uuid);

-- Sequences follow their tables; USAGE on a sequence is a real privilege and a
-- good test that the action vocabulary is keyed on object kind, not level.
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_rw;
