-- §24 #33 makes the idempotency key a day-one feature on every mutating
-- endpoint. §9.5 #3 keeps volatile state in the database rather than in a
-- process, so a restart does not lose a key mid-flight and let a retry run
-- the same request twice.

CREATE TABLE admin_idempotency (
  tenant_id    uuid        NOT NULL,
  surface      text        NOT NULL,
  key          text        NOT NULL,

  fingerprint  bytea       NOT NULL,
  state        text        NOT NULL,
  status_code  integer,
  body         jsonb,

  stored_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT admin_idempotency_pkey PRIMARY KEY (tenant_id, surface, key),

  CONSTRAINT admin_idempotency_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT admin_idempotency_key_length CHECK (length(key) BETWEEN 1 AND 255),
  CONSTRAINT admin_idempotency_key_is_printable CHECK (key ~ '^[\x21-\x7e]+$'),
  CONSTRAINT admin_idempotency_surface_is_known CHECK (surface IN ('platform', 'tenant')),
  CONSTRAINT admin_idempotency_fingerprint_is_a_digest CHECK (length(fingerprint) = 32),
  CONSTRAINT admin_idempotency_state_is_known
    CHECK (state IN ('in_flight', 'succeeded', 'failed')),
  -- A stored response only makes sense once there is one.
  CONSTRAINT admin_idempotency_terminal_carries_a_response
    CHECK (state = 'in_flight' OR status_code IS NOT NULL)
);

CREATE INDEX admin_idempotency_by_age ON admin_idempotency (tenant_id, stored_at);

-- §24 #28: bulk is an async job, not SCIM /Bulk. Every vendor surveyed
-- declared /Bulk unsupported and wrote this instead.
CREATE TABLE admin_jobs (
  tenant_id   uuid        NOT NULL,
  job_id      uuid        NOT NULL DEFAULT uuidv7(),

  kind        text        NOT NULL,
  state       text        NOT NULL DEFAULT 'pending',
  total       integer     NOT NULL,
  completed   integer     NOT NULL DEFAULT 0,
  failures    jsonb       NOT NULL DEFAULT '[]'::jsonb,

  created_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,

  CONSTRAINT admin_jobs_pkey PRIMARY KEY (tenant_id, job_id),

  CONSTRAINT admin_jobs_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT admin_jobs_state_is_known
    CHECK (state IN ('pending', 'running', 'succeeded', 'partially_succeeded', 'failed')),
  CONSTRAINT admin_jobs_total_is_bounded CHECK (total BETWEEN 1 AND 10000),
  CONSTRAINT admin_jobs_completed_is_within_total CHECK (completed BETWEEN 0 AND total),
  CONSTRAINT admin_jobs_failures_is_an_array CHECK (jsonb_typeof(failures) = 'array'),
  CONSTRAINT admin_jobs_finished_only_when_terminal
    CHECK (finished_at IS NULL OR state IN ('succeeded', 'partially_succeeded', 'failed'))
);

CREATE INDEX admin_jobs_live ON admin_jobs (tenant_id, created_at)
  WHERE state IN ('pending', 'running');

ALTER TABLE admin_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_idempotency FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_jobs FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON admin_idempotency
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON admin_jobs
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE admin_idempotency OWNER TO argus_owner;
ALTER TABLE admin_jobs OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON admin_idempotency TO argus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_jobs TO argus_app;

DO $$
DECLARE offending text;
BEGIN
  SELECT string_agg(c.relname, ', ')
    INTO offending
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p')
     AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR r.rolsuper OR r.rolbypassrls);

  IF offending IS NOT NULL THEN
    RAISE EXCEPTION 'tables without RLS+FORCE or owned by a superuser: %', offending;
  END IF;
END
$$;

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0021_admin_api');
