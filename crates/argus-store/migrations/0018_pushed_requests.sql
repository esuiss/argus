CREATE TABLE pushed_requests (
  tenant_id   uuid        NOT NULL,
  request_id  text        NOT NULL,

  client_id   text        NOT NULL,

  parameters  jsonb       NOT NULL,

  issued_at   timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,

  CONSTRAINT pushed_requests_pkey PRIMARY KEY (tenant_id, request_id),

  CONSTRAINT pushed_requests_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,

  CONSTRAINT pushed_requests_id_length CHECK (length(request_id) BETWEEN 22 AND 128),
  CONSTRAINT pushed_requests_parameters_is_array CHECK (jsonb_typeof(parameters) = 'array'),
  CONSTRAINT pushed_requests_expiry_after_issue CHECK (expires_at > issued_at),

  CONSTRAINT pushed_requests_max_lifetime
    CHECK (expires_at <= issued_at + interval '10 minutes'),

  CONSTRAINT pushed_requests_consumed_within_life
    CHECK (consumed_at IS NULL OR consumed_at >= issued_at)
);

CREATE INDEX pushed_requests_expiry
  ON pushed_requests (expires_at)
  WHERE consumed_at IS NULL;

ALTER TABLE pushed_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pushed_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON pushed_requests
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE pushed_requests OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON pushed_requests TO argus_app;

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

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0018_pushed_requests');
