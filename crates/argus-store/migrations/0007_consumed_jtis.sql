CREATE TABLE consumed_jtis (
  tenant_id  uuid        NOT NULL,
  purpose    text        NOT NULL,
  jti        text        NOT NULL,
  expires_at timestamptz NOT NULL,

  CONSTRAINT consumed_jtis_pkey PRIMARY KEY (tenant_id, purpose, jti),

  CONSTRAINT consumed_jtis_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE CASCADE,

  CONSTRAINT consumed_jtis_purpose_valid
    CHECK (purpose IN ('dpop_proof', 'client_assertion')),
  CONSTRAINT consumed_jtis_jti_length CHECK (length(jti) BETWEEN 1 AND 255)
);

CREATE INDEX consumed_jtis_expiry ON consumed_jtis (expires_at);

ALTER TABLE consumed_jtis ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumed_jtis FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON consumed_jtis
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE consumed_jtis OWNER TO argus_owner;

GRANT SELECT, INSERT, DELETE ON consumed_jtis TO argus_app;

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
