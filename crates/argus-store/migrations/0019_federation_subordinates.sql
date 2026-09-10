CREATE TABLE federation_subordinates (
  tenant_id       uuid        NOT NULL,
  subject         text        NOT NULL,

  jwks            jsonb       NOT NULL,
  metadata_policy jsonb,
  constraints     jsonb,

  added_at        timestamptz NOT NULL DEFAULT now(),
  withdrawn_at    timestamptz,

  CONSTRAINT federation_subordinates_pkey PRIMARY KEY (tenant_id, subject),

  CONSTRAINT federation_subordinates_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT federation_subordinates_subject_is_https
    CHECK (subject LIKE 'https://%' AND subject NOT LIKE '%?%' AND subject NOT LIKE '%#%'),
  CONSTRAINT federation_subordinates_subject_length CHECK (length(subject) BETWEEN 9 AND 1024),
  CONSTRAINT federation_subordinates_jwks_is_object CHECK (jsonb_typeof(jwks) = 'object'),
  CONSTRAINT federation_subordinates_policy_is_object
    CHECK (metadata_policy IS NULL OR jsonb_typeof(metadata_policy) = 'object'),
  CONSTRAINT federation_subordinates_constraints_is_object
    CHECK (constraints IS NULL OR jsonb_typeof(constraints) = 'object')
);

CREATE INDEX federation_subordinates_active
  ON federation_subordinates (tenant_id)
  WHERE withdrawn_at IS NULL;

ALTER TABLE federation_subordinates ENABLE ROW LEVEL SECURITY;
ALTER TABLE federation_subordinates FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON federation_subordinates
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE federation_subordinates OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON federation_subordinates TO argus_app;

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

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0019_federation_subordinates');
