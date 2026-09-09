CREATE TABLE protected_resources (
  tenant_id     uuid        NOT NULL,
  resource_uri  text        NOT NULL,
  resource_name text,
  scopes        text,
  created_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT protected_resources_pkey PRIMARY KEY (tenant_id, resource_uri),

  CONSTRAINT protected_resources_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE CASCADE,

  CONSTRAINT protected_resources_uri_absolute
    CHECK (resource_uri ~ '^https?://[^/?#]+'),
  CONSTRAINT protected_resources_uri_no_fragment
    CHECK (position('#' in resource_uri) = 0),
  CONSTRAINT protected_resources_uri_no_trailing_slash
    CHECK (resource_uri !~ '/$'),
  CONSTRAINT protected_resources_uri_length
    CHECK (length(resource_uri) BETWEEN 1 AND 2048),
  CONSTRAINT protected_resources_scopes_length
    CHECK (scopes IS NULL OR length(scopes) <= 4096)
);

ALTER TABLE protected_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_resources FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON protected_resources
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE protected_resources OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON protected_resources TO argus_app;

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0009_protected_resources');

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
