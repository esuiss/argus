CREATE TABLE cross_app_connections (
  tenant_id           uuid        NOT NULL,
  requesting_client_id text       NOT NULL,
  resource_as_issuer  text        NOT NULL,
  resource_uri        text,
  allowed_scopes      text        NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT cross_app_connections_pkey
    PRIMARY KEY (tenant_id, requesting_client_id, resource_as_issuer),

  CONSTRAINT cross_app_connections_client_fkey
    FOREIGN KEY (tenant_id, requesting_client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,

  CONSTRAINT cross_app_connections_issuer_https
    CHECK (resource_as_issuer ~ '^https?://[^/?#]+'),
  CONSTRAINT cross_app_connections_issuer_no_fragment
    CHECK (position('#' in resource_as_issuer) = 0),
  CONSTRAINT cross_app_connections_scopes_length
    CHECK (length(allowed_scopes) BETWEEN 1 AND 4096)
);

ALTER TABLE cross_app_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE cross_app_connections FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON cross_app_connections
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE cross_app_connections OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON cross_app_connections TO argus_app;

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0011_cross_app_connections');

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
