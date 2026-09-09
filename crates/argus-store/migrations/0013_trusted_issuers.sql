CREATE TABLE trusted_issuers (
  tenant_id  uuid        NOT NULL,
  issuer     text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT trusted_issuers_pkey PRIMARY KEY (tenant_id, issuer),

  CONSTRAINT trusted_issuers_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE CASCADE,

  CONSTRAINT trusted_issuers_https CHECK (issuer ~ '^https?://[^/?#]+'),
  CONSTRAINT trusted_issuers_no_fragment CHECK (position('#' in issuer) = 0)
);

CREATE TABLE trusted_issuer_keys (
  tenant_id uuid  NOT NULL,
  issuer    text  NOT NULL,
  kid       text  NOT NULL,
  x         bytea NOT NULL,
  y         bytea NOT NULL,

  CONSTRAINT trusted_issuer_keys_pkey PRIMARY KEY (tenant_id, issuer, kid),

  CONSTRAINT trusted_issuer_keys_issuer_fkey FOREIGN KEY (tenant_id, issuer)
    REFERENCES trusted_issuers (tenant_id, issuer) ON DELETE CASCADE,

  CONSTRAINT trusted_issuer_keys_x_length CHECK (octet_length(x) = 32),
  CONSTRAINT trusted_issuer_keys_y_length CHECK (octet_length(y) = 32)
);

ALTER TABLE trusted_issuers ENABLE ROW LEVEL SECURITY;
ALTER TABLE trusted_issuers FORCE ROW LEVEL SECURITY;
ALTER TABLE trusted_issuer_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE trusted_issuer_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON trusted_issuers
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON trusted_issuer_keys
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE trusted_issuers     OWNER TO argus_owner;
ALTER TABLE trusted_issuer_keys OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON trusted_issuers, trusted_issuer_keys TO argus_app;

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0013_trusted_issuers');

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
