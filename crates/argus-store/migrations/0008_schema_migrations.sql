CREATE SCHEMA IF NOT EXISTS argus_meta;

ALTER SCHEMA argus_meta OWNER TO argus_owner;

CREATE TABLE argus_meta.schema_migrations (
  name       text        NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT schema_migrations_pkey PRIMARY KEY (name)
);

ALTER TABLE argus_meta.schema_migrations OWNER TO argus_owner;

GRANT USAGE ON SCHEMA argus_meta TO argus_app;
GRANT SELECT ON argus_meta.schema_migrations TO argus_app;

INSERT INTO argus_meta.schema_migrations (name) VALUES
  ('0001_baseline'),
  ('0002_audit'),
  ('0003_oauth_grants'),
  ('0004_oidc_code_claims'),
  ('0005_client_authentication'),
  ('0006_redirect_uri_scheme'),
  ('0007_consumed_jtis'),
  ('0008_schema_migrations');

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
