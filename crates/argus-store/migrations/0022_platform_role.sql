-- §24 #21: a tenant administrator works from its own tenant's issuer, and the
-- platform control plane is separate and narrow. Keycloak routes every realm
-- through the master realm, which makes master both the single point of
-- failure and the single point of compromise.
--
-- The tenant policy on `tenants` is scoped to argus_current_tenant(), so no
-- role that serves tenant traffic can enumerate tenants. Rather than weaken
-- that policy or hand anything BYPASSRLS, the control plane gets its own role
-- with one explicit policy. §1 #3 is untouched: RLS stays enabled and forced,
-- and this role is NOSUPERUSER NOBYPASSRLS like every other.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_platform') THEN
    CREATE ROLE argus_platform NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END
$$;

-- Only the tenant registry, and only through this role. Nothing else in the
-- schema becomes visible by switching to it.
CREATE POLICY platform_control_plane ON tenants
  TO argus_platform
  USING (true)
  WITH CHECK (true);

GRANT SELECT, INSERT, UPDATE ON tenants TO argus_platform;

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

-- And the control plane role must not have picked up anything else.
DO $$
DECLARE leaked text;
BEGIN
  SELECT string_agg(DISTINCT c.relname, ', ')
    INTO leaked
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p')
     AND c.relname <> 'tenants'
     AND (
       has_table_privilege('argus_platform', c.oid, 'SELECT') OR
       has_table_privilege('argus_platform', c.oid, 'INSERT') OR
       has_table_privilege('argus_platform', c.oid, 'UPDATE') OR
       has_table_privilege('argus_platform', c.oid, 'DELETE')
     );

  IF leaked IS NOT NULL THEN
    RAISE EXCEPTION 'the control plane role reaches beyond the tenant registry: %', leaked;
  END IF;
END
$$;

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0022_platform_role');
