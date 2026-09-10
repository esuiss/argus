-- §24 #21: bir kiracı yöneticisi kendi kiracısının issuer'ından çalışır,
-- platform kontrol düzlemi ayrı ve dardır. Keycloak her realm'i master
-- realm'den geçiriyor, ki bu master'ı hem tek arıza hem tek ele geçirme
-- noktası yapıyor.
--
-- `tenants` üzerindeki kiracı politikası argus_current_tenant()'a kapsanmış
-- durumda, dolayısıyla kiracı trafiğine hizmet eden hiçbir rol kiracıları
-- listeleyemez. O politikayı gevşetmek ya da birine BYPASSRLS vermek yerine
-- kontrol düzlemi tek açık politikalı kendi rolünü alır. §1 #3'e dokunulmadı:
-- RLS açık ve FORCE'lu kalır, bu rol de diğer her rol gibi NOSUPERUSER
-- NOBYPASSRLS'tir.


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_platform') THEN
    CREATE ROLE argus_platform NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END
$$;

-- Yalnızca kiracı kaydı ve yalnızca bu rol üzerinden. Bu role geçerek şemada
-- başka hiçbir şey görünür hâle gelmez.
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
