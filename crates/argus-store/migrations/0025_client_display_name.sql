-- §1 karar 30. `client_id` yönetici tarafından SEÇİLMEZ: yerel kayıtta Argus
-- üretir, CIMD yolunda istemcinin kendi URL'idir. Karar 5 onu küresel benzersiz
-- yaptığı için, seçilebilir olduğu sürece ilk gelen `webapp` adını alıyordu ve
-- ikinci kiracı bir benzersizlik ihlaline çarpıyordu.
--
-- İnsanın gördüğü ad artık ayrı bir kolonda ve KİRACIYA YEREL: iki kiracı aynı
-- adı serbestçe kullanabilir. Bu kolon üzerinde benzersizlik kısıtı YOKTUR,
-- kasıtlı olarak; bir etiket kimlik değildir.
--
-- Nullable bırakılmıştır. CIMD yolundan gelen istemciler adlarını metadata
-- dokümanından alır ve yönetim API'sinden geçmez.

ALTER TABLE clients ADD COLUMN display_name text;

-- NOT VALID ile eklenir: doğrulamasız ekleme anlıktır. Doğrulamasız
-- eklemeyip doğrudan CHECK koymak, kısıtı AYNI DDL içinde ACCESS EXCLUSIVE
-- altında tüm satırları tarayarak doğrular ve tarama bitene kadar kilidi
-- bırakmaz. `clients` her OAuth isteğinin dokunduğu tablodur; bu, canlıda
-- kesinti demektir.
ALTER TABLE clients
  ADD CONSTRAINT clients_display_name_length
  CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 255)
  NOT VALID;

-- Ayrı ifade, ayrı transaction: SHARE UPDATE EXCLUSIVE alır ve eşzamanlı
-- okuma ile yazmayı engellemez.
ALTER TABLE clients VALIDATE CONSTRAINT clients_display_name_length;

COMMENT ON COLUMN clients.display_name IS
  'Tenant-local human label. Not an identifier: no uniqueness constraint, by design.';

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

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0025_client_display_name');
