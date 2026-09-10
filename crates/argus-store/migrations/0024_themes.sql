-- §1 K29. Tema verisi burada saklanır ama istek başına buradan OKUNMAZ:
-- başlangıçta kiracı kayıt defterine yüklenir ve render başına yapılan iş bir
-- map aramasıdır. Bir kiracının logosu yılda bir değişir.

CREATE TABLE themes (
  tenant_id   uuid        NOT NULL,
  -- §1 K29: Keycloak realm ve client düzeyinde tema seçimine izin veriyor.
  -- '' kiracının varsayılanı; dolu bir değer o istemciye özel temadır.
  client_id   text        NOT NULL DEFAULT '',

  name             text   NOT NULL,
  logo_url         text,
  primary_colour   text,
  background_colour text,

  -- Liquid kabuğu. NULL ise derlenmiş varsayılan kabuk kullanılır.
  -- §1 K28: burada sunucuda çalışan bir şablon YOK; Liquid'in fonksiyon
  -- çağırma sözdizimi yoktur ve şablon kendisine verilmeyene ulaşamaz.
  shell        text,

  strings      jsonb       NOT NULL DEFAULT '{}'::jsonb,
  footer_links jsonb       NOT NULL DEFAULT '[]'::jsonb,

  updated_at   timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT themes_pkey PRIMARY KEY (tenant_id, client_id),

  CONSTRAINT themes_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  -- clients'a FK YOK ve sebebi ölçüldü: kiracı varsayılanı client_id = ''
  -- ile geliyor, öyle bir istemci hiç var olmayacağı için FK o satırı
  -- imkânsız kılıyordu. Yetim satırın zararı da yok — arama var olan bir
  -- istemciden başlar, silinmiş bir istemcinin teması hiç seçilmez.
  -- Temizliği aşağıdaki trigger yapıyor.

  CONSTRAINT themes_name_length CHECK (length(name) BETWEEN 1 AND 256),
  -- argus-core'daki MAX_SHELL_BYTES ile aynı tavan; şema son kapıdır.
  CONSTRAINT themes_shell_length CHECK (shell IS NULL OR length(shell) <= 65536),
  -- §11 F ve §1 K28: kiracıdan gelen URL sayfaya girecekse şeması sabitlenir.
  -- javascript: ve data: bir logo alanından geçerse XSS olur.
  CONSTRAINT themes_logo_is_https
    CHECK (logo_url IS NULL OR logo_url LIKE 'https://%'),
  -- Renk doğrudan bir stil kuralına giriyor; biçimi sabitlenmezse kuraldan
  -- kaçar.
  CONSTRAINT themes_primary_is_hex
    CHECK (primary_colour IS NULL OR primary_colour ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'),
  CONSTRAINT themes_background_is_hex
    CHECK (background_colour IS NULL OR background_colour ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'),
  CONSTRAINT themes_strings_is_object CHECK (jsonb_typeof(strings) = 'object'),
  CONSTRAINT themes_links_is_array CHECK (jsonb_typeof(footer_links) = 'array')
);

-- Bir istemci silindiğinde temasi da gider. FK'nin yerine geçen kısım bu.
CREATE OR REPLACE FUNCTION themes_follow_client_deletion() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM themes
   WHERE tenant_id = OLD.tenant_id AND client_id = OLD.client_id;
  RETURN OLD;
END
$$;

CREATE TRIGGER clients_drop_theme
  AFTER DELETE ON clients
  FOR EACH ROW EXECUTE FUNCTION themes_follow_client_deletion();

ALTER TABLE themes ENABLE ROW LEVEL SECURITY;
ALTER TABLE themes FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON themes
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE themes OWNER TO argus_owner;
ALTER FUNCTION themes_follow_client_deletion() OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON themes TO argus_app;

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

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0024_themes');
