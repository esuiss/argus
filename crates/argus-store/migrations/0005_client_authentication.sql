-- İstemci kimlik doğrulaması — RFC 7523 §2.2 `private_key_jwt`.
--
-- # Neden paylaşılan sır YOK
--
-- §12529: *"Paylaşılan secret yok — confidential client yolu `private_key_jwt`
-- + yayımlanmış JWKS"*. Simetrik bir sır hem sunucuda hem istemcide durur;
-- sızıntı iki taraftan da olabilir ve hangisinden olduğu anlaşılamaz. Açık
-- anahtarda sunucu tarafında **sır yoktur**: bu tablonun tamamı sızsa bile
-- kimse istemci adına assertion imzalayamaz.
--
-- Bu yüzden burada `client_secret_hash` KOLONU YOK ve olmayacak.

-- ---------------------------------------------------------------------------
-- clients.auth_method
-- ---------------------------------------------------------------------------

-- `NOT NULL DEFAULT 'none'`: mevcut satırlar public client'tır ve PKCE ile
-- korunur (§1 #24 + OAuth 2.1). Expand-contract (§1 #26): varsayılan sayesinde
-- eski uygulama sürümü bu kolonu görmeden çalışmaya devam eder.
ALTER TABLE clients
  ADD COLUMN auth_method text NOT NULL DEFAULT 'none';

-- ⚠️ Bu kısıt, veritabanında `client_type = 'confidential'` satırı varsa
-- migration'ı DÜŞÜRÜR. Bu kasıtlı: o satırların her biri, kimlik doğrulaması
-- olmayan bir gizli istemcidir ve sessizce geçirilmemelidir. Operatör önce
-- `auth_method`'u doldurur, sonra migration'ı koşar.
ALTER TABLE clients
  ADD CONSTRAINT clients_auth_method_valid
    CHECK (auth_method IN ('none', 'private_key_jwt')),

  -- Tutarlılık: public client'ın sırrı ya da anahtarı olmaz, confidential
  -- client'ın kimlik bilgisi olmadan var olması anlamsızdır. Bu kontrol
  -- olmadan "confidential ama auth_method = none" satırı yazılabilirdi ve o
  -- satır, kimlik doğrulaması olmayan bir gizli istemci demektir.
  ADD CONSTRAINT clients_type_matches_auth_method CHECK (
    (client_type = 'public'       AND auth_method = 'none')
    OR (client_type = 'confidential' AND auth_method <> 'none')
  );

-- ---------------------------------------------------------------------------
-- client_keys
-- ---------------------------------------------------------------------------

-- İstemcinin açık imzalama anahtarları. Birden fazla satır olabilir: istemci de
-- anahtar döndürür ve rotasyon penceresinde eski ile yeni birlikte geçerli
-- olmalıdır — tek satıra zorlamak, istemcinin rotasyonunu kesinti hâline getirir.
CREATE TABLE client_keys (
  tenant_id  uuid  NOT NULL,
  client_id  text  NOT NULL,

  -- `JWS` başlığındaki `kid` ile eşleşir. Aynı istemcide iki anahtarın aynı
  -- `kid`'i olamaz, yoksa hangisinin doğrulayacağı belirsizleşir.
  kid        text  NOT NULL,

  -- `P-256` açık anahtarının bileşenleri, ÇÖZÜLMÜŞ 32 bayt.
  -- BASE64URL dizgesi değil: kodlama farkları (padding, hizalama) doğrulamayı
  -- sessizce kaydırır ve hata "imza tutmuyor" olarak görünür.
  x          bytea NOT NULL,
  y          bytea NOT NULL,

  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT client_keys_pkey PRIMARY KEY (tenant_id, client_id, kid),

  -- §1 #2: kiracı-kapsamlı tablolar arası FK COMPOSITE.
  CONSTRAINT client_keys_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,

  CONSTRAINT client_keys_x_length CHECK (octet_length(x) = 32),
  CONSTRAINT client_keys_y_length CHECK (octet_length(y) = 32),
  CONSTRAINT client_keys_kid_length CHECK (length(kid) BETWEEN 1 AND 255)
);

-- ---------------------------------------------------------------------------
-- RLS — §1 #3, istisnasız
-- ---------------------------------------------------------------------------

ALTER TABLE client_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON client_keys
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE client_keys OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON client_keys TO argus_app;

-- ---------------------------------------------------------------------------
-- Kendi kendini doğrulayan kontrol
-- ---------------------------------------------------------------------------

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
