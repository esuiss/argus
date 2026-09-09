-- Argus baseline şeması.
--
-- Bu dosya §1'deki sekiz KŞS (kalıcı şema sözleşmesi) kararını uygular. Hepsi
-- gün-1'de doğru olmak zorunda: sonradan değiştirmek çevrimdışı göç demek.
--
--   #1  tenant_id her tabloda VE her birincil anahtarda
--   #2  her yabancı anahtar composite (tenant_id dahil)
--   #3  RLS + FORCE + non-owner rol, istisnasız
--   #6  kullanıcı benzersizliği kiracı-yerel, asla global
--   #7  değişmez kiracı slug'ı (issuer URL'inde)
--  #10  denetim logu kiracı + zaman partition'lı  (0002'de)
--  #14  kullanıcı ID'si ve e-posta asla yeniden kullanılmaz
--  #17  her PII alanı kullanıcı başına DEK ile şifreli  (sonraki fazda)
--
-- Minimum PostgreSQL 18 (§1 #27): yerleşik `uuidv7()`.

-- ---------------------------------------------------------------------------
-- Roller
-- ---------------------------------------------------------------------------

-- Uygulama rolü tabloların SAHİBİ DEĞİLDİR. RLS varsayılan olarak tablo sahibine
-- uygulanmaz; FORCE ROW LEVEL SECURITY bunu düzeltir ama tek başına yeterli
-- güvenlik sınırı sayılmamalı. İki katman birlikte: ayrı rol + FORCE.
-- ⚠️ FORCE ROW LEVEL SECURITY superuser'ı KAPSAMAZ. Superuser ve BYPASSRLS
-- yetkisi olan roller RLS'i tümüyle atlar; FORCE yalnızca tablo SAHİBİNİ kapsar.
-- Bu yüzden tablolar bir superuser'a ait OLAMAZ: sahiplik `argus_owner`'a geçer,
-- ve o rol NOSUPERUSER + NOBYPASSRLS'tir. Migration'ı koşan superuser'ın kendisi
-- hâlâ her şeyi görür — bu kapatılabilir bir delik değildir, §25 K6'nın cevabı
-- checkpoint'leri dışarı yayınlamaktır, RLS değil.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_owner') THEN
    CREATE ROLE argus_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_app') THEN
    CREATE ROLE argus_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Kiracı kapsamı
-- ---------------------------------------------------------------------------

-- Kapsam transaction-yerel bir GUC'tan okunur; `SET LOCAL` ile yazılır ve COMMIT'te
-- kendiliğinden temizlenir. Havuzdan alınan bir bağlantı asla önceki isteğin
-- kapsamını taşımaz.
--
-- `current_setting(..., true)` ayar yoksa hata yerine NULL döner. NULL, aşağıdaki
-- politikalarda `tenant_id = NULL` karşılaştırmasına düşer; SQL üç değerli mantığı
-- gereği sonuç UNKNOWN olur ve HİÇBİR satır görünmez. Yani kapsamı set etmeyi
-- unutmak fail-closed'dur — sessizce tüm kiracıları görmek değil.
CREATE FUNCTION argus_current_tenant() RETURNS uuid
  LANGUAGE sql
  STABLE
  PARALLEL SAFE
  RETURNS NULL ON NULL INPUT
AS $$
  SELECT nullif(current_setting('argus.tenant_id', true), '')::uuid
$$;

COMMENT ON FUNCTION argus_current_tenant() IS
  'Transaction-yerel kiracı kapsamı. Ayarlanmamışsa NULL doner ve tum RLS politikalari fail-closed olur.';

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------

CREATE TABLE tenants (
  -- Kök tablo: burada tenant_id hem birincil anahtar hem kapsamın kendisidir.
  -- Diğer tablolarla aynı ismi taşıması bilinçli — RLS politikaları tek biçimli olur.
  tenant_id    uuid        NOT NULL DEFAULT uuidv7(),

  -- §1 #7: slug DEĞİŞMEZDİR. Issuer URL'inin içindedir; değişirse her RP'nin
  -- discovery'si kırılır. Değişmezlik aşağıda trigger ile zorlanır.
  slug         text        NOT NULL,

  -- §1 #8 (KKS): issuer stratejisi subdomain birincil, RFC 9207 `iss` gün-1'de.
  -- Issuer değişimi tüm RP'lerin yeniden yapılandırılması demek; slug gibi DEĞİŞMEZ.
  -- Path-based issuer bilinçli olarak YOK: iki spec aynı issuer için farklı
  -- well-known URL'i üretiyor ve ikisini birden servis etmek gerekiyor (§18).
  issuer_host  text        NOT NULL,

  -- §1 #9 (KŞS): silo-kaçış kolonu. Karar birebir "gün-1'de, KULLANILMASA BİLE"
  -- diyor ve sebebi net: yoksa düzenlemeye tabi tek bir kiracıyı ayrı bir kümeye
  -- taşımak mimari yeniden yazımdır. Bugün hepsi 'default'; yönlendirme katmanı
  -- geldiğinde bu kolon zaten yerinde olacak.
  placement_id text        NOT NULL DEFAULT 'default',

  status       text        NOT NULL DEFAULT 'active',

  -- Kiracı başına yetkilendirme ve anahtar sayaçları (§1 #18).
  -- session_epoch kullanıcı başınadır, users tablosunda.
  authz_epoch  bigint      NOT NULL DEFAULT 0,
  key_epoch    bigint      NOT NULL DEFAULT 0,

  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT tenants_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT tenants_slug_key UNIQUE (slug),

  -- Slug issuer URL'inde göründüğü için DNS-label güvenli olmalı.
  CONSTRAINT tenants_slug_format CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
  CONSTRAINT tenants_issuer_host_key UNIQUE (issuer_host),
  CONSTRAINT tenants_issuer_host_format CHECK (issuer_host ~ '^[a-z0-9.-]{1,253}$'),
  CONSTRAINT tenants_placement_id_format CHECK (placement_id ~ '^[a-z0-9-]{1,63}$'),
  CONSTRAINT tenants_status_valid CHECK (status IN ('active', 'suspended', 'deleting')),
  CONSTRAINT tenants_authz_epoch_non_negative CHECK (authz_epoch >= 0),
  CONSTRAINT tenants_key_epoch_non_negative CHECK (key_epoch >= 0)
);

-- §1 #7: slug değişmez. Uygulama katmanına bırakılmaz — her yol buradan geçer.
CREATE FUNCTION tenants_reject_identity_change() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.slug IS DISTINCT FROM OLD.slug THEN
    RAISE EXCEPTION 'tenant slug is immutable (decision #7): % -> %', OLD.slug, NEW.slug
      USING ERRCODE = 'restrict_violation';
  END IF;
  -- §1 #8: issuer da değişmez. Slug ile aynı sebep, aynı bedel.
  IF NEW.issuer_host IS DISTINCT FROM OLD.issuer_host THEN
    RAISE EXCEPTION 'tenant issuer_host is immutable (decision #8): % -> %',
      OLD.issuer_host, NEW.issuer_host
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER tenants_identity_immutable
  BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION tenants_reject_identity_change();

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------

-- §1 #17 (KŞS): her PII alanı KULLANICI BAŞINA DEK ile şifreli (envelope encryption).
--
-- Sonradan eklemek TÜM VERİYİ yeniden yazmaktır — bu yüzden gün-1'de. Model:
--   * Her kullanıcının bir DEK'i vardır; DEK, DB'nin DIŞINDAKİ bir KEK ile sarılır
--     (§1 #25 ile aynı backend: dosya/KMS/PKCS#11).
--   * PII kolonları `bytea` ciphertext'tir; DB düz metni hiç görmez.
--   * Yok etme = DEK imhası (crypto-shredding): `dek_wrapped` NULL'a çekilir,
--     satır keyref tombstone olarak KALIR (§25 K23).
--
-- ⚠️ Pazarlama uyarısı (§25 K23): bu "GDPR erasure" diye satılmaz. EDPB Guidelines
-- 01/2025 anahtar silmeyi otomatik anonimleştirme saymıyor. Doğru ifade:
-- "log içeriğinin geri döndürülemez kimliksizleştirilmesi, kontrolörün DPIA'sına tabi".
CREATE TABLE user_keys (
  tenant_id    uuid        NOT NULL,
  user_id      uuid        NOT NULL,

  -- KEK ile sarılmış DEK. Crypto-shred sonrası NULL olur ve satır tombstone kalır.
  dek_wrapped  bytea,

  -- Sarmalamayı yapan KEK'in kimliği. Anahtar rotasyonunda hangi KEK'in gerektiğini
  -- bilmek için şart; KEK'in KENDİSİ burada DEĞİL (§1 #25).
  kek_id       text        NOT NULL,

  wrapped_at   timestamptz NOT NULL DEFAULT now(),
  destroyed_at timestamptz,

  CONSTRAINT user_keys_pkey PRIMARY KEY (tenant_id, user_id),

  -- Tombstone tutarlılığı: DEK ya vardır ya imha edilmiştir, ikisi birden olamaz.
  CONSTRAINT user_keys_shred_consistent CHECK (
    (dek_wrapped IS NOT NULL AND destroyed_at IS NULL)
    OR (dek_wrapped IS NULL AND destroyed_at IS NOT NULL)
  )
);

CREATE TABLE users (
  tenant_id          uuid        NOT NULL,
  user_id            uuid        NOT NULL DEFAULT uuidv7(),

  -- §1 #17: e-posta ciphertext olarak durur; kullanıcının DEK'i ile şifreli.
  email_ciphertext   bytea,

  -- Kör indeks (blind index): HMAC(kiracı peppers, normalize(email)).
  -- Neden gerekli: ciphertext her kullanıcıda farklı DEK ile üretildiği için
  -- üzerinde UNIQUE kısıt kurulamaz — aynı e-posta iki farklı ciphertext verir.
  -- Deterministik HMAC ise #6'nın istediği kiracı-yerel benzersizliği sağlar.
  -- HMAC anahtarı DB'nin dışındadır; sızan bir dump üzerinde sözlük saldırısı
  -- yapılamaz.
  email_blind_index  bytea,

  -- §1 #18: oturum geçersizleme sayacı. Token'ın içinde claim olarak taşınır.
  session_epoch      bigint      NOT NULL DEFAULT 0,

  status             text        NOT NULL DEFAULT 'active',
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),

  -- §1 #1: tenant_id birincil anahtarın parçası.
  CONSTRAINT users_pkey PRIMARY KEY (tenant_id, user_id),

  -- §1 #2: kiracıya giden referans. tenants kök tablo olduğu için tek kolonlu;
  -- kiracı-kapsamlı tablolar arası her FK composite olacak (bkz. client_redirect_uris).
  CONSTRAINT users_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  -- §1 #17: her kullanıcının bir anahtar satırı olmalı. Composite FK (§1 #2).
  CONSTRAINT users_key_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES user_keys (tenant_id, user_id) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,

  -- §1 #6: kiracı-yerel benzersizlik, kör indeks üzerinden.
  CONSTRAINT users_tenant_email_key UNIQUE (tenant_id, email_blind_index),

  -- Ciphertext ve kör indeks birlikte bulunur ya da hiç bulunmaz.
  CONSTRAINT users_email_pair_consistent CHECK (
    (email_ciphertext IS NULL) = (email_blind_index IS NULL)
  ),

  CONSTRAINT users_status_valid CHECK (status IN ('active', 'suspended', 'deleted')),
  CONSTRAINT users_session_epoch_non_negative CHECK (session_epoch >= 0)
);

-- §1 #14: kullanıcı ID'si ve e-posta ASLA yeniden kullanılmaz.
--
-- Tombstone tekillik kısıtını sonradan eklemek çakışan kayıtları çözemez, bu yüzden
-- gün-1'de. `users` satırı silinse bile buradaki kayıt kalır ve aynı tanımlayıcının
-- ikinci bir özneye verilmesini engeller. Gmail ve GitHub'ın bu konudaki davranışı
-- ve RFC 9967 (mailbox devri) bu kararın gerekçesidir.
CREATE TABLE retired_user_identifiers (
  tenant_id       uuid        NOT NULL,
  identifier_kind text        NOT NULL,

  -- ⚠️ Tanımlayıcı DÜZ METİN OLARAK TUTULMAZ. Aksi hâlde tombstone tablosu,
  -- #17'nin şifrelediği her e-postanın açık bir kopyasına dönüşürdü — ve silinen
  -- kullanıcıların e-postaları, silinmeyenlerinkinden daha korumasız olurdu.
  -- Burada `users.email_blind_index` ile AYNI HMAC değeri tutulur: karşılaştırma
  -- yapılabilir, içerik okunamaz.
  identifier_hash bytea       NOT NULL,

  retired_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT retired_user_identifiers_pkey
    PRIMARY KEY (tenant_id, identifier_kind, identifier_hash),
  CONSTRAINT retired_user_identifiers_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT retired_user_identifiers_kind_valid
    CHECK (identifier_kind IN ('email', 'user_id'))
);

-- §1 #14: kullanıcı ID'si ve e-posta ASLA yeniden kullanılmaz.
--
-- Tablo tek başına bir belge; kuralı ZORLAYAN şey aşağıdaki iki trigger. Bunları
-- uygulama katmanına bırakmak, "her yol buradan geçer" garantisini kaybetmek olurdu:
-- SCIM deprovision, admin API, toplu import ve manuel SQL aynı kuralı ayrı ayrı
-- hatırlamak zorunda kalırdı.

-- (a) Kullanıcı silindiğinde veya 'deleted' işaretlendiğinde tanımlayıcıları emekliye ayır.
CREATE FUNCTION users_retire_identifiers() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO retired_user_identifiers (tenant_id, identifier_kind, identifier_hash)
    VALUES (OLD.tenant_id, 'user_id', digest_user_id(OLD.user_id))
    ON CONFLICT DO NOTHING;

  IF OLD.email_blind_index IS NOT NULL THEN
    INSERT INTO retired_user_identifiers (tenant_id, identifier_kind, identifier_hash)
      VALUES (OLD.tenant_id, 'email', OLD.email_blind_index)
      ON CONFLICT DO NOTHING;
  END IF;

  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;

-- `user_id` bir UUID; kör indeksle aynı sütunda durabilmesi için bayta çevrilir.
-- Burada gizlemeye gerek yok (UUID zaten opak), yalnızca tip birliği sağlanıyor.
CREATE FUNCTION digest_user_id(id uuid) RETURNS bytea
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT uuid_send(id)
$$;

CREATE TRIGGER users_retire_on_delete
  AFTER DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION users_retire_identifiers();

CREATE TRIGGER users_retire_on_soft_delete
  AFTER UPDATE OF status ON users
  FOR EACH ROW
  WHEN (NEW.status = 'deleted' AND OLD.status IS DISTINCT FROM 'deleted')
  EXECUTE FUNCTION users_retire_identifiers();

-- (b) Emekli bir tanımlayıcı ikinci bir özneye VERİLEMEZ.
CREATE FUNCTION users_reject_retired_identifiers() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM retired_user_identifiers
     WHERE tenant_id = NEW.tenant_id
       AND identifier_kind = 'user_id'
       AND identifier_hash = digest_user_id(NEW.user_id)
  ) THEN
    RAISE EXCEPTION 'user_id was retired and must not be reused (decision #14)'
      USING ERRCODE = 'unique_violation';
  END IF;

  IF NEW.email_blind_index IS NOT NULL AND EXISTS (
    SELECT 1 FROM retired_user_identifiers
     WHERE tenant_id = NEW.tenant_id
       AND identifier_kind = 'email'
       AND identifier_hash = NEW.email_blind_index
  ) THEN
    RAISE EXCEPTION 'email was retired and must not be reused (decision #14)'
      USING ERRCODE = 'unique_violation';
  END IF;

  RETURN NEW;
END
$$;

CREATE TRIGGER users_reject_retired
  BEFORE INSERT OR UPDATE OF email_blind_index ON users
  FOR EACH ROW EXECUTE FUNCTION users_reject_retired_identifiers();

-- ---------------------------------------------------------------------------
-- signing_keys — §1 #4 ve #25
-- ---------------------------------------------------------------------------
--
-- #4 (KKS): imzalama anahtarı KİRACI BAŞINADIR, ES256 varsayılan. Paylaşımlıdan
-- kiracı-başınaya geçiş, tüm RP'lerin JWKS cache invalidasyonu + koordineli kesinti
-- demek (Storm-0558 dersi).
--
-- #25 (MT): ÖZEL ANAHTAR MATERYALİ BU TABLODA DEĞİLDİR ve hiçbir zaman olmayacaktır.
-- Burada yalnızca metadata ve AÇIK anahtar durur; özel taraf pluggable bir backend'de
-- (dosya/KMS/PKCS#11) yaşar ve DB yedeğinden bağımsız yedeklenir. Keycloak
-- `rsa-generated` anahtarları DB'ye koyuyor ve yedekleme prosedürü dokümante
-- etmiyor; anahtar kaybı DB kaybından yıkıcıdır çünkü hiçbir RP eski JWT'leri
-- doğrulayamaz.
CREATE TABLE signing_keys (
  tenant_id     uuid        NOT NULL,

  -- JWKS'te görünen `kid`. Rotasyon sırasında eski ve yeni birlikte yayınlanır.
  kid           text        NOT NULL,

  alg           text        NOT NULL DEFAULT 'ES256',

  -- Yalnızca AÇIK anahtar. JWK'nin JSON gösterimi.
  public_jwk    jsonb       NOT NULL,

  -- Özel anahtara nasıl ulaşılacağı — anahtarın kendisi değil, ADRESİ.
  backend       text        NOT NULL,
  backend_ref   text        NOT NULL,

  status        text        NOT NULL DEFAULT 'pending',
  not_before    timestamptz NOT NULL DEFAULT now(),
  not_after     timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT signing_keys_pkey PRIMARY KEY (tenant_id, kid),
  CONSTRAINT signing_keys_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT signing_keys_alg_valid CHECK (alg IN ('ES256', 'EdDSA', 'PS256', 'RS256')),
  CONSTRAINT signing_keys_backend_valid CHECK (backend IN ('file', 'kms', 'pkcs11')),
  CONSTRAINT signing_keys_status_valid
    CHECK (status IN ('pending', 'active', 'retiring', 'retired')),
  CONSTRAINT signing_keys_validity_ordered
    CHECK (not_after IS NULL OR not_after > not_before),

  -- Özel anahtarın yanlışlıkla buraya yazılmasına karşı yapısal engel: JWK'de
  -- özel taraf alanları (`d`, `p`, `q`, `k`) bulunamaz.
  CONSTRAINT signing_keys_public_only CHECK (
    NOT (public_jwk ? 'd') AND NOT (public_jwk ? 'p')
    AND NOT (public_jwk ? 'q') AND NOT (public_jwk ? 'k')
  )
);

-- ---------------------------------------------------------------------------
-- clients
-- ---------------------------------------------------------------------------

CREATE TABLE clients (
  tenant_id       uuid        NOT NULL,

  -- §1 #5: client_id GLOBAL benzersizdir (Keycloak'ın aksine). Sonradan
  -- globalleştirmek her müşterinin client_id'sini yeniden adlandırmak, yani her RP
  -- konfigürasyonunu kırmak demektir. Aşağıdaki UNIQUE kısıt bunu zorlar.
  client_id       text        NOT NULL,

  client_type     text        NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),

  -- §1 #1: tenant_id PK'nın parçası; #5: client_id ayrıca global benzersiz.
  -- İkisi birlikte durur, biri diğerinin yerine geçmez.
  CONSTRAINT clients_pkey PRIMARY KEY (tenant_id, client_id),
  CONSTRAINT clients_client_id_global_key UNIQUE (client_id),

  CONSTRAINT clients_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  -- RFC 6749 Ek A: client_id = *VSCHAR (0x20-0x7E). argus-core'daki ClientId::new
  -- ile aynı kural; ikisi de zorlar çünkü veri katmanına uygulama dışından da
  -- yazılabilir.
  CONSTRAINT clients_client_id_vschar CHECK (client_id ~ '^[\x20-\x7E]+$'),
  CONSTRAINT clients_client_id_length CHECK (length(client_id) BETWEEN 1 AND 255),
  CONSTRAINT clients_type_valid CHECK (client_type IN ('confidential', 'public'))
);

-- §1 #24: redirect_uri eşleştirmesi YALNIZCA tam dizge. Bu yüzden URI'ler ayrı
-- satırlar hâlinde tutulur ve birincil anahtarın parçasıdır — bir desen kolonu
-- ya da regex alanı YOKTUR ve olmayacaktır.
CREATE TABLE client_redirect_uris (
  tenant_id    uuid NOT NULL,
  client_id    text NOT NULL,
  redirect_uri text NOT NULL,

  CONSTRAINT client_redirect_uris_pkey
    PRIMARY KEY (tenant_id, client_id, redirect_uri),

  -- §1 #2: kiracı-kapsamlı tablolar arasındaki FK COMPOSITE. Tek kolonlu olsaydı
  -- bir kiracının client'ına başka bir kiracının satırından referans verilebilirdi.
  CONSTRAINT client_redirect_uris_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,

  CONSTRAINT client_redirect_uris_no_wildcard CHECK (position('*' in redirect_uri) = 0),
  CONSTRAINT client_redirect_uris_no_fragment CHECK (position('#' in redirect_uri) = 0),
  CONSTRAINT client_redirect_uris_absolute CHECK (redirect_uri ~ '^[a-zA-Z][a-zA-Z0-9+.-]*:')
);

-- ---------------------------------------------------------------------------
-- Row Level Security — §1 #3, İSTİSNASIZ
-- ---------------------------------------------------------------------------
--
-- Sonradan eklemek "ya hep ya hiç"tir: atlanan tek tablo sessiz sızıntıdır
-- (Logto #7685). Bu yüzden her tablo aynı blokta ele alınır ve aşağıdaki
-- doğrulama sorgusu RLS'siz tablo bırakılmadığını kanıtlar.

ALTER TABLE tenants                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_keys                ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys             ENABLE ROW LEVEL SECURITY;
ALTER TABLE users                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE retired_user_identifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_redirect_uris     ENABLE ROW LEVEL SECURITY;

-- FORCE: politikalar tablo sahibine de uygulanır.
ALTER TABLE tenants                  FORCE ROW LEVEL SECURITY;
ALTER TABLE user_keys                FORCE ROW LEVEL SECURITY;
ALTER TABLE signing_keys             FORCE ROW LEVEL SECURITY;
ALTER TABLE users                    FORCE ROW LEVEL SECURITY;
ALTER TABLE retired_user_identifiers FORCE ROW LEVEL SECURITY;
ALTER TABLE clients                  FORCE ROW LEVEL SECURITY;
ALTER TABLE client_redirect_uris     FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON user_keys
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON signing_keys
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON tenants
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON users
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON retired_user_identifiers
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON clients
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON client_redirect_uris
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

-- ---------------------------------------------------------------------------
-- İzinler
-- ---------------------------------------------------------------------------

-- Sahiplik superuser'dan alınır. Bundan sonra FORCE ROW LEVEL SECURITY gerçek
-- bir sınırdır: `argus_owner` politikalara tabidir.
ALTER TABLE tenants                  OWNER TO argus_owner;
ALTER TABLE user_keys                OWNER TO argus_owner;
ALTER TABLE signing_keys             OWNER TO argus_owner;
ALTER TABLE users                    OWNER TO argus_owner;
ALTER TABLE retired_user_identifiers OWNER TO argus_owner;
ALTER TABLE clients                  OWNER TO argus_owner;
ALTER TABLE client_redirect_uris     OWNER TO argus_owner;
ALTER FUNCTION argus_current_tenant()          OWNER TO argus_owner;
ALTER FUNCTION digest_user_id(uuid)            OWNER TO argus_owner;
ALTER FUNCTION users_retire_identifiers()      OWNER TO argus_owner;
ALTER FUNCTION users_reject_retired_identifiers() OWNER TO argus_owner;
ALTER FUNCTION tenants_reject_identity_change()    OWNER TO argus_owner;

-- Sahip rolünün de şema üzerinde USAGE'a ihtiyacı var: yabancı anahtar doğrulama
-- trigger'ları (RI trigger) REFERANS VEREN tablonun SAHİBİ rolüyle koşar, isteği
-- yapan rolle değil. Bu olmadan her FK kontrolü "permission denied for schema"
-- ile patlar — sahiplik superuser'dan alınana kadar görünmeyen bir bağımlılık.
GRANT USAGE ON SCHEMA public TO argus_owner;
GRANT USAGE ON SCHEMA public TO argus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  tenants, user_keys, users, retired_user_identifiers,
  signing_keys, clients, client_redirect_uris
  TO argus_app;
GRANT EXECUTE ON FUNCTION argus_current_tenant() TO argus_app;
GRANT EXECUTE ON FUNCTION digest_user_id(uuid) TO argus_app;

-- ---------------------------------------------------------------------------
-- Kendi kendini doğrulayan kontrol
-- ---------------------------------------------------------------------------
--
-- Migration'ın kendisi, RLS'siz veya FORCE'suz bir tablo bırakılmadığını kanıtlar.
-- Bu, "atlanan tek tablo" hatasını gelecekteki migration'larda da yakalamak için
-- tekrarlanacak bir kalıptır.
DO $$
DECLARE
  offending text;
BEGIN
  SELECT string_agg(c.relname, ', ')
    INTO offending
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p')
     AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);

  IF offending IS NOT NULL THEN
    RAISE EXCEPTION 'tables without RLS+FORCE (decision #3): %', offending;
  END IF;

  -- Superuser'a ait bir tablo, FORCE'u anlamsız kılar.
  SELECT string_agg(c.relname, ', ')
    INTO offending
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p')
     AND (r.rolsuper OR r.rolbypassrls);

  IF offending IS NOT NULL THEN
    RAISE EXCEPTION 'tables owned by a superuser or BYPASSRLS role, FORCE is meaningless: %', offending;
  END IF;
END
$$;
