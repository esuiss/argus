-- OAuth grant durumu: authorization code'lar ve refresh token zincirleri.
--
-- # Sır değerleri burada YOK
--
-- Ne kod ne de refresh token'ın kendisi saklanır; yalnızca SHA-256 hash'i.
-- Sızan bir veritabanı dökümü, dolaşımdaki hiçbir grant'ı kullanılabilir kılmaz.
-- Bu, §25 K27'nin ("sır log'a düşmesin") depolama tarafındaki karşılığıdır.
--
-- # Neden `bytea` ve neden `PRIMARY KEY`in parçası
--
-- Hash aramanın anahtarıdır ve tekildir. Ayrı bir yüzey kimliği eklemek, hem
-- fazladan indeks hem de "hangisi otoriter" sorusu üretirdi.

-- ---------------------------------------------------------------------------
-- authorization_codes
-- ---------------------------------------------------------------------------

CREATE TABLE authorization_codes (
  tenant_id          uuid        NOT NULL,

  -- Kodun SHA-256'sı. Kodun kendisi hiçbir yerde saklanmaz.
  code_hash          bytea       NOT NULL,

  client_id          text        NOT NULL,
  user_id            uuid        NOT NULL,

  -- Yetkilendirme isteğindeki `redirect_uri`, token isteğinde yeniden
  -- doğrulanmak üzere (RFC 6749 §4.1.3).
  redirect_uri       text        NOT NULL,

  -- PKCE: challenge'ın ÇÖZÜLMÜŞ 32 baytı. BASE64URL dizgesi değil — kodlama
  -- farkları (padding, hizalama) karşılaştırmayı kaydırmasın.
  challenge_digest   bytea       NOT NULL,
  challenge_method   text        NOT NULL DEFAULT 'S256',

  issued_at          timestamptz NOT NULL,
  expires_at         timestamptz NOT NULL,

  -- §1 #16: durum bir bayrak değil, tipli bir geçiş. `redeemed_at`, "kullanıldı
  -- ama ne zaman" sorusunu cevaplar ve denetim kaydı için gereklidir.
  state              text        NOT NULL DEFAULT 'issued',
  redeemed_at        timestamptz,

  CONSTRAINT authorization_codes_pkey PRIMARY KEY (tenant_id, code_hash),

  -- §1 #2: kiracı-kapsamlı tablolar arası FK composite.
  CONSTRAINT authorization_codes_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,
  CONSTRAINT authorization_codes_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT authorization_codes_hash_length CHECK (octet_length(code_hash) = 32),
  CONSTRAINT authorization_codes_digest_length CHECK (octet_length(challenge_digest) = 32),
  CONSTRAINT authorization_codes_state_valid CHECK (state IN ('issued', 'redeemed')),
  CONSTRAINT authorization_codes_expiry_after_issue CHECK (expires_at > issued_at),

  -- RFC 6749 §4.1.2: kod ömrü azami on dakika. Konfigürasyon hatasının üretime
  -- sızmasını şema engeller; `argus-core` da aynı sınırı zorlar.
  CONSTRAINT authorization_codes_max_lifetime
    CHECK (expires_at <= issued_at + interval '10 minutes'),

  -- Durum tutarlılığı: tüketilmiş kodun zamanı vardır, tüketilmemişin yoktur.
  CONSTRAINT authorization_codes_state_consistent CHECK (
    (state = 'issued' AND redeemed_at IS NULL)
    OR (state = 'redeemed' AND redeemed_at IS NOT NULL)
  )
);

-- Süresi geçmiş kodları toplamak için. Kısmi indeks: yalnızca henüz
-- tüketilmemiş satırlar temizlik işini ilgilendiriyor.
CREATE INDEX authorization_codes_expiry
  ON authorization_codes (expires_at)
  WHERE state = 'issued';

-- ---------------------------------------------------------------------------
-- refresh_tokens
-- ---------------------------------------------------------------------------

CREATE TABLE refresh_tokens (
  tenant_id          uuid        NOT NULL,

  -- Token'ın SHA-256'sı.
  token_hash         bytea       NOT NULL,

  client_id          text        NOT NULL,
  user_id            uuid        NOT NULL,

  -- Zincir kimliği. Yeniden kullanım tespiti bunsuz IMKÂNSIZDIR: tespit
  -- edildiğinde düşürülecek küme tam olarak aynı `family_id`'yi paylaşanlardır
  -- (RFC 9700 §4.14.2). Bu yüzden ilk token verilirken yazılmak zorunda.
  family_id          uuid        NOT NULL,

  -- Zincir içindeki sıra; ilk token 0.
  generation         integer     NOT NULL DEFAULT 0,

  -- Zincirin İLK token'ının verildiği an. Mutlak ömür bundan sayılır ve
  -- rotasyonla YENİLENMEZ — aksi hâlde rotasyon sonsuz erişim üretirdi.
  family_started_at  timestamptz NOT NULL,

  expires_at         timestamptz NOT NULL,

  state              text        NOT NULL DEFAULT 'active',
  rotated_at         timestamptz,
  revoked_at         timestamptz,

  CONSTRAINT refresh_tokens_pkey PRIMARY KEY (tenant_id, token_hash),

  CONSTRAINT refresh_tokens_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,
  CONSTRAINT refresh_tokens_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT refresh_tokens_hash_length CHECK (octet_length(token_hash) = 32),
  CONSTRAINT refresh_tokens_generation_non_negative CHECK (generation >= 0),
  CONSTRAINT refresh_tokens_state_valid CHECK (state IN ('active', 'rotated', 'revoked')),

  CONSTRAINT refresh_tokens_state_consistent CHECK (
    (state = 'active' AND rotated_at IS NULL AND revoked_at IS NULL)
    OR (state = 'rotated' AND rotated_at IS NOT NULL)
    OR (state = 'revoked' AND revoked_at IS NOT NULL)
  )
);

-- Zincir iptali tek sorguda yapılabilmeli: yeniden kullanım tespit edildiğinde
-- gecikme, saldırganın penceresi demektir.
CREATE INDEX refresh_tokens_family ON refresh_tokens (tenant_id, family_id);

CREATE INDEX refresh_tokens_expiry
  ON refresh_tokens (expires_at)
  WHERE state = 'active';

-- ---------------------------------------------------------------------------
-- RLS — §1 #3, istisnasız
-- ---------------------------------------------------------------------------

ALTER TABLE authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens      ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens      FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON authorization_codes
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON refresh_tokens
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE authorization_codes OWNER TO argus_owner;
ALTER TABLE refresh_tokens      OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON authorization_codes, refresh_tokens TO argus_app;

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
