-- OIDC Core: authorization code'un taşıması gereken iki alan.
--
-- # Neden ayrı bir migration
--
-- `0003` yazıldıktan sonra eklendi ve expand-contract disiplini (§1 #26) bir kez
-- yazılmış migration'ın düzenlenmemesini söyler. İki kolon da **nullable**
-- ekleniyor: mevcut satırlar geçerli kalır, eski uygulama sürümü yeni kolonları
-- görmeden çalışmaya devam eder (N-1 uyumluluğu).

ALTER TABLE authorization_codes
  -- OIDC Core §3.1.2.1: yetkilendirme isteğindeki `nonce`, `id_token`'a aynen
  -- yazılır. İstemci onu kendi ürettiği değerle karşılaştırır; tutmuyorsa
  -- `id_token` başka bir oturuma aittir.
  --
  -- Kodla BİRLİKTE saklanmak zorunda: token isteği geldiğinde yetkilendirme
  -- isteği çoktan bitmiştir ve `nonce`'ı başka hiçbir yerden öğrenemeyiz.
  ADD COLUMN nonce text,

  -- Verilen kapsam. `openid` içeriyorsa `id_token` üretilir.
  ADD COLUMN scope text;

-- `nonce` uzunluğu sınırsız bırakılmaz: istemciden gelen ve aynen geri yazılan
-- her alan bir şişirme yüzeyidir.
ALTER TABLE authorization_codes
  ADD CONSTRAINT authorization_codes_nonce_length
    CHECK (nonce IS NULL OR length(nonce) <= 255),
  ADD CONSTRAINT authorization_codes_scope_length
    CHECK (scope IS NULL OR length(scope) <= 1024);

-- Kendi kendini doğrulayan kontrol.
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
