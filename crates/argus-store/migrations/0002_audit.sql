-- Denetim altyapısı.
--
--   §1 #10 (KŞS): denetim logu kiracı + zaman partition'lı.
--                 "Milyarlarca satırlı tabloyu sonradan partition'lamak pratikte imkânsız."
--   §1 #23 (MT) : denetim olayı iş değişikliğiyle AYNI transaction'da, minimal bir
--                 outbox satırı olarak kalıcılaşır; Merkle/imza/egress arkada.
--   §25 K7      : append-only ÜÇ katmanda zorlanır — `BEFORE TRUNCATE` dahil.
--   §25 K14     : üç ayrı zaman damgası (occurred_at / recorded_at / checkpoint_at).
--   §25 K20     : AU-3 + PCI 10.3 birleşik minimum alan seti.
--   §25 K22     : olay iskeleti PII'den AYRI — iskelet uzun, PII kısa yaşar.

-- ---------------------------------------------------------------------------
-- audit_events — iskelet (uzun ömürlü, PII taşımaz)
-- ---------------------------------------------------------------------------
--
-- §25 K22: PCI'ın 12 ayı olay İZİNE, CNIL'in 6 ayı PII'ye yöneliktir. İkisini aynı
-- tabloda tutmak, ikisinden birini ihlal etmeyi zorunlu kılardı. Bu tablo
-- pseudonymous kalır ve uzun yaşar; PII ayrı tabloda ve erken crypto-shred edilir.
CREATE TABLE audit_events (
  tenant_id        uuid        NOT NULL,

  -- §25 K14: occurred_at = olayın GERÇEKLEŞME zamanı (SET `toe`).
  -- recorded_at = kayda GİRİŞ zamanı (`iat`). Adli analizde bu ayrım kritiktir.
  occurred_at      timestamptz NOT NULL,
  recorded_at      timestamptz NOT NULL DEFAULT now(),

  event_id         uuid        NOT NULL DEFAULT uuidv7(),

  -- §25 K29: kendi taksonomimiz — OTel'de kimlik/auth convention YOK.
  -- Okta'nın `<parent>.<sublevel>.<action>` hiyerarşisi. Okta'da 1.178 tip var;
  -- olgun bir IdP'nin gerçek büyüklüğü budur.
  event_type       text        NOT NULL,

  -- §25 K20 minimum alan seti (AU-3 + PCI 10.3).
  outcome          text        NOT NULL,
  actor_kind       text        NOT NULL,
  actor_id         uuid,
  target_kind      text,
  target_id        text,

  -- §25 K15: SET yayınında per-subject sıralama garantisi zorunlu; `txn` korelasyon
  -- için birinci sınıf alan (RFC 8417).
  txn              uuid,

  -- Yapısal ek alanlar. ⚠️ PII BURAYA YAZILMAZ — `audit_event_pii`'ye gider.
  attributes       jsonb       NOT NULL DEFAULT '{}'::jsonb,

  -- §25 K1/K2: Merkle checkpoint'e dahil edildiği an. NULL = henüz dahil edilmedi.
  -- Per-event hash chain YOK (§6 §4.4: seri bağımlılık paralelliği öldürüyor).
  checkpoint_at    timestamptz,

  -- Partition anahtarları birincil anahtarın parçası olmak ZORUNDA.
  CONSTRAINT audit_events_pkey PRIMARY KEY (tenant_id, occurred_at, event_id),

  CONSTRAINT audit_events_outcome_valid CHECK (outcome IN ('success', 'failure', 'unknown')),
  CONSTRAINT audit_events_actor_kind_valid
    CHECK (actor_kind IN ('user', 'client', 'admin', 'system', 'agent', 'anonymous')),
  CONSTRAINT audit_events_recorded_after_occurred CHECK (recorded_at >= occurred_at)
) PARTITION BY RANGE (occurred_at);

-- §1 #10: kiracı + zaman. Zaman üstte (retention `DROP PARTITION` ile yapılacak),
-- kiracı altta hash ile (tek bir büyük kiracı tek partition'ı şişirmesin).
CREATE TABLE audit_event_pii (
  tenant_id        uuid        NOT NULL,
  occurred_at      timestamptz NOT NULL,
  event_id         uuid        NOT NULL,

  -- §1 #17 + §25 K22: PII kullanıcı başına DEK ile şifreli. Crypto-shred, iskelete
  -- dokunmadan bu satırı okunamaz kılar.
  subject_user_id  uuid,
  payload_cipher   bytea       NOT NULL,

  CONSTRAINT audit_event_pii_pkey PRIMARY KEY (tenant_id, occurred_at, event_id)
) PARTITION BY RANGE (occurred_at);

-- Partition üretimi normalde bir operatör işidir (§26). Burada baseline için
-- içinde bulunulan ay ve sonraki iki ay kuruluyor ki migration tek başına
-- çalışabilir bir sistem bıraksın.
DO $$
DECLARE
  month_start date := date_trunc('month', now())::date;
  i int;
  j int;
  parent text;
  child text;
  lo date;
  hi date;
BEGIN
  FOREACH parent IN ARRAY ARRAY['audit_events', 'audit_event_pii'] LOOP
    FOR i IN 0..2 LOOP
      lo := (month_start + (i || ' month')::interval)::date;
      hi := (month_start + ((i + 1) || ' month')::interval)::date;
      child := format('%s_%s', parent, to_char(lo, 'YYYY_MM'));

      EXECUTE format(
        'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L) PARTITION BY HASH (tenant_id)',
        child, parent, lo, hi);

      -- Dört hash parçası: tek bir büyük kiracı aylık partition'ı tek başına
      -- domine etmesin.
      FOR j IN 0..3 LOOP
        EXECUTE format(
          'CREATE TABLE %I PARTITION OF %I FOR VALUES WITH (MODULUS 4, REMAINDER %s)',
          format('%s_h%s', child, j), child, j);
      END LOOP;
    END LOOP;
  END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- audit_outbox — §1 #23, §1 §10.3 A1
-- ---------------------------------------------------------------------------
--
-- Kabul edilmiş yön: denetim olayı, iş değişikliğiyle AYNI transaction'da atomik
-- olarak kalıcılaşır. Ya ikisi de olur ya hiçbiri.
--
-- ⚠️ Bu, K8'in önceki hâlinin düzeltmesidir. Bounded in-memory kuyruk taşmayı
-- önlerdi ama süreç çökmesini karşılamazdı: iş değişikliği commit olur, kullanıcı
-- başarılı yanıt alır, olay bellekte beklerken süreç ölür — değişiklik kalıcı,
-- denetim kaydı yok. AU-12/PCI 10.2'nin "all" gereği tam olarak bunu yasaklar.
--
-- Buradaki satır MİNİMALDİR: tek küçük insert. Merkle birleştirme, checkpoint
-- imzalama ve dışa yayın arka planda, request path'in dışında yürür (K4, K5).
--
-- ⚠️ AÇIK KARAR (§1 §10.2): bu tablonun TÜKETİM algoritması — cursor semantiği,
-- yeniden senkronizasyon, retention penceresi — hâlâ açıktır. İki aday
-- (xid watermark polling · logical decoding) ortak arıza matrisinde sınanmadan
-- buraya bir tüketici yazılmayacak.
CREATE TABLE audit_outbox (
  tenant_id     uuid        NOT NULL,
  occurred_at   timestamptz NOT NULL,
  event_id      uuid        NOT NULL,

  -- Tüketici ilerlemesi için. §10.2 kapanana kadar YALNIZCA gözlem amaçlıdır;
  -- doğruluk mekanizması olarak kullanılmaz (sequence sırası commit sırası değildir).
  seq           bigserial   NOT NULL,

  -- §10.2 Aday A: üst-seviye transaction kimliği. Şimdiden yazılıyor ki adaylar
  -- gerçek veriyle sınanabilsin — ama hangi algoritmanın seçileceği açık.
  producer_xid  xid8        NOT NULL DEFAULT pg_current_xact_id(),

  enqueued_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at  timestamptz,

  CONSTRAINT audit_outbox_pkey PRIMARY KEY (tenant_id, occurred_at, event_id)
);

CREATE INDEX audit_outbox_pending ON audit_outbox (seq) WHERE delivered_at IS NULL;
CREATE INDEX audit_outbox_producer_xid ON audit_outbox (producer_xid);

-- ---------------------------------------------------------------------------
-- Append-only — §25 K7, ÜÇ katman
-- ---------------------------------------------------------------------------

CREATE FUNCTION audit_reject_mutation() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit tables are append-only (§25 K7): % on %', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'restrict_violation';
END
$$;

-- Katman (a): rol seviyesinde yetki reddi.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, audit_event_pii FROM PUBLIC;

-- Katman (b): row-level trigger.
CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_reject_mutation();

CREATE TRIGGER audit_event_pii_append_only
  BEFORE UPDATE OR DELETE ON audit_event_pii
  FOR EACH ROW EXECUTE FUNCTION audit_reject_mutation();

-- Katman (c): statement-level TRUNCATE trigger.
-- ⚠️ Row-level trigger'lar TRUNCATE'te ATEŞLENMEZ. Bu, "append-only" iddiasındaki
-- en yaygın sessiz deliktir ve K7'nin özellikle uyardığı şeydir.
CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_reject_mutation();

CREATE TRIGGER audit_event_pii_no_truncate
  BEFORE TRUNCATE ON audit_event_pii
  FOR EACH STATEMENT EXECUTE FUNCTION audit_reject_mutation();

-- ---------------------------------------------------------------------------
-- RLS — §1 #3, istisnasız
-- ---------------------------------------------------------------------------

DO $$
DECLARE t text;
BEGIN
  -- Partition'lar da dahil: parent'a politika koymak, partition'a DOĞRUDAN
  -- erişimi engellemez.
  FOR t IN
    SELECT c.relname
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p')
       AND (c.relname LIKE 'audit\_%')
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = argus_current_tenant()) WITH CHECK (tenant_id = argus_current_tenant())', t);
    EXECUTE format('ALTER TABLE %I OWNER TO argus_owner', t);
  END LOOP;
END
$$;

ALTER FUNCTION audit_reject_mutation() OWNER TO argus_owner;

-- Denetim tablolarında UPDATE/DELETE yetkisi VERİLMEZ.
GRANT SELECT, INSERT ON audit_events, audit_event_pii TO argus_app;
GRANT SELECT, INSERT, UPDATE ON audit_outbox TO argus_app;
GRANT USAGE, SELECT ON SEQUENCE audit_outbox_seq_seq TO argus_app;

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
