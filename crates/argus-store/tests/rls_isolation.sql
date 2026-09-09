-- Faz 0 çıkış kriteri: "RLS testleri geçiyor".
--
-- Her izolasyon testi `argus_app` rolüyle koşar — tabloların SAHİBİ OLMAYAN rolle.
-- Sahip rolüyle koşmak yanıltıcı olurdu: RLS varsayılan olarak sahibe uygulanmaz.
-- `FORCE ROW LEVEL SECURITY` sahibi de kapsar ve o da ayrıca sınanır (test 6).
--
-- Başarısızlıkta `RAISE EXCEPTION` ile durur; sessiz geçiş yoktur.

\set ON_ERROR_STOP on

\set t_a '''00000000-0000-7000-8000-00000000000a'''
\set t_b '''00000000-0000-7000-8000-00000000000b'''
\set u_a1 '''00000000-0000-7000-8000-0000000000a1'''
\set u_b1 '''00000000-0000-7000-8000-0000000000b1'''

-- ---------------------------------------------------------------------------
-- Hazırlık
-- ---------------------------------------------------------------------------

BEGIN;
  SET LOCAL argus.tenant_id = :t_a;
  INSERT INTO tenants (tenant_id, slug, issuer_host)
    VALUES (:t_a, 'acme', 'acme.argus.test');
  INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id)
    VALUES (:t_a, :u_a1, '\x0102'::bytea, 'kek-1');
  INSERT INTO users (tenant_id, user_id, email_ciphertext, email_blind_index)
    VALUES (:t_a, :u_a1, '\xdead'::bytea, '\xaaaa'::bytea);
  INSERT INTO clients (tenant_id, client_id, client_type)
    VALUES (:t_a, 'acme-web', 'confidential');
COMMIT;

BEGIN;
  SET LOCAL argus.tenant_id = :t_b;
  INSERT INTO tenants (tenant_id, slug, issuer_host)
    VALUES (:t_b, 'globex', 'globex.argus.test');
  INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id)
    VALUES (:t_b, :u_b1, '\x0304'::bytea, 'kek-1');
  INSERT INTO users (tenant_id, user_id, email_ciphertext, email_blind_index)
    VALUES (:t_b, :u_b1, '\xbeef'::bytea, '\xbbbb'::bytea);
COMMIT;

-- ---------------------------------------------------------------------------
-- 1. Kapsam ayarlanmamışsa HİÇBİR satır görünmez (fail-closed)
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL ROLE argus_app;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM users;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL unscoped_read_users: got % rows', n; END IF;
    SELECT count(*) INTO n FROM tenants;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL unscoped_read_tenants: got % rows', n; END IF;
    SELECT count(*) INTO n FROM user_keys;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL unscoped_read_user_keys: got % rows', n; END IF;
  END $$;
COMMIT;

-- ---------------------------------------------------------------------------
-- 2. Kapsam içinde yalnızca kendi satırları görünür
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  DECLARE n int; c bytea;
  BEGIN
    SELECT count(*) INTO n FROM users;
    IF n <> 1 THEN RAISE EXCEPTION 'FAIL scoped_read_count: got %', n; END IF;
    SELECT email_ciphertext INTO c FROM users;
    IF c <> '\xdead'::bytea THEN RAISE EXCEPTION 'FAIL scoped_read_wrong_row'; END IF;
  END $$;
COMMIT;

-- ---------------------------------------------------------------------------
-- 3. Başka kiracının satırı ID'si bilinse bile görünmez
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM users
     WHERE user_id = '00000000-0000-7000-8000-0000000000b1';
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL cross_tenant_read_by_known_id: leaked %', n; END IF;
  END $$;
COMMIT;

-- ---------------------------------------------------------------------------
-- 4. Başka kiracı adına satır YAZILAMAZ (WITH CHECK)
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  BEGIN
    BEGIN
      INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id)
        VALUES ('00000000-0000-7000-8000-00000000000b',
                '00000000-0000-7000-8000-0000000000b9', '\x05'::bytea, 'kek-1');
      RAISE EXCEPTION 'FAIL cross_tenant_insert: WITH CHECK did not fire';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 5. Başka kiracının satırı GÜNCELLENEMEZ / SİLİNEMEZ
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  DECLARE n int;
  BEGIN
    UPDATE users SET session_epoch = 99
     WHERE user_id = '00000000-0000-7000-8000-0000000000b1';
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL cross_tenant_update: touched %', n; END IF;

    DELETE FROM users WHERE user_id = '00000000-0000-7000-8000-0000000000b1';
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL cross_tenant_delete: touched %', n; END IF;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 6. FORCE: tablo SAHİBİ de politikaya tabidir
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL ROLE argus_owner;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM users;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL force_rls_owner: owner saw % rows', n; END IF;
  END $$;
COMMIT;

-- 6b. Bilinen ve KAPATILAMAYAN sınır: superuser RLS'i tümüyle atlar.
-- Bunu test etmek kusuru kabullenmek değil, sınırı kayda geçirmektir. §25 K6'nın
-- cevabı RLS değil, checkpoint'leri dışarı yayınlamaktır.
BEGIN;
  DO $$
  DECLARE n int;
  BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
      RAISE EXCEPTION 'test setup error: expected a superuser here';
    END IF;
    SELECT count(*) INTO n FROM users;
    IF n = 0 THEN
      RAISE EXCEPTION 'FAIL superuser_bypass_documented: limitation no longer holds';
    END IF;
  END $$;
COMMIT;

-- ---------------------------------------------------------------------------
-- 7. Composite FK çapraz-kiracı referansı engeller (§1 #2)
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL argus.tenant_id = :t_b;
  DO $$
  BEGIN
    BEGIN
      INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri)
        VALUES ('00000000-0000-7000-8000-00000000000b', 'acme-web', 'https://evil.test/cb');
      RAISE EXCEPTION 'FAIL composite_fk_cross_tenant';
    EXCEPTION WHEN foreign_key_violation THEN NULL;
    END;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 8. client_id GLOBAL benzersizdir (§1 #5)
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL argus.tenant_id = :t_b;
  DO $$
  BEGIN
    BEGIN
      INSERT INTO clients (tenant_id, client_id, client_type)
        VALUES ('00000000-0000-7000-8000-00000000000b', 'acme-web', 'public');
      RAISE EXCEPTION 'FAIL client_id_not_globally_unique';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 9. Kiracı kimliği DEĞİŞMEZ: slug (§1 #7) ve issuer_host (§1 #8)
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  BEGIN
    BEGIN
      UPDATE tenants SET slug = 'acme-renamed'
       WHERE tenant_id = '00000000-0000-7000-8000-00000000000a';
      RAISE EXCEPTION 'FAIL tenant_slug_mutable';
    EXCEPTION WHEN restrict_violation THEN NULL;
    END;

    BEGIN
      UPDATE tenants SET issuer_host = 'evil.argus.test'
       WHERE tenant_id = '00000000-0000-7000-8000-00000000000a';
      RAISE EXCEPTION 'FAIL tenant_issuer_mutable';
    EXCEPTION WHEN restrict_violation THEN NULL;
    END;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 10. redirect_uri: wildcard, fragment, göreli reddedilir (§1 #24)
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  DECLARE bad text;
  BEGIN
    FOREACH bad IN ARRAY ARRAY[
      'https://*.acme.test/cb', 'https://acme.test/cb#frag', '/relative/cb'
    ] LOOP
      BEGIN
        INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri)
          VALUES ('00000000-0000-7000-8000-00000000000a', 'acme-web', bad);
        RAISE EXCEPTION 'FAIL redirect_uri_accepted: %', bad;
      EXCEPTION WHEN check_violation THEN NULL;
      END;
    END LOOP;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 11. Kiracı-yerel benzersizlik (§1 #6) — kör indeks üzerinden
-- ---------------------------------------------------------------------------
-- Aynı kör indeks İKİ FARKLI kiracıda serbest, aynı kiracıda değil.
BEGIN;
  SET LOCAL argus.tenant_id = :t_b;
  INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id)
    VALUES (:t_b, '00000000-0000-7000-8000-0000000000b3', '\x06'::bytea, 'kek-1');
  -- Kiracı A'nın kör indeksi, kiracı B'de serbest olmalı.
  INSERT INTO users (tenant_id, user_id, email_ciphertext, email_blind_index)
    VALUES (:t_b, '00000000-0000-7000-8000-0000000000b3', '\xcafe'::bytea, '\xaaaa'::bytea);

  INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id)
    VALUES (:t_b, '00000000-0000-7000-8000-0000000000b4', '\x07'::bytea, 'kek-1');
  DO $$
  BEGIN
    BEGIN
      INSERT INTO users (tenant_id, user_id, email_ciphertext, email_blind_index)
        VALUES ('00000000-0000-7000-8000-00000000000b',
                '00000000-0000-7000-8000-0000000000b4', '\xf00d'::bytea, '\xaaaa'::bytea);
      RAISE EXCEPTION 'FAIL blind_index_not_unique_within_tenant';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 12. §1 #17: PII düz metin olarak SAKLANAMAZ
-- ---------------------------------------------------------------------------
-- Yapısal kontrol: kullanıcı tablosunda `text` tipinde bir e-posta kolonu KALMAMALI.
-- Bu test, ileride "geçici olarak" düz metin kolon ekleyen bir migration'ı yakalar.
BEGIN;
  DO $$
  DECLARE offending text;
  BEGIN
    SELECT string_agg(a.attname, ', ')
      INTO offending
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname = 'users'
       AND a.attnum > 0 AND NOT a.attisdropped
       AND a.atttypid = 'text'::regtype
       AND a.attname NOT IN ('status');
    IF offending IS NOT NULL THEN
      RAISE EXCEPTION 'FAIL plaintext_pii_column_present: %', offending;
    END IF;
  END $$;
COMMIT;

-- ---------------------------------------------------------------------------
-- 13. §1 #14: emekli tanımlayıcı yeniden kullanılamaz
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL argus.tenant_id = :t_a;
  -- Kullanıcıyı 'deleted' yap: trigger tanımlayıcıları emekliye ayırmalı.
  UPDATE users SET status = 'deleted' WHERE user_id = :u_a1;

  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM retired_user_identifiers
     WHERE tenant_id = '00000000-0000-7000-8000-00000000000a';
    IF n <> 2 THEN
      RAISE EXCEPTION 'FAIL retire_trigger: expected 2 retired identifiers, got %', n;
    END IF;

    -- Aynı kör indeksle yeni kullanıcı açılamaz.
    BEGIN
      INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id)
        VALUES ('00000000-0000-7000-8000-00000000000a',
                '00000000-0000-7000-8000-0000000000a9', '\x08'::bytea, 'kek-1');
      INSERT INTO users (tenant_id, user_id, email_ciphertext, email_blind_index)
        VALUES ('00000000-0000-7000-8000-00000000000a',
                '00000000-0000-7000-8000-0000000000a9', '\x11'::bytea, '\xaaaa'::bytea);
      RAISE EXCEPTION 'FAIL retired_email_reused';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 14. §1 #25: özel anahtar materyali DB'ye yazılamaz
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  BEGIN
    BEGIN
      INSERT INTO signing_keys (tenant_id, kid, public_jwk, backend, backend_ref)
        VALUES ('00000000-0000-7000-8000-00000000000a', 'k1',
                '{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"SECRET"}'::jsonb,
                'kms', 'arn:test');
      RAISE EXCEPTION 'FAIL private_key_material_accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    -- Açık anahtar kabul edilmeli.
    INSERT INTO signing_keys (tenant_id, kid, public_jwk, backend, backend_ref)
      VALUES ('00000000-0000-7000-8000-00000000000a', 'k1',
              '{"kty":"EC","crv":"P-256","x":"a","y":"b"}'::jsonb, 'kms', 'arn:test');
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 15. §1 #10: denetim logu partition'lı
-- ---------------------------------------------------------------------------
BEGIN;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM pg_class c
      JOIN pg_namespace ns ON ns.oid = c.relnamespace
     WHERE ns.nspname = 'public' AND c.relname = 'audit_events' AND c.relkind = 'p';
    IF n <> 1 THEN RAISE EXCEPTION 'FAIL audit_events_not_partitioned'; END IF;

    -- Zaman + kiracı: aylık range partition, her biri 4 hash parçası.
    SELECT count(*) INTO n FROM pg_inherits i
      JOIN pg_class p ON p.oid = i.inhparent
     WHERE p.relname = 'audit_events';
    IF n < 3 THEN RAISE EXCEPTION 'FAIL audit_events_time_partitions: %', n; END IF;
  END $$;
COMMIT;

-- ---------------------------------------------------------------------------
-- 16. §25 K7: append-only ÜÇ katman — UPDATE, DELETE ve TRUNCATE
-- ---------------------------------------------------------------------------
BEGIN;
  SET LOCAL argus.tenant_id = :t_a;
  INSERT INTO audit_events (tenant_id, occurred_at, event_type, outcome, actor_kind)
    VALUES (:t_a, now(), 'user.session.start', 'success', 'user');

  DO $$
  BEGIN
    BEGIN
      UPDATE audit_events SET outcome = 'failure';
      RAISE EXCEPTION 'FAIL audit_update_allowed';
    EXCEPTION WHEN restrict_violation THEN NULL;
    END;

    BEGIN
      DELETE FROM audit_events;
      RAISE EXCEPTION 'FAIL audit_delete_allowed';
    EXCEPTION WHEN restrict_violation THEN NULL;
    END;

    -- En sık atlanan delik: row-level trigger'lar TRUNCATE'te ateşlenmez.
    BEGIN
      TRUNCATE audit_events;
      RAISE EXCEPTION 'FAIL audit_truncate_allowed';
    EXCEPTION WHEN restrict_violation THEN NULL;
    END;
  END $$;
ROLLBACK;

-- ---------------------------------------------------------------------------
-- 17. §1 #23: denetim olayı ve outbox satırı ATOMİK
-- ---------------------------------------------------------------------------
-- İş değişikliği geri alınırsa denetim kaydı da geri alınmalı; ikisi aynı
-- transaction'da olduğu için bu yapısal olarak garanti.
BEGIN;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  DECLARE ev_id uuid; n int;
  BEGIN
    INSERT INTO audit_events (tenant_id, occurred_at, event_type, outcome, actor_kind)
      VALUES ('00000000-0000-7000-8000-00000000000a', now(),
              'user.credential.change', 'success', 'user')
      RETURNING event_id INTO ev_id;

    INSERT INTO audit_outbox (tenant_id, occurred_at, event_id)
      SELECT tenant_id, occurred_at, event_id FROM audit_events WHERE event_id = ev_id;

    SELECT count(*) INTO n FROM audit_outbox WHERE event_id = ev_id;
    IF n <> 1 THEN RAISE EXCEPTION 'FAIL audit_outbox_insert'; END IF;

    -- §10.2 adayı için üst-seviye transaction kimliği yazılmış olmalı.
    SELECT count(*) INTO n FROM audit_outbox
     WHERE event_id = ev_id AND producer_xid IS NOT NULL;
    IF n <> 1 THEN RAISE EXCEPTION 'FAIL audit_outbox_producer_xid_missing'; END IF;
  END $$;
ROLLBACK;

BEGIN;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM audit_outbox;
    IF n <> 0 THEN
      RAISE EXCEPTION 'FAIL audit_outbox_not_atomic: % rows survived rollback', n;
    END IF;
  END $$;
COMMIT;

-- ---------------------------------------------------------------------------
-- 18. §1 #9: placement_id gün-1'de mevcut
-- ---------------------------------------------------------------------------
BEGIN;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace ns ON ns.oid = c.relnamespace
     WHERE ns.nspname = 'public' AND c.relname = 'tenants'
       AND a.attname = 'placement_id' AND NOT a.attisdropped;
    IF n <> 1 THEN
      RAISE EXCEPTION 'FAIL placement_id_missing (decision #9: day-1, even if unused)';
    END IF;
  END $$;
COMMIT;

\echo 'RLS + sema: 18/18 gecti'
