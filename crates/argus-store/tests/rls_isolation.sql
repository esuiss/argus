\set ON_ERROR_STOP on

\set t_a '''00000000-0000-7000-8000-00000000000a'''
\set t_b '''00000000-0000-7000-8000-00000000000b'''
\set u_a1 '''00000000-0000-7000-8000-0000000000a1'''
\set u_b1 '''00000000-0000-7000-8000-0000000000b1'''

BEGIN;
  SET LOCAL argus.tenant_id = :t_a;
  INSERT INTO tenants (tenant_id, slug, issuer_host)
    VALUES (:t_a, 'acme', 'acme.argus.test');
  INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id)
    VALUES (:t_a, :u_a1, '\x0102'::bytea, 'kek-1');
  INSERT INTO users (tenant_id, user_id, email_ciphertext, email_blind_index)
    VALUES (:t_a, :u_a1, '\xdead'::bytea, '\xaaaa'::bytea);

  INSERT INTO clients (tenant_id, client_id, client_type, auth_method)
    VALUES (:t_a, 'acme-web', 'confidential', 'private_key_jwt');
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

BEGIN;
  SET LOCAL ROLE argus_owner;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM users;
    IF n <> 0 THEN RAISE EXCEPTION 'FAIL force_rls_owner: owner saw % rows', n; END IF;
  END $$;
COMMIT;

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

BEGIN;
  SET LOCAL argus.tenant_id = :t_b;
  INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id)
    VALUES (:t_b, '00000000-0000-7000-8000-0000000000b3', '\x06'::bytea, 'kek-1');

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

BEGIN;
  SET LOCAL argus.tenant_id = :t_a;

  UPDATE users SET status = 'deleted' WHERE user_id = :u_a1;

  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM retired_user_identifiers
     WHERE tenant_id = '00000000-0000-7000-8000-00000000000a';
    IF n <> 2 THEN
      RAISE EXCEPTION 'FAIL retire_trigger: expected 2 retired identifiers, got %', n;
    END IF;

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

    INSERT INTO signing_keys (tenant_id, kid, public_jwk, backend, backend_ref)
      VALUES ('00000000-0000-7000-8000-00000000000a', 'k1',
              '{"kty":"EC","crv":"P-256","x":"a","y":"b"}'::jsonb, 'kms', 'arn:test');
  END $$;
ROLLBACK;

BEGIN;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM pg_class c
      JOIN pg_namespace ns ON ns.oid = c.relnamespace
     WHERE ns.nspname = 'public' AND c.relname = 'audit_events' AND c.relkind = 'p';
    IF n <> 1 THEN RAISE EXCEPTION 'FAIL audit_events_not_partitioned'; END IF;

    SELECT count(*) INTO n FROM pg_inherits i
      JOIN pg_class p ON p.oid = i.inhparent
     WHERE p.relname = 'audit_events';
    IF n < 3 THEN RAISE EXCEPTION 'FAIL audit_events_time_partitions: %', n; END IF;
  END $$;
COMMIT;

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

    BEGIN
      TRUNCATE audit_events;
      RAISE EXCEPTION 'FAIL audit_truncate_allowed';
    EXCEPTION WHEN restrict_violation THEN NULL;
    END;
  END $$;
ROLLBACK;

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

BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  INSERT INTO client_keys (tenant_id, client_id, kid, x, y)
    VALUES (:t_a, 'acme-web', 'k1',
            decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'));
COMMIT;

BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_b;
  DO $$
  DECLARE n int;
  BEGIN
    SELECT count(*) INTO n FROM client_keys;
    IF n <> 0 THEN
      RAISE EXCEPTION 'FAIL client_keys_cross_tenant_read: leaked % rows', n;
    END IF;
  END $$;
COMMIT;

BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  BEGIN
    BEGIN
      INSERT INTO clients (tenant_id, client_id, client_type, auth_method)
        VALUES ('00000000-0000-7000-8000-00000000000a', 'sneaky', 'confidential', 'none');
      RAISE EXCEPTION 'FAIL confidential_without_auth_method_accepted';
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;

    BEGIN
      INSERT INTO clients (tenant_id, client_id, client_type, auth_method)
        VALUES ('00000000-0000-7000-8000-00000000000a', 'sneaky2', 'public', 'private_key_jwt');
      RAISE EXCEPTION 'FAIL public_with_auth_method_accepted';
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;
  END $$;
ROLLBACK;

BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  DECLARE bad text;
  BEGIN
    FOREACH bad IN ARRAY ARRAY[
      'http://evil.example.com/cb',
      'http://10.0.0.5/cb',
      'ftp://x.test/cb',
      'javascript:alert(1)',
      'data:text/html,x'
    ] LOOP
      BEGIN
        INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri)
          VALUES ('00000000-0000-7000-8000-00000000000a', 'acme-web', bad);
        RAISE EXCEPTION 'FAIL redirect_uri_scheme_accepted: %', bad;
      EXCEPTION WHEN check_violation THEN
        NULL;
      END;
    END LOOP;

    FOREACH bad IN ARRAY ARRAY[
      'https://app.example.com/ok',
      'http://127.0.0.1:8080/cb',
      'http://localhost/cb',
      'http://[::1]/cb',
      'com.example.app:/oauth'
    ] LOOP
      INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri)
        VALUES ('00000000-0000-7000-8000-00000000000a', 'acme-web', bad);
    END LOOP;
  END $$;
ROLLBACK;

BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  BEGIN
    BEGIN
      INSERT INTO recovery_attempts (tenant_id, user_id, state, achieved_aal, required_aal)
        VALUES ('00000000-0000-7000-8000-00000000000a',
                '00000000-0000-7000-8000-0000000000a1',
                'rebind_open', 'aal1', 'aal2');
      RAISE EXCEPTION 'FAIL recovery_weaker_than_account_accepted';
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;

    BEGIN
      INSERT INTO recovery_attempts (tenant_id, user_id, state, achieved_aal, required_aal,
                                     evidence_consumed)
        VALUES ('00000000-0000-7000-8000-00000000000a',
                '00000000-0000-7000-8000-0000000000a1',
                'rebind_open', NULL, NULL, true);
      RAISE EXCEPTION 'FAIL recovery_null_assurance_slipped_through';
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;

    BEGIN
      INSERT INTO recovery_attempts (tenant_id, user_id, state, achieved_aal, required_aal,
                                     evidence_consumed)
        VALUES ('00000000-0000-7000-8000-00000000000a',
                '00000000-0000-7000-8000-0000000000a1',
                'rebind_open', 'aal2', NULL, true);
      RAISE EXCEPTION 'FAIL recovery_half_null_assurance_slipped_through';
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;

    INSERT INTO recovery_attempts (tenant_id, user_id, state, achieved_aal, required_aal,
                                   evidence_consumed)
      VALUES ('00000000-0000-7000-8000-00000000000a',
              '00000000-0000-7000-8000-0000000000a1',
              'rebind_open', 'aal2', 'aal2', true);

    INSERT INTO recovery_attempts (tenant_id, user_id, state)
      VALUES ('00000000-0000-7000-8000-00000000000a',
              '00000000-0000-7000-8000-0000000000a1',
              'requested');

    BEGIN
      INSERT INTO recovery_attempts (tenant_id, user_id, state, achieved_aal, required_aal,
                                     evidence_consumed)
        VALUES ('00000000-0000-7000-8000-00000000000a',
                '00000000-0000-7000-8000-0000000000a1',
                'rebind_open', 'aal2', 'aal2', false);
      RAISE EXCEPTION 'FAIL recovery_unconsumed_evidence_accepted';
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;
  END $$;
ROLLBACK;

BEGIN;
  SET LOCAL ROLE argus_app;
  SET LOCAL argus.tenant_id = :t_a;
  DO $$
  BEGIN
    BEGIN
      INSERT INTO password_credentials (tenant_id, user_id, phc)
        VALUES ('00000000-0000-7000-8000-00000000000a',
                '00000000-0000-7000-8000-0000000000a1',
                '$2b$12$K3JNi5xUOqZ8xJvKPQ0Zru3Qa5mzZ8FZ0O9wq3sJ1rG7hV8kYcFqK');
      RAISE EXCEPTION 'FAIL non_argon2id_password_accepted';
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;

    INSERT INTO password_credentials (tenant_id, user_id, phc)
      VALUES ('00000000-0000-7000-8000-00000000000a',
              '00000000-0000-7000-8000-0000000000a1',
              '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$JvRTMv2FeHhBEz8xLcQK1JhDlxRj4Bi1cCPq1xIVUQU');
  END $$;
ROLLBACK;

BEGIN;
  DO $$
  DECLARE ordered boolean;
  BEGIN
    SELECT 'aal1'::aal < 'aal2'::aal AND 'aal2'::aal < 'aal3'::aal INTO ordered;
    IF NOT ordered THEN
      RAISE EXCEPTION 'FAIL aal_enum_order: the schema contract aal1<aal2<aal3 is broken';
    END IF;
  END $$;
COMMIT;

\echo 'RLS + sema: 24/24 gecti'
