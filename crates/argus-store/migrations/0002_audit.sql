CREATE TABLE audit_events (
  tenant_id        uuid        NOT NULL,

  occurred_at      timestamptz NOT NULL,
  recorded_at      timestamptz NOT NULL DEFAULT now(),

  event_id         uuid        NOT NULL DEFAULT uuidv7(),

  event_type       text        NOT NULL,

  outcome          text        NOT NULL,
  actor_kind       text        NOT NULL,
  actor_id         uuid,
  target_kind      text,
  target_id        text,

  txn              uuid,

  attributes       jsonb       NOT NULL DEFAULT '{}'::jsonb,

  checkpoint_at    timestamptz,

  CONSTRAINT audit_events_pkey PRIMARY KEY (tenant_id, occurred_at, event_id),

  CONSTRAINT audit_events_outcome_valid CHECK (outcome IN ('success', 'failure', 'unknown')),
  CONSTRAINT audit_events_actor_kind_valid
    CHECK (actor_kind IN ('user', 'client', 'admin', 'system', 'agent', 'anonymous')),
  CONSTRAINT audit_events_recorded_after_occurred CHECK (recorded_at >= occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE audit_event_pii (
  tenant_id        uuid        NOT NULL,
  occurred_at      timestamptz NOT NULL,
  event_id         uuid        NOT NULL,

  subject_user_id  uuid,
  payload_cipher   bytea       NOT NULL,

  CONSTRAINT audit_event_pii_pkey PRIMARY KEY (tenant_id, occurred_at, event_id)
) PARTITION BY RANGE (occurred_at);

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

      FOR j IN 0..3 LOOP
        EXECUTE format(
          'CREATE TABLE %I PARTITION OF %I FOR VALUES WITH (MODULUS 4, REMAINDER %s)',
          format('%s_h%s', child, j), child, j);
      END LOOP;
    END LOOP;
  END LOOP;
END
$$;

CREATE TABLE audit_outbox (
  tenant_id     uuid        NOT NULL,
  occurred_at   timestamptz NOT NULL,
  event_id      uuid        NOT NULL,

  seq           bigserial   NOT NULL,

  producer_xid  xid8        NOT NULL DEFAULT pg_current_xact_id(),

  enqueued_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at  timestamptz,

  CONSTRAINT audit_outbox_pkey PRIMARY KEY (tenant_id, occurred_at, event_id)
);

CREATE INDEX audit_outbox_pending ON audit_outbox (seq) WHERE delivered_at IS NULL;
CREATE INDEX audit_outbox_producer_xid ON audit_outbox (producer_xid);

CREATE FUNCTION audit_reject_mutation() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit tables are append-only (§25 K7): % on %', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'restrict_violation';
END
$$;

REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, audit_event_pii FROM PUBLIC;

CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_reject_mutation();

CREATE TRIGGER audit_event_pii_append_only
  BEFORE UPDATE OR DELETE ON audit_event_pii
  FOR EACH ROW EXECUTE FUNCTION audit_reject_mutation();

CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_reject_mutation();

CREATE TRIGGER audit_event_pii_no_truncate
  BEFORE TRUNCATE ON audit_event_pii
  FOR EACH STATEMENT EXECUTE FUNCTION audit_reject_mutation();

DO $$
DECLARE t text;
BEGIN

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

GRANT SELECT, INSERT ON audit_events, audit_event_pii TO argus_app;
GRANT SELECT, INSERT, UPDATE ON audit_outbox TO argus_app;
GRANT USAGE, SELECT ON SEQUENCE audit_outbox_seq_seq TO argus_app;

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
