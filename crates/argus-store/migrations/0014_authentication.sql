CREATE TYPE aal AS ENUM ('aal1', 'aal2', 'aal3');

ALTER TABLE users
  ADD COLUMN required_aal aal NOT NULL DEFAULT 'aal1';

CREATE TABLE password_credentials (
  tenant_id     uuid        NOT NULL,
  user_id       uuid        NOT NULL,
  phc           text        NOT NULL,
  updated_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT password_credentials_pkey PRIMARY KEY (tenant_id, user_id),

  CONSTRAINT password_credentials_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT password_credentials_is_argon2id CHECK (phc LIKE '$argon2id$%'),
  CONSTRAINT password_credentials_phc_length CHECK (length(phc) BETWEEN 40 AND 512)
);

CREATE TABLE webauthn_credentials (
  tenant_id       uuid        NOT NULL,
  credential_id   bytea       NOT NULL,
  user_id         uuid        NOT NULL,
  rp_id           text        NOT NULL,
  public_key      bytea       NOT NULL,
  sign_count      bigint      NOT NULL DEFAULT 0,
  user_verified   boolean     NOT NULL DEFAULT false,
  backup_eligible boolean     NOT NULL DEFAULT false,
  attested_aal    aal         NOT NULL DEFAULT 'aal2',
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_used_at    timestamptz,

  CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (tenant_id, credential_id),

  CONSTRAINT webauthn_credentials_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT webauthn_credentials_id_length
    CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
  CONSTRAINT webauthn_credentials_sign_count_non_negative CHECK (sign_count >= 0),
  CONSTRAINT webauthn_credentials_rp_id_is_bare
    CHECK (rp_id !~ '[:/?#]' AND rp_id = lower(rp_id))
);

CREATE INDEX webauthn_credentials_by_user
  ON webauthn_credentials (tenant_id, user_id);

CREATE TABLE recovery_attempts (
  tenant_id        uuid        NOT NULL,
  attempt_id       uuid        NOT NULL DEFAULT uuidv7(),
  user_id          uuid        NOT NULL,

  state            text        NOT NULL DEFAULT 'requested',
  achieved_aal     aal,
  required_aal     aal,

  evidence_consumed boolean    NOT NULL DEFAULT false,
  requested_at     timestamptz NOT NULL DEFAULT now(),
  state_changed_at timestamptz NOT NULL DEFAULT now(),
  cooldown_until   timestamptz,
  grace_until      timestamptz,

  CONSTRAINT recovery_attempts_pkey PRIMARY KEY (tenant_id, attempt_id),

  CONSTRAINT recovery_attempts_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT recovery_attempts_state_valid CHECK (state IN (
    'requested', 'evidence_met', 'cooling_down', 'rebind_open',
    'grace_period', 'closed', 'denied', 'throttled', 'locked'
  )),

  CONSTRAINT recovery_attempts_assurance CHECK (
    state IN ('requested', 'throttled', 'locked', 'denied')
    OR (achieved_aal IS NOT NULL AND required_aal IS NOT NULL
        AND achieved_aal >= required_aal)
  ),

  CONSTRAINT recovery_attempts_evidence_consumed_past_requested CHECK (
    state IN ('requested', 'throttled', 'locked', 'denied')
    OR evidence_consumed
  )
);

CREATE INDEX recovery_attempts_by_user
  ON recovery_attempts (tenant_id, user_id, requested_at DESC);

ALTER TABLE password_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE recovery_attempts    ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_attempts    FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON password_credentials
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON webauthn_credentials
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON recovery_attempts
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE password_credentials OWNER TO argus_owner;
ALTER TABLE webauthn_credentials OWNER TO argus_owner;
ALTER TABLE recovery_attempts    OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE
  ON password_credentials, webauthn_credentials, recovery_attempts TO argus_app;

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0014_authentication');

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
