CREATE TABLE authn_sessions (
  tenant_id     uuid        NOT NULL,
  session_hash  bytea       NOT NULL,
  user_id       uuid        NOT NULL,
  achieved_aal  aal         NOT NULL,
  authenticated_at timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz,

  CONSTRAINT authn_sessions_pkey PRIMARY KEY (tenant_id, session_hash),

  CONSTRAINT authn_sessions_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT authn_sessions_hash_length CHECK (octet_length(session_hash) = 32),
  CONSTRAINT authn_sessions_expiry_after_auth CHECK (expires_at > authenticated_at)
);

CREATE INDEX authn_sessions_expiry
  ON authn_sessions (expires_at)
  WHERE revoked_at IS NULL;

CREATE INDEX authn_sessions_by_user
  ON authn_sessions (tenant_id, user_id);

CREATE TABLE webauthn_ceremonies (
  tenant_id    uuid        NOT NULL,
  ceremony_hash bytea      NOT NULL,
  user_id      uuid,
  purpose      text        NOT NULL,
  state        text        NOT NULL,
  issued_at    timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,

  CONSTRAINT webauthn_ceremonies_pkey PRIMARY KEY (tenant_id, ceremony_hash),

  CONSTRAINT webauthn_ceremonies_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT webauthn_ceremonies_hash_length CHECK (octet_length(ceremony_hash) = 32),
  CONSTRAINT webauthn_ceremonies_purpose_valid
    CHECK (purpose IN ('registration', 'authentication')),
  CONSTRAINT webauthn_ceremonies_state_length CHECK (length(state) BETWEEN 1 AND 8192),
  CONSTRAINT webauthn_ceremonies_expiry_after_issue CHECK (expires_at > issued_at),
  CONSTRAINT webauthn_ceremonies_max_lifetime
    CHECK (expires_at <= issued_at + interval '10 minutes'),
  CONSTRAINT webauthn_ceremonies_registration_has_a_user
    CHECK (purpose <> 'registration' OR user_id IS NOT NULL)
);

CREATE INDEX webauthn_ceremonies_expiry ON webauthn_ceremonies (expires_at);

ALTER TABLE authn_sessions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn_sessions       FORCE ROW LEVEL SECURITY;
ALTER TABLE webauthn_ceremonies  ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_ceremonies  FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON authn_sessions
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON webauthn_ceremonies
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE authn_sessions      OWNER TO argus_owner;
ALTER TABLE webauthn_ceremonies OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE
  ON authn_sessions, webauthn_ceremonies TO argus_app;

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0015_sessions_and_ceremonies');

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
