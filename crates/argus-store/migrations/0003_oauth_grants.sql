CREATE TABLE authorization_codes (
  tenant_id          uuid        NOT NULL,

  code_hash          bytea       NOT NULL,

  client_id          text        NOT NULL,
  user_id            uuid        NOT NULL,

  redirect_uri       text        NOT NULL,

  challenge_digest   bytea       NOT NULL,
  challenge_method   text        NOT NULL DEFAULT 'S256',

  issued_at          timestamptz NOT NULL,
  expires_at         timestamptz NOT NULL,

  state              text        NOT NULL DEFAULT 'issued',
  redeemed_at        timestamptz,

  CONSTRAINT authorization_codes_pkey PRIMARY KEY (tenant_id, code_hash),

  CONSTRAINT authorization_codes_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,
  CONSTRAINT authorization_codes_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT authorization_codes_hash_length CHECK (octet_length(code_hash) = 32),
  CONSTRAINT authorization_codes_digest_length CHECK (octet_length(challenge_digest) = 32),
  CONSTRAINT authorization_codes_state_valid CHECK (state IN ('issued', 'redeemed')),
  CONSTRAINT authorization_codes_expiry_after_issue CHECK (expires_at > issued_at),

  CONSTRAINT authorization_codes_max_lifetime
    CHECK (expires_at <= issued_at + interval '10 minutes'),

  CONSTRAINT authorization_codes_state_consistent CHECK (
    (state = 'issued' AND redeemed_at IS NULL)
    OR (state = 'redeemed' AND redeemed_at IS NOT NULL)
  )
);

CREATE INDEX authorization_codes_expiry
  ON authorization_codes (expires_at)
  WHERE state = 'issued';

CREATE TABLE refresh_tokens (
  tenant_id          uuid        NOT NULL,

  token_hash         bytea       NOT NULL,

  client_id          text        NOT NULL,
  user_id            uuid        NOT NULL,

  family_id          uuid        NOT NULL,

  generation         integer     NOT NULL DEFAULT 0,

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

CREATE INDEX refresh_tokens_family ON refresh_tokens (tenant_id, family_id);

CREATE INDEX refresh_tokens_expiry
  ON refresh_tokens (expires_at)
  WHERE state = 'active';

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
