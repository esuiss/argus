CREATE TABLE vault_secrets (
  tenant_id      uuid        NOT NULL,
  secret_id      text        NOT NULL,

  owner_user_id  uuid,

  audience       text        NOT NULL,
  kind           text        NOT NULL,
  required_scope text        NOT NULL DEFAULT '',

  nonce          bytea       NOT NULL,
  ciphertext     bytea       NOT NULL,

  created_at     timestamptz NOT NULL DEFAULT now(),
  rotated_at     timestamptz,
  expires_at     timestamptz,
  revoked_at     timestamptz,

  CONSTRAINT vault_secrets_pkey PRIMARY KEY (tenant_id, secret_id),

  CONSTRAINT vault_secrets_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT vault_secrets_owner_fkey FOREIGN KEY (tenant_id, owner_user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT vault_secrets_id_length CHECK (length(secret_id) BETWEEN 1 AND 256),
  CONSTRAINT vault_secrets_audience_length CHECK (length(audience) BETWEEN 1 AND 1024),
  CONSTRAINT vault_secrets_kind_valid
    CHECK (kind IN ('bearer', 'api_key', 'basic', 'upstream_refresh_token')),
  CONSTRAINT vault_secrets_nonce_length CHECK (octet_length(nonce) = 12),
  CONSTRAINT vault_secrets_ciphertext_sealed CHECK (octet_length(ciphertext) >= 16),
  CONSTRAINT vault_secrets_ciphertext_bounded CHECK (octet_length(ciphertext) <= 65552),
  CONSTRAINT vault_secrets_expiry_after_creation
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX vault_secrets_by_owner
  ON vault_secrets (tenant_id, owner_user_id)
  WHERE owner_user_id IS NOT NULL;

CREATE INDEX vault_secrets_by_audience ON vault_secrets (tenant_id, audience);

CREATE TABLE vault_leases (
  tenant_id   uuid        NOT NULL,
  lease_id    uuid        NOT NULL DEFAULT uuidv7(),

  secret_id   text        NOT NULL,
  holder      text        NOT NULL,

  issued_at   timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  spent_at    timestamptz,

  CONSTRAINT vault_leases_pkey PRIMARY KEY (tenant_id, lease_id),

  CONSTRAINT vault_leases_secret_fkey FOREIGN KEY (tenant_id, secret_id)
    REFERENCES vault_secrets (tenant_id, secret_id) ON DELETE CASCADE,

  CONSTRAINT vault_leases_holder_length CHECK (length(holder) BETWEEN 1 AND 512),
  CONSTRAINT vault_leases_expiry_after_issue CHECK (expires_at > issued_at),

  CONSTRAINT vault_leases_max_lifetime
    CHECK (expires_at <= issued_at + interval '5 minutes'),

  CONSTRAINT vault_leases_spent_within_life
    CHECK (spent_at IS NULL OR spent_at >= issued_at)
);

CREATE INDEX vault_leases_expiry
  ON vault_leases (expires_at)
  WHERE spent_at IS NULL;

ALTER TABLE vault_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_leases  ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE vault_leases  FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON vault_secrets
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON vault_leases
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE vault_secrets OWNER TO argus_owner;
ALTER TABLE vault_leases  OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON vault_secrets, vault_leases TO argus_app;

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

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0017_vault');
