DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_owner') THEN
    CREATE ROLE argus_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_app') THEN
    CREATE ROLE argus_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END
$$;

CREATE FUNCTION argus_current_tenant() RETURNS uuid
  LANGUAGE sql
  STABLE
  PARALLEL SAFE
  RETURNS NULL ON NULL INPUT
AS $$
  SELECT nullif(current_setting('argus.tenant_id', true), '')::uuid
$$;

COMMENT ON FUNCTION argus_current_tenant() IS
  'Transaction-yerel kiracı kapsamı. Ayarlanmamışsa NULL doner ve tum RLS politikalari fail-closed olur.';

CREATE TABLE tenants (
  tenant_id    uuid        NOT NULL DEFAULT uuidv7(),

  slug         text        NOT NULL,

  issuer_host  text        NOT NULL,

  placement_id text        NOT NULL DEFAULT 'default',

  status       text        NOT NULL DEFAULT 'active',

  authz_epoch  bigint      NOT NULL DEFAULT 0,
  key_epoch    bigint      NOT NULL DEFAULT 0,

  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT tenants_pkey PRIMARY KEY (tenant_id),
  CONSTRAINT tenants_slug_key UNIQUE (slug),

  CONSTRAINT tenants_slug_format CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
  CONSTRAINT tenants_issuer_host_key UNIQUE (issuer_host),
  CONSTRAINT tenants_issuer_host_format CHECK (issuer_host ~ '^[a-z0-9.-]{1,253}$'),
  CONSTRAINT tenants_placement_id_format CHECK (placement_id ~ '^[a-z0-9-]{1,63}$'),
  CONSTRAINT tenants_status_valid CHECK (status IN ('active', 'suspended', 'deleting')),
  CONSTRAINT tenants_authz_epoch_non_negative CHECK (authz_epoch >= 0),
  CONSTRAINT tenants_key_epoch_non_negative CHECK (key_epoch >= 0)
);

CREATE FUNCTION tenants_reject_identity_change() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.slug IS DISTINCT FROM OLD.slug THEN
    RAISE EXCEPTION 'tenant slug is immutable (decision #7): % -> %', OLD.slug, NEW.slug
      USING ERRCODE = 'restrict_violation';
  END IF;

  IF NEW.issuer_host IS DISTINCT FROM OLD.issuer_host THEN
    RAISE EXCEPTION 'tenant issuer_host is immutable (decision #8): % -> %',
      OLD.issuer_host, NEW.issuer_host
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER tenants_identity_immutable
  BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION tenants_reject_identity_change();

CREATE TABLE user_keys (
  tenant_id    uuid        NOT NULL,
  user_id      uuid        NOT NULL,

  dek_wrapped  bytea,

  kek_id       text        NOT NULL,

  wrapped_at   timestamptz NOT NULL DEFAULT now(),
  destroyed_at timestamptz,

  CONSTRAINT user_keys_pkey PRIMARY KEY (tenant_id, user_id),

  CONSTRAINT user_keys_shred_consistent CHECK (
    (dek_wrapped IS NOT NULL AND destroyed_at IS NULL)
    OR (dek_wrapped IS NULL AND destroyed_at IS NOT NULL)
  )
);

CREATE TABLE users (
  tenant_id          uuid        NOT NULL,
  user_id            uuid        NOT NULL DEFAULT uuidv7(),

  email_ciphertext   bytea,

  email_blind_index  bytea,

  session_epoch      bigint      NOT NULL DEFAULT 0,

  status             text        NOT NULL DEFAULT 'active',
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT users_pkey PRIMARY KEY (tenant_id, user_id),

  CONSTRAINT users_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT users_key_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES user_keys (tenant_id, user_id) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,

  CONSTRAINT users_tenant_email_key UNIQUE (tenant_id, email_blind_index),

  CONSTRAINT users_email_pair_consistent CHECK (
    (email_ciphertext IS NULL) = (email_blind_index IS NULL)
  ),

  CONSTRAINT users_status_valid CHECK (status IN ('active', 'suspended', 'deleted')),
  CONSTRAINT users_session_epoch_non_negative CHECK (session_epoch >= 0)
);

CREATE TABLE retired_user_identifiers (
  tenant_id       uuid        NOT NULL,
  identifier_kind text        NOT NULL,

  identifier_hash bytea       NOT NULL,

  retired_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT retired_user_identifiers_pkey
    PRIMARY KEY (tenant_id, identifier_kind, identifier_hash),
  CONSTRAINT retired_user_identifiers_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
  CONSTRAINT retired_user_identifiers_kind_valid
    CHECK (identifier_kind IN ('email', 'user_id'))
);

CREATE FUNCTION users_retire_identifiers() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO retired_user_identifiers (tenant_id, identifier_kind, identifier_hash)
    VALUES (OLD.tenant_id, 'user_id', digest_user_id(OLD.user_id))
    ON CONFLICT DO NOTHING;

  IF OLD.email_blind_index IS NOT NULL THEN
    INSERT INTO retired_user_identifiers (tenant_id, identifier_kind, identifier_hash)
      VALUES (OLD.tenant_id, 'email', OLD.email_blind_index)
      ON CONFLICT DO NOTHING;
  END IF;

  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;

CREATE FUNCTION digest_user_id(id uuid) RETURNS bytea
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
  SELECT uuid_send(id)
$$;

CREATE TRIGGER users_retire_on_delete
  AFTER DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION users_retire_identifiers();

CREATE TRIGGER users_retire_on_soft_delete
  AFTER UPDATE OF status ON users
  FOR EACH ROW
  WHEN (NEW.status = 'deleted' AND OLD.status IS DISTINCT FROM 'deleted')
  EXECUTE FUNCTION users_retire_identifiers();

CREATE FUNCTION users_reject_retired_identifiers() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM retired_user_identifiers
     WHERE tenant_id = NEW.tenant_id
       AND identifier_kind = 'user_id'
       AND identifier_hash = digest_user_id(NEW.user_id)
  ) THEN
    RAISE EXCEPTION 'user_id was retired and must not be reused (decision #14)'
      USING ERRCODE = 'unique_violation';
  END IF;

  IF NEW.email_blind_index IS NOT NULL AND EXISTS (
    SELECT 1 FROM retired_user_identifiers
     WHERE tenant_id = NEW.tenant_id
       AND identifier_kind = 'email'
       AND identifier_hash = NEW.email_blind_index
  ) THEN
    RAISE EXCEPTION 'email was retired and must not be reused (decision #14)'
      USING ERRCODE = 'unique_violation';
  END IF;

  RETURN NEW;
END
$$;

CREATE TRIGGER users_reject_retired
  BEFORE INSERT OR UPDATE OF email_blind_index ON users
  FOR EACH ROW EXECUTE FUNCTION users_reject_retired_identifiers();

CREATE TABLE signing_keys (
  tenant_id     uuid        NOT NULL,

  kid           text        NOT NULL,

  alg           text        NOT NULL DEFAULT 'ES256',

  public_jwk    jsonb       NOT NULL,

  backend       text        NOT NULL,
  backend_ref   text        NOT NULL,

  status        text        NOT NULL DEFAULT 'pending',
  not_before    timestamptz NOT NULL DEFAULT now(),
  not_after     timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT signing_keys_pkey PRIMARY KEY (tenant_id, kid),
  CONSTRAINT signing_keys_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT signing_keys_alg_valid CHECK (alg IN ('ES256', 'EdDSA', 'PS256', 'RS256')),
  CONSTRAINT signing_keys_backend_valid CHECK (backend IN ('file', 'kms', 'pkcs11')),
  CONSTRAINT signing_keys_status_valid
    CHECK (status IN ('pending', 'active', 'retiring', 'retired')),
  CONSTRAINT signing_keys_validity_ordered
    CHECK (not_after IS NULL OR not_after > not_before),

  CONSTRAINT signing_keys_public_only CHECK (
    NOT (public_jwk ? 'd') AND NOT (public_jwk ? 'p')
    AND NOT (public_jwk ? 'q') AND NOT (public_jwk ? 'k')
  )
);

CREATE TABLE clients (
  tenant_id       uuid        NOT NULL,

  client_id       text        NOT NULL,

  client_type     text        NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT clients_pkey PRIMARY KEY (tenant_id, client_id),
  CONSTRAINT clients_client_id_global_key UNIQUE (client_id),

  CONSTRAINT clients_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT clients_client_id_vschar CHECK (client_id ~ '^[\x20-\x7E]+$'),
  CONSTRAINT clients_client_id_length CHECK (length(client_id) BETWEEN 1 AND 255),
  CONSTRAINT clients_type_valid CHECK (client_type IN ('confidential', 'public'))
);

CREATE TABLE client_redirect_uris (
  tenant_id    uuid NOT NULL,
  client_id    text NOT NULL,
  redirect_uri text NOT NULL,

  CONSTRAINT client_redirect_uris_pkey
    PRIMARY KEY (tenant_id, client_id, redirect_uri),

  CONSTRAINT client_redirect_uris_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,

  CONSTRAINT client_redirect_uris_no_wildcard CHECK (position('*' in redirect_uri) = 0),
  CONSTRAINT client_redirect_uris_no_fragment CHECK (position('#' in redirect_uri) = 0),
  CONSTRAINT client_redirect_uris_absolute CHECK (redirect_uri ~ '^[a-zA-Z][a-zA-Z0-9+.-]*:')
);

ALTER TABLE tenants                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_keys                ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys             ENABLE ROW LEVEL SECURITY;
ALTER TABLE users                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE retired_user_identifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_redirect_uris     ENABLE ROW LEVEL SECURITY;

ALTER TABLE tenants                  FORCE ROW LEVEL SECURITY;
ALTER TABLE user_keys                FORCE ROW LEVEL SECURITY;
ALTER TABLE signing_keys             FORCE ROW LEVEL SECURITY;
ALTER TABLE users                    FORCE ROW LEVEL SECURITY;
ALTER TABLE retired_user_identifiers FORCE ROW LEVEL SECURITY;
ALTER TABLE clients                  FORCE ROW LEVEL SECURITY;
ALTER TABLE client_redirect_uris     FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON user_keys
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON signing_keys
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON tenants
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON users
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON retired_user_identifiers
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON clients
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON client_redirect_uris
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE tenants                  OWNER TO argus_owner;
ALTER TABLE user_keys                OWNER TO argus_owner;
ALTER TABLE signing_keys             OWNER TO argus_owner;
ALTER TABLE users                    OWNER TO argus_owner;
ALTER TABLE retired_user_identifiers OWNER TO argus_owner;
ALTER TABLE clients                  OWNER TO argus_owner;
ALTER TABLE client_redirect_uris     OWNER TO argus_owner;
ALTER FUNCTION argus_current_tenant()          OWNER TO argus_owner;
ALTER FUNCTION digest_user_id(uuid)            OWNER TO argus_owner;
ALTER FUNCTION users_retire_identifiers()      OWNER TO argus_owner;
ALTER FUNCTION users_reject_retired_identifiers() OWNER TO argus_owner;
ALTER FUNCTION tenants_reject_identity_change()    OWNER TO argus_owner;

GRANT USAGE ON SCHEMA public TO argus_owner;
GRANT USAGE ON SCHEMA public TO argus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  tenants, user_keys, users, retired_user_identifiers,
  signing_keys, clients, client_redirect_uris
  TO argus_app;
GRANT EXECUTE ON FUNCTION argus_current_tenant() TO argus_app;
GRANT EXECUTE ON FUNCTION digest_user_id(uuid) TO argus_app;

DO $$
DECLARE
  offending text;
BEGIN
  SELECT string_agg(c.relname, ', ')
    INTO offending
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p')
     AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);

  IF offending IS NOT NULL THEN
    RAISE EXCEPTION 'tables without RLS+FORCE (decision #3): %', offending;
  END IF;

  SELECT string_agg(c.relname, ', ')
    INTO offending
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p')
     AND (r.rolsuper OR r.rolbypassrls);

  IF offending IS NOT NULL THEN
    RAISE EXCEPTION 'tables owned by a superuser or BYPASSRLS role, FORCE is meaningless: %', offending;
  END IF;
END
$$;
