ALTER TABLE clients
  ADD COLUMN auth_method text NOT NULL DEFAULT 'none';

ALTER TABLE clients
  ADD CONSTRAINT clients_auth_method_valid
    CHECK (auth_method IN ('none', 'private_key_jwt')),

  ADD CONSTRAINT clients_type_matches_auth_method CHECK (
    (client_type = 'public'       AND auth_method = 'none')
    OR (client_type = 'confidential' AND auth_method <> 'none')
  );

CREATE TABLE client_keys (
  tenant_id  uuid  NOT NULL,
  client_id  text  NOT NULL,

  kid        text  NOT NULL,

  x          bytea NOT NULL,
  y          bytea NOT NULL,

  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT client_keys_pkey PRIMARY KEY (tenant_id, client_id, kid),

  CONSTRAINT client_keys_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,

  CONSTRAINT client_keys_x_length CHECK (octet_length(x) = 32),
  CONSTRAINT client_keys_y_length CHECK (octet_length(y) = 32),
  CONSTRAINT client_keys_kid_length CHECK (length(kid) BETWEEN 1 AND 255)
);

ALTER TABLE client_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON client_keys
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE client_keys OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON client_keys TO argus_app;

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
