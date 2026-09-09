CREATE TABLE backchannel_requests (
  tenant_id       uuid        NOT NULL,
  auth_req_hash   bytea       NOT NULL,
  client_id       text        NOT NULL,
  user_id         uuid        NOT NULL,
  scope           text,
  resources       text,
  state           text        NOT NULL DEFAULT 'pending',
  issued_at       timestamptz NOT NULL,
  expires_at      timestamptz NOT NULL,
  poll_interval   integer     NOT NULL DEFAULT 5,
  last_polled_at  timestamptz,
  decided_at      timestamptz,

  CONSTRAINT backchannel_requests_pkey PRIMARY KEY (tenant_id, auth_req_hash),

  CONSTRAINT backchannel_requests_client_fkey FOREIGN KEY (tenant_id, client_id)
    REFERENCES clients (tenant_id, client_id) ON DELETE CASCADE,
  CONSTRAINT backchannel_requests_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT backchannel_requests_hash_length CHECK (octet_length(auth_req_hash) = 32),
  CONSTRAINT backchannel_requests_state_valid
    CHECK (state IN ('pending', 'approved', 'denied', 'consumed')),
  CONSTRAINT backchannel_requests_interval_sane
    CHECK (poll_interval BETWEEN 1 AND 60),
  CONSTRAINT backchannel_requests_expiry_after_issue
    CHECK (expires_at > issued_at),
  CONSTRAINT backchannel_requests_max_lifetime
    CHECK (expires_at <= issued_at + interval '10 minutes'),
  CONSTRAINT backchannel_requests_decision_consistent CHECK (
    (state = 'pending' AND decided_at IS NULL)
    OR (state <> 'pending' AND decided_at IS NOT NULL)
  )
);

CREATE INDEX backchannel_requests_expiry
  ON backchannel_requests (expires_at)
  WHERE state = 'pending';

ALTER TABLE backchannel_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE backchannel_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON backchannel_requests
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE backchannel_requests OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON backchannel_requests TO argus_app;

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0012_backchannel_requests');

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
