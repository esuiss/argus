
CREATE TABLE audit_checkpoints (
  tenant_id    uuid        NOT NULL,
  tree_size    bigint      NOT NULL,

  root         bytea       NOT NULL,
  issued_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT audit_checkpoints_pkey PRIMARY KEY (tenant_id, tree_size),

  CONSTRAINT audit_checkpoints_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT audit_checkpoints_tree_size_is_positive CHECK (tree_size > 0),
  CONSTRAINT audit_checkpoints_root_is_a_digest CHECK (length(root) = 32)
);

CREATE TABLE audit_leaves (
  tenant_id   uuid    NOT NULL,
  leaf_index  bigint  NOT NULL,
  leaf_hash   bytea   NOT NULL,
  event_id    uuid    NOT NULL,

  CONSTRAINT audit_leaves_pkey PRIMARY KEY (tenant_id, leaf_index),

  CONSTRAINT audit_leaves_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT audit_leaves_index_is_not_negative CHECK (leaf_index >= 0),
  CONSTRAINT audit_leaves_hash_is_a_digest CHECK (length(leaf_hash) = 32)
);

CREATE INDEX audit_leaves_by_event ON audit_leaves (tenant_id, event_id);

CREATE OR REPLACE FUNCTION audit_leaves_are_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit leaves are append-only (§25 K7): % on %', TG_OP, TG_TABLE_NAME;
END
$$;

CREATE TRIGGER audit_leaves_no_update
  BEFORE UPDATE OR DELETE ON audit_leaves
  FOR EACH ROW EXECUTE FUNCTION audit_leaves_are_append_only();

CREATE TRIGGER audit_leaves_no_truncate
  BEFORE TRUNCATE ON audit_leaves
  EXECUTE FUNCTION audit_leaves_are_append_only();

CREATE TRIGGER audit_checkpoints_no_truncate
  BEFORE TRUNCATE ON audit_checkpoints
  EXECUTE FUNCTION audit_leaves_are_append_only();

ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_leaves ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_leaves FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON audit_checkpoints
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON audit_leaves
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE audit_checkpoints OWNER TO argus_owner;
ALTER TABLE audit_leaves OWNER TO argus_owner;
ALTER FUNCTION audit_leaves_are_append_only() OWNER TO argus_owner;

GRANT SELECT, INSERT ON audit_checkpoints TO argus_app;
GRANT SELECT, INSERT ON audit_leaves TO argus_app;

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

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0023_audit_checkpoints');
