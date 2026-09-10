CREATE SEQUENCE scim_create_seq;

CREATE TABLE scim_users (
  tenant_id     uuid        NOT NULL,
  user_id       uuid        NOT NULL,

  user_name     text        NOT NULL,
  external_id   text,

  active        boolean     NOT NULL DEFAULT true,

  payload       jsonb       NOT NULL,

  create_seq    bigint      NOT NULL DEFAULT nextval('scim_create_seq'),

  created_at    timestamptz NOT NULL DEFAULT now(),
  last_modified timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT scim_users_pkey PRIMARY KEY (tenant_id, user_id),

  CONSTRAINT scim_users_user_fkey FOREIGN KEY (tenant_id, user_id)
    REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT scim_users_user_name_length CHECK (length(user_name) BETWEEN 1 AND 1024),
  CONSTRAINT scim_users_external_id_length CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 1024),
  CONSTRAINT scim_users_payload_is_object CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT scim_users_modified_after_creation CHECK (last_modified >= created_at)
);

CREATE UNIQUE INDEX scim_users_user_name_key
  ON scim_users (tenant_id, lower(user_name));

CREATE UNIQUE INDEX scim_users_external_id_key
  ON scim_users (tenant_id, external_id)
  WHERE external_id IS NOT NULL;

CREATE UNIQUE INDEX scim_users_create_seq_key
  ON scim_users (tenant_id, create_seq);

CREATE TABLE scim_groups (
  tenant_id     uuid        NOT NULL,
  group_id      uuid        NOT NULL DEFAULT uuidv7(),

  display_name  text        NOT NULL,
  external_id   text,

  payload       jsonb       NOT NULL,

  create_seq    bigint      NOT NULL DEFAULT nextval('scim_create_seq'),

  created_at    timestamptz NOT NULL DEFAULT now(),
  last_modified timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT scim_groups_pkey PRIMARY KEY (tenant_id, group_id),

  CONSTRAINT scim_groups_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT scim_groups_display_name_length CHECK (length(display_name) BETWEEN 1 AND 1024),
  CONSTRAINT scim_groups_external_id_length CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 1024),
  CONSTRAINT scim_groups_payload_is_object CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT scim_groups_modified_after_creation CHECK (last_modified >= created_at)
);

CREATE UNIQUE INDEX scim_groups_external_id_key
  ON scim_groups (tenant_id, external_id)
  WHERE external_id IS NOT NULL;

CREATE UNIQUE INDEX scim_groups_create_seq_key
  ON scim_groups (tenant_id, create_seq);

CREATE INDEX scim_groups_display_name
  ON scim_groups (tenant_id, lower(display_name));

CREATE TABLE scim_group_members (
  tenant_id       uuid NOT NULL,
  group_id        uuid NOT NULL,

  member_user_id  uuid,
  member_group_id uuid,

  member_id       uuid GENERATED ALWAYS AS (coalesce(member_user_id, member_group_id)) STORED,

  CONSTRAINT scim_group_members_pkey PRIMARY KEY (tenant_id, group_id, member_id),

  CONSTRAINT scim_group_members_group_fkey FOREIGN KEY (tenant_id, group_id)
    REFERENCES scim_groups (tenant_id, group_id) ON DELETE CASCADE,

  CONSTRAINT scim_group_members_user_fkey FOREIGN KEY (tenant_id, member_user_id)
    REFERENCES scim_users (tenant_id, user_id) ON DELETE CASCADE,

  CONSTRAINT scim_group_members_subgroup_fkey FOREIGN KEY (tenant_id, member_group_id)
    REFERENCES scim_groups (tenant_id, group_id) ON DELETE CASCADE,

  CONSTRAINT scim_group_members_exactly_one_kind CHECK (
    (member_user_id IS NULL) <> (member_group_id IS NULL)
  ),

  CONSTRAINT scim_group_members_not_self CHECK (member_group_id IS NULL OR member_group_id <> group_id)
);

CREATE INDEX scim_group_members_by_user
  ON scim_group_members (tenant_id, member_user_id)
  WHERE member_user_id IS NOT NULL;

ALTER TABLE scim_users        ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups       ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_users        FORCE ROW LEVEL SECURITY;
ALTER TABLE scim_groups       FORCE ROW LEVEL SECURITY;
ALTER TABLE scim_group_members FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON scim_users
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON scim_groups
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON scim_group_members
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE scim_users         OWNER TO argus_owner;
ALTER TABLE scim_groups        OWNER TO argus_owner;
ALTER TABLE scim_group_members OWNER TO argus_owner;
ALTER SEQUENCE scim_create_seq OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE
  ON scim_users, scim_groups, scim_group_members TO argus_app;
GRANT USAGE ON SEQUENCE scim_create_seq TO argus_app;

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

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0016_scim');
