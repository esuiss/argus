-- §20 §7.4. The MVCC columns are what make a consistency token meaningful:
-- a read at revision R sees exactly the rows created at or before R and not
-- yet deleted at R, so a decision can be reproduced later.

CREATE TABLE authz_models (
  tenant_id   uuid        NOT NULL,
  model_id    uuid        NOT NULL DEFAULT uuidv7(),

  definition  jsonb       NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  retired_at  timestamptz,

  CONSTRAINT authz_models_pkey PRIMARY KEY (tenant_id, model_id),

  CONSTRAINT authz_models_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT authz_models_definition_is_object CHECK (jsonb_typeof(definition) = 'object'),
  CONSTRAINT authz_models_retired_after_created
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE UNIQUE INDEX authz_models_live
  ON authz_models (tenant_id)
  WHERE retired_at IS NULL;

-- One sequence per tenant would be ideal but a sequence is a schema object;
-- a counter row gives the same monotonic revision under the tenant policy.
CREATE TABLE authz_revisions (
  tenant_id   uuid        NOT NULL,
  revision    bigint      NOT NULL DEFAULT 0,
  updated_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT authz_revisions_pkey PRIMARY KEY (tenant_id),

  CONSTRAINT authz_revisions_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT authz_revisions_is_not_negative CHECK (revision >= 0)
);

CREATE TABLE authz_tuples (
  tenant_id        uuid   NOT NULL,

  object_type      text   NOT NULL,
  object_id        text   NOT NULL,
  relation         text   NOT NULL,
  subject_type     text   NOT NULL,
  subject_id       text   NOT NULL,
  -- '' is a direct subject; anything else is a userset.
  subject_relation text   NOT NULL DEFAULT '',

  created_rev      bigint NOT NULL,
  -- The sentinel is the largest bigint: a row alive now is alive at every
  -- future revision, so a range predicate needs no NULL handling.
  deleted_rev      bigint NOT NULL DEFAULT 9223372036854775807,

  CONSTRAINT authz_tuples_pkey PRIMARY KEY
    (tenant_id, object_type, object_id, relation,
     subject_type, subject_id, subject_relation, created_rev),

  CONSTRAINT authz_tuples_tenant_fkey FOREIGN KEY (tenant_id)
    REFERENCES tenants (tenant_id) ON DELETE RESTRICT,

  CONSTRAINT authz_tuples_deleted_after_created CHECK (deleted_rev >= created_rev),

  CONSTRAINT authz_tuples_identifiers_are_bounded CHECK (
    length(object_type) BETWEEN 1 AND 256 AND
    length(object_id) BETWEEN 1 AND 256 AND
    length(relation) BETWEEN 1 AND 256 AND
    length(subject_type) BETWEEN 1 AND 256 AND
    length(subject_id) BETWEEN 1 AND 256 AND
    length(subject_relation) <= 256
  ),

  -- The grammar separators must not appear inside a field or a rendered
  -- tuple could be read back as a different tuple.
  CONSTRAINT authz_tuples_identifiers_are_unambiguous CHECK (
    object_type !~ '[:#@]' AND object_id !~ '[:#@]' AND relation !~ '[:#@]' AND
    subject_type !~ '[:#@]' AND subject_id !~ '[:#@]' AND subject_relation !~ '[:#@]'
  )
);

-- Forward: a check asks "who holds this relation on this object".
CREATE INDEX authz_tuples_forward
  ON authz_tuples (tenant_id, object_type, object_id, relation)
  INCLUDE (subject_type, subject_id, subject_relation)
  WHERE deleted_rev = 9223372036854775807;

-- Reverse: a search asks "what is this subject attached to". §20 §7.4 keeps
-- both because no single ordering answers both, which is also the reason a
-- search costs more than a check.
CREATE INDEX authz_tuples_reverse
  ON authz_tuples (tenant_id, subject_type, subject_id, subject_relation, relation)
  INCLUDE (object_type, object_id)
  WHERE deleted_rev = 9223372036854775807;

CREATE INDEX authz_tuples_changelog
  ON authz_tuples (tenant_id, created_rev);

ALTER TABLE authz_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_models FORCE ROW LEVEL SECURITY;
ALTER TABLE authz_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE authz_tuples ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_tuples FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON authz_models
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON authz_revisions
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

CREATE POLICY tenant_isolation ON authz_tuples
  USING (tenant_id = argus_current_tenant())
  WITH CHECK (tenant_id = argus_current_tenant());

ALTER TABLE authz_models OWNER TO argus_owner;
ALTER TABLE authz_revisions OWNER TO argus_owner;
ALTER TABLE authz_tuples OWNER TO argus_owner;

GRANT SELECT, INSERT, UPDATE, DELETE ON authz_models TO argus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON authz_revisions TO argus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON authz_tuples TO argus_app;

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

INSERT INTO argus_meta.schema_migrations (name) VALUES ('0020_authz_tuples');
