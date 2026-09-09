ALTER TABLE authorization_codes

  ADD COLUMN nonce text,

  ADD COLUMN scope text;

ALTER TABLE authorization_codes
  ADD CONSTRAINT authorization_codes_nonce_length
    CHECK (nonce IS NULL OR length(nonce) <= 255),
  ADD CONSTRAINT authorization_codes_scope_length
    CHECK (scope IS NULL OR length(scope) <= 1024);

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
