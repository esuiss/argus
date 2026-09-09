ALTER TABLE client_redirect_uris
  ADD CONSTRAINT client_redirect_uris_scheme_allowed CHECK (
    redirect_uri ~ '^https://'
    OR redirect_uri ~ '^http://(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|localhost|\[::1\])([:/]|$)'
    OR redirect_uri ~ '^[a-zA-Z][a-zA-Z0-9+-]*\.[a-zA-Z0-9+.-]*:'
  );

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
