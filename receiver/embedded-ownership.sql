-- Embedded database initialization only. These tables are created by init.sql
-- as postgres, but the application role must own them for schema migrations.
-- This is not executed against externally managed PostgreSQL databases.
ALTER TABLE IF EXISTS public.roles OWNER TO unifi;
ALTER TABLE IF EXISTS public.users OWNER TO unifi;
ALTER TABLE IF EXISTS public.sessions OWNER TO unifi;
ALTER TABLE IF EXISTS public.api_tokens OWNER TO unifi;
ALTER TABLE IF EXISTS public.audit_log OWNER TO unifi;
ALTER TABLE IF EXISTS public.threat_backfill_queue OWNER TO unifi;
ALTER SEQUENCE IF EXISTS public.roles_id_seq OWNER TO unifi;
ALTER SEQUENCE IF EXISTS public.users_id_seq OWNER TO unifi;
ALTER SEQUENCE IF EXISTS public.audit_log_id_seq OWNER TO unifi;
