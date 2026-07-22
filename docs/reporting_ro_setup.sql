-- ============================================================================
-- reporting_ro — read-only role for external BI (Grafana) on the mart schema
-- ============================================================================
-- DEFERRED (Phase 4): the in-app dashboard reads the mart via the Django ORM
-- over the `ticket` connection and does NOT need this role. Create it only when
-- wiring Grafana (or another external BI tool) at the mart.
--
-- Run ONCE as a superuser (e.g. postgres) AFTER `manage.py migrate` has created
-- the `mart` schema and its objects. The `ticket` app role cannot create roles,
-- which is why this lives outside the Django migrations (same pattern as the
-- Wazuh Indexer's grafanaro).
--
-- Grafana must connect as reporting_ro — NEVER as ticket, soc, or postgres.
-- Supply the password out-of-band (secret manager); do not commit a real one.
--
-- Usage:
--   psql -h localhost -U postgres -d ticketdata \
--        -v pw="'CHANGE_ME_STRONG_PASSWORD'" -f docs/reporting_ro_setup.sql
-- ----------------------------------------------------------------------------

-- 1. The login role (idempotent).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'reporting_ro') THEN
        CREATE ROLE reporting_ro LOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END
$$;

-- Set/rotate the password (kept separate so the CREATE stays idempotent).
ALTER ROLE reporting_ro PASSWORD :pw;

-- 2. Read access to the mart schema and everything currently in it
--    (GRANT ... ON ALL TABLES covers views and materialized views too).
GRANT USAGE  ON SCHEMA mart TO reporting_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA mart TO reporting_ro;

-- 3. Auto-grant SELECT on any future mart object created by the `ticket` role,
--    so new views/tables in later phases don't need a manual grant.
ALTER DEFAULT PRIVILEGES FOR ROLE ticket IN SCHEMA mart
    GRANT SELECT ON TABLES TO reporting_ro;

-- Explicitly ensure reporting_ro can reach ONLY the mart (no operational tables).
-- (No GRANT on schema public is issued here by design.)
