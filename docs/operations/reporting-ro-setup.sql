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
-- Grafana must connect as reporting_ro — NEVER as the app role, soc, or postgres.
-- Supply the password out-of-band (secret manager); do not commit a real one.
--
-- ── Two knobs you MUST get right for the target environment ──────────────────
--   -d <database>   the database that holds the `mart` schema. Canonical dev/UAT
--                   name is `ticketdata`; the first PRODUCTION build deviated to
--                   `ticketdata_prod` (see production-deployment.windows.md §
--                   deviation note). Pick the one that matches the host.
--   -v owner=<role> the role that OWNS the mart objects — i.e. DB_USER from the
--                   app's .env. Canonical `ticket`; production is `ticket_prod`.
--                   ALTER DEFAULT PRIVILEGES FOR ROLE names this role explicitly,
--                   so passing the wrong owner silently grants nothing on future
--                   objects. Defaults to `ticket` when omitted.
--
-- Usage (dev/UAT — canonical names):
--   psql -h localhost -U postgres -d ticketdata \
--        -v pw="'CHANGE_ME_STRONG_PASSWORD'" \
--        -f docs/operations/reporting-ro-setup.sql
--
-- Usage (production — as-built names):
--   psql -h localhost -U postgres -d ticketdata_prod \
--        -v owner=ticket_prod -v pw="'CHANGE_ME_STRONG_PASSWORD'" \
--        -f docs/operations/reporting-ro-setup.sql
-- ----------------------------------------------------------------------------

-- 0. Default the owner role to `ticket` unless the caller passed -v owner=...
--    (a command-line -v wins because it is set before this file runs).
\if :{?owner}
\else
  \set owner ticket
\endif

\echo Configuring reporting_ro on database ':DBNAME' with mart owner ':owner'

-- Fail fast if the named owner role does not exist on this host, rather than
-- letting ALTER DEFAULT PRIVILEGES below succeed against the wrong owner.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'owner') THEN
        RAISE EXCEPTION
            'mart owner role "%" does not exist — pass -v owner=<DB_USER> matching this host (e.g. ticket_prod in production)',
            :'owner';
    END IF;
END
$$;

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

-- 3. Auto-grant SELECT on any future mart object created by the OWNER role,
--    so new views/tables in later phases don't need a manual grant. The owner
--    must match DB_USER (:owner) — objects created by a different role would
--    not be covered by this default.
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA mart
    GRANT SELECT ON TABLES TO reporting_ro;

-- Explicitly ensure reporting_ro can reach ONLY the mart (no operational tables).
-- (No GRANT on schema public is issued here by design.)
