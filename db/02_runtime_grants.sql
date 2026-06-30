\set ON_ERROR_STOP on

-- Re-apply runtime permissions after Alembic migration.
--
-- Normal docker-compose deployment uses the same role for migration and runtime,
-- so this script is usually not required. It is useful when a DBA creates or
-- owns objects and must grant the application role access afterwards.
--
-- Example:
--   psql -h <postgres-host> -U postgres -d devsecops \
--     -v app_db=devsecops \
--     -v app_user=devsecops \
--     -f db/02_runtime_grants.sql

\if :{?app_db}
\else
  \set app_db devsecops
\endif

\if :{?app_user}
\else
  \set app_user devsecops
\endif

\connect :app_db

GRANT CONNECT, TEMPORARY ON DATABASE :"app_db" TO :"app_user";
GRANT USAGE ON SCHEMA public TO :"app_user";

GRANT SELECT, INSERT, UPDATE, DELETE
ON ALL TABLES IN SCHEMA public
TO :"app_user";

GRANT USAGE, SELECT, UPDATE
ON ALL SEQUENCES IN SCHEMA public
TO :"app_user";

GRANT USAGE ON TYPE processing_status TO :"app_user";
GRANT USAGE ON TYPE notification_status TO :"app_user";

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO :"app_user";

SELECT
    current_database() AS database_name,
    :'app_user' AS app_user,
    'runtime grants applied' AS result;
