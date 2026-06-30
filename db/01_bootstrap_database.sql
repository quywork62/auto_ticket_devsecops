\set ON_ERROR_STOP on

-- Bootstrap database and login role for DevSecOps Auto Ticket.
--
-- Run this as a PostgreSQL admin user only when the database is managed
-- outside docker-compose, for example an existing EC2 PostgreSQL service or RDS.
--
-- Example:
--   psql -h <postgres-host> -U postgres -d postgres \
--     -v app_db=devsecops \
--     -v app_user=devsecops \
--     -f db/01_bootstrap_database.sql
--
-- The script prompts for app_password if it is not passed with -v.
-- Avoid passing real passwords in shell history on shared machines.

\if :{?app_db}
\else
  \set app_db devsecops
\endif

\if :{?app_user}
\else
  \set app_user devsecops
\endif

\if :{?app_password}
\else
  \prompt 'Application database password: ' app_password
\endif

SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'app_user', :'app_password')
WHERE NOT EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = :'app_user'
);
\gexec

SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'app_user', :'app_password');
\gexec

SELECT format(
    'CREATE DATABASE %I OWNER %I ENCODING %L TEMPLATE template0',
    :'app_db',
    :'app_user',
    'UTF8'
)
WHERE NOT EXISTS (
    SELECT 1
    FROM pg_database
    WHERE datname = :'app_db'
);
\gexec

\connect :app_db

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"app_db" TO :"app_user";
GRANT USAGE, CREATE ON SCHEMA public TO :"app_user";

COMMENT ON DATABASE :"app_db" IS 'DevSecOps Auto Ticket database';

SELECT
    current_database() AS database_name,
    :'app_user' AS app_user,
    'bootstrap complete; run alembic upgrade head next' AS next_step;
