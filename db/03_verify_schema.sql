\set ON_ERROR_STOP on

-- Verify database objects, migration version, columns, indexes, and grants.
--
-- Example:
--   psql -h <postgres-host> -U devsecops -d devsecops \
--     -v app_user=devsecops \
--     -f db/03_verify_schema.sql

\if :{?app_user}
\else
  \set app_user devsecops
\endif

SELECT current_database() AS database_name, current_user AS connected_as;

SELECT version_num AS alembic_version
FROM alembic_version;

SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;

SELECT
    table_name,
    ordinal_position,
    column_name,
    data_type,
    character_maximum_length,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name IN (
      'processing_logs',
      'smtp_send_events',
      'notification_deliveries',
      'alembic_version'
  )
ORDER BY table_name, ordinal_position;

SELECT
    t.typname AS enum_type,
    e.enumlabel AS enum_value
FROM pg_type t
JOIN pg_enum e ON e.enumtypid = t.oid
WHERE t.typname IN ('processing_status', 'notification_status')
ORDER BY t.typname, e.enumsortorder;

SELECT
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename IN (
      'processing_logs',
      'smtp_send_events',
      'notification_deliveries',
      'alembic_version'
  )
ORDER BY tablename, indexname;

SELECT
    table_name,
    grantee,
    string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privileges
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND grantee = :'app_user'
GROUP BY table_name, grantee
ORDER BY table_name;
