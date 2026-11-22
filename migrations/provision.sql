-- Database provisioning for Hermes (run ONCE per database as a superuser, before Alembic).
-- docker compose runs it at the first start of the db volume; tests run it on each throwaway database.
-- Extensions and roles need superuser or CREATEROLE; Alembic then runs as the migrator role (DAT-05).
-- Login passwords are set apart (docker/db/20-role-passwords.sh), never in this file.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS unaccent;

-- Roles are cluster-wide. Hermes marks the roles it creates; an existing role with the same name and without
-- the mark belongs to something else, and provisioning stops instead of granting it access to Hermes.
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['migrator', 'app', 'retention', 'slack_module'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN', r);
      EXECUTE format('COMMENT ON ROLE %I IS %L', r, 'hermes-managed');
    ELSIF shobj_description((SELECT oid FROM pg_roles WHERE rolname = r), 'pg_authid') IS DISTINCT FROM 'hermes-managed' THEN
      RAISE EXCEPTION 'role % already exists and is not managed by Hermes', r;
    END IF;
  END LOOP;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO migrator, app, retention, slack_module', current_database());
END $$;

-- migrator owns the schema (foreign key checks run as the table owner and need USAGE).
ALTER SCHEMA public OWNER TO migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app, retention, slack_module;

-- Functions created by migrator are not executable by PUBLIC (global default, before any migration runs).
ALTER DEFAULT PRIVILEGES FOR ROLE migrator REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
