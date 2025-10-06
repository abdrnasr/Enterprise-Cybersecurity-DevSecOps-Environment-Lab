-- === Create application role/user ===
-- Change this password before using in production.
CREATE ROLE sonarqube WITH LOGIN PASSWORD 'change_me_sonar_user' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

-- === Ensure we are operating in the sonarqube database ===
-- docker sets POSTGRES_DB=sonarqube; connect and configure there.
\connect sonarqube

-- === Create a dedicated schema (not "public") and own it by sonarqube ===
CREATE SCHEMA IF NOT EXISTS sonar AUTHORIZATION sonarqube;

-- Optionally lock down "public" if you don't want general write access:
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE USAGE  ON SCHEMA public FROM PUBLIC;

-- === Search path so the custom schema is used transparently ===
-- Set at the database level (safe default) and for the role (extra safety).
ALTER DATABASE sonarqube SET search_path = sonar, public;
ALTER ROLE sonarqube SET search_path = sonar, public;

-- === Privileges for the sonarqube role on the custom schema ===
-- If the role owns the schema, it already has CREATE/USAGE, but we grant explicitly.
GRANT USAGE, CREATE ON SCHEMA sonar TO sonarqube;

-- Existing objects (none yet, but included for completeness):
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sonar TO sonarqube;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA sonar TO sonarqube;

-- Future objects: make sure new tables/sequences are granted automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA sonar GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sonarqube;
ALTER DEFAULT PRIVILEGES IN SCHEMA sonar GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO sonarqube;

-- (Optional) Let sonarqube create extensions if you plan to use any:
-- GRANT CREATE ON DATABASE sonarqube TO sonarqube;

-- (Optional) Tighter DB-level access:
GRANT CONNECT ON DATABASE sonarqube TO sonarqube;
