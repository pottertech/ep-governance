-- Deployment-specific proxy target database grants.
--
-- This is a TEMPLATE, not a migration. Copy this file, replace the
-- placeholders, and run it while connected to the PostgreSQL cluster
-- as a superuser during deployment setup.
--
-- The core migration (003_proxy_role.sql) creates the ep_proxy role
-- without any target database grants. Target database access must be
-- provisioned separately because database names are deployment-specific.
--
-- Usage:
--   psql -f grant-proxy-target.sql -v target_db=your_target_database -v proxy_role=ep_proxy
--
-- Or edit the placeholders below and run directly.

-- Grant CONNECT on the target database (cluster-level)
GRANT CONNECT ON DATABASE :target_db TO :proxy_role;

-- Connect to the target database and grant schema access:
-- \c :target_db
-- GRANT USAGE ON SCHEMA public TO :proxy_role;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :proxy_role;

-- Provision the proxy login credential (use a secret manager in production):
-- CREATE ROLE ep_proxy_runtime LOGIN PASSWORD :'proxy_password'
--     IN ROLE :proxy_role;