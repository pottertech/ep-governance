-- EP-Governance proxy database role
-- Creates a dedicated role for the governed proxy to access target databases.
-- The proxy role can connect to target databases but NOT the governance schema.
-- The agent does NOT have this role — only the proxy does.

-- Create the proxy role (NOLOGIN — credentials injected at deployment)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ep_proxy') THEN
        CREATE ROLE ep_proxy NOLOGIN;
    END IF;
END
$$;

-- Grant schema-level access on target databases
-- Target database CONNECT grants must be provisioned separately by the
-- deployment installer, because database names are deployment-specific.
-- See: deployment/examples/grant-proxy-target.sql for a template.
--
-- Example (run while connected to each target database):
--   GRANT CONNECT ON DATABASE <TARGET_DATABASE> TO ep_proxy;
--   GRANT USAGE ON SCHEMA public TO ep_proxy;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ep_proxy;

-- Explicitly deny access to the governance schema
REVOKE ALL ON SCHEMA ep_governance FROM ep_proxy;

-- Create a login role for the proxy (NOLOGIN by default).
-- The actual login credential must be provisioned separately through a
-- secret manager, certificate-based auth, or a deployment tool:
--
--   CREATE ROLE ep_proxy_runtime LOGIN PASSWORD :'proxy_password'
--       IN ROLE ep_proxy;
--
-- Do NOT create a login role with a default password in the migration.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ep_proxy_user') THEN
        CREATE ROLE ep_proxy_user NOLOGIN IN ROLE ep_proxy;
    END IF;
END
$$;

-- Note: The agent must NOT have the ep_proxy role and must NOT have
-- the ep_proxy_user credentials. The agent can only reach the target
-- DB through the governed proxy.