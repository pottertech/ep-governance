-- EP-Governance proxy database role
-- Creates a dedicated role for the governed proxy to access target databases.
-- The proxy role can connect to target databases but NOT the governance schema.
-- The agent (Mary Wise, Brodie) does NOT have this role — only the proxy does.

-- Create the proxy role (NOLOGIN — credentials injected at deployment)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ep_proxy') THEN
        CREATE ROLE ep_proxy NOLOGIN;
    END IF;
END
$$;

-- Grant the proxy role access to target databases
-- These are the databases the proxy will execute SQL against
GRANT CONNECT ON DATABASE gbrain_pilot_test TO ep_proxy;
GRANT CONNECT ON DATABASE gbrain_pilot TO ep_proxy;
GRANT CONNECT ON DATABASE openclaw TO ep_proxy;

-- Grant schema-level access on target databases
-- (Run these while connected to each target database)
-- GRANT USAGE ON SCHEMA public TO ep_proxy;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ep_proxy;

-- Explicitly deny access to the governance schema
REVOKE ALL ON SCHEMA ep_governance FROM ep_proxy;

-- Create a login role for the proxy with a password
-- IMPORTANT: Change this password before production deployment!
-- In production, use a secret manager or certificate-based auth.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ep_proxy_user') THEN
        CREATE ROLE ep_proxy_user LOGIN PASSWORD 'change_me_in_production'
            IN ROLE ep_proxy;
    END IF;
END
$$;

-- Note: The agent (Mary Wise, Brodie) must NOT have the ep_proxy role
-- and must NOT have the ep_proxy_user credentials.
-- The agent can only reach the target DB through the governed proxy.