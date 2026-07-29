-- EP-Governance database roles and permissions
-- Version: v1.1.1
-- Enforces the immutability of ep_events via database roles (no triggers).
-- Only ep_service can INSERT into ep_events; no role can UPDATE or DELETE.

-- ============================================================================
-- ep_service role: full application access with audit-log protections
-- Security note: roles are created WITHOUT LOGIN passwords.
-- In production, credentials must be injected at deployment time via
-- a secret manager, managed identity, or certificate authentication.
-- A static migration MUST NOT install a working default password.
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ep_service') THEN
        CREATE ROLE ep_service NOLOGIN;
    END IF;
END
$$;

-- Audit tables: ep_events is INSERT/SELECT only (no UPDATE, no DELETE)
GRANT SELECT, INSERT ON ep_events TO ep_service;

-- ep_audit_heads: the service updates the head pointer as it appends events
GRANT SELECT, INSERT, UPDATE ON ep_audit_heads TO ep_service;

-- All other EP tables: full CRUD for the service role
GRANT ALL ON
    ep_projects,
    ep_lattices,
    ep_branches,
    ep_nodes,
    ep_edges,
    ep_policies,
    ep_principals,
    ep_roles,
    ep_role_bindings,
    ep_credentials,
    ep_transitions,
    ep_authorizations,
    ep_approval_requests,
    ep_approval_decisions,
    ep_risk_ledger,
    ep_risk_mitigations,
    ep_work_claims,
    ep_sessions,
    ep_transfer_packages,
    ep_import_mappings,
    ep_policy_versions
TO ep_service;

-- Grant sequence usage (for any SERIAL/BIGSERIAL columns if added later)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ep_service;

-- ============================================================================
-- ep_agent role: read-only access to a limited set of tables
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ep_agent') THEN
        CREATE ROLE ep_agent NOLOGIN;
    END IF;
END
$$;

-- Read-only on a small subset of governance tables
GRANT SELECT ON ep_policies    TO ep_agent;
GRANT SELECT ON ep_transitions TO ep_agent;
GRANT SELECT ON ep_branches    TO ep_agent;
GRANT SELECT ON ep_nodes       TO ep_agent;

-- Explicitly NO privileges on ep_events (no INSERT, UPDATE, DELETE, or even SELECT)
-- ep_agent has no grant on ep_events at all.
REVOKE ALL ON ep_events FROM ep_agent;

-- Ensure ep_agent has no privileges on other audit / internal tables
REVOKE ALL ON ep_audit_heads        FROM ep_agent;
REVOKE ALL ON ep_authorizations     FROM ep_agent;
REVOKE ALL ON ep_approval_requests  FROM ep_agent;
REVOKE ALL ON ep_approval_decisions FROM ep_agent;
REVOKE ALL ON ep_risk_ledger        FROM ep_agent;
REVOKE ALL ON ep_risk_mitigations   FROM ep_agent;
REVOKE ALL ON ep_work_claims        FROM ep_agent;
REVOKE ALL ON ep_sessions           FROM ep_agent;
REVOKE ALL ON ep_transfer_packages  FROM ep_agent;
REVOKE ALL ON ep_import_mappings    FROM ep_agent;
REVOKE ALL ON ep_policy_versions    FROM ep_agent;
REVOKE ALL ON ep_projects           FROM ep_agent;
REVOKE ALL ON ep_lattices           FROM ep_agent;
REVOKE ALL ON ep_edges              FROM ep_agent;
REVOKE ALL ON ep_principals         FROM ep_agent;
REVOKE ALL ON ep_roles              FROM ep_agent;
REVOKE ALL ON ep_role_bindings      FROM ep_agent;
REVOKE ALL ON ep_credentials        FROM ep_agent;