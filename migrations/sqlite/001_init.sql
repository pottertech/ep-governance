-- EP-Governance SQLite initial schema migration
-- Version: v1.1.1
-- SQLite equivalent of the PostgreSQL schema.
-- Differences: TEXT for timestamps, TEXT for JSON (JSONB), no GIN indexes,
-- no partial indexes, no per-role permissions.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ============================================================================
-- Core Graph
-- ============================================================================

CREATE TABLE ep_projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'completed', 'archived')),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE ep_lattices (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES ep_projects(id),
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (project_id)
);

CREATE TABLE ep_branches (
    id           TEXT PRIMARY KEY,
    lattice_id   TEXT NOT NULL REFERENCES ep_lattices(id),
    name         TEXT NOT NULL,
    head_node_id TEXT,  -- FK to ep_nodes(id) added via deferred constraint below
    version      INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active', 'merged', 'abandoned')),
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE ep_nodes (
    id                 TEXT PRIMARY KEY,
    branch_id          TEXT NOT NULL REFERENCES ep_branches(id),
    agent_id           TEXT NOT NULL,
    description        TEXT,
    bt_planning_budget REAL CHECK (bt_planning_budget >= 0),
    metadata           TEXT NOT NULL DEFAULT '{}',  -- JSON string
    status             TEXT NOT NULL DEFAULT 'committed'
                           CHECK (status IN ('committed', 'quarantined', 'at_risk', 'superseded', 'archived')),
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    committed_at       TEXT
);

-- Self-referencing FK: ep_branches.head_node_id -> ep_nodes(id)
-- SQLite does not support ALTER TABLE ADD FOREIGN KEY, so we use a PRAGMA
-- deferred foreign key approach. Since SQLite enforces FKs at statement time
-- when foreign_keys=ON, and ep_nodes now exists, we recreate ep_branches
-- is not needed — instead we note that head_node_id FK is enforced by
-- application logic or a trigger. For simplicity, head_node_id has no
-- explicit FK constraint in SQLite (deferred self-reference).

CREATE TABLE ep_edges (
    id                 TEXT PRIMARY KEY,
    upstream_node_id   TEXT NOT NULL REFERENCES ep_nodes(id),
    downstream_node_id TEXT NOT NULL REFERENCES ep_nodes(id),
    edge_type          TEXT NOT NULL CHECK (edge_type IN ('dependency', 'establishes', 'requires', 'conflicts_with')),
    weight             REAL NOT NULL DEFAULT 1.0,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (upstream_node_id <> downstream_node_id)
);

CREATE INDEX idx_ep_edges_upstream   ON ep_edges (upstream_node_id);
CREATE INDEX idx_ep_edges_downstream ON ep_edges (downstream_node_id);

-- ============================================================================
-- Identity
-- ============================================================================

CREATE TABLE ep_principals (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    type          TEXT NOT NULL CHECK (type IN ('human', 'agent', 'service', 'proxy')),
    machine       TEXT,
    description   TEXT,
    status        TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'suspended', 'revoked')),
    registered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE ep_roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    permissions TEXT NOT NULL DEFAULT '[]'  -- JSON string
);

CREATE TABLE ep_role_bindings (
    id           TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES ep_principals(id),
    role_id      TEXT NOT NULL REFERENCES ep_roles(id),
    project_id   TEXT REFERENCES ep_projects(id),
    bound_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE ep_credentials (
    id              TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL REFERENCES ep_principals(id),
    credential_type TEXT NOT NULL CHECK (credential_type IN ('api_key', 'enrollment_token', 'tls_cert')),
    credential_hash TEXT NOT NULL,
    expires_at      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Policies
-- ============================================================================

CREATE TABLE ep_policies (
    id                 TEXT PRIMARY KEY,
    created_by         TEXT NOT NULL REFERENCES ep_principals(id),
    scope              TEXT NOT NULL CHECK (scope IN ('global', 'agent')),
    agent_scope        TEXT REFERENCES ep_principals(id),
    effect             TEXT NOT NULL CHECK (effect IN ('deny', 'require_approval', 'warn', 'allow')),
    actions            TEXT NOT NULL DEFAULT '[]',   -- JSON string
    resources          TEXT NOT NULL DEFAULT '[]',   -- JSON string
    conditions         TEXT NOT NULL DEFAULT '{}',   -- JSON string
    priority           INTEGER NOT NULL DEFAULT 0 CHECK (priority >= 0),
    description        TEXT,
    status             TEXT NOT NULL DEFAULT 'draft'
                           CHECK (status IN ('draft', 'pending_approval', 'active', 'rejected', 'superseded', 'retired')),
    supersedes         TEXT REFERENCES ep_policies(id),
    policy_version     INTEGER NOT NULL DEFAULT 1,
    established_at     TEXT,
    retired_at         TEXT,
    approved_by        TEXT REFERENCES ep_principals(id),
    approved_at        TEXT,
    activation_version INTEGER,
    exception_to       TEXT NOT NULL DEFAULT '[]',   -- JSON string
    valid_from         TEXT,
    valid_until        TEXT,
    justification      TEXT,
    origin             TEXT NOT NULL DEFAULT 'local',
    trust_status       TEXT NOT NULL DEFAULT 'trusted',
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- No GIN in SQLite — regular index on actions (limited utility for JSON text)
CREATE INDEX idx_ep_policies_actions      ON ep_policies (actions);
CREATE INDEX idx_ep_policies_status_scope ON ep_policies (status, scope, agent_scope);

-- ============================================================================
-- Transitions
-- ============================================================================

CREATE TABLE ep_transitions (
    id                            TEXT PRIMARY KEY,
    agent_id                      TEXT NOT NULL REFERENCES ep_principals(id),
    branch_id                     TEXT NOT NULL REFERENCES ep_branches(id),
    from_node_id                  TEXT REFERENCES ep_nodes(id),
    to_node_id                    TEXT REFERENCES ep_nodes(id),
    tool                          TEXT NOT NULL,
    arguments                     TEXT NOT NULL DEFAULT '{}',   -- JSON string
    payload_hash                  TEXT NOT NULL,
    classification                TEXT NOT NULL DEFAULT '{}',   -- JSON string
    risk_assessments              TEXT NOT NULL DEFAULT '{}',   -- JSON string
    residual_risk_after           TEXT,                         -- JSON string, nullable
    verification_result           TEXT NOT NULL DEFAULT 'pending_approval'
                                      CHECK (verification_result IN ('admissible', 'denied', 'pending_approval', 'resource_exhausted')),
    pulse_trace                   TEXT NOT NULL DEFAULT '[]',   -- JSON string
    matched_policies              TEXT NOT NULL DEFAULT '[]',   -- JSON string
    stage                         TEXT NOT NULL DEFAULT 'proposed'
                                      CHECK (stage IN ('proposed', 'pending_approval', 'authorized', 'executing', 'succeeded', 'failed', 'execution_uncertain', 'cancelled', 'expired', 'denied')),
    expected_head_id              TEXT,
    expected_version              INTEGER,
    idempotency_key               TEXT NOT NULL,
    executor_id                   TEXT REFERENCES ep_principals(id),
    execution_started_at          TEXT,
    execution_completed_at        TEXT,
    exit_status                   TEXT CHECK (exit_status IN ('success', 'failure', 'timeout')),
    result_summary                TEXT,
    execution_attempt_id          TEXT,
    requires_manual_reconciliation INTEGER NOT NULL DEFAULT 0,  -- SQLite uses 0/1 for BOOLEAN
    action                        TEXT,                         -- classified action type
    resource                      TEXT,                         -- classified resource
    payload                       TEXT NOT NULL DEFAULT '{}',   -- JSON string, canonical arguments
    bt_planning_budget_before     REAL,
    bt_planning_budget_after      REAL,
    policy_set_hash               TEXT,
    matched_policy_versions       TEXT NOT NULL DEFAULT '{}',   -- JSON string
    updated_at                    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_at                    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX idx_ep_transitions_idempotency ON ep_transitions (idempotency_key);
CREATE INDEX idx_ep_transitions_agent  ON ep_transitions (agent_id, created_at DESC);
CREATE INDEX idx_ep_transitions_branch ON ep_transitions (branch_id, created_at DESC);

-- ============================================================================
-- Authorizations
-- ============================================================================

CREATE TABLE ep_authorizations (
    id                      TEXT PRIMARY KEY,
    transition_id           TEXT NOT NULL REFERENCES ep_transitions(id),
    token_hash              TEXT NOT NULL,
    payload_hash            TEXT NOT NULL,
    policy_set_hash         TEXT NOT NULL,
    matched_policy_versions TEXT NOT NULL DEFAULT '[]',   -- JSON string
    proxy_audience          TEXT,
    agent_id                TEXT NOT NULL REFERENCES ep_principals(id),
    project_id              TEXT NOT NULL REFERENCES ep_projects(id),
    branch_id               TEXT NOT NULL REFERENCES ep_branches(id),
    issued_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at              TEXT NOT NULL,
    used                    INTEGER NOT NULL DEFAULT 0,    -- 0/1 for BOOLEAN
    used_at                 TEXT,
    execution_attempt_id    TEXT,
    tool                    TEXT,
    nonce                   TEXT,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Approvals
-- ============================================================================

CREATE TABLE ep_approval_requests (
    id            TEXT PRIMARY KEY,
    transition_id TEXT NOT NULL REFERENCES ep_transitions(id),
    policy_id     TEXT NOT NULL REFERENCES ep_policies(id),
    requested_by  TEXT NOT NULL REFERENCES ep_principals(id),
    justification TEXT,
    status        TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    decided_at    TEXT,
    decided_by    TEXT REFERENCES ep_principals(id),
    decision      TEXT,
    reason        TEXT,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE ep_approval_decisions (
    id                  TEXT PRIMARY KEY,
    approval_request_id TEXT NOT NULL REFERENCES ep_approval_requests(id),
    decided_by          TEXT NOT NULL REFERENCES ep_principals(id),
    decision            TEXT NOT NULL CHECK (decision IN ('approved', 'denied')),
    reason              TEXT,
    decided_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Risk
-- ============================================================================

CREATE TABLE ep_risk_ledger (
    id                       TEXT PRIMARY KEY,
    branch_id                TEXT NOT NULL REFERENCES ep_branches(id),
    risk_domain              TEXT NOT NULL
                                 CHECK (risk_domain IN ('production_database', 'external_communications', 'deployment', 'data_privacy', 'security')),
    inherent_risk            REAL NOT NULL,
    residual_risk            REAL NOT NULL,
    required_approval_level  TEXT NOT NULL DEFAULT 'none'
                                 CHECK (required_approval_level IN ('none', 'agent', 'policy_approver', 'human')),
    accepted_by              TEXT REFERENCES ep_principals(id),
    accepted_at              TEXT,
    expiration               TEXT,
    updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE ep_risk_mitigations (
    id              TEXT PRIMARY KEY,
    risk_ledger_id  TEXT NOT NULL REFERENCES ep_risk_ledger(id),
    mitigation_type TEXT NOT NULL,
    credit          REAL NOT NULL,
    evidence        TEXT,
    evidence_type   TEXT,
    evidence_uri    TEXT,
    evidence_hash   TEXT,
    verified_by     TEXT REFERENCES ep_principals(id),
    verified_at     TEXT,
    expires_at      TEXT,
    scope           TEXT,
    applied_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Audit (per v1.1.1 sections 4-5)
-- ============================================================================

CREATE TABLE ep_audit_heads (
    lattice_id    TEXT PRIMARY KEY REFERENCES ep_lattices(id),
    last_sequence INTEGER NOT NULL DEFAULT 0,  -- SQLite INTEGER for BIGINT equivalent
    last_hash     TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
);

CREATE TABLE ep_events (
    id                       TEXT PRIMARY KEY,
    lattice_id               TEXT NOT NULL REFERENCES ep_lattices(id),
    sequence                 INTEGER NOT NULL,  -- SQLite INTEGER for BIGINT equivalent
    event_type               TEXT NOT NULL,
    event_data               TEXT NOT NULL DEFAULT '{}',  -- JSON string
    previous_hash            TEXT,
    event_hash               TEXT NOT NULL,
    actor_principal_id       TEXT REFERENCES ep_principals(id),
    authenticated_caller_id TEXT REFERENCES ep_principals(id),
    event_writer_id          TEXT REFERENCES ep_principals(id),
    created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX idx_ep_events_lattice_seq ON ep_events (lattice_id, sequence);

-- ============================================================================
-- Work Management
-- ============================================================================

CREATE TABLE ep_work_claims (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES ep_principals(id),
    branch_id   TEXT NOT NULL REFERENCES ep_branches(id),
    region      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'completed', 'released')),
    claimed_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    released_at TEXT
);

-- SQLite does not support partial unique indexes (pre-3.8.0), so use a
-- regular unique index on (branch_id, region). Application logic must
-- ensure that only one 'active' claim exists per (branch_id, region).
CREATE UNIQUE INDEX idx_ep_work_claims_branch_region ON ep_work_claims (branch_id, region);

-- ============================================================================
-- Sessions
-- ============================================================================

CREATE TABLE ep_sessions (
    id         TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL REFERENCES ep_principals(id),
    branch_id  TEXT NOT NULL REFERENCES ep_branches(id),
    model_info TEXT,
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ended_at   TEXT
);

-- ============================================================================
-- Transfer
-- ============================================================================

CREATE TABLE ep_transfer_packages (
    id                TEXT PRIMARY KEY,
    lattice_id        TEXT NOT NULL REFERENCES ep_lattices(id),
    schema_version    TEXT NOT NULL,
    package_version   TEXT NOT NULL,
    source_lattice_id TEXT,
    project_id        TEXT NOT NULL REFERENCES ep_projects(id),
    snapshot_sequence INTEGER NOT NULL,
    content_hash      TEXT NOT NULL,
    signature         TEXT NOT NULL,
    signer_id         TEXT NOT NULL REFERENCES ep_principals(id),
    trust_status      TEXT NOT NULL DEFAULT 'trusted'
                          CHECK (trust_status IN ('trusted', 'untrusted', 'imported')),
    lattice_state     TEXT NOT NULL DEFAULT '{}',  -- JSON string
    model_info        TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE ep_import_mappings (
    id                  TEXT PRIMARY KEY,
    source_entity_id    TEXT NOT NULL,
    imported_entity_id  TEXT NOT NULL,
    source_lattice_id   TEXT NOT NULL,
    source_package_id   TEXT NOT NULL,
    entity_type         TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- Policy Versions
-- ============================================================================

CREATE TABLE ep_policy_versions (
    id           TEXT PRIMARY KEY,
    version      INTEGER NOT NULL,
    branch_id    TEXT NOT NULL REFERENCES ep_branches(id),
    policy_count INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);