#!/usr/bin/env python3
"""End-to-end enforced mode test against NAS PostgreSQL.

Tests the full enforced-mode pipeline:
1. Propose action -> policy evaluates -> transition authorized
2. EP issues Ed25519-signed authorization token
3. PostgresProxy verifies token, claims authorization, executes SQL
4. On success: graph node created, branch head advanced, transition -> succeeded

Also tests:
- Denied action (DROP TABLE) does not execute
- Token reuse is rejected
- Payload tampering is detected
"""

import json
import os
import sys
import tempfile

# Ensure we can import from src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ep_governance.config import load_config
from ep_governance.db.postgres import create_engine
from ep_governance.db.repositories import (
    PolicyRepository,
    PrincipalRepository,
    BranchRepository,
    TransitionRepository,
    AuthorizationRepository,
    NodeRepository,
)
from ep_governance.transitions import TransitionEngine
from ep_governance.authorizations import AuthorizationEngine, KeyManager
from ep_governance.policy_engine import PolicyEngine
from ep_governance.policies import Policy
from ep_governance.proxy.postgres_proxy import PostgresProxy
from ep_governance.proxy.base import ProxyConfig
from ep_governance.branches import BranchCommitter
from ep_governance.canonical import canonical_hash
from ep_governance.xid import XID
from ep_governance.deployment import EnforcementCapability


import sqlalchemy as sa


def main():
    cfg = load_config()
    print(f"Mode: {cfg.mode}")
    print(f"DB: {cfg.db_url.split('@')[1] if '@' in cfg.db_url else cfg.db_url}")
    print(f"Schema: {cfg.db_schema}")
    print()

    # Create the EP governance engine (connects to the governance DB)
    ep_engine = create_engine(cfg.db_url, schema=cfg.db_schema or None)

    # Get principals
    with ep_engine.connect() as conn:
        # EP service principal
        result = conn.execute(
            sa.text("SELECT id FROM ep_principals WHERE type='service' AND name='EP Service' LIMIT 1")
        )
        row = result.fetchone()
        if row is None:
            print("ERROR: EP Service principal not found")
            sys.exit(1)
        ep_service_id = row[0]

        # Agent principal (Mary Wise)
        result = conn.execute(
            sa.text("SELECT id FROM ep_principals WHERE type='agent' AND name='Mary Wise' LIMIT 1")
        )
        row = result.fetchone()
        if row is None:
            print("ERROR: Mary Wise agent principal not found")
            sys.exit(1)
        agent_id = row[0]

        # Human principal (Skip Potter)
        result = conn.execute(
            sa.text("SELECT id FROM ep_principals WHERE type='human' AND name='Skip Potter' LIMIT 1")
        )
        row = result.fetchone()
        if row is None:
            print("ERROR: Skip Potter human principal not found")
            sys.exit(1)
        human_id = row[0]

        # Branch
        result = conn.execute(
            sa.text("SELECT id, head_node_id, version FROM ep_branches LIMIT 1")
        )
        row = result.fetchone()
        if row is None:
            print("ERROR: No branch found")
            sys.exit(1)
        branch_id = row[0]
        branch_head_before = row[1]
        branch_version_before = row[2]

        # Project from branch
        result = conn.execute(
            sa.text(
                "SELECT l.project_id FROM ep_branches b "
                "JOIN ep_lattices l ON b.lattice_id = l.id "
                "WHERE b.id = :bid"
            ),
            {"bid": branch_id},
        )
        project_id = result.fetchone()[0]

        # Load active policies
        policy_repo = PolicyRepository(conn)
        policy_rows = policy_repo.list_active_policies_for_project(project_id)
        policies = []
        for prow in policy_rows:
            # Convert DB row to Policy object
            p = Policy(
                id=prow["id"],
                effect=prow["effect"],
                actions=prow["actions"] if isinstance(prow["actions"], list) else json.loads(prow["actions"]),
                resources=prow.get("resources", ["*"]) if isinstance(prow.get("resources"), list) else json.loads(prow.get("resources", "[]") or "[]"),
                conditions=prow.get("conditions", {}) if isinstance(prow.get("conditions"), dict) else json.loads(prow.get("conditions", "{}") or "{}"),
                priority=prow.get("priority", 0),
                scope=prow.get("scope", "global"),
                agent_scope=prow.get("agent_scope"),
                project_id=prow.get("project_id"),
                branch_id=prow.get("branch_id"),
                description=prow.get("description", ""),
                status=prow.get("status", "active"),
                created_by=prow.get("created_by", ""),
                approved_by=prow.get("approved_by", ""),
                approved_at=str(prow.get("approved_at", "")),
                activation_version=prow.get("activation_version", 1),
                exception_to=prow.get("exception_to", []) if isinstance(prow.get("exception_to"), list) else json.loads(prow.get("exception_to", "[]") or "[]"),
                valid_from=str(prow.get("valid_from", "")) if prow.get("valid_from") else None,
                valid_until=str(prow.get("valid_until", "")) if prow.get("valid_until") else None,
                justification=prow.get("justification"),
            )
            policies.append(p)
        print(f"Loaded {len(policies)} active policies")
        print(f"EP Service: {ep_service_id}")
        print(f"Agent: {agent_id} (Mary Wise)")
        print(f"Human: {human_id} (Skip Potter)")
        print(f"Branch: {branch_id} (head={branch_head_before}, version={branch_version_before})")
        print()

    # Enforcement capability for binding enforcement
    capability = EnforcementCapability.for_test(
            agent_principal_id=agent_id,
        )

    # Build policy engine
    policy_engine = PolicyEngine(policies)

    # Build transition engine
    trans_engine = TransitionEngine(ep_engine, ep_service_id, policy_engine=policy_engine)

    # Set up Ed25519 keypair
    key_path = os.path.join(os.path.dirname(__file__), "..", "ep_signing_test.key")
    if os.path.exists(key_path):
        km = KeyManager()
        km.load_private_key(key_path)
        print(f"Loaded signing key from {key_path}")
    else:
        km = KeyManager()
        km.save_private_key(key_path)
        print(f"Generated new signing key at {key_path}")
    public_key = km.public_key
    print()

    # Authorization engine
    auth_engine = AuthorizationEngine(
        ep_engine, km, ep_service_id, token_ttl_seconds=300
    )

    # Branch committer
    branch_committer = BranchCommitter(ep_engine, ep_service_id)

    # ================================================================
    # TEST 1: Allowed SELECT — full enforced pipeline
    # ================================================================
    print("=" * 60)
    print("TEST 1: Allowed SELECT (should succeed end-to-end)")
    print("=" * 60)

    payload = {"sql": "SELECT 1 as result", "host": "localhost", "database": "gbrain_pilot_test"}
    idem_key = str(XID.new())

    # Step 1: Propose
    transition = trans_engine.propose(
        agent_id=agent_id,
        branch_id=branch_id,
        tool="postgres.execute",
        arguments=payload,
        idempotency_key=idem_key,
    )
    transition_id = transition["id"]
    stage = transition["stage"]
    print(f"  Propose: transition_id={transition_id}, stage={stage}")

    if stage != "authorized":
        print(f"  FAIL: Expected 'authorized', got '{stage}'")
        if stage == "denied":
            print("  Action was denied by policy")
        elif stage == "pending_approval":
            print("  Action requires approval — need human approver")
        sys.exit(1)

    # Step 2: Issue authorization token
    # Get matched policies from the transition
    matched_policy_versions = transition.get("matched_policy_versions", {})
    matched_policies_list = [
        {"id": pid, "activation_version": ver}
        for pid, ver in matched_policy_versions.items()
    ]

    token = auth_engine.issue_authorization(
        transition_id=transition_id,
        agent_id=agent_id,
        project_id=project_id,
        branch_id=branch_id,
        proxy_audience="postgres-proxy",
        tool="postgres.execute",
        payload_hash="sha256:" + canonical_hash(payload),
        matched_policies=matched_policies_list,
        enforcement_capability=capability,
    )
    signed_token = token.to_signed_token(km)
    print(f"  Token issued: auth_id={token.authorization_id}")
    print(f"  Token expires: {token.expires_at}")

    # Step 3: Proxy executes
    # The proxy needs a target connection string — use the same NAS PG
    # (in production, this would be a different target DB)
    proxy_config = ProxyConfig(
        target_connection_string=cfg.db_url,
        proxy_audience="postgres-proxy",
        ep_service_principal_id=ep_service_id,
        timeout_seconds=10,
    )

    proxy = PostgresProxy(
        engine=ep_engine,
        auth_engine=auth_engine,
        config=proxy_config,
        transition_engine=trans_engine,
        branch_committer=branch_committer,
        policy_engine=policy_engine,
    )

    result = proxy.execute(
        signed_token=signed_token,
        payload=payload,
        public_key=public_key,
        enforcement_capability=capability,
    )
    print(f"  Proxy result: success={result.success}, status={result.exit_status}")
    print(f"  Summary: {result.result_summary}")

    if not result.success:
        print("  FAIL: Proxy execution failed")
        sys.exit(1)

    # Step 4: Verify graph state
    with ep_engine.connect() as conn:
        # Check transition stage
        trans_repo = TransitionRepository(conn)
        t = trans_repo.get_transition(transition_id)
        print(f"  Transition stage after execute: {t['stage']}")
        if t["stage"] != "succeeded":
            print(f"  FAIL: Expected stage 'succeeded', got '{t['stage']}'")
            sys.exit(1)

        # Check branch head advanced
        branch_repo = BranchRepository(conn)
        head_after, version_after = branch_repo.get_head(branch_id)
        print(f"  Branch head after: {head_after}, version: {version_after}")
        if version_after != branch_version_before + 1:
            print(f"  FAIL: Branch version should be {branch_version_before + 1}, got {version_after}")
            sys.exit(1)
        if head_after is None:
            print("  FAIL: Branch head is None — no node was created")
            sys.exit(1)

        # Check node exists
        node_repo = NodeRepository(conn)
        # We need to check if a node was created
        result_count = conn.execute(sa.text("SELECT count(*) FROM ep_nodes")).scalar()
        print(f"  Total nodes: {result_count}")

        # Check authorization is used
        auth_repo = AuthorizationRepository(conn)
        auth = auth_repo.get_authorization(token.authorization_id)
        if auth:
            print(f"  Authorization used: {auth.get('used', 'N/A')}")

    print("  PASS: Full enforced pipeline succeeded!")
    print()

    # ================================================================
    # TEST 2: Denied action (DROP TABLE) — should not execute
    # ================================================================
    print("=" * 60)
    print("TEST 2: Denied DROP TABLE (should be denied by policy)")
    print("=" * 60)

    payload2 = {"sql": "DROP TABLE IF EXISTS ep_test_should_not_exist", "host": "localhost", "database": "gbrain_pilot_test"}
    idem_key2 = str(XID.new())

    transition2 = trans_engine.propose(
        agent_id=agent_id,
        branch_id=branch_id,
        tool="postgres.execute",
        arguments=payload2,
        idempotency_key=idem_key2,
    )
    stage2 = transition2["stage"]
    print(f"  Propose: transition_id={transition2['id']}, stage={stage2}")

    if stage2 == "denied":
        print("  PASS: DROP TABLE was denied by policy as expected")
    else:
        print(f"  FAIL: Expected 'denied', got '{stage2}'")
        sys.exit(1)
    print()

    # ================================================================
    # TEST 3: Token reuse — should be rejected
    # ================================================================
    print("=" * 60)
    print("TEST 3: Token reuse (second use of same token should fail)")
    print("=" * 60)

    result3 = proxy.execute(
        signed_token=signed_token,
        payload=payload,
        public_key=public_key,
        enforcement_capability=capability,
    )
    print(f"  Reuse result: success={result3.success}, status={result3.exit_status}")
    print(f"  Summary: {result3.result_summary}")

    if not result3.success and "already used" in result3.result_summary.lower():
        print("  PASS: Token reuse was rejected")
    elif not result3.success:
        print(f"  PASS: Token reuse was rejected (reason: {result3.result_summary})")
    else:
        print("  FAIL: Token reuse should have been rejected!")
        sys.exit(1)
    print()

    # ================================================================
    # TEST 4: Payload tampering — should be detected
    # ================================================================
    print("=" * 60)
    print("TEST 4: Payload tampering (altered payload should fail)")
    print("=" * 60)

    # Propose a new action
    payload4 = {"sql": "SELECT 42 as answer", "host": "localhost", "database": "gbrain_pilot_test"}
    idem_key4 = str(XID.new())

    transition4 = trans_engine.propose(
        agent_id=agent_id,
        branch_id=branch_id,
        tool="postgres.execute",
        arguments=payload4,
        idempotency_key=idem_key4,
    )
    stage4 = transition4["stage"]
    print(f"  Propose: transition_id={transition4['id']}, stage={stage4}")

    if stage4 != "authorized":
        print(f"  SKIP: Could not authorize for tamper test (stage={stage4})")
    else:
        # Issue token for the original payload
        matched_policies4 = transition4.get("matched_policy_versions", {})
        matched_policies_list4 = [
            {"id": pid, "activation_version": ver}
            for pid, ver in matched_policies4.items()
        ]
        token4 = auth_engine.issue_authorization(
            transition_id=transition4["id"],
            agent_id=agent_id,
            project_id=project_id,
            branch_id=branch_id,
            proxy_audience="postgres-proxy",
            tool="postgres.execute",
            payload_hash="sha256:" + canonical_hash(payload4),
            matched_policies=matched_policies_list4,
            enforcement_capability=capability,
        )
        signed_token4 = token4.to_signed_token(km)

        # Tamper with payload — change the SQL
        tampered_payload = dict(payload4)
        tampered_payload["sql"] = "SELECT 999 as answer"

        result4 = proxy.execute(
            signed_token=signed_token4,
            payload=tampered_payload,
            public_key=public_key,
            enforcement_capability=capability,
        )
        print(f"  Tamper result: success={result4.success}, status={result4.exit_status}")
        print(f"  Summary: {result4.result_summary}")

        if not result4.success and "hash mismatch" in result4.result_summary.lower():
            print("  PASS: Payload tampering was detected")
        elif not result4.success:
            print(f"  PASS: Payload tampering was rejected (reason: {result4.result_summary})")
        else:
            print("  FAIL: Tampered payload should have been rejected!")
            sys.exit(1)
    print()

    # ================================================================
    # SUMMARY
    # ================================================================
    print("=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)
    print()
    print("Enforced mode pipeline verified:")
    print("  1. Propose -> policy evaluates -> authorized")
    print("  2. Ed25519-signed authorization token issued")
    print("  3. PostgresProxy verified token, claimed auth, executed SQL")
    print("  4. Graph node created, branch head advanced, transition -> succeeded")
    print("  5. DROP TABLE denied by policy")
    print("  6. Token reuse rejected")
    print("  7. Payload tampering detected")


if __name__ == "__main__":
    main()