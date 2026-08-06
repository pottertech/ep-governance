#!/usr/bin/env python3
"""EP-Governance controlled trial — daily health check + governed action exercise.

Runs daily via cron. Performs:
1. Audit chain integrity verification
2. Proposes and executes a governed SELECT through the proxy
3. Verifies the transition reached 'succeeded'
4. Verifies a graph node was created and branch head advanced
5. Verifies the audit chain remains valid after execution
6. Reports any issues

Configuration via environment variables:
- EP_PROXY_URL: Proxy endpoint URL (required for execution)
- EP_PROXY_ATTESTATION_PATH: Path to signed attestation JSON (required)
- EP_CONTROLLER_PUBLIC_KEY: Hex-encoded Ed25519 public key of the deployment controller (required)
- EP_SIGNING_KEY_FILE: Path to the EP signing key (required, no default)
- EP_AGENT_ID: Agent principal XID (optional, defaults to first agent in DB)
- EP_SERVICE_ID: EP service principal XID (optional, defaults to first service in DB)
- EP_BRANCH_ID: Branch XID (optional, defaults to first branch)

Outputs to stdout (captured by cron). Silent on success, verbose on failure.
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ep_governance.config import load_config
from ep_governance.db.postgres import create_engine
from ep_governance.db.repositories import (
    PolicyRepository,
    BranchRepository,
    TransitionRepository,
    NodeRepository,
)
from ep_governance.transitions import TransitionEngine
from ep_governance.authorizations import AuthorizationEngine, KeyManager
from ep_governance.deployment import EnforcementCapability
from ep_governance.policy_engine import PolicyEngine
from ep_governance.policies import Policy
from ep_governance.canonical import canonical_hash
from ep_governance.audit import AuditVerifier
from ep_governance.xid import XID
import sqlalchemy as sa


def _lookup_entity(conn, query, params, description):
    """Look up a single entity, returning (value, error_message)."""
    row = conn.execute(sa.text(query), params).fetchone()
    if row is None:
        return None, f"{description} not found in database"
    return row[0], None


def main():
    cfg = load_config()
    engine = create_engine(cfg.db_url, schema=cfg.db_schema or None)

    issues = []

    # --- 1. Audit chain verification ---
    lattice_id = None
    with engine.connect() as conn:
        result = conn.execute(sa.text(
            "SELECT lattice_id FROM ep_audit_heads ORDER BY last_sequence DESC LIMIT 1"
        ))
        row = result.fetchone()
        if row is None:
            issues.append("No audit heads found — audit chain cannot be verified")
            _report(issues)
            return
        lattice_id = row[0]
        verifier = AuditVerifier(engine)
        if not verifier.verify(lattice_id):
            issues.append(f"Audit chain INVALID for lattice {lattice_id}")
            _report(issues)
            return

    # --- 2. Load signing key (must be explicitly configured) ---
    key_path = os.environ.get("EP_SIGNING_KEY_FILE")
    if not key_path:
        issues.append("EP_SIGNING_KEY_FILE not configured — operational trial must not use a test key")
        _report(issues)
        return
    if not os.path.exists(key_path):
        issues.append(f"Signing key not found at {key_path}")
        _report(issues)
        return
    km = KeyManager()
    km.load_private_key(key_path)

    # --- 3. Load signed attestation for enforcement capability ---
    attestation_path = os.environ.get("EP_PROXY_ATTESTATION_PATH", "")
    controller_key_hex = os.environ.get("EP_CONTROLLER_PUBLIC_KEY", "")

    if not attestation_path:
        issues.append("EP_PROXY_ATTESTATION_PATH not configured — cannot create production capability")
        _report(issues)
        return

    if not controller_key_hex:
        issues.append("EP_CONTROLLER_PUBLIC_KEY not configured — cannot verify attestation")
        _report(issues)
        return

    if not os.path.exists(attestation_path):
        issues.append(f"Attestation file not found: {attestation_path}")
        _report(issues)
        return

    # --- 4. Get entities (parameterized, fail-safe) ---
    with engine.connect() as conn:
        # EP service ID
        ep_service_id = os.environ.get("EP_SERVICE_ID")
        if not ep_service_id:
            ep_service_id, err = _lookup_entity(
                conn,
                "SELECT id FROM ep_principals WHERE type='service' AND name='EP Service' LIMIT 1",
                {},
                "EP Service principal",
            )
            if err:
                issues.append(err)
                _report(issues)
                return

        # Agent ID
        agent_id = os.environ.get("EP_AGENT_ID")
        if not agent_id:
            agent_id, err = _lookup_entity(
                conn,
                "SELECT id FROM ep_principals WHERE type='agent' LIMIT 1",
                {},
                "Agent principal",
            )
            if err:
                issues.append(err)
                _report(issues)
                return

        # Branch ID
        branch_id = os.environ.get("EP_BRANCH_ID")
        if not branch_id:
            branch_id, err = _lookup_entity(
                conn,
                "SELECT id FROM ep_branches LIMIT 1",
                {},
                "Branch",
            )
            if err:
                issues.append(err)
                _report(issues)
                return

        # Project ID from branch
        project_id, err = _lookup_entity(
            conn,
            "SELECT l.project_id FROM ep_branches b "
            "JOIN ep_lattices l ON b.lattice_id = l.id WHERE b.id = :bid",
            {"bid": branch_id},
            "Project for branch",
        )
        if err:
            issues.append(err)
            _report(issues)
            return

        # --- 5. Load policies (fail on parse errors, don't silently drop) ---
        rows = PolicyRepository(conn).list_active_policies_for_project(project_id)
        policies = []
        policy_errors = []
        for r in rows:
            try:
                actions = r.get("actions", [])
                if isinstance(actions, str): actions = json.loads(actions)
                resources = r.get("resources", [])
                if isinstance(resources, str): resources = json.loads(resources)
                conditions = r.get("conditions", {})
                if isinstance(conditions, str): conditions = json.loads(conditions)
                exception_to = r.get("exception_to", [])
                if isinstance(exception_to, str): exception_to = json.loads(exception_to)
                policies.append(Policy(
                    id=r["id"], effect=r["effect"], actions=actions, resources=resources,
                    conditions=conditions, priority=r.get("priority", 0),
                    scope=r.get("scope", "global"), agent_scope=r.get("agent_scope"),
                    project_id=r.get("project_id"), branch_id=r.get("branch_id"),
                    description=r.get("description", ""), status=r.get("status", "active"),
                    created_by=r.get("created_by", ""), approved_by=r.get("approved_by", ""),
                    approved_at=str(r.get("approved_at", "")),
                    activation_version=r.get("activation_version", 1),
                    exception_to=exception_to,
                    valid_from=str(r["valid_from"]) if r.get("valid_from") else None,
                    valid_until=str(r["valid_until"]) if r.get("valid_until") else None,
                    justification=r.get("justification"),
                ))
            except Exception as exc:
                policy_errors.append(f"Policy {r.get('id', '<unknown>')} parse error: {exc}")

        if policy_errors:
            for pe in policy_errors:
                issues.append(pe)
            _report(issues)
            return

    # --- 6. Record branch head before execution (for later verification) ---
    with engine.connect() as conn:
        branch_repo = BranchRepository(conn)
        head_before, version_before = branch_repo.get_head(branch_id)

    # --- 7. Load attestation and create production enforcement capability ---
    proxy_audience = os.environ.get("EP_PROXY_AUDIENCE", "postgres-proxy")
    proxy_principal_id = os.environ.get("EP_PROXY_PRINCIPAL_ID", "")
    deployment_id = os.environ.get("EP_DEPLOYMENT_ID", "")
    target_id = os.environ.get("EP_TARGET_ID", "")

    try:
        with open(attestation_path) as f:
            attestation_json = f.read()

        from nacl.signing import VerifyKey
        controller_key = VerifyKey(bytes.fromhex(controller_key_hex))

        capability = EnforcementCapability.from_signed_attestation(
            attestation=attestation_json,
            trusted_public_key=controller_key,
            expected_proxy_audience=proxy_audience or None,
            expected_proxy_principal_id=proxy_principal_id or None,
            expected_deployment_id=deployment_id or None,
            expected_target_id=target_id or None,
        )

        # Verify the capability supports the tool we're about to use
        if not capability.supports_action_type("postgres.execute"):
            issues.append(
                f"Capability does not support postgres.execute. "
                f"Supported: {capability.supported_action_types}"
            )
            _report(issues)
            return
    except Exception as exc:
        issues.append(f"Failed to load/verify attestation: {exc}")
        _report(issues)
        return

    # --- 8. Propose + execute a governed SELECT ---
    pe = PolicyEngine(policies)
    te = TransitionEngine(engine, ep_service_id, policy_engine=pe)
    ae = AuthorizationEngine(engine, km, ep_service_id)

    import time as _time
    payload = {"sql": f"SELECT {int(_time.time())} as trial_check", "host": "configured", "database": "configured"}
    transition = te.propose(
        agent_id=agent_id, branch_id=branch_id, tool="postgres.execute",
        arguments=payload, idempotency_key=str(XID.new()),
    )

    if transition["stage"] != "authorized":
        issues.append(f"Trial SELECT not authorized: stage={transition['stage']}")
        _report(issues)
        return

    mpv = transition.get("matched_policy_versions", {})
    token = ae.issue_authorization(
        transition_id=transition["id"], agent_id=agent_id,
        project_id=project_id, branch_id=branch_id,
        proxy_audience=proxy_audience, tool="postgres.execute",
        payload_hash="sha256:" + canonical_hash(payload),
        matched_policies=[{"id": k, "activation_version": v} for k, v in mpv.items()],
        enforcement_capability=capability,
    )
    signed = token.to_signed_token(km)

    proxy_url = os.environ.get("EP_PROXY_URL")
    if not proxy_url:
        issues.append("EP_PROXY_URL not configured — cannot execute trial")
        _report(issues)
        return

    req = urllib.request.Request(proxy_url,
        data=json.dumps({"signed_token": signed, "payload": payload}).encode(),
        headers={"Content-Type": "application/json"})

    proxy_success = False
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
        if not result.get("success"):
            issues.append(f"Proxy execution failed: {result.get('result_summary', 'unknown')}")
        else:
            proxy_success = True
    except Exception as exc:
        issues.append(f"Proxy request failed: {exc}")

    # --- 9. Verify governance graph completion ---
    if proxy_success:
        transition_id = transition["id"]
        with engine.connect() as conn:
            # Check transition reached 'succeeded'
            trans_repo = TransitionRepository(conn)
            t = trans_repo.get_transition(transition_id)
            if t is None:
                issues.append(f"Transition {transition_id} not found after execution")
            elif t["stage"] != "succeeded":
                issues.append(f"Transition stage is '{t['stage']}', expected 'succeeded'")

            # Check branch head advanced
            branch_repo = BranchRepository(conn)
            head_after, version_after = branch_repo.get_head(branch_id)
            if head_after is None:
                issues.append("Branch head is None — no node was created")
            elif version_after <= version_before:
                issues.append(
                    f"Branch version should be > {version_before}, got {version_after}"
                )
            else:
                # Verify the result node belongs to this transition.
                # Use the transition's to_node_id field (the authoritative
                # result-node reference). We verify the node exists and
                # belongs to the correct branch, but we do NOT require it
                # to be the current branch head -- a concurrent execution
                # may have advanced the branch after this trial completed.
                t_after = trans_repo.get_transition(transition_id)
                result_node_id = t_after.get("to_node_id") if t_after else None
                if not result_node_id:
                    issues.append("Transition has no result node (to_node_id is empty)")
                else:
                    node_repo = NodeRepository(conn)
                    result_node = node_repo.get_node(result_node_id)
                    if result_node is None:
                        issues.append(
                            f"Transition result node {result_node_id!r} "
                            f"does not exist in ep_nodes"
                        )
                    elif result_node.get("branch_id") != branch_id:
                        issues.append(
                            f"Transition result node belongs to branch "
                            f"'{result_node.get('branch_id')}', expected "
                            f"'{branch_id}'"
                        )
                    # Note: we do not require result_node_id == head_after.
                    # If a concurrent execution advanced the branch after
                    # this trial completed, the result node may be an
                    # ancestor of the current head rather than the head
                    # itself. The transition reaching 'succeeded' with a
                    # valid to_node_id is sufficient evidence of completion.

            # Check audit chain still valid
            if lattice_id:
                verifier = AuditVerifier(engine)
                if not verifier.verify(lattice_id):
                    issues.append(f"Audit chain INVALID after execution for lattice {lattice_id}")

    # --- 10. Report ---
    _report(issues)


def _report(issues):
    if issues:
        print("EP-GOVERNANCE TRIAL: ISSUES FOUND")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)
    # Silent on success (watchdog pattern)


if __name__ == "__main__":
    main()