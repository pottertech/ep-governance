#!/usr/bin/env python3
"""EP-Governance controlled trial — daily health check + governed action exercise.

Runs daily via cron. Performs:
1. Audit chain integrity verification
2. Proposes and executes a governed SELECT through the proxy
3. Verifies the transition reached 'succeeded'
4. Reports any issues

Outputs to stdout (captured by cron). Silent on success, verbose on failure.
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ep_governance.config import load_config
from ep_governance.db.postgres import create_engine
from ep_governance.db.repositories import PolicyRepository
from ep_governance.transitions import TransitionEngine
from ep_governance.authorizations import AuthorizationEngine, KeyManager
from ep_governance.policy_engine import PolicyEngine
from ep_governance.policies import Policy
from ep_governance.canonical import canonical_hash
from ep_governance.audit import AuditVerifier
from ep_governance.xid import XID
import sqlalchemy as sa


def main():
    cfg = load_config()
    engine = create_engine(cfg.db_url, schema=cfg.db_schema or None)

    issues = []

    # 1. Audit chain verification
    with engine.connect() as conn:
        result = conn.execute(sa.text(
            "SELECT lattice_id FROM ep_audit_heads ORDER BY last_sequence DESC LIMIT 1"
        ))
        row = result.fetchone()
        if row:
            lattice_id = row[0]
            verifier = AuditVerifier(engine)
            if not verifier.verify(lattice_id):
                issues.append(f"Audit chain INVALID for lattice {lattice_id}")

    # 2. Load signing key
    key_path = os.path.join(os.path.dirname(__file__), "..", "ep_signing_test.key")
    km = KeyManager()
    km.load_private_key(key_path)

    # 3. Get entities
    with engine.connect() as conn:
        ep_service_id = conn.execute(sa.text(
            "SELECT id FROM ep_principals WHERE type='service' AND name='EP Service' LIMIT 1"
        )).fetchone()[0]
        agent_id = conn.execute(sa.text(
            "SELECT id FROM ep_principals WHERE type='agent' AND name='Mary Wise' LIMIT 1"
        )).fetchone()[0]
        branch_id = conn.execute(sa.text("SELECT id FROM ep_branches LIMIT 1")).fetchone()[0]
        project_id = conn.execute(sa.text(
            "SELECT l.project_id FROM ep_branches b "
            "JOIN ep_lattices l ON b.lattice_id = l.id WHERE b.id = :bid"
        ), {"bid": branch_id}).fetchone()[0]

        rows = PolicyRepository(conn).list_active_policies_for_project(project_id)
        policies = []
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
            except Exception:
                continue

    # 4. Propose + execute a governed SELECT
    pe = PolicyEngine(policies)
    te = TransitionEngine(engine, ep_service_id, policy_engine=pe)
    ae = AuthorizationEngine(engine, km, ep_service_id)

    import time as _time
    payload = {"sql": f"SELECT {int(_time.time())} as trial_check", "host": "nas", "database": "gbrain_pilot_test"}
    transition = te.propose(
        agent_id=agent_id, branch_id=branch_id, tool="postgres.execute",
        arguments=payload, idempotency_key=str(XID.new()),
    )

    if transition["stage"] != "authorized":
        issues.append(f"Trial SELECT not authorized: stage={transition['stage']}")
    else:
        mpv = transition.get("matched_policy_versions", {})
        token = ae.issue_authorization(
            transition_id=transition["id"], agent_id=agent_id,
            project_id=project_id, branch_id=branch_id,
            proxy_audience="postgres-proxy", tool="postgres.execute",
            payload_hash="sha256:" + canonical_hash(payload),
            matched_policies=[{"id": k, "activation_version": v} for k, v in mpv.items()],
        )
        signed = token.to_signed_token(km)

        proxy_url = os.environ.get("EP_PROXY_URL", "http://100.98.247.27:8201/execute")
        req = urllib.request.Request(proxy_url,
            data=json.dumps({"signed_token": signed, "payload": payload}).encode(),
            headers={"Content-Type": "application/json"})

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
            if not result["success"]:
                issues.append(f"Proxy execution failed: {result['result_summary']}")
        except Exception as exc:
            issues.append(f"Proxy request failed: {exc}")

    # 5. Report
    if issues:
        print("EP-GOVERNANCE TRIAL: ISSUES FOUND")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)
    else:
        # Silent on success (watchdog pattern)
        pass


if __name__ == "__main__":
    main()