#!/usr/bin/env python3
"""Audit chain watchdog -- verifies the EP-Governance audit chain integrity.

Checks:
1. Audit chain hash continuity (each event's previous_hash matches the prior event's event_hash)
2. Audit head matches the last event
3. Proxy health endpoint responds
4. Reports issues to stderr (for cron/monitoring)

Usage:
    python3 scripts/audit_watchdog.py

Exit codes:
    0 -- all checks pass
    1 -- audit chain broken or proxy unhealthy
"""
import json
import os
import sys
import subprocess
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

PROXY_HEALTH_URL = os.environ.get("EP_PROXY_HEALTH_URL", "https://100.98.247.27:8201/health")


def check_proxy_health():
    """Check if the proxy health endpoint responds."""
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(PROXY_HEALTH_URL)
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "ok":
                print("PASS: proxy health OK")
                return True
            else:
                print(f"FAIL: proxy health returned {data}")
                return False
    except Exception as e:
        print(f"FAIL: proxy health check error: {e}")
        return False


def check_audit_chain():
    """Verify audit chain integrity on the NAS PostgreSQL."""
    # Load config
    from ep_governance.config import load_config
    cfg = load_config()

    if not cfg.db_url:
        print("FAIL: No EP_DB_URL configured")
        return False

    import sqlalchemy as sa
    if cfg.db_schema:
        from ep_governance.db.postgres import create_engine
        engine = create_engine(cfg.db_url, schema=cfg.db_schema)
    else:
        engine = sa.create_engine(cfg.db_url)

    from ep_governance.audit import AuditVerifier
    from ep_governance.db.repositories import BranchRepository

    with engine.connect() as conn:
        # Get all lattices
        result = conn.execute(sa.text(
            "SELECT id FROM ep_lattices"
        ))
        lattice_ids = [row[0] for row in result]

        if not lattice_ids:
            print("PASS: no lattices to verify (empty database)")
            return True

        all_ok = True
        for lattice_id in lattice_ids:
            try:
                verifier = AuditVerifier(engine)
                valid = verifier.verify(lattice_id)
                if valid:
                    # Count events
                    count_result = conn.execute(sa.text(
                        "SELECT count(*) FROM ep_events WHERE lattice_id = :lid"
                    ), {"lid": lattice_id})
                    count = count_result.scalar()
                    print(f"PASS: lattice {lattice_id} audit chain valid ({count} events)")
                else:
                    print(f"FAIL: lattice {lattice_id} audit chain BROKEN")
                    all_ok = False
            except Exception as e:
                print(f"FAIL: lattice {lattice_id} audit verification error: {e}")
                all_ok = False

        return all_ok


def main():
    print("=== EP-Governance Audit Watchdog ===")
    print()

    audit_ok = check_audit_chain()
    proxy_ok = check_proxy_health()

    print()
    if audit_ok and proxy_ok:
        print("ALL CHECKS PASSED")
        sys.exit(0)
    else:
        print("CHECKS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()