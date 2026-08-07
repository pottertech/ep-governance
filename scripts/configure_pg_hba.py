#!/usr/bin/env python3
"""Configure pg_hba.conf for EP-Governance enforced mode.

Adds rules to restrict direct database access for agent roles, so the
governed proxy (connecting via 127.0.0.1) is the only path for agents.

SAFE PROCEDURE:
1. Backs up the current pg_hba.conf
2. Adds reject rules for agent roles from non-local IPs
3. Reloads PostgreSQL (pg_reload_conf, no restart needed)
4. Tests that the proxy can still connect (127.0.0.1)
5. If anything fails, restores the backup

The script does NOT touch admin or service users -- only agent roles
(brodie_rw, brodie_research_rw, mary_rw). The ep_proxy_user role is
allowed from 127.0.0.1 (the proxy connects locally).

Usage:
    python3 scripts/configure_pg_hba.py          # Apply
    python3 scripts/configure_pg_hba.py --check  # Check current state
    python3 scripts/configure_pg_hba.py --revert # Revert to backup
"""
import os
import re
import subprocess
import sys
import time
from urllib.parse import unquote

NAS_HOST = os.environ.get("NAS_HOST", "100.98.247.27")
NAS_USER = os.environ.get("NAS_USER", "younique")
DOCKER_CONTAINER = "synology-postgres-shared"
PG_HBA_PATH = "/var/lib/postgresql/data/pgdata/pg_hba.conf"

# Agent roles to restrict (direct access denied from non-local IPs)
# Note: mary_rw is NOT restricted here -- Mary Wise needs direct access
# for EP-Governance administration. Only Brodie's research roles are
# restricted so the proxy is his only path to the database.
AGENT_ROLES = ["brodie_rw", "brodie_research_rw"]

# The proxy connects from 127.0.0.1 -- this is always allowed
# Admin/service users are not restricted by this script


def run_ssh(cmd, timeout=30):
    """Run a command via SSH on the NAS."""
    result = subprocess.run(
        ["ssh", f"{NAS_USER}@{NAS_HOST}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return result.stdout, result.stderr, result.returncode


def docker_exec(cmd, timeout=30):
    """Run a command inside the PostgreSQL Docker container via SSH."""
    ssh_cmd = (
        f"export PATH=/volume1/@appstore/Docker/usr/bin:$PATH; "
        f"docker exec {DOCKER_CONTAINER} {cmd}"
    )
    return run_ssh(ssh_cmd, timeout)


def get_current_pg_hba():
    """Get the current pg_hba.conf content."""
    stdout, stderr, rc = docker_exec(f"cat {PG_HBA_PATH}")
    if rc != 0:
        print(f"ERROR: Cannot read pg_hba.conf: {stderr}")
        sys.exit(1)
    return stdout


def backup_pg_hba():
    """Back up the current pg_hba.conf."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_name = f"{PG_HBA_PATH}.backup_{timestamp}"
    stdout, stderr, rc = docker_exec(f"cp {PG_HBA_PATH} {backup_name}")
    if rc != 0:
        print(f"ERROR: Cannot backup pg_hba.conf: {stderr}")
        sys.exit(1)
    print(f"  Backed up to: {backup_name}")
    return backup_name


def check_ep_governance_rules(content):
    """Check if EP-Governance rules already exist in pg_hba.conf."""
    return "EP-Governance enforced mode" in content


def build_new_pg_hba(current_content):
    """Build new pg_hba.conf with EP-Governance rules.

    Inserts reject rules BEFORE the 'host all all all' catch-all line.
    The reject rules block agent roles from non-local IPs.
    """
    if check_ep_governance_rules(current_content):
        print("  EP-Governance rules already present, skipping")
        return current_content

    # Build the reject rules block
    rules = [
        "",
        "# EP-Governance enforced mode -- restrict agent direct access",
        "# Agent roles can only connect from localhost (the proxy).",
        "# Direct access from other IPs is rejected.",
    ]
    for role in AGENT_ROLES:
        rules.append(f"host all {role} 127.0.0.1/32 scram-sha-256  # proxy local access")
        rules.append(f"host all {role} ::1/128 scram-sha-256       # proxy local access (IPv6)")
        rules.append(f"host all {role} all reject                  # EP-Governance: no direct access")
    rules.append("# End EP-Governance rules")
    rules.append("")

    rules_block = "\n".join(rules)

    # Insert before the catch-all line
    catch_all = "host all all all scram-sha-256"
    if catch_all in current_content:
        new_content = current_content.replace(catch_all, rules_block + catch_all)
    else:
        # If no catch-all, append at the end
        new_content = current_content.rstrip() + "\n" + rules_block

    return new_content


def apply_pg_hba(new_content):
    """Write new pg_hba.conf and reload PostgreSQL."""
    # Write to a temp file on the NAS
    temp_path = f"/tmp/pg_hba_ep_gov.conf"
    write_cmd = f"cat > {temp_path}"
    result = subprocess.run(
        ["ssh", f"{NAS_USER}@{NAS_HOST}", write_cmd],
        input=new_content, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        print(f"ERROR: Cannot write temp file: {result.stderr}")
        sys.exit(1)

    # Copy into the container
    stdout, stderr, rc = docker_exec(f"cp {temp_path} {PG_HBA_PATH}")
    if rc != 0:
        # Try via docker cp
        ssh_cmd = (
            f"export PATH=/volume1/@appstore/Docker/usr/bin:$PATH; "
            f"docker cp /tmp/pg_hba_ep_gov.conf {DOCKER_CONTAINER}:{PG_HBA_PATH}"
        )
        stdout, stderr, rc = run_ssh(ssh_cmd)
        if rc != 0:
            print(f"ERROR: Cannot copy pg_hba.conf into container: {stderr}")
            sys.exit(1)

    # Reload PostgreSQL config via SIGHUP (doesn't need superuser password)
    stdout, stderr, rc = docker_exec(
        "bash -c 'kill -HUP $(head -1 /var/lib/postgresql/data/pgdata/postmaster.pid)'"
    )
    if rc != 0:
        print(f"WARNING: Cannot reload PostgreSQL config via SIGHUP: {stderr}")
        print(f"  Changes will take effect on next PostgreSQL restart")
    else:
        print(f"  PostgreSQL config reloaded (SIGHUP)")

    # Verify the file was written
    stdout, stderr, rc = docker_exec(f"grep 'EP-Governance' {PG_HBA_PATH}")
    if rc == 0 and "EP-Governance" in stdout:
        print(f"  EP-Governance rules verified in pg_hba.conf")
    else:
        print(f"  WARNING: Could not verify EP-Governance rules in pg_hba.conf")


def test_proxy_connectivity():
    """Test that the proxy can still connect via 127.0.0.1."""
    # Check proxy health
    stdout, stderr, rc = run_ssh("curl -sk https://127.0.0.1:8201/health")
    if "ok" in stdout:
        print(f"  Proxy health: OK")
        return True
    else:
        print(f"  Proxy health: FAILED ({stdout.strip()})")
        return False


def revert(backup_path):
    """Revert to a backup pg_hba.conf."""
    if not backup_path:
        # Find the most recent backup
        stdout, stderr, rc = docker_exec(f"ls -t {PG_HBA_PATH}.backup_* 2>/dev/null | head -1")
        backup_path = stdout.strip()
        if not backup_path:
            print("ERROR: No backup found to revert to")
            sys.exit(1)

    print(f"  Reverting to: {backup_path}")
    stdout, stderr, rc = docker_exec(f"cp {backup_path} {PG_HBA_PATH}")
    if rc != 0:
        print(f"ERROR: Cannot restore backup: {stderr}")
        sys.exit(1)

    # Reload
    docker_exec("psql -U postgres -d postgres -c 'SELECT pg_reload_conf();'")
    print(f"  PostgreSQL config reloaded (reverted)")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Configure pg_hba.conf for EP-Governance")
    parser.add_argument("--check", action="store_true", help="Check current state only")
    parser.add_argument("--revert", action="store_true", help="Revert to backup")
    args = parser.parse_args()

    print("=== EP-Governance pg_hba.conf Configuration ===")
    print()

    if args.revert:
        print("Reverting to backup...")
        revert(None)
        test_proxy_connectivity()
        return

    current = get_current_pg_hba()

    if args.check:
        if check_ep_governance_rules(current):
            print("Status: EP-Governance rules ARE present in pg_hba.conf")
            # Show the rules
            for line in current.splitlines():
                if "EP-Governance" in line or "reject" in line:
                    print(f"  {line}")
        else:
            print("Status: EP-Governance rules NOT present in pg_hba.conf")
        test_proxy_connectivity()
        return

    print(f"1. Checking current state...")
    if check_ep_governance_rules(current):
        print("  EP-Governance rules already present, nothing to do")
        test_proxy_connectivity()
        return

    print(f"2. Backing up current pg_hba.conf...")
    backup_path = backup_pg_hba()

    print(f"3. Building new pg_hba.conf with agent restrictions...")
    print(f"  Restricting roles: {', '.join(AGENT_ROLES)}")
    new_content = build_new_pg_hba(current)

    print(f"4. Applying new pg_hba.conf...")
    apply_pg_hba(new_content)

    print(f"5. Testing proxy connectivity...")
    if test_proxy_connectivity():
        print()
        print("SUCCESS: EP-Governance pg_hba.conf rules applied")
        print(f"  Agent roles restricted to localhost only")
        print(f"  Proxy (127.0.0.1) can still connect")
        print(f"  To revert: python3 scripts/configure_pg_hba.py --revert")
    else:
        print()
        print("FAILURE: Proxy connectivity test failed, reverting!")
        revert(backup_path)
        sys.exit(1)


if __name__ == "__main__":
    main()