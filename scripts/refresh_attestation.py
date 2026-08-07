#!/usr/bin/env python3
"""Generate a fresh signed proxy attestation and deploy it to the NAS.

This script:
1. Loads the controller signing key
2. Creates a new attestation JSON with a 55-minute TTL
3. Signs it with Ed25519
4. Transfers it to the NAS via SSH
5. Restarts the proxy container

Usage:
    python3 scripts/refresh_attestation.py

Required env vars:
    EP_SIGNING_KEY_FILE  -- path to the controller signing key
    NAS_HOST             -- NAS host (default: 100.98.247.27)
    NAS_USER             -- NAS SSH user (default: younique)
    NAS_PROXY_DIR        -- proxy dir on NAS (default: /volume1/docker/ep-governance-proxy)

The attestation binding values (proxy_principal_id, deployment_id, target_id)
are read from the existing .env.proxy on the NAS so they stay stable across
refreshes.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ep_governance.authorizations import KeyManager

NAS_HOST = os.environ.get("NAS_HOST", "100.98.247.27")
NAS_USER = os.environ.get("NAS_USER", "younique")
NAS_PROXY_DIR = os.environ.get("NAS_PROXY_DIR", "/volume1/docker/ep-governance-proxy")
CONTROLLER_KEY = os.environ.get("EP_SIGNING_KEY_FILE", "")

# Attestation lifetime (must be <= 1 hour per MAX_SIGNED_ATTESTATION_LIFETIME)
ATTESTATION_TTL_MINUTES = 55


def read_nas_env_proxy():
    """Read the .env.proxy from the NAS to get stable binding values."""
    result = subprocess.run(
        ["ssh", f"{NAS_USER}@{NAS_HOST}",
         f"cat {NAS_PROXY_DIR}/.env.proxy"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        print(f"ERROR: Cannot read .env.proxy from NAS: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    env = {}
    for line in result.stdout.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def generate_attestation(env_proxy):
    """Generate a fresh signed attestation using binding values from .env.proxy."""
    proxy_principal_id = env_proxy.get("EP_PROXY_PRINCIPAL_ID", "")
    deployment_id = env_proxy.get("EP_DEPLOYMENT_ID", "")
    target_id = env_proxy.get("EP_PROXY_TARGET_ID", "")
    proxy_audience = env_proxy.get("EP_PROXY_AUDIENCE", "postgres-proxy")

    if not all([proxy_principal_id, deployment_id, target_id]):
        print("ERROR: Missing binding values in .env.proxy "
              "(EP_PROXY_PRINCIPAL_ID, EP_DEPLOYMENT_ID, EP_PROXY_TARGET_ID)",
              file=sys.stderr)
        sys.exit(1)

    # Load controller signing key
    if not CONTROLLER_KEY or not os.path.isfile(CONTROLLER_KEY):
        print(f"ERROR: EP_SIGNING_KEY_FILE not set or file not found: {CONTROLLER_KEY}",
              file=sys.stderr)
        sys.exit(1)

    km = KeyManager()
    km.load_private_key(CONTROLLER_KEY)

    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(minutes=ATTESTATION_TTL_MINUTES)

    attestation_data = {
        "effective_mode": "enforced",
        "binding_enforcement_active": True,
        "agent_principal_id": "proxy",
        "proxy_scoped": True,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "proxy_principal_id": proxy_principal_id,
        "proxy_audience": proxy_audience,
        "deployment_id": deployment_id,
        "target_id": target_id,
        "supported_action_types": ["select", "insert", "update", "delete"],
    }

    # Sign using canonical_json_bytes (same as from_signed_attestation verifies with)
    from ep_governance.canonical import canonical_json_bytes

    attestation_no_sig = {k: v for k, v in attestation_data.items() if k != "signature"}
    message = canonical_json_bytes(attestation_no_sig)
    signed = km.private_key.sign(message)
    attestation_data["signature"] = signed.signature.hex()

    return attestation_data


def deploy_attestation(attestation_json):
    """Transfer attestation to NAS and restart proxy."""
    attestation_str = json.dumps(attestation_json, indent=2)
    remote_path = f"{NAS_PROXY_DIR}/deployment/proxy-attestation.json"

    # Transfer via SSH pipe
    result = subprocess.run(
        ["ssh", f"{NAS_USER}@{NAS_HOST}",
         f"cat > {remote_path} && chmod 644 {remote_path}"],
        input=attestation_str, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        print(f"ERROR: Failed to transfer attestation: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    print(f"  Attestation deployed to {remote_path}")

    # Full stop/rm/run (docker restart doesn't always pick up volume changes)
    result = subprocess.run(
        ["ssh", f"{NAS_USER}@{NAS_HOST}",
         f"export PATH=/volume1/@appstore/Docker/usr/bin:$PATH; "
         f"docker stop ep-proxy; docker rm ep-proxy; "
         f"cd {NAS_PROXY_DIR} && "
         f"docker run -d --name ep-proxy --restart unless-stopped --network host "
         f"--env-file .env.proxy "
         f"-v {NAS_PROXY_DIR}/deployment/proxy-attestation.json:"
         f"/run/ep-governance/proxy-attestation.json:ro "
         f"-v {NAS_PROXY_DIR}/tls/proxy.crt:"
         f"/run/ep-governance/tls/proxy.crt:ro "
         f"-v {NAS_PROXY_DIR}/tls/proxy.key:"
         f"/run/ep-governance/tls/proxy.key:ro "
         f"--security-opt no-new-privileges:true --cap-drop ALL "
         f"ep-governance-proxy"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        print(f"ERROR: Failed to restart proxy: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    print("  Proxy restarted")

    # Wait and check health
    import time
    time.sleep(3)

    result = subprocess.run(
        ["ssh", f"{NAS_USER}@{NAS_HOST}",
         f"export PATH=/volume1/@appstore/Docker/usr/bin:$PATH; "
         f"docker logs ep-proxy 2>&1 | tail -5"],
        capture_output=True, text=True, timeout=15,
    )
    print(f"  Proxy logs: {result.stdout.strip()}")

    # Health check
    result = subprocess.run(
        ["ssh", f"{NAS_USER}@{NAS_HOST}", "curl -s http://127.0.0.1:8201/health"],
        capture_output=True, text=True, timeout=15,
    )
    if "ok" in result.stdout:
        print(f"  Health: {result.stdout.strip()}")
        print("  PASS: Proxy is healthy with fresh attestation")
    else:
        print(f"  WARNING: Health check returned: {result.stdout.strip()}")


def main():
    print("=== EP-Governance Attestation Refresh ===")
    print()

    print("1. Reading .env.proxy from NAS for binding values...")
    env_proxy = read_nas_env_proxy()
    print(f"  Proxy principal: {env_proxy.get('EP_PROXY_PRINCIPAL_ID', 'MISSING')}")
    print(f"  Deployment ID:   {env_proxy.get('EP_DEPLOYMENT_ID', 'MISSING')}")
    print(f"  Target ID:       {env_proxy.get('EP_PROXY_TARGET_ID', 'MISSING')}")
    print()

    print("2. Generating fresh signed attestation...")
    attestation = generate_attestation(env_proxy)
    print(f"  Issued at:  {attestation['issued_at']}")
    print(f"  Expires at: {attestation['expires_at']}")
    print(f"  Signed with controller key: {CONTROLLER_KEY}")
    print()

    print("3. Deploying to NAS and restarting proxy...")
    deploy_attestation(attestation)
    print()
    print("=== Attestation refresh complete ===")


if __name__ == "__main__":
    main()