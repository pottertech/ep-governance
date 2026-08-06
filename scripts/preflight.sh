#!/usr/bin/env bash
# EP-Governance proxy deployment preflight script.
# Verifies that all required configuration is present before starting the proxy.
set -euo pipefail

echo "=== EP-Governance proxy deployment preflight ==="

# --- 1. Check required environment variables ---
REQUIRED_VARS=(
    "EP_DB_URL"
    "EP_PROXY_TARGET_URL"
    "EP_PROXY_AUDIENCE"
    "EP_PROXY_PRINCIPAL_ID"
    "EP_DEPLOYMENT_ID"
    "EP_PROXY_TARGET_ID"
    "EP_EP_SERVICE_ID"
    "EP_PUBLIC_KEY"
    "EP_CONTROLLER_PUBLIC_KEY"
    "EP_PROXY_ATTESTATION_FILE"
)

MISSING=()
for var in "${REQUIRED_VARS[@]}"; do
    val="${!var:-}"
    if [[ -z "$val" || "$val" =~ ^[[:space:]]*$ ]]; then
        MISSING+=("$var")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "FATAL: Missing required environment variables:"
    for v in "${MISSING[@]}"; do
        echo "  - $v"
    done
    exit 1
fi

echo "  All required environment variables present."

# --- 2. Reject placeholder values ---
PLACEHOLDER_PATTERNS=(
    "CHANGE_ME"
    "<.*>"
    "example"
    "your-"
    "placeholder"
)

PLACEHOLDER_HITS=()
for var in "${REQUIRED_VARS[@]}"; do
    val="${!var:-}"
    for pattern in "${PLACEHOLDER_PATTERNS[@]}"; do
        if [[ "$val" =~ $pattern ]]; then
            PLACEHOLDER_HITS+=("$var contains placeholder pattern: $pattern")
        fi
    done
done

if [[ ${#PLACEHOLDER_HITS[@]} -gt 0 ]]; then
    echo "FATAL: Placeholder values detected:"
    for hit in "${PLACEHOLDER_HITS[@]}"; do
        echo "  - $hit"
    done
    exit 1
fi

echo "  No placeholder values detected."

# --- 3. Verify attestation file exists and is readable ---
if [[ ! -f "$EP_PROXY_ATTESTATION_FILE" ]]; then
    echo "FATAL: Attestation file does not exist: $EP_PROXY_ATTESTATION_FILE"
    exit 1
fi

if [[ ! -r "$EP_PROXY_ATTESTATION_FILE" ]]; then
    echo "FATAL: Attestation file is not readable: $EP_PROXY_ATTESTATION_FILE"
    exit 1
fi

echo "  Attestation file exists and is readable: $EP_PROXY_ATTESTATION_FILE"

# --- 4. Verify attestation file is valid JSON ---
if ! python3 -c "import json; json.load(open('$EP_PROXY_ATTESTATION_FILE'))" 2>/dev/null; then
    echo "FATAL: Attestation file is not valid JSON: $EP_PROXY_ATTESTATION_FILE"
    exit 1
fi

echo "  Attestation file is valid JSON."

# --- 5. Check file permissions (should be 640 or stricter) ---
PERMS=$(stat -f "%Lp" "$EP_PROXY_ATTESTATION_FILE" 2>/dev/null || stat -c "%a" "$EP_PROXY_ATTESTATION_FILE" 2>/dev/null || echo "unknown")
if [[ "$PERMS" != "unknown" && "$PERMS" -gt 640 ]]; then
    echo "WARNING: Attestation file permissions are $PERMS (recommended: 640 or stricter)"
fi

# --- 6. Validate Docker Compose configuration (if docker compose is available) ---
if command -v docker &>/dev/null; then
    echo "  Validating Docker Compose configuration..."
    if docker compose -f docker/proxy/docker-compose.proxy.yml config >/dev/null 2>&1; then
        echo "  Docker Compose configuration is valid."
    else
        echo "WARNING: docker compose config failed. Check your .env.proxy file."
        docker compose -f docker/proxy/docker-compose.proxy.yml config 2>&1 || true
    fi
else
    echo "  Docker not available — skipping Compose validation."
fi

echo ""
echo "Preflight checks passed. Ready to deploy."
echo ""
echo "Start the proxy with:"
echo "  docker compose -f docker/proxy/docker-compose.proxy.yml --env-file .env.proxy up -d"