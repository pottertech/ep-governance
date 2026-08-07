#!/bin/bash
# EP-Governance MCP server launcher for Hermes (Mary Wise agent)
# Uses --unsafe-dev-service-identity because the Mac is a dev/advisory
# environment. Production deployments must use --agent-config with a
# root-owned config file (chown root:root agent-mary.toml).
export EP_ENV_DIR="/Users/skippotter/ep-governance"
cd "$EP_ENV_DIR" || exit 1
source "$EP_ENV_DIR/.venv/bin/activate" || exit 1
set -a
source "$EP_ENV_DIR/.env" 2>/dev/null
set +a
exec python -m ep_governance.cli serve --unsafe-dev-service-identity