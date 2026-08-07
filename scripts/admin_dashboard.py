#!/usr/bin/env python3
"""EP-Governance Admin Dashboard -- lightweight web UI for policy management.

Provides a simple web interface for human administrators to:
- View governance status (branch, version, policies, principals)
- View pending approvals and approve/deny them
- View recent transitions
- Verify audit chain integrity
- View proxy health and metrics

Runs on port 8202 (configurable via EP_DASHBOARD_PORT).
No external dependencies -- uses Python stdlib only.

Usage:
    python3 scripts/admin_dashboard.py
    EP_DASHBOARD_PORT=9000 python3 scripts/admin_dashboard.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.request
import ssl
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

DASHBOARD_PORT = int(os.environ.get("EP_DASHBOARD_PORT", "8202"))
PROXY_HEALTH_URL = os.environ.get("EP_PROXY_HEALTH_URL", "https://100.98.247.27:8201/health")
PROXY_METRICS_URL = os.environ.get("EP_PROXY_METRICS_URL", "https://100.98.247.27:8201/metrics")


def parse_db_url():
    """Parse EP_DB_URL from .env."""
    env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    db_url = None
    schema = "ep_governance"
    with open(env_file) as f:
        for line in f:
            if line.startswith("EP_DB_URL="):
                db_url = line.split("=", 1)[1].strip()
            if line.startswith("EP_DB_SCHEMA="):
                schema = line.split("=", 1)[1].strip()
    if not db_url:
        return None, None, None, None, None, schema
    m = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not m:
        return None, None, None, None, None, schema
    user, pwd_raw, host, port, db = m.groups()
    return user, unquote(pwd_raw), host, port, db, schema


def query_db(sql, params=None):
    """Run a SQL query against the governance DB."""
    user, pwd, host, port, db, schema = parse_db_url()
    if not user:
        return []

    env = {**os.environ, "PGPASSWORD": pwd}
    cmd = ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-t", "-A", "-F", "||", "-c", sql]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, env=env)
    if result.returncode != 0:
        return []

    rows = []
    for line in result.stdout.strip().splitlines():
        if line:
            rows.append(line.split("||"))
    return rows


def check_proxy_health():
    """Check proxy health endpoint."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(PROXY_HEALTH_URL)
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return {"status": "error", "service": "unreachable"}


def get_proxy_metrics():
    """Get proxy metrics."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(PROXY_METRICS_URL)
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return resp.read().decode()
    except Exception:
        return "# Metrics unavailable"


def approve_transition(transition_id, reason="Approved via dashboard"):
    """Approve a pending transition."""
    user, pwd, host, port, db, schema = parse_db_url()
    if not user:
        return False, "DB not configured"

    env = {**os.environ, "PGPASSWORD": pwd}
    # Find the approval request for this transition
    sql = f"SELECT id FROM {schema}.ep_approval_requests WHERE transition_id = '{transition_id}' AND status = 'pending' LIMIT 1"
    result = subprocess.run(
        ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-t", "-A", "-c", sql],
        capture_output=True, text=True, timeout=15, env=env,
    )
    approval_id = result.stdout.strip()
    if not approval_id:
        return False, "No pending approval found for this transition"

    # Use the CLI to approve
    cli_result = subprocess.run(
        ["python3", "-m", "ep_governance.cli", "approve",
         "--approval", approval_id, "--reason", reason],
        capture_output=True, text=True, timeout=30, env=env,
        cwd=os.path.join(os.path.dirname(__file__), ".."),
    )
    if cli_result.returncode == 0:
        return True, f"Approved {transition_id}"
    return False, f"Approve failed: {cli_result.stderr}"


def deny_transition(transition_id, reason="Denied via dashboard"):
    """Deny a pending transition."""
    user, pwd, host, port, db, schema = parse_db_url()
    if not user:
        return False, "DB not configured"

    env = {**os.environ, "PGPASSWORD": pwd}
    sql = f"SELECT id FROM {schema}.ep_approval_requests WHERE transition_id = '{transition_id}' AND status = 'pending' LIMIT 1"
    result = subprocess.run(
        ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-t", "-A", "-c", sql],
        capture_output=True, text=True, timeout=15, env=env,
    )
    approval_id = result.stdout.strip()
    if not approval_id:
        return False, "No pending approval found for this transition"

    cli_result = subprocess.run(
        ["python3", "-m", "ep_governance.cli", "deny",
         "--approval", approval_id, "--reason", reason],
        capture_output=True, text=True, timeout=30, env=env,
        cwd=os.path.join(os.path.dirname(__file__), ".."),
    )
    if cli_result.returncode == 0:
        return True, f"Denied {transition_id}"
    return False, f"Deny failed: {cli_result.stderr}"


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EP-Governance Admin Dashboard</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
  h1 {{ color: #0f3460; background: #16213e; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; }}
  h2 {{ color: #e94560; margin: 20px 0 10px; font-size: 1.2em; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .card {{ background: #16213e; border-radius: 8px; padding: 15px 20px; }}
  .card h3 {{ color: #e94560; margin-bottom: 10px; font-size: 1em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
  th {{ text-align: left; padding: 8px 10px; border-bottom: 2px solid #0f3460; color: #e94560; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid #0f3460; }}
  tr:hover {{ background: #1a1a3e; }}
  .status-ok {{ color: #4caf50; font-weight: bold; }}
  .status-error {{ color: #f44336; font-weight: bold; }}
  .status-pending {{ color: #ff9800; font-weight: bold; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; }}
  .badge-allow {{ background: #2e7d32; }}
  .badge-deny {{ background: #c62828; }}
  .badge-require_approval {{ background: #e65100; }}
  .badge-warn {{ background: #f57f17; }}
  .badge-active {{ background: #2e7d32; }}
  .badge-pending {{ background: #e65100; }}
  .badge-denied {{ background: #c62828; }}
  .badge-succeeded {{ background: #1565c0; }}
  .btn {{ padding: 6px 14px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em; }}
  .btn-approve {{ background: #2e7d32; color: white; }}
  .btn-deny {{ background: #c62828; color: white; }}
  .btn:hover {{ opacity: 0.85; }}
  pre {{ background: #0a0a1e; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 0.8em; }}
  .flash {{ padding: 10px 15px; border-radius: 4px; margin: 10px 0; }}
  .flash-success {{ background: #2e7d32; }}
  .flash-error {{ background: #c62828; }}
  a {{ color: #64b5f6; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .footer {{ margin-top: 30px; text-align: center; color: #555; font-size: 0.8em; }}
</style>
</head>
<body>
<h1>EP-Governance Admin Dashboard</h1>

{flash_message}

<div class="grid">

<div class="card">
<h3>Proxy Health</h3>
<p>Status: <span class="status-{proxy_status_class}">{proxy_status}</span></p>
<p>Service: {proxy_service}</p>
</div>

<div class="card">
<h3>Governance State</h3>
<p>Branch: {branch_id}</p>
<p>Version: {branch_version}</p>
<p>Principals: {principal_count}</p>
<p>Active Policies: {policy_count}</p>
<p>Nodes: {node_count}</p>
<p>Transitions: {transition_count}</p>
</div>

</div>

<h2>Pending Approvals ({pending_count})</h2>
{pending_table}

<h2>Active Policies ({policy_count})</h2>
{policy_table}

<h2>Recent Transitions ({transition_count})</h2>
{transition_table}

<h2>Principals ({principal_count})</h2>
{principal_table}

<h2>Proxy Metrics</h2>
<pre>{proxy_metrics}</pre>

<div class="footer">
EP-Governance Admin Dashboard &middot; {timestamp}
</div>

</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/dashboard":
            self._serve_dashboard()
        elif path == "/health":
            self._send_json(200, {"status": "ok", "service": "ep-governance-dashboard"})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/approve":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            params = parse_qs(body)
            transition_id = params.get("transition_id", [""])[0]
            reason = params.get("reason", ["Approved via dashboard"])[0]
            success, message = approve_transition(transition_id, reason)
            flash = f'<div class="flash flash-{"success" if success else "error"}">{message}</div>'
            self._serve_dashboard(flash)
        elif path == "/deny":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            params = parse_qs(body)
            transition_id = params.get("transition_id", [""])[0]
            reason = params.get("reason", ["Denied via dashboard"])[0]
            success, message = deny_transition(transition_id, reason)
            flash = f'<div class="flash flash-{"success" if success else "error"}">{message}</div>'
            self._serve_dashboard(flash)
        else:
            self._send_json(404, {"error": "Not found"})

    def _send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_dashboard(self, flash_message=""):
        # Gather data
        health = check_proxy_health()
        proxy_status = health.get("status", "unknown")
        proxy_status_class = "ok" if proxy_status == "ok" else "error"
        proxy_service = health.get("service", "")

        metrics = get_proxy_metrics()

        # Governance state
        _, _, _, _, _, schema = parse_db_url()

        branch_rows = query_db(
            f"SELECT id, version FROM {schema}.ep_branches ORDER BY version DESC LIMIT 1"
        )
        branch_id = branch_rows[0][0] if branch_rows else "N/A"
        branch_version = branch_rows[0][1] if branch_rows else "N/A"

        principal_count = query_db(f"SELECT count(*) FROM {schema}.ep_principals")
        principal_count = principal_count[0][0] if principal_count else "0"

        policy_count = query_db(f"SELECT count(*) FROM {schema}.ep_policies WHERE status = 'active'")
        policy_count = policy_count[0][0] if policy_count else "0"

        node_count = query_db(f"SELECT count(*) FROM {schema}.ep_nodes")
        node_count = node_count[0][0] if node_count else "0"

        transition_count = query_db(f"SELECT count(*) FROM {schema}.ep_transitions")
        transition_count = transition_count[0][0] if transition_count else "0"

        # Pending approvals
        pending_rows = query_db(
            f"SELECT t.id, p.name, t.tool, t.created_at "
            f"FROM {schema}.ep_transitions t "
            f"LEFT JOIN {schema}.ep_principals p ON t.agent_id = p.id "
            f"WHERE t.stage = 'pending_approval' "
            f"ORDER BY t.created_at DESC LIMIT 20"
        )
        pending_count = len(pending_rows)
        if pending_rows:
            pending_table = '<table><tr><th>Transition ID</th><th>Agent</th><th>Tool</th><th>Created</th><th>Actions</th></tr>'
            for row in pending_rows:
                tid, agent, tool, created = row
                pending_table += (
                    f'<tr><td>{tid[:12]}...</td><td>{agent}</td><td>{tool}</td><td>{created}</td>'
                    f'<td>'
                    f'<form method="POST" action="/approve" style="display:inline">'
                    f'<input type="hidden" name="transition_id" value="{tid}">'
                    f'<button type="submit" class="btn btn-approve">Approve</button>'
                    f'</form> '
                    f'<form method="POST" action="/deny" style="display:inline">'
                    f'<input type="hidden" name="transition_id" value="{tid}">'
                    f'<button type="submit" class="btn btn-deny">Deny</button>'
                    f'</form>'
                    f'</td></tr>'
                )
            pending_table += '</table>'
        else:
            pending_table = '<p>No pending approvals.</p>'

        # Active policies
        policy_rows = query_db(
            f"SELECT id, scope, effect, actions, priority, description "
            f"FROM {schema}.ep_policies WHERE status = 'active' "
            f"ORDER BY priority DESC LIMIT 50"
        )
        if policy_rows:
            policy_table = '<table><tr><th>ID</th><th>Scope</th><th>Effect</th><th>Actions</th><th>Priority</th><th>Description</th></tr>'
            for row in policy_rows:
                pid, scope, effect, actions, priority, desc = row
                badge_class = f"badge-{effect}"
                policy_table += (
                    f'<tr><td>{pid[:12]}...</td><td>{scope}</td>'
                    f'<td><span class="badge {badge_class}">{effect}</span></td>'
                    f'<td>{actions[:50]}</td><td>{priority}</td><td>{desc[:60]}</td></tr>'
                )
            policy_table += '</table>'
        else:
            policy_table = '<p>No active policies.</p>'

        # Recent transitions
        trans_rows = query_db(
            f"SELECT t.id, p.name, t.tool, t.stage, t.created_at "
            f"FROM {schema}.ep_transitions t "
            f"LEFT JOIN {schema}.ep_principals p ON t.agent_id = p.id "
            f"ORDER BY t.created_at DESC LIMIT 20"
        )
        if trans_rows:
            trans_table = '<table><tr><th>ID</th><th>Agent</th><th>Tool</th><th>Stage</th><th>Created</th></tr>'
            for row in trans_rows:
                tid, agent, tool, stage, created = row
                stage_class = f"badge-{stage}" if stage in ("denied", "succeeded", "pending_approval") else "badge-active"
                trans_table += (
                    f'<tr><td>{tid[:12]}...</td><td>{agent}</td><td>{tool}</td>'
                    f'<td><span class="badge {stage_class}">{stage}</span></td><td>{created}</td></tr>'
                )
            trans_table += '</table>'
        else:
            trans_table = '<p>No transitions.</p>'

        # Principals
        principal_rows = query_db(
            f"SELECT id, name, type FROM {schema}.ep_principals ORDER BY name"
        )
        if principal_rows:
            principal_table = '<table><tr><th>ID</th><th>Name</th><th>Type</th></tr>'
            for row in principal_rows:
                pid, name, ptype = row
                principal_table += f'<tr><td>{pid[:12]}...</td><td>{name}</td><td>{ptype}</td></tr>'
            principal_table += '</table>'
        else:
            principal_table = '<p>No principals.</p>'

        html = HTML_TEMPLATE.format(
            flash_message=flash_message,
            proxy_status=proxy_status,
            proxy_status_class=proxy_status_class,
            proxy_service=proxy_service,
            branch_id=branch_id,
            branch_version=branch_version,
            principal_count=principal_count,
            policy_count=policy_count,
            node_count=node_count,
            transition_count=transition_count,
            pending_count=pending_count,
            pending_table=pending_table,
            policy_table=policy_table,
            transition_table=trans_table,
            principal_table=principal_table,
            proxy_metrics=metrics[:2000],
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Suppress default logging


def main():
    print(f"EP-Governance Admin Dashboard starting on port {DASHBOARD_PORT}")
    print(f"  Proxy health: {PROXY_HEALTH_URL}")
    print(f"  Open http://localhost:{DASHBOARD_PORT} in your browser")

    server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard shutting down")


if __name__ == "__main__":
    main()