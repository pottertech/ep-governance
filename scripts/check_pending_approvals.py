#!/usr/bin/env python3
"""Check for pending EP-Governance approvals and notify Discord.

Checks the governance DB for transitions in 'pending_approval' stage.
If any are found, posts them to Discord for the human administrator.

Silent when no pending approvals exist (watchdog pattern).

Usage:
    python3 scripts/check_pending_approvals.py
"""
import json
import os
import re
import subprocess
import sys
from urllib.parse import unquote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

DISCORD_CHANNEL = os.environ.get("DISCORD_CHANNEL_ID", "1505210063604940972")
DISCORD_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")


def get_pending_approvals():
    """Query the governance DB for pending approval transitions."""
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
        return []

    m = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not m:
        return []
    user, pwd_raw, host, port, db = m.groups()
    pwd = unquote(pwd_raw)
    env = {**os.environ, "PGPASSWORD": pwd}

    result = subprocess.run(
        ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-t", "-c",
         f"SELECT t.id, t.agent_id, t.tool, t.stage, t.created_at, "
         f"p.name as agent_name "
         f"FROM {schema}.ep_transitions t "
         f"LEFT JOIN {schema}.ep_principals p ON t.agent_id = p.id "
         f"WHERE t.stage = 'pending_approval' "
         f"ORDER BY t.created_at DESC LIMIT 10;"],
        capture_output=True, text=True, timeout=15, env=env,
    )

    approvals = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 6:
            approvals.append({
                "transition_id": parts[0],
                "agent_id": parts[1],
                "tool": parts[2],
                "stage": parts[3],
                "created_at": parts[4],
                "agent_name": parts[5],
            })
    return approvals


def send_discord(message):
    """Send a message to Discord."""
    if not DISCORD_TOKEN:
        print("DISCORD_BOT_TOKEN not set, skipping Discord notification")
        return False

    payload = json.dumps({"content": message})
    with open("/tmp/ep_discord_notify.json", "w") as f:
        f.write(payload)

    result = subprocess.run(
        ["curl", "-s", "-X", "POST",
         "-H", f"Authorization: Bot {DISCORD_TOKEN}",
         "-H", "Content-Type: application/json",
         "-d", "@/tmp/ep_discord_notify.json",
         f"https://discord.com/api/v10/channels/{DISCORD_CHANNEL}/messages"],
        capture_output=True, text=True, timeout=30,
    )
    return "type" in result.stdout


def main():
    approvals = get_pending_approvals()

    if not approvals:
        # Silent -- no pending approvals
        return

    lines = ["EP-Governance: Pending Approvals Need Your Attention", ""]
    for a in approvals:
        agent = a.get("agent_name") or a.get("agent_id", "unknown")
        lines.append(
            f"Transition: {a['transition_id']}\n"
            f"  Agent: {agent}\n"
            f"  Tool: {a['tool']}\n"
            f"  Stage: {a['stage']}\n"
            f"  Created: {a['created_at']}\n"
            f"  To approve: ep-governance approve --approval {a['transition_id']}\n"
            f"  To deny: ep-governance deny --approval {a['transition_id']}"
        )
        lines.append("")

    message = "\n".join(lines)
    if send_discord(message):
        print(f"Notified Discord about {len(approvals)} pending approval(s)")
    else:
        print(f"Found {len(approvals)} pending approval(s) but Discord notification failed")
        print(message)


if __name__ == "__main__":
    main()