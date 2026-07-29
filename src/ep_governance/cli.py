"""EP-Governance CLI.

Provides command-line access to all governance operations:
init, register, project/branch management, policy management,
check, execute, status, log, audit, approvals, transfer, serve.

Outputs machine-readable JSON with --json flag.
Human-readable output by default.
No secret leakage in any output.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import typer
from sqlalchemy.engine import Connection

from .audit import AuditVerifier
from .config import load_config
from .db import run_migrations
from .db.postgres import create_engine, is_sqlite
from .db.repositories import (
    ApprovalRepository,
    BranchRepository,
    LatticeRepository,
    PolicyRepository,
    PrincipalRepository,
    ProjectRepository,
    TransitionRepository,
)
from .errors import EPError
from .transitions import TransitionEngine
from .xid import XID

app = typer.Typer(
    name="ep-governance",
    help="Binding governance system for AI agents.",
    no_args_is_help=True,
)

# Sub-apps
policy_app = typer.Typer(name="policy", help="Policy management.")
project_app = typer.Typer(name="project", help="Project and branch management.")
audit_app = typer.Typer(name="audit", help="Audit log and verification.")

app.add_typer(policy_app, name="policy")
app.add_typer(project_app, name="project")
app.add_typer(audit_app, name="audit")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_conn() -> Connection:
    """Load config and return a database connection."""
    cfg = load_config()
    engine = create_engine(cfg.db_url)
    return engine.connect()


def _get_conn_with_migrations() -> Connection:
    """Load config, run migrations, return connection."""
    cfg = load_config()
    engine = create_engine(cfg.db_url)
    conn = engine.connect()
    dialect = "sqlite" if is_sqlite(conn) else "postgres"
    run_migrations(conn, dialect)
    conn.commit()
    return conn


def _ensure_ep_service_principal(conn: Connection) -> str:
    """Get or create the EP service principal."""
    repo = PrincipalRepository(conn)
    result = conn.execute(
        __import__("sqlalchemy").text(
            "SELECT id FROM ep_principals WHERE type = 'service' AND name = 'EP Service' LIMIT 1"
        )
    )
    row = result.fetchone()
    if row:
        return row[0]
    p = repo.insert_principal(
        principal_id=str(XID.new()),
        name="EP Service",
        type="service",
        machine=None,
        description="Trusted EP service principal",
    )
    conn.commit()
    return p["id"]


def _output(data: Any, json_mode: bool = False) -> None:
    """Print data as JSON or human-readable."""
    if json_mode:
        print(json.dumps(data, indent=2, default=str))
    else:
        if isinstance(data, dict):
            for k, v in data.items():
                print(f"  {k}: {v}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    print(json.dumps(item, default=str))
                else:
                    print(item)
        else:
            print(data)


def _error(msg: str, json_mode: bool = False) -> None:
    """Print an error message."""
    if json_mode:
        print(json.dumps({"error": msg}))
    else:
        print(f"Error: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Setup commands
# ---------------------------------------------------------------------------


@app.command()
def init(
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize the database schema."""
    try:
        conn = _get_conn_with_migrations()
        ep_id = _ensure_ep_service_principal(conn)
        conn.close()
        _output({"status": "initialized", "ep_service_principal_id": ep_id}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@app.command()
def register(
    name: str = typer.Option(..., "--name", help="Principal name."),
    type: str = typer.Option(..., "--type", help="Principal type: human, agent, service, proxy."),
    enrollment_token: str = typer.Option(
        None, "--enrollment-token", help="Enrollment token (for agents)."
    ),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Register a new principal."""
    try:
        conn = _get_conn()
        repo = PrincipalRepository(conn)
        principal = repo.insert_principal(
            principal_id=str(XID.new()),
            name=name,
            type=type,
            machine=None,
            description=f"Registered via CLI ({type})",
        )
        conn.commit()
        conn.close()
        _output({"principal_id": principal["id"], "name": name, "type": type}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Project commands
# ---------------------------------------------------------------------------


@project_app.command("create")
def create_project(
    name: str = typer.Argument(..., help="Project name."),
    description: str = typer.Option("", "--description", "-d", help="Project description."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Create a new project."""
    try:
        conn = _get_conn()
        repo = ProjectRepository(conn)
        project = repo.create_project(name, description)
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")
        branch_repo = BranchRepository(conn)
        branch = branch_repo.create_branch(lattice["id"], "main")
        conn.commit()
        conn.close()
        _output(
            {
                "project_id": project["id"],
                "lattice_id": lattice["id"],
                "branch_id": branch["id"],
                "name": name,
            },
            json,
        )
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@project_app.command("create-branch")
def create_branch(
    project: str = typer.Option(..., "--project", help="Project XID."),
    name: str = typer.Option(..., "--name", help="Branch name."),
    from_branch: str = typer.Option(None, "--from-branch", help="Parent branch name to fork from."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Create a new branch."""
    try:
        conn = _get_conn()
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.get_by_project(project)
        if lattice is None:
            _error(f"No lattice found for project {project}", json)
            raise typer.Exit(1)
        branch_repo = BranchRepository(conn)
        head_node_id = None
        if from_branch:
            # Find the parent branch and use its head
            branches = conn.execute(
                __import__("sqlalchemy").text(
                    "SELECT id, head_node_id FROM ep_branches "
                    "WHERE lattice_id = :lid AND name = :name AND status = 'active'"
                ),
                {"lid": lattice["id"], "name": from_branch},
            )
            row = branches.fetchone()
            if row:
                head_node_id = row[1]
        branch = branch_repo.create_branch(lattice["id"], name, head_node_id)
        conn.commit()
        conn.close()
        _output({"branch_id": branch["id"], "name": name, "head_node_id": head_node_id}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@project_app.command("list")
def list_projects(
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List all projects."""
    try:
        conn = _get_conn()
        repo = ProjectRepository(conn)
        projects = repo.list_projects()
        conn.close()
        _output(projects, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Policy commands
# ---------------------------------------------------------------------------


@policy_app.command("add")
def add_policy(
    effect: str = typer.Option(..., "--effect", help="deny, require_approval, warn, allow."),
    actions: str = typer.Option(..., "--actions", help="JSON array of action types."),
    resources: str = typer.Option(..., "--resources", help="JSON array of resource patterns."),
    scope: str = typer.Option("global", "--scope", help="global or agent."),
    priority: int = typer.Option(0, "--priority", help="Priority (higher wins)."),
    description: str = typer.Option("", "--description", "-d"),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Create a new policy in draft status."""
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        repo = PolicyRepository(conn)
        import json as json_mod

        policy = repo.insert_policy(
            {
                "id": str(XID.new()),
                "effect": effect,
                "actions": json_mod.loads(actions),
                "resources": json_mod.loads(resources),
                "conditions": {},
                "priority": priority,
                "scope": scope,
                "agent_scope": None,
                "description": description,
                "status": "draft",
                "created_by": ep_id,
                "approved_by": None,
                "approved_at": None,
                "activation_version": None,
                "exception_to": [],
                "valid_from": None,
                "valid_until": None,
                "justification": None,
            }
        )
        conn.commit()
        conn.close()
        _output({"policy_id": policy["id"], "status": "draft", "effect": effect}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@policy_app.command("submit")
def submit_policy(
    policy_id: str = typer.Argument(..., help="Policy XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Submit a draft policy for approval."""
    try:
        conn = _get_conn()
        repo = PolicyRepository(conn)
        repo.update_status(policy_id, "pending_approval")
        conn.commit()
        conn.close()
        _output({"policy_id": policy_id, "status": "pending_approval"}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@policy_app.command("approve")
def approve_policy(
    policy_id: str = typer.Argument(..., help="Policy XID."),
    approver: str = typer.Option(..., "--approver", help="Approver principal XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Approve a pending policy (moves to active)."""
    try:
        conn = _get_conn()
        from datetime import UTC, datetime

        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        repo = PolicyRepository(conn)
        repo.approve_policy(policy_id, approver, now)
        conn.commit()
        conn.close()
        _output({"policy_id": policy_id, "status": "active", "approved_by": approver}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@policy_app.command("list")
def list_policies(
    agent: str = typer.Option(None, "--agent", help="Filter by agent XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List active policies."""
    try:
        conn = _get_conn()
        repo = PolicyRepository(conn)
        policies = repo.list_active_policies()
        conn.close()
        _output(policies, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@policy_app.command("retire")
def retire_policy(
    policy_id: str = typer.Argument(..., help="Policy XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Retire a policy."""
    try:
        conn = _get_conn()
        repo = PolicyRepository(conn)
        repo.update_status(policy_id, "retired")
        conn.commit()
        conn.close()
        _output({"policy_id": policy_id, "status": "retired"}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Check and execute
# ---------------------------------------------------------------------------


@app.command()
def check(
    tool: str = typer.Option(..., "--tool", help="Tool name."),
    arguments: str = typer.Option(..., "--arguments", help="JSON arguments."),
    branch: str = typer.Option(None, "--branch", help="Branch XID."),
    agent: str = typer.Option(..., "--agent", help="Agent principal XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Evaluate a proposed action without executing (advisory mode)."""
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        import json as json_mod

        args = json_mod.loads(arguments)
        trans_engine = TransitionEngine(conn, ep_id)
        transition = trans_engine.propose(
            agent_id=agent,
            branch_id=branch or "",
            tool=tool,
            arguments=args,
            idempotency_key=str(XID.new()),
        )
        conn.commit()
        conn.close()
        _output(transition, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@app.command()
def execute(
    tool: str = typer.Option(..., "--tool", help="Tool name."),
    arguments: str = typer.Option(..., "--arguments", help="JSON arguments."),
    branch: str = typer.Option(..., "--branch", help="Branch XID."),
    agent: str = typer.Option(..., "--agent", help="Agent principal XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Request authorization and execute through the governed proxy."""
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        import json as json_mod

        args = json_mod.loads(arguments)
        trans_engine = TransitionEngine(conn, ep_id)
        transition = trans_engine.propose(
            agent_id=agent,
            branch_id=branch,
            tool=tool,
            arguments=args,
            idempotency_key=str(XID.new()),
        )
        conn.commit()
        _output({"transition_id": transition["id"], "stage": transition["stage"]}, json)
        conn.close()
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Status and log
# ---------------------------------------------------------------------------


@app.command()
def status(
    branch: str = typer.Option(None, "--branch", help="Branch XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show current branch head, BT, risk per domain, policy count."""
    try:
        conn = _get_conn()
        if branch:
            branch_repo = BranchRepository(conn)
            head_id, version = branch_repo.get_head(branch)
            policy_repo = PolicyRepository(conn)
            policies = policy_repo.list_active_policies()
            _output(
                {
                    "branch_id": branch,
                    "head_node_id": head_id,
                    "version": version,
                    "active_policies": len(policies),
                },
                json,
            )
        else:
            _output({"message": "Specify --branch to see status"}, json)
        conn.close()
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@app.command()
def log(
    agent: str = typer.Option(None, "--agent", help="Filter by agent XID."),
    violations: bool = typer.Option(False, "--violations", help="Only denials and overrides."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show recent transitions."""
    try:
        conn = _get_conn()
        trans_repo = TransitionRepository(conn)
        # Simple: list recent transitions
        result = conn.execute(
            __import__("sqlalchemy").text(
                "SELECT id, agent_id, branch_id, tool, stage, created_at "
                "FROM ep_transitions ORDER BY created_at DESC LIMIT 20"
            )
        )
        rows = [dict(r._mapping) for r in result.fetchall()]
        conn.close()
        _output(rows, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Audit commands
# ---------------------------------------------------------------------------


@audit_app.command("verify")
def audit_verify(
    lattice: str = typer.Option(..., "--lattice", help="Lattice XID to verify."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Verify the audit chain for a lattice."""
    try:
        conn = _get_conn()
        verifier = AuditVerifier(conn)
        result = verifier.verify(lattice)
        conn.close()
        _output({"lattice_id": lattice, "valid": result}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@audit_app.command("list")
def audit_list(
    lattice: str = typer.Option(..., "--lattice", help="Lattice XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List audit events for a lattice."""
    try:
        conn = _get_conn()
        result = conn.execute(
            __import__("sqlalchemy").text(
                "SELECT id, sequence, event_type, previous_hash, event_hash, created_at "
                "FROM ep_events WHERE lattice_id = :lid ORDER BY sequence"
            ),
            {"lid": lattice},
        )
        rows = [dict(r._mapping) for r in result.fetchall()]
        conn.close()
        _output(rows, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------


@app.command()
def pending_approvals(
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List pending approval requests."""
    try:
        conn = _get_conn()
        result = conn.execute(
            __import__("sqlalchemy").text(
                "SELECT id, transition_id, policy_id, requested_by, justification, status "
                "FROM ep_approval_requests WHERE status = 'pending' ORDER BY created_at"
            )
        )
        rows = [dict(r._mapping) for r in result.fetchall()]
        conn.close()
        _output(rows, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@app.command()
def approve(
    approval_id: str = typer.Argument(..., help="Approval request XID."),
    reason: str = typer.Option("Approved", "--reason", "-r"),
    approver: str = typer.Option(..., "--approver", help="Approver principal XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Approve a pending request."""
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        approval_repo = ApprovalRepository(conn)
        req = approval_repo.get_request(approval_id)
        if req is None:
            _error(f"Approval request {approval_id} not found", json)
            raise typer.Exit(1)
        # Commit any pending reads so TransitionEngine.approve receives a clean
        # connection (it opens its own transaction — Issue Critical 2 / High 6).
        conn.commit()
        trans_engine = TransitionEngine(conn, ep_id)
        result = trans_engine.approve(
            transition_id=req["transition_id"],
            approver_id=approver,
            approver_type="human",
            reason=reason,
        )
        conn.commit()
        conn.close()
        _output(
            {
                "approval_id": approval_id,
                "transition_id": req["transition_id"],
                "stage": result["stage"],
            },
            json,
        )
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@app.command()
def deny(
    approval_id: str = typer.Argument(..., help="Approval request XID."),
    reason: str = typer.Option("Denied", "--reason", "-r"),
    approver: str = typer.Option(..., "--approver", help="Approver principal XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Deny a pending request."""
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        approval_repo = ApprovalRepository(conn)
        req = approval_repo.get_request(approval_id)
        if req is None:
            _error(f"Approval request {approval_id} not found", json)
            raise typer.Exit(1)
        # Commit any pending reads so TransitionEngine.deny_approval receives a
        # clean connection (it opens its own transaction — Issue Critical 2 / High 6).
        conn.commit()
        trans_engine = TransitionEngine(conn, ep_id)
        result = trans_engine.deny_approval(
            transition_id=req["transition_id"],
            approver_id=approver,
            reason=reason,
        )
        conn.commit()
        conn.close()
        _output(
            {
                "approval_id": approval_id,
                "transition_id": req["transition_id"],
                "stage": result["stage"],
            },
            json,
        )
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------


@app.command()
def serve(
    http: bool = typer.Option(False, "--http", help="Use HTTP transport instead of stdio."),
    port: int = typer.Option(8200, "--port", help="HTTP port."),
) -> None:
    """Start the MCP server."""
    typer.echo("MCP server not yet implemented (Phase 7).")


def main() -> None:
    """Entry point for the ep-governance CLI."""
    app()


if __name__ == "__main__":
    main()
