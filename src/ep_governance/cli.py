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
from .errors import EPError, PolicyIntegrityError
from .transitions import TransitionEngine
from .branches import BranchCommitter
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
    engine = create_engine(cfg.db_url, schema=cfg.db_schema or None)
    return engine.connect()


def _get_engine():
    """Load config and return a SQLAlchemy Engine."""
    cfg = load_config()
    return create_engine(cfg.db_url, schema=cfg.db_schema or None)


def _get_conn_with_migrations() -> Connection:
    """Load config, run migrations, return connection."""
    cfg = load_config()
    engine = create_engine(cfg.db_url, schema=cfg.db_schema or None)
    conn = engine.connect()
    dialect = "sqlite" if is_sqlite(conn) else "postgres"
    run_migrations(conn, dialect)
    conn.commit()
    return conn


def _ensure_ep_service_principal_in_transaction(conn: Connection) -> str:
    """Get or create the EP service principal without committing."""
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
    return p["id"]


def _ensure_ep_service_principal(conn: Connection) -> str:
    """Get or create the EP service principal and commit standalone use."""
    ep_id = _ensure_ep_service_principal_in_transaction(conn)
    conn.commit()
    return ep_id


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


def _build_policy_engine_cli(conn, branch_id: str | None = None, agent_id: str | None = None):
    """Load active policies and build a PolicyEngine for the given context."""
    from .policies import Policy
    from .policy_engine import PolicyEngine
    from .db.repositories import PolicyRepository

    repo = PolicyRepository(conn)
    project_id = None
    if branch_id:
        # Resolve project_id from branch_id
        import sqlalchemy as _sa
        result = conn.execute(
            _sa.text(
                "SELECT l.project_id FROM ep_branches b "
                "JOIN ep_lattices l ON b.lattice_id = l.id "
                "WHERE b.id = :bid"
            ),
            {"bid": branch_id},
        )
        row = result.fetchone()
        if row:
            project_id = row[0]

    if not branch_id or not project_id or not agent_id:
        raise PolicyIntegrityError(
            "branch_id, project_id, and agent_id are required for governed policy evaluation"
        )

    policy_rows = repo.list_effective_policies(project_id, branch_id, agent_id)
    allowed_fields = {
        "id", "effect", "actions", "resources", "conditions", "priority",
        "scope", "agent_scope", "project_id", "branch_id", "description",
        "status", "created_by", "approved_by", "approved_at",
        "activation_version", "exception_to", "valid_from", "valid_until",
        "justification",
    }
    import datetime as _dt
    policies = []
    for row in policy_rows:
        filtered = {k: v for k, v in row.items() if k in allowed_fields}
        for k, v in filtered.items():
            if isinstance(v, _dt.datetime):
                filtered[k] = v.isoformat()
        try:
            policies.append(Policy.model_validate(filtered))
        except Exception as exc:
            raise PolicyIntegrityError(
                f"Active policy {row.get('id', '<unknown>')} is invalid"
            ) from exc

    return PolicyEngine(policies)


# ---------------------------------------------------------------------------
# Check and execute
# ---------------------------------------------------------------------------


@app.command()
def check(
    tool: str = typer.Option(..., "--tool", help="Tool name."),
    arguments: str = typer.Option(..., "--arguments", help="JSON arguments."),
    branch: str = typer.Option(..., "--branch", help="Branch XID (required for governed evaluation)."),
    agent: str = typer.Option(..., "--agent", help="Agent principal XID."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Evaluate a proposed action without executing (advisory mode)."""
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        import json as json_mod

        args = json_mod.loads(arguments)
        policy_engine = _build_policy_engine_cli(conn, branch_id=branch, agent_id=agent)
        trans_engine = TransitionEngine(conn.engine, ep_id, policy_engine=policy_engine)
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
        policy_engine = _build_policy_engine_cli(conn, branch_id=branch, agent_id=agent)
        trans_engine = TransitionEngine(conn.engine, ep_id, policy_engine=policy_engine)
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
            # Resolve project_id from branch for scoped policy count
            import sqlalchemy as _sa
            proj_result = conn.execute(
                _sa.text(
                    "SELECT l.project_id FROM ep_branches b "
                    "JOIN ep_lattices l ON b.lattice_id = l.id "
                    "WHERE b.id = :bid"
                ),
                {"bid": branch},
            )
            proj_row = proj_result.fetchone()
            if proj_row:
                policies = policy_repo.list_active_policies_for_project(proj_row[0])
            else:
                policies = []
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
        verifier = AuditVerifier(conn.engine)
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
        trans_engine = TransitionEngine(conn.engine, ep_id)
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
        trans_engine = TransitionEngine(conn.engine, ep_id)
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
# Bootstrap administrator
# ---------------------------------------------------------------------------


@app.command()
def bootstrap_admin(
    principal: str = typer.Option(..., "--principal", help="Principal XID to bind as administrator."),
    bootstrap_token: str = typer.Option(
        None, "--bootstrap-token", help="High-entropy bootstrap credential (or EP_BOOTSTRAP_TOKEN env var)."
    ),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """One-time secure administrator enrollment.

    Requires a separate high-entropy bootstrap credential (provided via
    --bootstrap-token or the EP_BOOTSTRAP_TOKEN environment variable).
    The supplied token is verified against ``bootstrap_token_hash`` in the
    loaded configuration (set via the ``EP_BOOTSTRAP_TOKEN_HASH`` environment
    variable) using a constant-time SHA-256 comparison.  The plaintext token
    is never stored.

    All checks and enrollment happen inside a single SERIALIZABLE
    transaction with a singleton constraint on ``ep_bootstrap_state``
    (``singleton_id = 1``), eliminating the TOCTOU race where two operators
    could bootstrap concurrently.  All subsequent bootstrap attempts are
    rejected.

    Generate a token and its hash with:
        python3 -c "import secrets, hashlib; t=secrets.token_urlsafe(32); print(t, hashlib.sha256(t.encode()).hexdigest())"
    """
    import os as _os
    import sqlalchemy as _sa
    from .xid import XID as _XID
    from .db.transactions import serializable_transaction
    from .audit import AuditWriter

    # Allow environment variable override (avoids CLI history leakage)
    token = bootstrap_token or _os.environ.get("EP_BOOTSTRAP_TOKEN", "")
    if not token:
        _error("Bootstrap token required. Use --bootstrap-token or set EP_BOOTSTRAP_TOKEN env var.", json)
        raise typer.Exit(1)

    # Load config to obtain the configured bootstrap token hash
    cfg = load_config()
    configured_hash = cfg.bootstrap_token_hash
    if not configured_hash:
        _error(
            "Bootstrap token hash must be configured before running bootstrap-admin. "
            "Set EP_BOOTSTRAP_TOKEN_HASH environment variable.",
            json,
        )
        raise typer.Exit(1)

    try:
        conn = _get_conn()

        # Commit any pending autobegun transaction so the
        # serializable_transaction context manager receives a clean connection.
        if conn.in_transaction():
            conn.commit()

        # --- ALL reads and writes inside ONE serializable transaction ---
        with serializable_transaction(conn):
            # a. Check ep_bootstrap_state singleton — reject if already completed
            bs_result = conn.execute(
                _sa.text("SELECT completed FROM ep_bootstrap_state WHERE singleton_id = 1")
            )
            bs_row = bs_result.fetchone()
            if bs_row is not None and bs_row[0]:
                _error(
                    "Bootstrap is already complete. Administrator enrollment is a one-time operation.",
                    json,
                )
                raise typer.Exit(1)

            # b. Verify no administrator role binding exists
            result = conn.execute(
                _sa.text(
                    "SELECT rb.id FROM ep_role_bindings rb "
                    "JOIN ep_roles r ON rb.role_id = r.id "
                    "WHERE r.name = 'administrator' LIMIT 1"
                )
            )
            if result.fetchone() is not None:
                _error("An administrator role binding already exists. Bootstrap is not needed.", json)
                raise typer.Exit(1)

            # c. Verify the principal exists and is a human
            principal_repo = PrincipalRepository(conn)
            p = principal_repo.get_principal(principal)
            if p is None:
                _error(f"Principal '{principal}' not found.", json)
                raise typer.Exit(1)
            if p.get("type") != "human":
                _error(f"Principal must be type 'human', got '{p.get('type')}'.", json)
                raise typer.Exit(1)

            # d. Verify bootstrap token hash (constant-time compare)
            import hashlib
            import secrets

            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if not secrets.compare_digest(token_hash, configured_hash):
                _error("Bootstrap token verification failed.", json)
                raise typer.Exit(1)

            # e. Ensure EP service principal exists (NO commit — caller owns tx)
            ep_id = _ensure_ep_service_principal_in_transaction(conn)

            # f. Create or find administrator role
            result = conn.execute(
                _sa.text("SELECT id FROM ep_roles WHERE name = 'administrator' LIMIT 1")
            )
            role_row = result.fetchone()
            if role_row is not None:
                role_id = role_row[0]
            else:
                role_id = str(_XID.new())
                conn.execute(
                    _sa.text(
                        "INSERT INTO ep_roles (id, name, permissions) VALUES (:id, 'administrator', :perms)"
                    ),
                    {"id": role_id, "perms": '["*"]'},
                )

            # g. Bind the principal as administrator (global scope)
            binding_id = str(_XID.new())
            conn.execute(
                _sa.text(
                    "INSERT INTO ep_role_bindings (id, principal_id, role_id, project_id) "
                    "VALUES (:id, :principal_id, :role_id, NULL)"
                ),
                {"id": binding_id, "principal_id": principal, "role_id": role_id},
            )

            # h. Record bootstrap completion in the singleton row.
            #    Use INSERT OR IGNORE (SQLite) / INSERT ON CONFLICT DO NOTHING
            #    (Postgres) to create the initial row, then UPDATE it.
            dialect = conn.dialect.name
            if dialect == "sqlite":
                conn.execute(
                    _sa.text(
                        "INSERT OR IGNORE INTO ep_bootstrap_state (singleton_id, completed, completed_by) "
                        "VALUES (1, FALSE, :completed_by)"
                    ),
                    {"completed_by": principal},
                )
                conn.execute(
                    _sa.text(
                        "UPDATE ep_bootstrap_state "
                        "SET completed = TRUE, completed_by = :completed_by, "
                        "    completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') "
                        "WHERE singleton_id = 1"
                    ),
                    {"completed_by": principal},
                )
            else:
                conn.execute(
                    _sa.text(
                        "INSERT INTO ep_bootstrap_state (singleton_id, completed, completed_by) "
                        "VALUES (1, FALSE, :completed_by) "
                        "ON CONFLICT (singleton_id) DO NOTHING"
                    ),
                    {"completed_by": principal},
                )
                conn.execute(
                    _sa.text(
                        "UPDATE ep_bootstrap_state "
                        "SET completed = TRUE, completed_by = :completed_by, "
                        "    completed_at = NOW() "
                        "WHERE singleton_id = 1"
                    ),
                    {"completed_by": principal},
                )

            # i. Write audit event in the SAME transaction
            lat_result = conn.execute(_sa.text("SELECT id FROM ep_lattices LIMIT 1"))
            lat_row = lat_result.fetchone()
            lattice_id = lat_row[0] if lat_row is not None else None

            if lattice_id is not None:
                writer = AuditWriter(conn.engine, ep_id)
                writer.write_event_in_transaction(
                    conn,
                    lattice_id=lattice_id,
                    event_type="bootstrap.admin_enrolled",
                    event_data={
                        "principal_id": principal,
                        "role": "administrator",
                        "binding_id": binding_id,
                    },
                    actor_principal_id=principal,
                    authenticated_caller_id=principal,
                )

        conn.close()
        _output(
            {
                "status": "bootstrap_complete",
                "principal_id": principal,
                "role": "administrator",
                "binding_id": binding_id,
            },
            json,
        )
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Transition reconciliation (operator commands)
# ---------------------------------------------------------------------------


@app.command()
def mark_uncertain(
    transition: str = typer.Option(..., "--transition", help="Transition XID to mark as execution_uncertain."),
    reason: str = typer.Option("Operator-initiated timeout", "--reason", "-r"),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Mark a transition as execution_uncertain (operator override).

    Use when a transition is stuck in 'executing' and the proxy is
    unreachable or has crashed. This moves the transition to
    execution_uncertain so it can be reconciled later.
    """
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        trans_engine = TransitionEngine(conn.engine, ep_id)
        result = trans_engine.record_result(transition, "timeout", reason)
        conn.commit()
        conn.close()
        _output({"transition_id": transition, "stage": result["stage"], "reason": reason}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@app.command()
def reconcile(
    transition: str = typer.Option(..., "--transition", help="Transition XID to reconcile."),
    outcome: str = typer.Option(..., "--outcome", help="Final outcome: 'succeeded' or 'failed'."),
    reason: str = typer.Option("Operator reconciliation", "--reason", "-r"),
    branch: str = typer.Option(None, "--branch", help="Branch XID (required for succeeded)."),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Reconcile a transition from execution_uncertain to a final state.

    Use after investigating an execution_uncertain transition. If the
    action actually completed, use --outcome succeeded. If it did not,
    use --outcome failed.
    """
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        trans_engine = TransitionEngine(conn.engine, ep_id)

        if outcome == "succeeded":
            if not branch:
                _error("--branch is required when --outcome succeeded", json)
                raise typer.Exit(1)
            branch_committer = BranchCommitter(conn.engine, ep_id)
            # Get current branch head
            branch_repo = BranchRepository(conn)
            head_id, version = branch_repo.get_head(branch)
            lattice_result = conn.execute(
                __import__("sqlalchemy").text(
                    "SELECT lattice_id FROM ep_branches WHERE id = :bid"
                ),
                {"bid": branch},
            )
            lattice_row = lattice_result.fetchone()
            lattice_id = lattice_row[0] if lattice_row else branch
            conn.commit()
            result = trans_engine.reconcile(
                transition, "succeeded", reason,
                branch_committer=branch_committer,
                expected_head_id=head_id,
                expected_version=version,
                lattice_id=lattice_id,
            )
        else:
            result = trans_engine.reconcile(transition, "failed", reason)

        conn.commit()
        conn.close()
        _output({"transition_id": transition, "stage": result["stage"], "outcome": outcome}, json)
    except EPError as exc:
        _error(str(exc), json)
        raise typer.Exit(1)


@app.command()
def expire(
    transition: str = typer.Option(..., "--transition", help="Transition XID to expire."),
    reason: str = typer.Option("Authorization expired", "--reason", "-r"),
    json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Expire a transition that is authorized or pending_approval.

    Use when an authorization has been issued but never claimed, or
    an approval request has timed out. This moves the transition to
    the 'expired' terminal state. Only valid from 'authorized' or
    'pending_approval' stages.
    """
    try:
        conn = _get_conn()
        ep_id = _ensure_ep_service_principal(conn)
        trans_engine = TransitionEngine(conn.engine, ep_id)
        result = trans_engine.advance_stage(transition, "expired")
        conn.commit()
        conn.close()
        _output({"transition_id": transition, "stage": result["stage"], "reason": reason}, json)
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
    import asyncio
    from .mcp_server import run_server
    cfg = load_config()
    # In advisory/dev mode, use the EP service principal for MCP operations
    # In production, this must come from authenticated transport credentials
    import sqlalchemy as _sa
    engine = _sa.create_engine(cfg.db_url) if not cfg.db_schema else None
    if engine is None:
        from .db.postgres import create_engine as _ce
        engine = _ce(cfg.db_url, schema=cfg.db_schema or None)
    with engine.connect() as _conn:
        result = _conn.execute(_sa.text("SELECT id FROM ep_principals WHERE type='service' AND name='EP Service' LIMIT 1"))
        row = result.fetchone()
        principal_id = row[0] if row else None
    if not principal_id:
        typer.echo("ERROR: EP Service principal not found. Run 'ep-governance init' first.")
        raise typer.Exit(1)
    asyncio.run(run_server(
        mode=cfg.mode,
        authenticated_principal_id=principal_id,
    ))


def main() -> None:
    """Entry point for the ep-governance CLI."""
    app()


if __name__ == "__main__":
    main()
