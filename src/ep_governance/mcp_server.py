"""EP-Governance MCP server.

Exposes governance operations as MCP tools for AI agent integration.

In enforced mode, only governed execution and governance management tools
are exposed. Raw protected tools (shell.exec, postgres.execute, etc.) are
NOT exposed — agents must go through ep_execute.

In advisory mode, ep_check and governance management tools are available.
"""

from __future__ import annotations

import json
import os
import secrets
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .config import load_config
from .db.postgres import create_engine
from .db.repositories import (
    ApprovalRepository,
    BranchRepository,
    PolicyRepository,
    PrincipalRepository,
)
from .errors import PolicyIntegrityError, EPError
from .policy_engine import PolicyEngine
from .transitions import TransitionEngine
from .xid import XID

__all__ = ["create_server", "run_server", "get_tools"]


# --------------------------------------------------------------------------- #
# Role-based authorization for MCP tools
# --------------------------------------------------------------------------- #

# Required roles per tool name.  A principal must hold at least one of the
# listed roles to invoke the tool.  See ``_check_role`` for the lookup logic.
TOOL_REQUIRED_ROLES: dict[str, list[str]] = {
    "ep_check": ["agent", "operator", "administrator"],
    "ep_execute": ["agent", "operator", "administrator"],
    "ep_status": ["observer", "agent", "operator", "administrator"],
    "ep_log": ["observer", "agent", "operator", "administrator"],
    "ep_list_policies": ["observer", "agent", "operator", "administrator"],
    "ep_pending_approvals": ["observer", "agent", "operator", "administrator"],
    "ep_approve": ["policy_approver", "administrator"],
    "ep_deny": ["policy_approver", "administrator"],
    "ep_audit_verify": ["auditor", "administrator"],
}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

ADVISORY_TOOLS: list[Tool] = [
    Tool(
        name="ep_check",
        description="Evaluate a proposed action without executing. Returns admissible/denied/pending.",
        inputSchema={
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Tool name (e.g. postgres.execute)"},
                "arguments": {"type": "object", "description": "Tool arguments as JSON"},
                "branch_id": {"type": "string", "description": "Branch XID"},
                # agent_id is no longer caller-supplied; it is derived from the
                # authenticated MCP session principal (see create_server).
            },
            "required": ["tool", "arguments"],
        },
    ),
    Tool(
        name="ep_status",
        description="Get current governance status: branch head, version, active policies.",
        inputSchema={
            "type": "object",
            "properties": {
                "branch_id": {"type": "string", "description": "Branch XID (optional)"},
            },
        },
    ),
    Tool(
        name="ep_log",
        description="List recent transitions.",
        inputSchema={
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Filter by agent XID (optional)"},
                "branch_id": {
                    "type": "string",
                    "description": "Branch XID (scopes results to project)",
                },
                "project_id": {
                    "type": "string",
                    "description": "Project XID (scopes results to project)",
                },
            },
        },
    ),
    Tool(
        name="ep_list_policies",
        description="List active governance policies.",
        inputSchema={
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Filter by agent XID (optional)"},
                "branch_id": {
                    "type": "string",
                    "description": "Branch XID (scopes results to project)",
                },
                "project_id": {
                    "type": "string",
                    "description": "Project XID (scopes results to project)",
                },
            },
        },
    ),
    Tool(
        name="ep_pending_approvals",
        description="List pending approval requests.",
        inputSchema={
            "type": "object",
            "properties": {
                "branch_id": {
                    "type": "string",
                    "description": "Branch XID (scopes results to project)",
                },
                "project_id": {
                    "type": "string",
                    "description": "Project XID (scopes results to project)",
                },
            },
        },
    ),
    Tool(
        name="ep_approve",
        description="Approve a pending request. Requires policy_approver role.",
        inputSchema={
            "type": "object",
            "properties": {
                "approval_id": {"type": "string", "description": "Approval request XID"},
                # approver_id is no longer caller-supplied; it is derived from
                # the authenticated MCP session principal (see create_server).
                "reason": {"type": "string", "description": "Approval reason"},
            },
            "required": ["approval_id"],
        },
    ),
    Tool(
        name="ep_deny",
        description="Deny a pending request. Requires policy_approver role.",
        inputSchema={
            "type": "object",
            "properties": {
                "approval_id": {"type": "string", "description": "Approval request XID"},
                # approver_id is no longer caller-supplied; it is derived from
                # the authenticated MCP session principal (see create_server).
                "reason": {"type": "string", "description": "Denial reason"},
            },
            "required": ["approval_id"],
        },
    ),
    Tool(
        name="ep_audit_verify",
        description="Verify the audit chain for a lattice.",
        inputSchema={
            "type": "object",
            "properties": {
                "lattice_id": {"type": "string", "description": "Lattice XID"},
            },
            "required": ["lattice_id"],
        },
    ),
]

ENFORCED_TOOLS: list[Tool] = [
    Tool(
        name="ep_execute",
        description="Request authorization and execute through the governed proxy. "
        "The agent does not hold target credentials — the proxy executes on the agent's behalf.",
        inputSchema={
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Tool name (e.g. postgres.execute)"},
                "arguments": {"type": "object", "description": "Tool arguments as JSON"},
                "branch_id": {"type": "string", "description": "Branch XID"},
                # agent_id is no longer caller-supplied; it is derived from the
                # authenticated MCP session principal (see create_server).
            },
            "required": ["tool", "arguments", "branch_id"],
        },
    ),
    Tool(
        name="ep_status",
        description="Get current governance status.",
        inputSchema={
            "type": "object",
            "properties": {
                "branch_id": {"type": "string"},
            },
        },
    ),
    Tool(
        name="ep_list_policies",
        description="List active governance policies.",
        inputSchema={
            "type": "object",
            "properties": {
                "branch_id": {
                    "type": "string",
                    "description": "Branch XID (scopes results to project)",
                },
                "project_id": {
                    "type": "string",
                    "description": "Project XID (scopes results to project)",
                },
            },
        },
    ),
    Tool(
        name="ep_pending_approvals",
        description="List pending approval requests.",
        inputSchema={
            "type": "object",
            "properties": {
                "branch_id": {
                    "type": "string",
                    "description": "Branch XID (scopes results to project)",
                },
                "project_id": {
                    "type": "string",
                    "description": "Project XID (scopes results to project)",
                },
            },
        },
    ),
    Tool(
        name="ep_approve",
        description="Approve a pending request. Requires policy_approver role and human principal.",
        inputSchema={
            "type": "object",
            "properties": {
                "approval_id": {"type": "string"},
                # approver_id is no longer caller-supplied; it is derived from
                # the authenticated MCP session principal (see create_server).
                "reason": {"type": "string"},
            },
            "required": ["approval_id"],
        },
    ),
    Tool(
        name="ep_audit_verify",
        description="Verify the audit chain for a lattice.",
        inputSchema={
            "type": "object",
            "properties": {"lattice_id": {"type": "string"}},
            "required": ["lattice_id"],
        },
    ),
]


def get_tools(mode: str = "enforced") -> list[Tool]:
    """Return the tool list for the given mode."""
    if mode == "enforced":
        return ENFORCED_TOOLS
    return ADVISORY_TOOLS


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def create_server(
    mode: str = "enforced",
    authenticated_principal_id: str | None = None,
) -> Server:
    """Create an MCP server with EP-Governance tools.

    Args:
        mode: 'enforced' or 'advisory'. In enforced mode, only ep_execute
              and governance management tools are exposed. In advisory mode,
              ep_check and all management tools are exposed.
        authenticated_principal_id: Principal XID of the authenticated caller.
              In production, this MUST come from the authenticated MCP session
              (TLS client certificate subject, API key identity, OAuth token
              subject, mTLS SPIFFE ID, etc.) — NOT from a constructor argument.
              The constructor argument is an interim convenience until a
              deployment-specific identity provider integration is wired in.

    The principal's type is NOT trusted from the caller.  It is loaded from
    the database on every tool invocation via :class:`PrincipalRepository`
    and verified to be active.  See :func:`_handle_tool_call`.
    """
    if not authenticated_principal_id:
        raise EPError(
            "create_server requires authenticated_principal_id; in production "
            "this must be derived from the MCP session (TLS cert, API key, "
            "OAuth token), not passed by the caller."
        )
    server: Server = Server("ep-governance")

    async def _list_tools(_request: Any) -> list[Tool]:
        return get_tools(mode)

    async def _call_tool(request: Any) -> list[TextContent]:
        name = request.params.name if hasattr(request, "params") else request.name
        arguments = request.params.arguments if hasattr(request, "params") else request.arguments
        if arguments is None:
            arguments = {}
        try:
            result = _handle_tool_call(
                name,
                arguments,
                mode,
                authenticated_principal_id,
            )
            return [TextContent(type="text", text=json.dumps(result, default=str))]
        except EPError as exc:
            return [TextContent(type="text", text=json.dumps({"error": str(exc)}))]
        except Exception:
            attempt_id = secrets.token_hex(8)
            return [
                TextContent(
                    type="text",
                    text=json.dumps({"error": f"Internal error (reference: {attempt_id})"}),
                )
            ]

    from mcp.types import CallToolRequest, ListToolsRequest

    server.add_request_handler("tools/list", ListToolsRequest, _list_tools)
    server.add_request_handler("tools/call", CallToolRequest, _call_tool)

    return server


def _handle_tool_call(
    name: str,
    arguments: dict[str, Any],
    mode: str,
    authenticated_principal_id: str,
) -> dict[str, Any]:
    """Handle a tool call and return a result dict.

    The caller's identity is taken from ``authenticated_principal_id`` (set
    at server creation time from authenticated session context), NOT from
    any field in ``arguments``.  Tool input schemas no longer accept
    ``agent_id`` or ``approver_id``.

    The principal's type is loaded from the database on every call and
    verified to be active.  The type is NOT trusted from the caller.
    """
    cfg = load_config()
    engine = create_engine(cfg.db_url)

    with engine.connect() as conn:
        # --- Verify the authenticated principal from the database --------
        repo = PrincipalRepository(conn)
        principal = repo.get_principal(authenticated_principal_id)
        if principal is None:
            return {
                "error": (
                    f"Authenticated principal '{authenticated_principal_id}' "
                    "not found in the database."
                )
            }
        if principal.get("status") != "active":
            return {
                "error": (
                    f"Authenticated principal '{authenticated_principal_id}' "
                    f"is not active (status: {principal.get('status')})."
                )
            }
        authenticated_principal_type: str = principal["type"]

        # --- Role-based authorization -----------------------------------
        required_roles = TOOL_REQUIRED_ROLES.get(name)
        if required_roles is not None:
            # Resolve project_id from tool arguments for project-scoped auth.
            project_id: str | None = None
            if name in ("ep_status", "ep_log", "ep_pending_approvals"):
                project_id = _resolve_project_id(conn, branch_id=arguments.get("branch_id"))
            elif name in ("ep_list_policies",):
                project_id = arguments.get("project_id") or _resolve_project_id(
                    conn, branch_id=arguments.get("branch_id")
                )
            elif name in ("ep_audit_verify",):
                project_id = _resolve_project_id(conn, lattice_id=arguments.get("lattice_id"))
            elif name in ("ep_approve", "ep_deny"):
                project_id = _resolve_project_id(conn, approval_id=arguments.get("approval_id"))
            # ep_check and ep_execute use branch_id for project context.
            elif name in ("ep_check", "ep_execute"):
                project_id = _resolve_project_id(conn, branch_id=arguments.get("branch_id"))

            role_err = _check_role(
                conn,
                authenticated_principal_id,
                required_roles,
                project_id=project_id,
                tool_name=name,
            )
            if role_err is not None:
                return role_err

        # --- Dispatch ----------------------------------------------------
        if name == "ep_check":
            return _ep_check(conn, arguments, authenticated_principal_id)
        elif name == "ep_execute":
            return _ep_execute(conn, arguments, authenticated_principal_id)
        elif name == "ep_status":
            return _ep_status(conn, arguments)
        elif name == "ep_log":
            return _ep_log(conn, arguments)
        elif name == "ep_list_policies":
            return _ep_list_policies(conn, arguments)
        elif name == "ep_pending_approvals":
            return _ep_pending_approvals(conn, arguments)
        elif name == "ep_approve":
            return _ep_approve(
                conn, arguments, authenticated_principal_id, authenticated_principal_type
            )
        elif name == "ep_deny":
            return _ep_deny(
                conn, arguments, authenticated_principal_id, authenticated_principal_type
            )
        elif name == "ep_audit_verify":
            return _ep_audit_verify(conn, arguments)
        else:
            return {"error": f"Unknown tool: {name}"}


# Tools allowed during bootstrap mode (setup-only operations only).
# Bootstrap mode grants access to read current policies and view state —
# it does NOT allow execution, approvals, denials, audit, log, or checks.
BOOTSTRAP_ALLOWED_TOOLS: frozenset[str] = frozenset(
    {
        "ep_list_policies",
        "ep_status",
    }
)


def _check_role(
    conn: Any,
    principal_id: str,
    required_roles: list[str],
    project_id: str | None = None,
    tool_name: str | None = None,
) -> dict[str, Any] | None:
    """Check whether *principal_id* holds any of *required_roles*.

    Queries ``ep_role_bindings`` joined with ``ep_roles`` to determine the
    principal's roles, scoped to *project_id*.  Global role bindings
    (``project_id IS NULL``) always apply; project-scoped bindings apply only
    when their ``project_id`` matches.  If *project_id* is ``None`` (no
    project context), only global role bindings are considered — this
    prevents a principal with a role in Project A from accessing Project B.

    Fail closed: if no matching role bindings exist, access is denied unless
    ``EP_BOOTSTRAP_MODE=true`` is set in the environment, in which case the
    first human principal is allowed access to **setup-only tools** (see
    ``BOOTSTRAP_ALLOWED_TOOLS``) for initial bootstrapping.  All other tools
    are denied with an instruction to create an administrator role binding.

    Returns ``None`` if authorized, or an error dict if denied.
    """
    import sqlalchemy as sa

    if project_id is None:
        # No project context — only global role bindings (project_id IS NULL).
        query = (
            "SELECT r.name "
            "FROM ep_role_bindings rb "
            "JOIN ep_roles r ON rb.role_id = r.id "
            "WHERE rb.principal_id = :principal_id "
            "  AND rb.project_id IS NULL"
        )
        params: dict[str, Any] = {"principal_id": principal_id}
    else:
        query = (
            "SELECT r.name "
            "FROM ep_role_bindings rb "
            "JOIN ep_roles r ON rb.role_id = r.id "
            "WHERE rb.principal_id = :principal_id "
            "  AND (rb.project_id IS NULL OR rb.project_id = :project_id)"
        )
        params = {"principal_id": principal_id, "project_id": project_id}

    result = conn.execute(sa.text(query), params)
    held_roles = {row[0] for row in result.fetchall()}

    if held_roles:
        # The principal has role bindings — check against required roles.
        if held_roles & set(required_roles):
            return None
        return {
            "error": (
                f"Principal '{principal_id}' lacks required role "
                f"(needs one of: {', '.join(required_roles)}; "
                f"has: {', '.join(sorted(held_roles))})."
            )
        }

    # No matching role bindings exist — fail closed.
    # The ONLY exception is explicit bootstrap mode (EP_BOOTSTRAP_MODE=true),
    # which allows the first human principal to access setup-only tools for
    # initial setup.  This must be turned off after bootstrapping is complete.
    bootstrap_mode = os.environ.get("EP_BOOTSTRAP_MODE", "").lower() == "true"
    if bootstrap_mode:
        repo = PrincipalRepository(conn)
        principal = repo.get_principal(principal_id)
        if principal and principal.get("type") == "human":
            # Verify this is truly the first human (no other humans have
            # role bindings yet) to limit bootstrap access to initial setup.
            human_with_roles = conn.execute(
                sa.text(
                    "SELECT COUNT(*) FROM ep_role_bindings rb "
                    "JOIN ep_principals p ON rb.principal_id = p.id "
                    "WHERE p.type = 'human'"
                )
            ).scalar()
            if human_with_roles == 0:
                # Bootstrap mode: only setup-only tools are allowed.
                if tool_name is not None and tool_name in BOOTSTRAP_ALLOWED_TOOLS:
                    return None
                return {
                    "error": (
                        "Bootstrap mode allows only setup operations. "
                        "Create an administrator role binding first."
                    )
                }

    return {
        "error": (
            f"Principal '{principal_id}' has no role bindings; access denied. "
            "Set EP_BOOTSTRAP_MODE=true for initial setup."
        )
    }


def _get_ep_service_id(conn: Any) -> str:
    """Get or create the EP service principal."""
    import sqlalchemy as sa

    result = conn.execute(
        sa.text("SELECT id FROM ep_principals WHERE type='service' AND name='EP Service' LIMIT 1")
    )
    row = result.fetchone()
    if row:
        return row[0]
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()),
        name="EP Service",
        type="service",
        machine=None,
        description="EP service",
    )
    return p["id"]


def _resolve_project_id(
    conn: Any,
    branch_id: str | None = None,
    lattice_id: str | None = None,
    transition_id: str | None = None,
    approval_id: str | None = None,
) -> str | None:
    """Resolve any object reference to its project_id.

    Resolution chain:
      * branch_id -> ep_branches.lattice_id -> ep_lattices.project_id
      * lattice_id -> ep_lattices.project_id
      * transition_id -> ep_transitions.branch_id -> lattice_id -> project_id
      * approval_id -> ep_approval_requests.transition_id -> branch_id
        -> lattice_id -> project_id

    Returns the resolved ``project_id`` or ``None`` if the object cannot be
    found or no identifiers were provided.
    """
    import sqlalchemy as sa

    def _lattice_to_project(lid: str) -> str | None:
        row = conn.execute(
            sa.text("SELECT project_id FROM ep_lattices WHERE id = :id"),
            {"id": lid},
        ).fetchone()
        return row[0] if row else None

    def _branch_to_lattice(bid: str) -> str | None:
        row = conn.execute(
            sa.text("SELECT lattice_id FROM ep_branches WHERE id = :id"),
            {"id": bid},
        ).fetchone()
        return row[0] if row else None

    # lattice_id — direct lookup
    if lattice_id:
        return _lattice_to_project(lattice_id)

    # branch_id -> lattice_id -> project_id
    if branch_id:
        lid = _branch_to_lattice(branch_id)
        if lid:
            return _lattice_to_project(lid)
        return None

    # transition_id -> branch_id -> lattice_id -> project_id
    if transition_id:
        row = conn.execute(
            sa.text("SELECT branch_id FROM ep_transitions WHERE id = :id"),
            {"id": transition_id},
        ).fetchone()
        if row:
            bid = row[0]
            lid = _branch_to_lattice(bid) if bid else None
            if lid:
                return _lattice_to_project(lid)
        return None

    # approval_id -> transition_id -> branch_id -> lattice_id -> project_id
    if approval_id:
        row = conn.execute(
            sa.text("SELECT transition_id FROM ep_approval_requests WHERE id = :id"),
            {"id": approval_id},
        ).fetchone()
        if row:
            tid = row[0]
            if tid:
                trow = conn.execute(
                    sa.text("SELECT branch_id FROM ep_transitions WHERE id = :id"),
                    {"id": tid},
                ).fetchone()
                if trow:
                    bid = trow[0]
                    lid = _branch_to_lattice(bid) if bid else None
                    if lid:
                        return _lattice_to_project(lid)
        return None

    return None


def _build_policy_engine(
    conn: Any,
    branch_id: str | None = None,
    agent_id: str | None = None,
) -> PolicyEngine | None:
    """Load active policies for the given context and build a PolicyEngine.

    Resolves the project_id from the branch_id, loads policies applicable
    to that project (global + project-scoped + branch-scoped), validates
    them into Policy models, and returns a configured PolicyEngine.

    Raises PolicyIntegrityError if required context is missing or an active
    policy cannot be validated.
    """
    from .policies import Policy
    from .db.repositories import PolicyRepository

    repo = PolicyRepository(conn)
    project_id = None
    if branch_id:
        project_id = _resolve_project_id(conn, branch_id=branch_id)

    if not branch_id or not project_id or not agent_id:
        raise PolicyIntegrityError(
            "branch_id, project_id, and agent_id are required for governed policy evaluation"
        )

    policy_rows = repo.list_effective_policies(project_id, branch_id, agent_id)
    policies: list[Policy] = []
    for row in policy_rows:
        try:
            policies.append(Policy.model_validate(row))
        except Exception as exc:
            raise PolicyIntegrityError(
                f"Active policy {row.get('id', '<unknown>')} is invalid"
            ) from exc

    return PolicyEngine(policies)


def _ep_check(conn: Any, args: dict[str, Any], agent_id: str) -> dict[str, Any]:
    ep_id = _get_ep_service_id(conn)
    branch_id = args.get("branch_id")
    if not branch_id:
        raise PolicyIntegrityError("branch_id is required for governed checks")
    policy_engine = _build_policy_engine(
        conn, branch_id=branch_id if branch_id else None, agent_id=agent_id
    )
    trans_engine = TransitionEngine(conn.engine, ep_id, policy_engine=policy_engine)
    transition = trans_engine.propose(
        agent_id=agent_id,
        branch_id=branch_id,
        tool=args["tool"],
        arguments=args["arguments"],
        idempotency_key=str(XID.new()),
    )
    return {"transition_id": transition["id"], "stage": transition["stage"]}


def _ep_execute(conn: Any, args: dict[str, Any], agent_id: str) -> dict[str, Any]:
    ep_id = _get_ep_service_id(conn)
    branch_id = args["branch_id"]
    policy_engine = _build_policy_engine(
        conn, branch_id=branch_id, agent_id=agent_id
    )
    trans_engine = TransitionEngine(conn.engine, ep_id, policy_engine=policy_engine)
    transition = trans_engine.propose(
        agent_id=agent_id,
        branch_id=branch_id,
        tool=args["tool"],
        arguments=args["arguments"],
        idempotency_key=str(XID.new()),
    )
    return {"transition_id": transition["id"], "stage": transition["stage"]}


def _ep_status(conn: Any, args: dict[str, Any]) -> dict[str, Any]:

    branch_id = args.get("branch_id")
    if not branch_id:
        return {"message": "Specify branch_id"}
    repo = BranchRepository(conn)
    head_id, version = repo.get_head(branch_id)
    policy_repo = PolicyRepository(conn)
    project_id = _resolve_project_id(conn, branch_id=branch_id)
    if project_id:
        policies = policy_repo.list_active_policies_for_project(project_id)
    else:
        policies = []
    return {
        "branch_id": branch_id,
        "head_node_id": head_id,
        "version": version,
        "active_policies": len(policies),
    }


def _ep_log(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    import sqlalchemy as sa

    # High fix 5: filter by project_id to prevent cross-project data leakage.
    project_id = _resolve_project_id(conn, branch_id=args.get("branch_id"))
    if project_id is None and args.get("project_id"):
        project_id = args.get("project_id")
    if project_id is None:
        # No project_id or branch_id provided — return empty results.
        return {"transitions": []}

    result = conn.execute(
        sa.text(
            "SELECT t.id, t.agent_id, t.branch_id, t.tool, t.stage, t.created_at "
            "FROM ep_transitions t "
            "JOIN ep_branches b ON t.branch_id = b.id "
            "JOIN ep_lattices l ON b.lattice_id = l.id "
            "WHERE l.project_id = :project_id "
            "ORDER BY t.created_at DESC LIMIT 20"
        ),
        {"project_id": project_id},
    )
    rows = [dict(r._mapping) for r in result.fetchall()]
    return {"transitions": rows}


def _ep_list_policies(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    # Filter policies by authoritative scope: global policies are visible to
    # all projects, project-scoped policies are visible only within their
    # project, and branch-scoped policies are visible only within branches of
    # the project's lattice.  A project context is required.
    project_id = _resolve_project_id(conn, branch_id=args.get("branch_id"))
    if project_id is None and args.get("project_id"):
        project_id = args.get("project_id")
    if project_id is None:
        return {"policies": []}

    repo = PolicyRepository(conn)
    policies = repo.list_active_policies_for_project(project_id)
    return {"policies": policies}


def _ep_pending_approvals(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    import sqlalchemy as sa

    # High fix 5: filter by project_id to prevent cross-project data leakage.
    project_id = _resolve_project_id(conn, branch_id=args.get("branch_id"))
    if project_id is None and args.get("project_id"):
        project_id = args.get("project_id")
    if project_id is None:
        return {"pending_approvals": []}

    result = conn.execute(
        sa.text(
            "SELECT ar.id, ar.transition_id, ar.policy_id, ar.requested_by, "
            "ar.justification, ar.status "
            "FROM ep_approval_requests ar "
            "JOIN ep_transitions t ON ar.transition_id = t.id "
            "JOIN ep_branches b ON t.branch_id = b.id "
            "JOIN ep_lattices l ON b.lattice_id = l.id "
            "WHERE ar.status = 'pending' AND l.project_id = :project_id "
            "ORDER BY ar.created_at"
        ),
        {"project_id": project_id},
    )
    rows = [dict(r._mapping) for r in result.fetchall()]
    return {"pending_approvals": rows}


def _ep_approve(
    conn: Any,
    args: dict[str, Any],
    approver_id: str,
    approver_type: str,
) -> dict[str, Any]:
    # Only humans may approve requests. Agents/services/proxies cannot.
    if approver_type != "human":
        return {
            "error": (
                f"Approval requires a human principal; authenticated principal "
                f"type is '{approver_type}'. Agents cannot approve requests."
            )
        }
    ep_id = _get_ep_service_id(conn)
    approval_repo = ApprovalRepository(conn)
    req = approval_repo.get_request(args["approval_id"])
    if req is None:
        return {"error": "Approval request not found"}
    # Commit any pending reads so TransitionEngine.approve receives a clean
    # connection (it opens its own transaction — Issue Critical 2 / High 6).
    trans_engine = TransitionEngine(conn.engine, ep_id)
    # Separation-of-duties (approver != requester) is enforced by
    # TransitionEngine.approve; the approver_id here is the authenticated
    # human principal, not a caller-supplied value.
    result = trans_engine.approve(
        transition_id=req["transition_id"],
        approver_id=approver_id,
        approver_type="human",
        reason=args.get("reason", "Approved"),
    )
    return {"transition_id": req["transition_id"], "stage": result["stage"]}


def _ep_deny(
    conn: Any,
    args: dict[str, Any],
    approver_id: str,
    approver_type: str,
) -> dict[str, Any]:
    # Only humans may deny requests. Agents/services/proxies cannot.
    if approver_type != "human":
        return {
            "error": (
                f"Denial requires a human principal; authenticated principal "
                f"type is '{approver_type}'. Agents cannot deny requests."
            )
        }
    ep_id = _get_ep_service_id(conn)
    approval_repo = ApprovalRepository(conn)
    req = approval_repo.get_request(args["approval_id"])
    if req is None:
        return {"error": "Approval request not found"}
    # Commit any pending reads so TransitionEngine.deny_approval receives a
    # clean connection (it opens its own transaction — Issue Critical 2 / High 6).
    trans_engine = TransitionEngine(conn.engine, ep_id)
    result = trans_engine.deny_approval(
        transition_id=req["transition_id"],
        approver_id=approver_id,
        reason=args.get("reason", "Denied"),
    )
    return {"transition_id": req["transition_id"], "stage": result["stage"]}


def _ep_audit_verify(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    from .audit import AuditVerifier

    verifier = AuditVerifier(conn.engine)
    result = verifier.verify(args["lattice_id"])
    return {"lattice_id": args["lattice_id"], "valid": result}


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


async def run_server(
    mode: str = "enforced",
    authenticated_principal_id: str | None = None,
) -> None:
    """Run the MCP server over stdio.

    In production, ``authenticated_principal_id`` must be derived from the
    authenticated MCP transport/session (TLS client certificate, API key,
    OAuth token, mTLS SPIFFE ID, etc.) — NOT supplied by the process command
    line.  The argument here is an interim bridge until that integration
    exists; callers must populate it from a trusted source.

    The principal's type is loaded from the database at runtime, not trusted
    from the caller.
    """
    server = create_server(
        mode,
        authenticated_principal_id=authenticated_principal_id,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
