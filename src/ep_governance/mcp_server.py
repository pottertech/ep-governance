"""EP-Governance MCP server.

Exposes governance operations as MCP tools for AI agent integration.

In enforced mode, only governed execution and governance management tools
are exposed. Raw protected tools (shell.exec, postgres.execute, etc.) are
NOT exposed — agents must go through ep_execute.

In advisory mode, ep_check and governance management tools are available.
"""

from __future__ import annotations

import json
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
from .errors import EPError
from .transitions import TransitionEngine
from .xid import XID

__all__ = ["create_server", "run_server", "get_tools"]


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
                "agent_id": {"type": "string", "description": "Agent principal XID"},
            },
            "required": ["tool", "arguments", "agent_id"],
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
            },
        },
    ),
    Tool(
        name="ep_pending_approvals",
        description="List pending approval requests.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="ep_approve",
        description="Approve a pending request. Requires policy_approver role.",
        inputSchema={
            "type": "object",
            "properties": {
                "approval_id": {"type": "string", "description": "Approval request XID"},
                "approver_id": {"type": "string", "description": "Approver principal XID"},
                "reason": {"type": "string", "description": "Approval reason"},
            },
            "required": ["approval_id", "approver_id"],
        },
    ),
    Tool(
        name="ep_deny",
        description="Deny a pending request. Requires policy_approver role.",
        inputSchema={
            "type": "object",
            "properties": {
                "approval_id": {"type": "string", "description": "Approval request XID"},
                "approver_id": {"type": "string", "description": "Approver principal XID"},
                "reason": {"type": "string", "description": "Denial reason"},
            },
            "required": ["approval_id", "approver_id"],
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
                "agent_id": {"type": "string", "description": "Agent principal XID"},
            },
            "required": ["tool", "arguments", "branch_id", "agent_id"],
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
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="ep_pending_approvals",
        description="List pending approval requests.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="ep_approve",
        description="Approve a pending request. Requires policy_approver role and human principal.",
        inputSchema={
            "type": "object",
            "properties": {
                "approval_id": {"type": "string"},
                "approver_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["approval_id", "approver_id"],
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


def create_server(mode: str = "enforced") -> Server:
    """Create an MCP server with EP-Governance tools.

    Args:
        mode: 'enforced' or 'advisory'. In enforced mode, only ep_execute
              and governance management tools are exposed. In advisory mode,
              ep_check and all management tools are exposed.
    """
    server: Server = Server("ep-governance")

    async def _list_tools(_request: Any) -> list[Tool]:
        return get_tools(mode)

    async def _call_tool(request: Any) -> list[TextContent]:
        name = request.params.name if hasattr(request, "params") else request.name
        arguments = request.params.arguments if hasattr(request, "params") else request.arguments
        if arguments is None:
            arguments = {}
        try:
            result = _handle_tool_call(name, arguments, mode)
            return [TextContent(type="text", text=json.dumps(result, default=str))]
        except EPError as exc:
            return [TextContent(type="text", text=json.dumps({"error": str(exc)}))]
        except Exception as exc:
            return [TextContent(type="text", text=json.dumps({"error": f"Unexpected: {exc!s}"}))]

    from mcp.types import CallToolRequest, ListToolsRequest

    server.add_request_handler("tools/list", ListToolsRequest, _list_tools)
    server.add_request_handler("tools/call", CallToolRequest, _call_tool)

    return server


def _handle_tool_call(name: str, arguments: dict[str, Any], mode: str) -> dict[str, Any]:
    """Handle a tool call and return a result dict."""
    cfg = load_config()
    engine = create_engine(cfg.db_url)

    with engine.connect() as conn:
        if name == "ep_check":
            return _ep_check(conn, arguments)
        elif name == "ep_execute":
            return _ep_execute(conn, arguments)
        elif name == "ep_status":
            return _ep_status(conn, arguments)
        elif name == "ep_log":
            return _ep_log(conn, arguments)
        elif name == "ep_list_policies":
            return _ep_list_policies(conn, arguments)
        elif name == "ep_pending_approvals":
            return _ep_pending_approvals(conn, arguments)
        elif name == "ep_approve":
            return _ep_approve(conn, arguments)
        elif name == "ep_deny":
            return _ep_deny(conn, arguments)
        elif name == "ep_audit_verify":
            return _ep_audit_verify(conn, arguments)
        else:
            return {"error": f"Unknown tool: {name}"}


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
    conn.commit()
    return p["id"]


def _ep_check(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    ep_id = _get_ep_service_id(conn)
    engine = TransitionEngine(conn, ep_id)
    transition = engine.propose(
        agent_id=args["agent_id"],
        branch_id=args.get("branch_id", ""),
        tool=args["tool"],
        arguments=args["arguments"],
        idempotency_key=str(XID.new()),
    )
    conn.commit()
    return {"transition_id": transition["id"], "stage": transition["stage"]}


def _ep_execute(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    ep_id = _get_ep_service_id(conn)
    engine = TransitionEngine(conn, ep_id)
    transition = engine.propose(
        agent_id=args["agent_id"],
        branch_id=args["branch_id"],
        tool=args["tool"],
        arguments=args["arguments"],
        idempotency_key=str(XID.new()),
    )
    conn.commit()
    return {"transition_id": transition["id"], "stage": transition["stage"]}


def _ep_status(conn: Any, args: dict[str, Any]) -> dict[str, Any]:

    branch_id = args.get("branch_id")
    if not branch_id:
        return {"message": "Specify branch_id"}
    repo = BranchRepository(conn)
    head_id, version = repo.get_head(branch_id)
    policy_repo = PolicyRepository(conn)
    policies = policy_repo.list_active_policies()
    return {
        "branch_id": branch_id,
        "head_node_id": head_id,
        "version": version,
        "active_policies": len(policies),
    }


def _ep_log(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    import sqlalchemy as sa

    result = conn.execute(
        sa.text(
            "SELECT id, agent_id, branch_id, tool, stage, created_at "
            "FROM ep_transitions ORDER BY created_at DESC LIMIT 20"
        )
    )
    rows = [dict(r._mapping) for r in result.fetchall()]
    return {"transitions": rows}


def _ep_list_policies(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    repo = PolicyRepository(conn)
    policies = repo.list_active_policies()
    return {"policies": policies}


def _ep_pending_approvals(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    import sqlalchemy as sa

    result = conn.execute(
        sa.text(
            "SELECT id, transition_id, policy_id, requested_by, justification, status "
            "FROM ep_approval_requests WHERE status='pending' ORDER BY created_at"
        )
    )
    rows = [dict(r._mapping) for r in result.fetchall()]
    return {"pending_approvals": rows}


def _ep_approve(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    ep_id = _get_ep_service_id(conn)
    approval_repo = ApprovalRepository(conn)
    req = approval_repo.get_request(args["approval_id"])
    if req is None:
        return {"error": "Approval request not found"}
    engine = TransitionEngine(conn, ep_id)
    result = engine.approve(
        transition_id=req["transition_id"],
        approver_id=args["approver_id"],
        approver_type="human",
        reason=args.get("reason", "Approved"),
    )
    conn.commit()
    return {"transition_id": req["transition_id"], "stage": result["stage"]}


def _ep_deny(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    ep_id = _get_ep_service_id(conn)
    approval_repo = ApprovalRepository(conn)
    req = approval_repo.get_request(args["approval_id"])
    if req is None:
        return {"error": "Approval request not found"}
    engine = TransitionEngine(conn, ep_id)
    result = engine.deny_approval(
        transition_id=req["transition_id"],
        approver_id=args["approver_id"],
        reason=args.get("reason", "Denied"),
    )
    conn.commit()
    return {"transition_id": req["transition_id"], "stage": result["stage"]}


def _ep_audit_verify(conn: Any, args: dict[str, Any]) -> dict[str, Any]:
    from .audit import AuditVerifier

    verifier = AuditVerifier(conn)
    result = verifier.verify(args["lattice_id"])
    return {"lattice_id": args["lattice_id"], "valid": result}


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


async def run_server(mode: str = "enforced") -> None:
    """Run the MCP server over stdio."""
    server = create_server(mode)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
