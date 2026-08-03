"""Tool catalog for EP-Governance — dependency-free tool definitions.

This module contains the governed-tool definitions (names, schemas, role
requirements) WITHOUT importing the MCP package.  It is importable in
environments that lack ``mcp``, ``PyNaCl``, or ``hypothesis``.

:mcp_server: imports from this module and converts the plain-dict definitions
into MCP ``Tool`` objects at runtime.
:tests/contracts: import from this module directly to verify the tool
catalog without pulling in the MCP package.

Public API
----------
``GOVERNED_TOOL_NAMES`` — frozenset of tool names allowed in enforced mode.
``RAW_TOOL_NAMES``      — frozenset of prohibited (raw) tool names.
``TOOL_REQUIRED_ROLES`` — dict mapping tool name -> required role list.
``get_governed_tools``  — list of tool name strings for enforced mode.
``is_governed_tool``    — True if *name* is a governed tool.
``get_tool_definitions``— list of plain-dict tool defs for a mode.
``get_tools``           — alias retained for backwards compatibility.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "GOVERNED_TOOL_NAMES",
    "RAW_TOOL_NAMES",
    "TOOL_REQUIRED_ROLES",
    "ADVISORY_TOOL_DEFS",
    "ENFORCED_TOOL_DEFS",
    "get_governed_tools",
    "is_governed_tool",
    "get_tool_definitions",
    "get_tools",
]


# --------------------------------------------------------------------------- #
# Role-based authorization
# --------------------------------------------------------------------------- #

# Required roles per tool name.  A principal must hold at least one of the
# listed roles to invoke the tool.
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


# --------------------------------------------------------------------------- #
# Tool definitions — plain dicts (no MCP dependency)
# --------------------------------------------------------------------------- #
#
# Each definition is a dict with keys: name, description, inputSchema.
# These are the raw material that mcp_server.py wraps in mcp.types.Tool at
# runtime.

ADVISORY_TOOL_DEFS: list[dict[str, Any]] = [
    {
        "name": "ep_check",
        "description": "Evaluate a proposed action without executing. Returns admissible/denied/pending.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Tool name (e.g. postgres.execute)"},
                "arguments": {"type": "object", "description": "Tool arguments as JSON"},
                "branch_id": {"type": "string", "description": "Branch XID"},
            },
            "required": ["tool", "arguments"],
        },
    },
    {
        "name": "ep_status",
        "description": "Get current governance status: branch head, version, active policies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "branch_id": {"type": "string", "description": "Branch XID (optional)"},
            },
        },
    },
    {
        "name": "ep_log",
        "description": "List recent transitions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Filter by agent XID (optional)"},
                "branch_id": {"type": "string", "description": "Branch XID (scopes results to project)"},
                "project_id": {"type": "string", "description": "Project XID (scopes results to project)"},
            },
        },
    },
    {
        "name": "ep_list_policies",
        "description": "List active governance policies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Filter by agent XID (optional)"},
                "branch_id": {"type": "string", "description": "Branch XID (scopes results to project)"},
                "project_id": {"type": "string", "description": "Project XID (scopes results to project)"},
            },
        },
    },
    {
        "name": "ep_pending_approvals",
        "description": "List pending approval requests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "branch_id": {"type": "string", "description": "Branch XID (scopes results to project)"},
                "project_id": {"type": "string", "description": "Project XID (scopes results to project)"},
            },
        },
    },
    {
        "name": "ep_approve",
        "description": "Approve a pending request. Requires policy_approver role.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "approval_id": {"type": "string", "description": "Approval request XID"},
                "reason": {"type": "string", "description": "Approval reason"},
            },
            "required": ["approval_id"],
        },
    },
    {
        "name": "ep_deny",
        "description": "Deny a pending request. Requires policy_approver role.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "approval_id": {"type": "string", "description": "Approval request XID"},
                "reason": {"type": "string", "description": "Denial reason"},
            },
            "required": ["approval_id"],
        },
    },
    {
        "name": "ep_audit_verify",
        "description": "Verify the audit chain for a lattice.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lattice_id": {"type": "string", "description": "Lattice XID"},
            },
            "required": ["lattice_id"],
        },
    },
]

ENFORCED_TOOL_DEFS: list[dict[str, Any]] = [
    {
        "name": "ep_execute",
        "description": (
            "Request authorization and execute through the governed proxy. "
            "The agent does not hold target credentials — the proxy executes on the agent's behalf."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Tool name (e.g. postgres.execute)"},
                "arguments": {"type": "object", "description": "Tool arguments as JSON"},
                "branch_id": {"type": "string", "description": "Branch XID"},
            },
            "required": ["tool", "arguments", "branch_id"],
        },
    },
    {
        "name": "ep_status",
        "description": "Get current governance status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "branch_id": {"type": "string"},
            },
        },
    },
    {
        "name": "ep_list_policies",
        "description": "List active governance policies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "branch_id": {"type": "string", "description": "Branch XID (scopes results to project)"},
                "project_id": {"type": "string", "description": "Project XID (scopes results to project)"},
            },
        },
    },
    {
        "name": "ep_pending_approvals",
        "description": "List pending approval requests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "branch_id": {"type": "string", "description": "Branch XID (scopes results to project)"},
                "project_id": {"type": "string", "description": "Project XID (scopes results to project)"},
            },
        },
    },
    {
        "name": "ep_approve",
        "description": "Approve a pending request. Requires policy_approver role and human principal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "approval_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["approval_id"],
        },
    },
    {
        "name": "ep_audit_verify",
        "description": "Verify the audit chain for a lattice.",
        "inputSchema": {
            "type": "object",
            "properties": {"lattice_id": {"type": "string"}},
            "required": ["lattice_id"],
        },
    },
]


# --------------------------------------------------------------------------- #
# Governed / raw tool name sets
# --------------------------------------------------------------------------- #

GOVERNED_TOOL_NAMES: frozenset[str] = frozenset(
    {d["name"] for d in ENFORCED_TOOL_DEFS}
)

RAW_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "shell.exec",
        "postgres.execute",
        "docker.exec",
        "ssh.exec",
    }
)


# --------------------------------------------------------------------------- #
# Public helpers
# --------------------------------------------------------------------------- #


def get_governed_tools() -> list[str]:
    """Return the list of governed tool names (enforced-mode tools)."""
    return [d["name"] for d in ENFORCED_TOOL_DEFS]


def is_governed_tool(name: str) -> bool:
    """True if *name* is a governed tool exposed in enforced mode."""
    return name in GOVERNED_TOOL_NAMES


def get_tool_definitions(mode: str = "enforced") -> list[dict[str, Any]]:
    """Return the plain-dict tool definitions for the given mode."""
    if mode == "enforced":
        return ENFORCED_TOOL_DEFS
    return ADVISORY_TOOL_DEFS


def get_tools(mode: str = "enforced") -> list[dict[str, Any]]:
    """Backwards-compatible alias for :func:`get_tool_definitions`.

    Returns plain dicts.  ``mcp_server.get_tools`` wraps these in MCP
    ``Tool`` objects.
    """
    return get_tool_definitions(mode)