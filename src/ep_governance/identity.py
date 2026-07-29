"""Identity, roles, and permissions for EP-Governance.

Pydantic v2 models for principals and role bindings, plus a static
permission table mapping roles to permission strings.

Permission strings:
  read_policy, propose_action, create_agent_policy, create_global_policy,
  approve_request, retire_policy, supersede_policy, repair_quarantine,
  manage_branches, read_audit, register_agent, manage_credentials,
  create_lattice
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "PrincipalType",
    "Role",
    "PrincipalStatus",
    "Principal",
    "RoleBinding",
    "PERMISSIONS",
    "check_permission",
    "is_human",
]


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class PrincipalType(StrEnum):
    """The type of a principal."""

    human = "human"
    agent = "agent"
    service = "service"
    proxy = "proxy"


class Role(StrEnum):
    """Roles within EP-Governance.

    Roles are cumulative in the sense that higher-privilege roles inherit
    the permissions of lower-privilege roles via the :data:`PERMISSIONS`
    table.  Callers should use :func:`check_permission` to test whether a
    set of roles grants a specific permission.
    """

    observer = "observer"
    agent = "agent"
    policy_author = "policy_author"
    policy_approver = "policy_approver"
    operator = "operator"
    auditor = "auditor"
    administrator = "administrator"


class PrincipalStatus(StrEnum):
    """The lifecycle status of a principal."""

    active = "active"
    suspended = "suspended"
    revoked = "revoked"


# --------------------------------------------------------------------------- #
# Permission strings
# --------------------------------------------------------------------------- #

# Canonical permission strings used throughout EP-Governance.
PERMISSION_READ_POLICY = "read_policy"
PERMISSION_PROPOSE_ACTION = "propose_action"
PERMISSION_CREATE_AGENT_POLICY = "create_agent_policy"
PERMISSION_CREATE_GLOBAL_POLICY = "create_global_policy"
PERMISSION_APPROVE_REQUEST = "approve_request"
PERMISSION_RETIRE_POLICY = "retire_policy"
PERMISSION_SUPERSEDE_POLICY = "supersede_policy"
PERMISSION_REPAIR_QUARANTINE = "repair_quarantine"
PERMISSION_MANAGE_BRANCHES = "manage_branches"
PERMISSION_READ_AUDIT = "read_audit"
PERMISSION_REGISTER_AGENT = "register_agent"
PERMISSION_MANAGE_CREDENTIALS = "manage_credentials"
PERMISSION_CREATE_LATTICE = "create_lattice"


# --------------------------------------------------------------------------- #
# Role → Permissions mapping
# --------------------------------------------------------------------------- #
#
# Permission inheritance (cumulative):
#   observer        → read_policy, read_audit
#   agent           = observer + propose_action
#   policy_author   = agent + create_agent_policy + create_global_policy + supersede_policy + retire_policy
#   policy_approver = observer + approve_request
#   operator        = observer + propose_action + repair_quarantine + manage_branches
#   auditor        = observer (read-only, no write)
#   administrator   = everything

PERMISSIONS: dict[Role, set[str]] = {
    Role.observer: {
        PERMISSION_READ_POLICY,
        PERMISSION_READ_AUDIT,
    },
    Role.agent: {
        PERMISSION_READ_POLICY,
        PERMISSION_READ_AUDIT,
        PERMISSION_PROPOSE_ACTION,
    },
    Role.policy_author: {
        PERMISSION_READ_POLICY,
        PERMISSION_READ_AUDIT,
        PERMISSION_PROPOSE_ACTION,
        PERMISSION_CREATE_AGENT_POLICY,
        PERMISSION_CREATE_GLOBAL_POLICY,
        PERMISSION_SUPERSEDE_POLICY,
        PERMISSION_RETIRE_POLICY,
    },
    Role.policy_approver: {
        PERMISSION_READ_POLICY,
        PERMISSION_READ_AUDIT,
        PERMISSION_APPROVE_REQUEST,
    },
    Role.operator: {
        PERMISSION_READ_POLICY,
        PERMISSION_READ_AUDIT,
        PERMISSION_PROPOSE_ACTION,
        PERMISSION_REPAIR_QUARANTINE,
        PERMISSION_MANAGE_BRANCHES,
    },
    Role.auditor: {
        PERMISSION_READ_POLICY,
        PERMISSION_READ_AUDIT,
    },
    Role.administrator: {
        PERMISSION_READ_POLICY,
        PERMISSION_PROPOSE_ACTION,
        PERMISSION_CREATE_AGENT_POLICY,
        PERMISSION_CREATE_GLOBAL_POLICY,
        PERMISSION_APPROVE_REQUEST,
        PERMISSION_RETIRE_POLICY,
        PERMISSION_SUPERSEDE_POLICY,
        PERMISSION_REPAIR_QUARANTINE,
        PERMISSION_MANAGE_BRANCHES,
        PERMISSION_READ_AUDIT,
        PERMISSION_REGISTER_AGENT,
        PERMISSION_MANAGE_CREDENTIALS,
        PERMISSION_CREATE_LATTICE,
    },
}


# --------------------------------------------------------------------------- #
# Pydantic models
# --------------------------------------------------------------------------- #


class Principal(BaseModel):
    """A principal (human, agent, service, or proxy).

    Attributes:
        id:           XID of the principal.
        name:         Human-readable name.
        type:         :class:`PrincipalType`.
        machine:      Machine identifier (optional, for agents/services).
        description:  Free-text description.
        status:       :class:`PrincipalStatus`.
        registered_at: ISO 8601 UTC registration timestamp.
    """

    model_config = ConfigDict(use_enum_values=True, validate_assignment=True, extra="forbid")

    id: str = Field(..., pattern=r"^[0-9a-v]{20}$", description="XID of the principal.")
    name: str = Field(..., description="Human-readable name.")
    type: PrincipalType = Field(..., description="Type of principal.")
    machine: str | None = Field(
        default=None, description="Machine identifier (for agents/services)."
    )
    description: str = Field(default="", description="Free-text description.")
    status: PrincipalStatus = Field(..., description="Lifecycle status.")
    registered_at: str = Field(..., description="ISO 8601 UTC registration timestamp.")


class RoleBinding(BaseModel):
    """Binds a principal to a role, optionally scoped to a project.

    Attributes:
        principal_id: XID of the principal.
        role:         :class:`Role`.
        project_id:   Optional project scope; ``None`` means global.
    """

    model_config = ConfigDict(use_enum_values=True, validate_assignment=True, extra="forbid")

    principal_id: str = Field(..., pattern=r"^[0-9a-v]{20}$", description="XID of the principal.")
    role: Role = Field(..., description="Role assigned.")
    project_id: str | None = Field(default=None, description="Project scope; None means global.")


# --------------------------------------------------------------------------- #
# Functions
# --------------------------------------------------------------------------- #


def check_permission(principal_roles: list[Role], required_permission: str) -> bool:
    """Check whether any of the principal's roles grant *required_permission*.

    Args:
        principal_roles:     List of roles held by the principal.
        required_permission: Permission string to check.

    Returns:
        ``True`` if at least one role grants the permission.
    """
    for role in principal_roles:
        # Handle both Role enum and raw string values
        role_key: Role
        if isinstance(role, Role):
            role_key = role
        else:
            try:
                role_key = Role(role)
            except ValueError:
                continue
        perms = PERMISSIONS.get(role_key, set())
        if required_permission in perms:
            return True
    return False


def is_human(principal: Principal) -> bool:
    """Return ``True`` if *principal* is a human.

    Uses the ``type`` field of the principal.  Works whether the enum
    value has been stored as a string or as the enum itself.
    """
    ptype = principal.type
    if isinstance(ptype, PrincipalType):
        return ptype == PrincipalType.human
    return str(ptype) == PrincipalType.human.value
