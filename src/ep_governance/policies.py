"""Policy models for EP-Governance.

Pydantic v2 models representing governance policies that control agent
transitions within the EP-Governance lattice.

The fields mirror ``schemas/policy.schema.json`` exactly.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "PolicyEffect",
    "PolicyScope",
    "PolicyStatus",
    "Policy",
    "EFFECT_PRECEDENCE",
]


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class PolicyEffect(StrEnum):
    """The effect a policy has when matched."""

    deny = "deny"
    require_approval = "require_approval"
    warn = "warn"
    allow = "allow"


class PolicyScope(StrEnum):
    """Whether a policy is global or scoped to a specific agent."""

    global_ = "global"
    agent = "agent"


class PolicyStatus(StrEnum):
    """Lifecycle status of a policy."""

    draft = "draft"
    pending_approval = "pending_approval"
    active = "active"
    rejected = "rejected"
    superseded = "superseded"
    retired = "retired"


# --------------------------------------------------------------------------- #
# Effect precedence (higher value = higher precedence)
# --------------------------------------------------------------------------- #

EFFECT_PRECEDENCE: dict[str, int] = {
    "deny": 4,
    "require_approval": 3,
    "warn": 2,
    "allow": 1,
}


# --------------------------------------------------------------------------- #
# Pydantic model
# --------------------------------------------------------------------------- #


class Policy(BaseModel):
    """A governance policy.

    All fields correspond to ``schemas/policy.schema.json``.  Enum fields
    store their string values (``use_enum_values=True``) so that serialised
    policies are plain JSON.
    """

    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        extra="forbid",
    )

    id: str = Field(
        ...,
        pattern=r"^[0-9a-v]{20}$",
        description="Unique 20-char lowercase base32hex identifier.",
    )
    effect: PolicyEffect = Field(..., description="Effect when matched.")
    actions: list[str] = Field(..., description="List of action strings this policy applies to.")
    resources: list[str] = Field(
        ..., description="List of resource strings this policy applies to."
    )
    conditions: dict[str, Any] = Field(
        default_factory=dict,
        description="Condition object evaluated against the transition context.",
    )
    priority: int = Field(..., ge=0, description="Priority — higher values take precedence.")
    scope: PolicyScope = Field(..., description="Global or agent scope.")
    agent_scope: str | None = Field(
        default=None,
        pattern=r"^[0-9a-v]{20}$",
        description="Agent XID when scope=agent; null when scope=global.",
    )
    description: str = Field(..., description="Human-readable description.")
    status: PolicyStatus = Field(..., description="Lifecycle status.")
    created_by: str = Field(..., pattern=r"^[0-9a-v]{20}$", description="XID of the creator.")
    approved_by: str | None = Field(
        default=None,
        pattern=r"^[0-9a-v]{20}$",
        description="XID of the approver. Null if not yet approved.",
    )
    approved_at: str | None = Field(
        default=None,
        description="ISO 8601 UTC timestamp of approval. Null if not yet approved.",
    )
    activation_version: int | None = Field(
        default=None,
        ge=0,
        description="Lattice version at which this policy became active.",
    )
    exception_to: list[str] = Field(
        default_factory=list,
        description="List of policy XIDs that this policy is an exception to.",
    )
    valid_from: str | None = Field(
        default=None,
        description="ISO 8601 UTC timestamp from which this policy is valid.",
    )
    valid_until: str | None = Field(
        default=None,
        description="ISO 8601 UTC timestamp until which this policy is valid.",
    )
    justification: str | None = Field(
        default=None,
        description="Justification for this policy or exception.",
    )

    # ------------------------------------------------------------------ #
    # Methods
    # ------------------------------------------------------------------ #

    def is_in_force(self, now: str | None = None) -> bool:
        """Return ``True`` if this policy is currently in force.

        A policy is in force when:
          - ``status`` is ``"active"``; AND
          - ``valid_from`` is ``None`` or ``valid_from <= now``; AND
          - ``valid_until`` is ``None`` or ``valid_until > now``.

        Args:
            now: ISO 8601 UTC timestamp string.  If ``None``, the current
                UTC time is used.

        Returns:
            ``True`` if the policy is in force.
        """
        status_val = self.status
        if isinstance(status_val, PolicyStatus):
            status_val = status_val.value
        if status_val != PolicyStatus.active.value:
            return False

        if now is None:
            now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        # Normalize: strip trailing Z for comparison
        now_cmp = now.rstrip("Z")

        if self.valid_from is not None:
            vf = self.valid_from.rstrip("Z")
            if vf > now_cmp:
                return False

        if self.valid_until is not None:
            vu = self.valid_until.rstrip("Z")
            if vu <= now_cmp:
                return False

        return True
