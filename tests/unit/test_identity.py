"""Unit tests for EP-Governance identity, roles, and permissions.

References normative rules:
  EP-IDENTITY-001: principal types (human, agent, service, proxy)
  EP-IDENTITY-002: roles (observer, agent, policy_author, policy_approver, operator, auditor, administrator)
  EP-IDENTITY-003: authenticate and authorize every mutation request
"""

from __future__ import annotations

import pytest

from ep_governance.identity import (
    PERMISSIONS,
    Principal,
    PrincipalStatus,
    PrincipalType,
    Role,
    RoleBinding,
    check_permission,
    is_human,
)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

VALID_XID = "0123456789abcdefghij"  # 20-char base32hex


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_principal(
    ptype: PrincipalType = PrincipalType.human,
    status: PrincipalStatus = PrincipalStatus.active,
    **overrides,
) -> Principal:
    defaults = dict(
        id=VALID_XID,
        name="Test Principal",
        type=ptype,
        status=status,
        registered_at=_now_iso(),
    )
    defaults.update(overrides)
    return Principal(**defaults)


# --------------------------------------------------------------------------- #
# EP-IDENTITY-001: PrincipalType enum
# --------------------------------------------------------------------------- #


class TestPrincipalType:
    """Tests for PrincipalType enum (EP-IDENTITY-001)."""

    def test_human(self):
        assert PrincipalType.human.value == "human"

    def test_agent(self):
        assert PrincipalType.agent.value == "agent"

    def test_service(self):
        assert PrincipalType.service.value == "service"

    def test_proxy(self):
        assert PrincipalType.proxy.value == "proxy"

    @pytest.mark.parametrize("ptype", list(PrincipalType))
    def test_all_types_are_str_enum(self, ptype):
        assert isinstance(ptype, str)
        assert isinstance(ptype, PrincipalType)

    def test_all_four_types(self):
        """EP-IDENTITY-001: exactly 4 principal types."""
        assert len(list(PrincipalType)) == 4


# --------------------------------------------------------------------------- #
# EP-IDENTITY-002: Role enum
# --------------------------------------------------------------------------- #


class TestRole:
    """Tests for Role enum (EP-IDENTITY-002)."""

    def test_observer(self):
        assert Role.observer.value == "observer"

    def test_agent(self):
        assert Role.agent.value == "agent"

    def test_policy_author(self):
        assert Role.policy_author.value == "policy_author"

    def test_policy_approver(self):
        assert Role.policy_approver.value == "policy_approver"

    def test_operator(self):
        assert Role.operator.value == "operator"

    def test_auditor(self):
        assert Role.auditor.value == "auditor"

    def test_administrator(self):
        assert Role.administrator.value == "administrator"

    @pytest.mark.parametrize("role", list(Role))
    def test_all_roles_are_str_enum(self, role):
        assert isinstance(role, str)
        assert isinstance(role, Role)

    def test_all_seven_roles(self):
        """EP-IDENTITY-002: exactly 7 roles."""
        assert len(list(Role)) == 7


# --------------------------------------------------------------------------- #
# PrincipalStatus enum
# --------------------------------------------------------------------------- #


class TestPrincipalStatus:
    """Tests for PrincipalStatus enum."""

    def test_active(self):
        assert PrincipalStatus.active.value == "active"

    def test_suspended(self):
        assert PrincipalStatus.suspended.value == "suspended"

    def test_revoked(self):
        assert PrincipalStatus.revoked.value == "revoked"

    @pytest.mark.parametrize("status", list(PrincipalStatus))
    def test_all_statuses_are_str_enum(self, status):
        assert isinstance(status, str)
        assert isinstance(status, PrincipalStatus)

    def test_all_three_statuses(self):
        assert len(list(PrincipalStatus)) == 3


# --------------------------------------------------------------------------- #
# PERMISSIONS table
# --------------------------------------------------------------------------- #


class TestPermissionsTable:
    """Tests for the PERMISSIONS role→permission mapping."""

    def test_observer_permissions(self):
        perms = PERMISSIONS[Role.observer]
        assert "read_policy" in perms
        assert "read_audit" in perms

    def test_agent_permissions(self):
        perms = PERMISSIONS[Role.agent]
        assert "read_policy" in perms
        assert "read_audit" in perms
        assert "propose_action" in perms

    def test_policy_author_permissions(self):
        perms = PERMISSIONS[Role.policy_author]
        assert "create_agent_policy" in perms
        assert "create_global_policy" in perms
        assert "supersede_policy" in perms
        assert "retire_policy" in perms
        assert "propose_action" in perms

    def test_policy_approver_permissions(self):
        perms = PERMISSIONS[Role.policy_approver]
        assert "approve_request" in perms
        assert "read_policy" in perms
        assert "read_audit" in perms

    def test_operator_permissions(self):
        perms = PERMISSIONS[Role.operator]
        assert "propose_action" in perms
        assert "repair_quarantine" in perms
        assert "manage_branches" in perms

    def test_auditor_permissions(self):
        """Auditor is read-only (observer-level permissions)."""
        perms = PERMISSIONS[Role.auditor]
        assert "read_policy" in perms
        assert "read_audit" in perms
        # Auditor should NOT have write permissions
        assert "propose_action" not in perms
        assert "create_agent_policy" not in perms

    def test_administrator_has_all_permissions(self):
        """Administrator has every permission."""
        perms = PERMISSIONS[Role.administrator]
        all_perms = {
            "read_policy",
            "propose_action",
            "create_agent_policy",
            "create_global_policy",
            "approve_request",
            "retire_policy",
            "supersede_policy",
            "repair_quarantine",
            "manage_branches",
            "read_audit",
            "register_agent",
            "manage_credentials",
            "create_lattice",
        }
        assert all_perms.issubset(perms)

    def test_all_roles_have_permissions(self):
        """Every role has at least one permission."""
        for role in Role:
            assert len(PERMISSIONS[role]) > 0, f"Role {role} has no permissions"


# --------------------------------------------------------------------------- #
# check_permission
# --------------------------------------------------------------------------- #


class TestCheckPermission:
    """Tests for check_permission function."""

    def test_role_with_permission_returns_true(self):
        """Role that has the permission -> True."""
        assert check_permission([Role.administrator], "create_lattice") is True

    def test_role_without_permission_returns_false(self):
        """Role that lacks the permission -> False."""
        assert check_permission([Role.observer], "create_lattice") is False

    def test_observer_has_read_policy(self):
        assert check_permission([Role.observer], "read_policy") is True

    def test_observer_lacks_propose_action(self):
        assert check_permission([Role.observer], "propose_action") is False

    def test_agent_has_propose_action(self):
        assert check_permission([Role.agent], "propose_action") is True

    def test_policy_approver_has_approve_request(self):
        assert check_permission([Role.policy_approver], "approve_request") is True

    def test_policy_author_lacks_approve_request(self):
        assert check_permission([Role.policy_author], "approve_request") is False

    def test_operator_has_repair_quarantine(self):
        assert check_permission([Role.operator], "repair_quarantine") is True

    def test_auditor_lacks_write_permissions(self):
        assert check_permission([Role.auditor], "propose_action") is False

    def test_multiple_roles_one_has_permission(self):
        """Multiple roles, at least one has the permission -> True."""
        assert check_permission([Role.observer, Role.administrator], "create_lattice") is True

    def test_multiple_roles_none_has_permission(self):
        """Multiple roles, none has the permission -> False."""
        assert check_permission([Role.observer, Role.auditor], "create_lattice") is False

    def test_empty_roles_returns_false(self):
        assert check_permission([], "read_policy") is False

    def test_string_role_values_accepted(self):
        """check_permission accepts string role values, not just enum."""
        assert check_permission(["administrator"], "create_lattice") is True

    def test_invalid_string_role_ignored(self):
        """Invalid string role is skipped, not an error."""
        assert check_permission(["bad_role", Role.administrator], "create_lattice") is True
        assert check_permission(["bad_role"], "read_policy") is False


# --------------------------------------------------------------------------- #
# is_human
# --------------------------------------------------------------------------- #


class TestIsHuman:
    """Tests for is_human function."""

    def test_human_principal_returns_true(self):
        """Principal with type=human -> True."""
        p = _make_principal(ptype=PrincipalType.human)
        assert is_human(p) is True

    def test_agent_principal_returns_false(self):
        """Principal with type=agent -> False."""
        p = _make_principal(ptype=PrincipalType.agent)
        assert is_human(p) is False

    def test_service_principal_returns_false(self):
        p = _make_principal(ptype=PrincipalType.service)
        assert is_human(p) is False

    def test_proxy_principal_returns_false(self):
        p = _make_principal(ptype=PrincipalType.proxy)
        assert is_human(p) is False

    def test_is_human_with_string_type(self):
        """is_human works when type is stored as string (use_enum_values)."""
        p = Principal(
            id=VALID_XID,
            name="Test",
            type="human",
            status="active",
            registered_at=_now_iso(),
        )
        assert is_human(p) is True

    def test_is_human_with_string_agent_type(self):
        p = Principal(
            id=VALID_XID,
            name="Test",
            type="agent",
            status="active",
            registered_at=_now_iso(),
        )
        assert is_human(p) is False


# --------------------------------------------------------------------------- #
# Principal model
# --------------------------------------------------------------------------- #


class TestPrincipalModel:
    """Tests for Principal model."""

    def test_principal_fields(self):
        p = _make_principal()
        assert p.id == VALID_XID
        assert p.name == "Test Principal"
        assert p.status == "active"

    def test_principal_invalid_id_raises(self):
        with pytest.raises(Exception):
            Principal(
                id="too-short",
                name="Test",
                type=PrincipalType.human,
                status=PrincipalStatus.active,
                registered_at=_now_iso(),
            )

    def test_principal_extra_fields_rejected(self):
        with pytest.raises(Exception):
            Principal(
                id=VALID_XID,
                name="Test",
                type=PrincipalType.human,
                status=PrincipalStatus.active,
                registered_at=_now_iso(),
                extra_field="bad",  # type: ignore[call-arg]
            )

    def test_principal_default_description(self):
        p = _make_principal()
        assert p.description == ""

    def test_principal_machine_optional(self):
        p = _make_principal(machine="host-001")
        assert p.machine == "host-001"


# --------------------------------------------------------------------------- #
# RoleBinding model
# --------------------------------------------------------------------------- #


class TestRoleBinding:
    """Tests for RoleBinding model."""

    def test_role_binding_basic(self):
        rb = RoleBinding(
            principal_id=VALID_XID,
            role=Role.administrator,
        )
        assert rb.principal_id == VALID_XID
        assert rb.role == "administrator"
        assert rb.project_id is None

    def test_role_binding_with_project(self):
        rb = RoleBinding(
            principal_id=VALID_XID,
            role=Role.observer,
            project_id="proj-123",
        )
        assert rb.project_id == "proj-123"

    def test_role_binding_invalid_principal_id(self):
        with pytest.raises(Exception):
            RoleBinding(
                principal_id="bad",
                role=Role.observer,
            )
