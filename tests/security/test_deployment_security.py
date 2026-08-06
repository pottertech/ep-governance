"""Tests for new deployment.py security functions.

Covers:
  - verify_file_ownership: file-not-found, symlink, wrong UID,
    group-writable, world-writable, correct ownership
  - EnforcementCapability: from_status active/inactive,
    require_binding_enforcement raises/passes, frozen/immutability
  - verify_deployment: rejects invalid requested_mode with ValueError
"""

from __future__ import annotations

import os
import stat
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from ep_governance.deployment import (
    EnforcementCapability,
    EnforcementStatus,
    EnforcementUnavailableError,
    IsolationCheck,
    verify_deployment,
    verify_file_ownership,
)
from ep_governance.errors import EPError


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _make_status(
    effective: str = "enforced",
    passed: bool = True,
    reasons: list[str] | None = None,
) -> EnforcementStatus:
    """Build an EnforcementStatus with a single required check."""
    check = IsolationCheck(
        name="test_check",
        passed=passed,
        evidence="test evidence",
        required=True,
    )
    return EnforcementStatus(
        requested_mode="enforced" if effective == "enforced" else "advisory",
        effective_mode=effective,
        checks=[check],
        reasons=reasons or [],
    )


# --------------------------------------------------------------------------- #
# verify_file_ownership
# --------------------------------------------------------------------------- #


class TestVerifyFileOwnership:
    """Tests for verify_file_ownership()."""

    def test_file_not_found(self, tmp_path):
        """A missing file should fail with 'File not found' evidence."""
        missing = str(tmp_path / "does_not_exist")
        result = verify_file_ownership(missing)
        assert result.passed is False
        assert "not found" in result.evidence.lower()
        assert result.name == f"file_ownership:{missing}"

    def test_symlink_rejected(self, tmp_path):
        """A symlink should be rejected when reject_symlinks=True."""
        target = tmp_path / "real.txt"
        target.write_text("hello")
        link = tmp_path / "link.txt"
        os.symlink(target, link)

        result = verify_file_ownership(str(link), require_uid=os.getuid())
        assert result.passed is False
        assert "symlink" in result.evidence.lower()

    def test_symlink_allowed_when_reject_disabled(self, tmp_path):
        """A symlink is not rejected on symlink grounds when reject_symlinks=False.

        We verify this by confirming the evidence does not contain the
        canonical symlink-rejection message.  (We cannot simply check
        for the substring "symlink" because tmp_path may contain that
        word in the directory name.)
        """
        target = tmp_path / "real.txt"
        target.write_text("hello")
        os.chmod(target, 0o644)
        link = tmp_path / "link.txt"
        os.symlink(target, link)

        result = verify_file_ownership(
            str(link),
            require_uid=os.getuid(),
            reject_symlinks=False,
        )
        # The canonical symlink rejection evidence is:
        #   "File is a symlink: ... — symlinks are not trusted"
        # When reject_symlinks=False we should never see that message.
        assert "symlinks are not trusted" not in result.evidence
        assert "is a symlink" not in result.evidence

    def test_wrong_uid(self, tmp_path):
        """A file owned by the wrong UID should fail."""
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        os.chmod(f, 0o644)

        # Request a UID that is very unlikely to be the current user.
        wrong_uid = 999_999
        if wrong_uid == os.getuid():
            wrong_uid = 888_888

        result = verify_file_ownership(str(f), require_uid=wrong_uid)
        assert result.passed is False
        assert "uid" in result.evidence.lower()
        assert str(wrong_uid) in result.evidence

    def test_group_writable_rejected(self, tmp_path):
        """A group-writable file should fail when reject_group_writable=True."""
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        os.chmod(f, 0o664)  # group-writable

        result = verify_file_ownership(str(f), require_uid=os.getuid())
        assert result.passed is False
        assert "group-writable" in result.evidence.lower()

    def test_group_writable_allowed_when_reject_disabled(self, tmp_path):
        """A group-writable file passes when reject_group_writable=False."""
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        os.chmod(f, 0o664)  # group-writable but not world-writable

        result = verify_file_ownership(
            str(f),
            require_uid=os.getuid(),
            reject_group_writable=False,
        )
        assert result.passed is True

    def test_world_writable_rejected(self, tmp_path):
        """A world-writable file should fail when reject_world_writable=True."""
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        os.chmod(f, 0o606)  # world-writable, not group-writable

        result = verify_file_ownership(str(f), require_uid=os.getuid())
        assert result.passed is False
        assert "world-writable" in result.evidence.lower()

    def test_world_writable_allowed_when_reject_disabled(self, tmp_path):
        """A world-writable file passes when reject_world_writable=False."""
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        os.chmod(f, 0o606)  # world-writable but not group-writable

        result = verify_file_ownership(
            str(f),
            require_uid=os.getuid(),
            reject_world_writable=False,
        )
        assert result.passed is True

    def test_correct_ownership_passes(self, tmp_path):
        """A file with correct UID and safe permissions should pass."""
        f = tmp_path / "config.yaml"
        f.write_text("key: value")
        os.chmod(f, 0o644)  # owner rw, group r, world r — safe

        result = verify_file_ownership(str(f), require_uid=os.getuid())
        assert result.passed is True
        assert str(os.getuid()) in result.evidence

    def test_correct_ownership_strict_mode(self, tmp_path):
        """A 0o600 file with correct UID passes."""
        f = tmp_path / "secret.key"
        f.write_text("secret")
        os.chmod(f, 0o600)

        result = verify_file_ownership(str(f), require_uid=os.getuid())
        assert result.passed is True

    def test_oserror_returns_failed_check(self, tmp_path, monkeypatch):
        """An OSError during file open should produce a failed check."""
        f = tmp_path / "config.yaml"
        f.write_text("data")
        os.chmod(f, 0o644)

        real_open = os.open

        def _raise_oserror(path, flags, *args, **kwargs):  # noqa: ANN001
            if str(path) == str(f):
                raise OSError("simulated open failure")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", _raise_oserror)

        result = verify_file_ownership(str(f), require_uid=os.getuid())
        assert result.passed is False
        assert "cannot open" in result.evidence.lower()

    def test_returns_isolation_check(self, tmp_path):
        """verify_file_ownership always returns an IsolationCheck."""
        missing = str(tmp_path / "nope")
        result = verify_file_ownership(missing)
        assert isinstance(result, IsolationCheck)
        assert result.required is True  # default


# --------------------------------------------------------------------------- #
# EnforcementCapability
# --------------------------------------------------------------------------- #


class TestEnforcementCapability:
    """Tests for the EnforcementCapability dataclass."""

    def test_from_status_active(self):
        """from_status with an enforced+passing status yields active capability."""
        status = _make_status(effective="enforced", passed=True)
        cap = EnforcementCapability.from_status(status, agent_principal_id="agent-1")

        assert cap.effective_mode == "enforced"
        assert cap.binding_enforcement_active is True
        assert cap.agent_principal_id == "agent-1"
        assert cap.failure_reasons == []
        # verification_time should be an ISO timestamp
        assert cap.verification_time
        # should parse as ISO
        datetime.fromisoformat(cap.verification_time)

    def test_from_status_inactive(self):
        """from_status with an advisory status yields inactive capability."""
        status = _make_status(effective="advisory", passed=False, reasons=["bad"])
        cap = EnforcementCapability.from_status(status, agent_principal_id="agent-2")

        assert cap.effective_mode == "advisory"
        assert cap.binding_enforcement_active is False
        assert cap.failure_reasons == ["bad"]

    def test_from_status_inactive_no_reasons(self):
        """from_status copies status.reasons only when inactive."""
        status = _make_status(effective="enforced", passed=True, reasons=["ignored"])
        cap = EnforcementCapability.from_status(status, agent_principal_id="a")
        # When active, failure_reasons is forced to [] regardless of status.reasons
        assert cap.failure_reasons == []

    def test_require_binding_enforcement_raises_when_inactive(self):
        """require_binding_enforcement raises when not active."""
        cap = EnforcementCapability(
            effective_mode="advisory",
            binding_enforcement_active=False,
            agent_principal_id="agent-x",
            verification_time=datetime.now(UTC).isoformat(),
            failure_reasons=["check A failed", "check B failed"],
        )
        with pytest.raises(EnforcementUnavailableError) as exc_info:
            cap.require_binding_enforcement()

        msg = str(exc_info.value)
        assert "not active" in msg.lower()
        assert "advisory" in msg
        assert "check A failed" in msg
        assert "check B failed" in msg

    def test_require_binding_enforcement_raises_no_reasons(self):
        """require_binding_enforcement raises with 'unknown' when no reasons."""
        cap = EnforcementCapability(
            effective_mode="advisory",
            binding_enforcement_active=False,
            agent_principal_id="agent-x",
            verification_time=datetime.now(UTC).isoformat(),
            failure_reasons=[],
        )
        with pytest.raises(EnforcementUnavailableError) as exc_info:
            cap.require_binding_enforcement()
        assert "unknown" in str(exc_info.value).lower()

    def test_require_binding_enforcement_passes_when_active(self):
        """require_binding_enforcement does not raise when active."""
        cap = EnforcementCapability(
            effective_mode="enforced",
            binding_enforcement_active=True,
            agent_principal_id="agent-y",
            verification_time=datetime.now(UTC).isoformat(),
            failure_reasons=[],
        )
        # Should return None without raising
        result = cap.require_binding_enforcement()
        assert result is None

    def test_frozen_immutability(self):
        """EnforcementCapability is frozen — attribute assignment raises."""
        cap = EnforcementCapability(
            effective_mode="enforced",
            binding_enforcement_active=True,
            agent_principal_id="agent-z",
            verification_time=datetime.now(UTC).isoformat(),
            failure_reasons=[],
        )
        with pytest.raises(FrozenInstanceError):
            cap.effective_mode = "advisory"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            cap.binding_enforcement_active = False  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            cap.agent_principal_id = "other"  # type: ignore[misc]

    def test_frozen_cannot_append_failure_reasons(self):
        """The failure_reasons list field on a frozen dataclass cannot be
        reassigned, though the list itself is mutable (default_factory).
        Reassignment must raise."""
        cap = EnforcementCapability(
            effective_mode="advisory",
            binding_enforcement_active=False,
            agent_principal_id="agent-w",
            verification_time=datetime.now(UTC).isoformat(),
            failure_reasons=["x"],
        )
        with pytest.raises(FrozenInstanceError):
            cap.failure_reasons = ["y"]  # type: ignore[misc]

    def test_is_ep_error_subclass(self):
        """EnforcementUnavailableError is an EPError subclass."""
        assert issubclass(EnforcementUnavailableError, EPError)


# --------------------------------------------------------------------------- #
# verify_deployment requested_mode validation
# --------------------------------------------------------------------------- #


class TestVerifyDeploymentModeValidation:
    """Tests that verify_deployment validates requested_mode."""

    @pytest.mark.parametrize("bad_mode", ["", "Enforced", "ENFORCED", "strict", "none", "off", "true", "1"])
    def test_invalid_requested_mode_raises_valueerror(self, bad_mode):
        """verify_deployment raises ValueError for invalid mode strings."""
        with pytest.raises(ValueError, match="requested_mode"):
            verify_deployment(bad_mode, env={})

    def test_empty_string_raises(self):
        """Empty string is not a valid mode."""
        with pytest.raises(ValueError):
            verify_deployment("", env={})

    def test_none_not_accepted(self):
        """None is not a valid mode (raises before any checks run)."""
        with pytest.raises((ValueError, TypeError)):
            verify_deployment(None, env={})  # type: ignore[arg-type]

    def test_advisory_mode_accepted(self):
        """'advisory' is accepted and returns immediately without checks."""
        status = verify_deployment("advisory", env={})
        assert status.requested_mode == "advisory"
        assert status.effective_mode == "advisory"
        assert status.binding_enforcement_active is False

    def test_enforced_mode_accepted(self):
        """'enforced' is accepted (does not raise ValueError).

        It will run checks and likely return advisory effective_mode
        in this bare environment, but the key assertion is that no
        ValueError is raised for the mode itself.
        """
        # Use empty env and no tools — will fail checks but must not
        # raise ValueError.
        status = verify_deployment("enforced", env={})
        assert status.requested_mode == "enforced"
        # In a bare environment, effective will be advisory because checks fail
        # but we only care that no ValueError was raised.

    def test_error_message_contains_value(self):
        """The ValueError message includes the offending value."""
        with pytest.raises(ValueError, match="banana"):
            verify_deployment("banana", env={})