"""EP-Governance exception hierarchy.

All EP-Governance errors derive from EPError.  Specific error types allow
callers to distinguish failure modes without string-matching messages.
"""

from __future__ import annotations


class EPError(Exception):
    """Base exception for all EP-Governance errors."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigError(EPError):
    """Configuration is missing or invalid."""


# ---------------------------------------------------------------------------
# Identity and authorization
# ---------------------------------------------------------------------------


class AuthenticationError(EPError):
    """The caller could not be authenticated."""


class AuthorizationError(EPError):
    """The caller is authenticated but not permitted to perform the operation."""


class CredentialError(EPError):
    """A credential is invalid, expired, or not found."""


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class PolicyError(EPError):
    """Base error for policy-related failures."""


class PolicyConflictError(PolicyError):
    """Two active policies with the same priority and conflicting effects."""


class PolicyNotActiveError(PolicyError):
    """A policy is not in the active lifecycle state."""


class PolicyNotFoundError(PolicyError):
    """A referenced policy does not exist."""


class OverrideError(PolicyError):
    """An override attempt does not satisfy all required controls."""


class SeparationOfDutiesError(EPError):
    """The requester attempted to approve their own action."""


# ---------------------------------------------------------------------------
# Transition and branch
# ---------------------------------------------------------------------------


class TransitionError(EPError):
    """Base error for transition-related failures."""


class IllegalTransitionError(TransitionError):
    """A transition from one stage to another is not legal."""


class ApprovalAlreadyDecidedError(TransitionError):
    """The approval request was already decided by another approver.

    Raised when :meth:`ApprovalRepository.decide` returns ``None`` because its
    ``WHERE status = 'pending'`` guard failed — i.e. a concurrent approver
    already approved or denied the request (Issue Critical 3).
    """


class StaleHeadError(TransitionError):
    """The branch head has advanced since the proposal was created.

    The caller must re-read branch state and retry.
    """


class ResourceExhaustedError(TransitionError):
    """The planning budget (BT) is exhausted for this branch."""


# ---------------------------------------------------------------------------
# Authorization tokens
# ---------------------------------------------------------------------------


class TokenError(EPError):
    """Base error for authorization-token failures."""


class TokenExpiredError(TokenError):
    """The authorization token has expired."""


class TokenUsedError(TokenError):
    """The authorization token has already been claimed."""


class TokenInvalidError(TokenError):
    """The authorization token is invalid (bad signature, wrong audience, etc.)."""


class StaleAuthorizationError(TokenError):
    """Relevant governance changed between authorization and execution."""


class PayloadMismatchError(TokenError):
    """The payload hash does not match the authorized payload hash."""


# ---------------------------------------------------------------------------
# Classification and resources
# ---------------------------------------------------------------------------


class ClassificationError(EPError):
    """Action classification failed."""


class ResourceCanonicalizationError(EPError):
    """A resource could not be canonicalized with sufficient confidence."""


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


class RiskError(EPError):
    """Base error for risk-assessment failures."""


class RiskThresholdExceededError(RiskError):
    """Residual risk exceeds the threshold for the domain."""


class MitigationError(RiskError):
    """A mitigation is invalid, expired, or lacks evidence."""


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditError(EPError):
    """Base error for audit-related failures."""


class AuditChainError(AuditError):
    """The audit chain verification failed (hash mismatch or broken linkage)."""


class AuditWriteError(AuditError):
    """An attempt to write an audit event by an unauthorized caller."""


# ---------------------------------------------------------------------------
# Transfer
# ---------------------------------------------------------------------------


class TransferError(EPError):
    """Base error for transfer-package failures."""


class TransferSignatureError(TransferError):
    """A transfer package signature is invalid or cannot be verified."""


class TransferImportError(TransferError):
    """A transfer package import failed."""


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


class DatabaseError(EPError):
    """Base error for database-related failures."""


class MigrationError(DatabaseError):
    """A database migration failed."""


class ConcurrencyError(DatabaseError):
    """A database concurrency conflict occurred."""


class TransactionOwnershipError(DatabaseError):
    """A transaction context manager was entered while the connection already
    had a pending (autobegun or explicit) transaction.

    The ``transaction()`` / ``serializable_transaction()`` helpers require a
    clean connection so that the caller's pending work is not silently
    committed or rolled back by the context manager.  Callers must commit (or
    roll back) any open transaction before entering these helpers.
    """


# ---------------------------------------------------------------------------
# XID
# ---------------------------------------------------------------------------


class XIDError(EPError):
    """XID generation or parsing failed."""
