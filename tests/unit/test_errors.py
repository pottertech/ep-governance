"""Unit tests for EP-Governance exception hierarchy."""

from __future__ import annotations

import pytest

from ep_governance.errors import (
    EPError,
    ConfigError,
    AuthenticationError,
    AuthorizationError,
    PolicyError,
    PolicyConflictError,
    TransitionError,
    IllegalTransitionError,
    StaleHeadError,
    TokenError,
    TokenExpiredError,
    TokenUsedError,
    TokenInvalidError,
    ClassificationError,
    ResourceCanonicalizationError,
    RiskError,
    AuditError,
    AuditChainError,
    TransferError,
    XIDError,
    DatabaseError,
    ConcurrencyError,
    TransactionOwnershipError,
)


class TestErrorHierarchy:
    @pytest.mark.parametrize(
        "err_class",
        [
            ConfigError,
            AuthenticationError,
            AuthorizationError,
            PolicyError,
            PolicyConflictError,
            TransitionError,
            IllegalTransitionError,
            StaleHeadError,
            TokenError,
            TokenExpiredError,
            TokenUsedError,
            TokenInvalidError,
            ClassificationError,
            ResourceCanonicalizationError,
            RiskError,
            AuditError,
            AuditChainError,
            TransferError,
            XIDError,
            DatabaseError,
            ConcurrencyError,
            TransactionOwnershipError,
        ],
    )
    def test_all_errors_derive_from_eperror(self, err_class):
        assert issubclass(err_class, EPError)

    def test_policy_errors_derive_from_policy_error(self):
        assert issubclass(PolicyConflictError, PolicyError)

    def test_transition_errors_derive_from_transition_error(self):
        assert issubclass(IllegalTransitionError, TransitionError)
        assert issubclass(StaleHeadError, TransitionError)

    def test_token_errors_derive_from_token_error(self):
        assert issubclass(TokenExpiredError, TokenError)
        assert issubclass(TokenUsedError, TokenError)
        assert issubclass(TokenInvalidError, TokenError)

    def test_audit_errors_derive_from_audit_error(self):
        assert issubclass(AuditChainError, AuditError)

    def test_database_errors_derive_from_database_error(self):
        assert issubclass(ConcurrencyError, DatabaseError)
        assert issubclass(TransactionOwnershipError, DatabaseError)

    def test_can_raise_and_catch_base(self):
        with pytest.raises(EPError):
            raise ConfigError("test")

    def test_can_catch_specific(self):
        with pytest.raises(StaleHeadError):
            raise StaleHeadError("branch head advanced")
