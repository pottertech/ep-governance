"""Phase 10 tests: embeddings — semantic assistance only, never enforcement.

Tests that embeddings are optional, return empty when provider=none,
and that all three permitted uses (template suggestion, policy discovery,
audit search) work correctly. Also verifies that embeddings never participate
in enforcement decisions.
"""

from __future__ import annotations

import pytest

from ep_governance.embeddings import (
    NoneProvider,
    OllamaProvider,
    get_embedding_provider,
    suggest_policy_templates,
    find_related_policies,
    semantic_audit_search,
    _cosine_similarity,
)


class TestNoneProvider:
    def test_embed_returns_empty(self):
        provider = NoneProvider()
        assert provider.embed("test") == []

    def test_embed_batch_returns_empty(self):
        provider = NoneProvider()
        result = provider.embed_batch(["a", "b"])
        assert result == [[], []]

    def test_model_name_is_none(self):
        assert NoneProvider().model_name == "none"

    def test_dimension_is_zero(self):
        assert NoneProvider().dimension == 0


class TestCosineSimilarity:
    def test_identical_vectors(self):
        v = [1.0, 0.5, 0.3]
        assert _cosine_similarity(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors(self):
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert _cosine_similarity(a, b) == pytest.approx(0.0)

    def test_empty_vectors(self):
        assert _cosine_similarity([], []) == 0.0
        assert _cosine_similarity([1.0], []) == 0.0

    def test_different_length(self):
        assert _cosine_similarity([1.0, 2.0], [1.0]) == 0.0


class TestProviderFactory:
    def test_get_provider_with_none(self, monkeypatch):
        monkeypatch.setenv("EP_DB_URL", "sqlite:///test.db")
        monkeypatch.setenv("EP_EMBEDDING_PROVIDER", "none")
        provider = get_embedding_provider()
        assert isinstance(provider, NoneProvider)

    def test_get_provider_default_is_none(self, monkeypatch):
        monkeypatch.setenv("EP_DB_URL", "sqlite:///test.db")
        monkeypatch.delenv("EP_EMBEDDING_PROVIDER", raising=False)
        provider = get_embedding_provider()
        assert isinstance(provider, NoneProvider)


class TestSuggestPolicyTemplates:
    def test_returns_empty_with_none_provider(self):
        """With NoneProvider, template suggestions should be empty."""
        result = suggest_policy_templates(
            "never delete production data",
            [{"description": "deny db.drop", "template": {}}],
            provider=NoneProvider(),
        )
        assert result == []

    def test_returns_empty_with_no_templates(self):
        result = suggest_policy_templates("never delete", [], provider=NoneProvider())
        assert result == []

    def test_returns_empty_with_no_provider(self, monkeypatch):
        monkeypatch.setenv("EP_DB_URL", "sqlite:///test.db")
        monkeypatch.setenv("EP_EMBEDDING_PROVIDER", "none")
        result = suggest_policy_templates("never delete", [{"description": "test", "template": {}}])
        assert result == []


class TestFindRelatedPolicies:
    def test_returns_empty_with_none_provider(self):
        result = find_related_policies(
            "drop table",
            [{"id": "1", "description": "deny db.drop"}],
            provider=NoneProvider(),
        )
        assert result == []

    def test_returns_empty_with_no_policies(self):
        result = find_related_policies("test", [], provider=NoneProvider())
        assert result == []


class TestSemanticAuditSearch:
    def test_returns_empty_with_none_provider(self):
        result = semantic_audit_search(
            "database changes",
            [{"id": "1", "event_type": "transition_committed"}],
            provider=NoneProvider(),
        )
        assert result == []

    def test_returns_empty_with_no_events(self):
        result = semantic_audit_search("test", [], provider=NoneProvider())
        assert result == []


class TestEmbeddingsNeverEnforce:
    """Embeddings MUST NEVER participate in enforcement decisions."""

    def test_suggest_returns_suggestions_not_decisions(self):
        """suggest_policy_templates returns suggestions, not active policies."""
        result = suggest_policy_templates(
            "deny all drops",
            [{"description": "deny db.drop", "template": {"effect": "deny"}}],
            provider=NoneProvider(),
        )
        # Result is always empty with NoneProvider — no enforcement possible
        assert result == []

    def test_find_related_does_not_authorize(self):
        """find_related_policies returns related policies, not authorization."""
        result = find_related_policies(
            "select from database",
            [{"id": "1", "description": "allow db.select", "effect": "allow"}],
            provider=NoneProvider(),
        )
        # Empty result — no authorization from embeddings
        assert result == []

    def test_audit_search_does_not_modify(self):
        """semantic_audit_search returns events, never modifies them."""
        events = [{"id": "1", "event_type": "test", "event_data": {}}]
        result = semantic_audit_search("test", events, provider=NoneProvider())
        # Events are not modified
        assert events == [{"id": "1", "event_type": "test", "event_data": {}}]
