"""EP-Governance embeddings — semantic assistance only, NEVER enforcement.

Permitted uses:
- suggest policy templates from natural language intent
- find possibly related policies for a proposed action
- semantic audit search

Forbidden uses:
- final allow or deny decision
- approval bypass
- policy priority
- risk acceptance

Embeddings are optional. When EP_EMBEDDING_PROVIDER=none, all functions
return empty results or None. All enforcement is fully functional without
embeddings.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from .config import load_config

__all__ = [
    "EmbeddingProvider",
    "NoneProvider",
    "OllamaProvider",
    "get_embedding_provider",
    "suggest_policy_templates",
    "find_related_policies",
    "semantic_audit_search",
]

# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class EmbeddingProvider(Protocol):
    """Protocol for embedding providers."""

    def embed(self, text: str) -> list[float]: ...

    def embed_batch(self, texts: list[str]) -> list[list[float]]: ...

    @property
    def model_name(self) -> str: ...

    @property
    def dimension(self) -> int: ...


# ---------------------------------------------------------------------------
# None provider (no embeddings)
# ---------------------------------------------------------------------------


class NoneProvider:
    """No-op embedding provider. Returns empty vectors."""

    def embed(self, text: str) -> list[float]:
        return []

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [[] for _ in texts]

    @property
    def model_name(self) -> str:
        return "none"

    @property
    def dimension(self) -> int:
        return 0


# ---------------------------------------------------------------------------
# Ollama provider (local, no API key needed)
# ---------------------------------------------------------------------------


class OllamaProvider:
    """Ollama embedding provider (local inference).

    Uses Ollama's /api/embeddings endpoint.
    Requires Ollama running at the configured host.
    """

    def __init__(self, model: str = "bge-m3", host: str = "localhost:11434") -> None:
        self._model = model
        self._host = host
        self._dim: int | None = None

    def embed(self, text: str) -> list[float]:
        try:
            import urllib.request

            url = f"http://{self._host}/api/embeddings"
            data = json.dumps({"model": self._model, "prompt": text}).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                embedding = result.get("embedding", [])
                if self._dim is None and embedding:
                    self._dim = len(embedding)
                return embedding
        except Exception:
            return []

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def dimension(self) -> int:
        return self._dim or 1024  # bge-m3 default


# ---------------------------------------------------------------------------
# Cosine similarity
# ---------------------------------------------------------------------------


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors. Returns 0.0 if either is empty."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def get_embedding_provider() -> EmbeddingProvider:
    """Get the configured embedding provider.

    Returns NoneProvider when EP_EMBEDDING_PROVIDER=none or not configured.
    """
    cfg = load_config()
    if cfg.embedding_provider == "none":
        return NoneProvider()
    elif cfg.embedding_provider == "ollama":
        return OllamaProvider(
            model=cfg.embedding_model or "bge-m3",
            host=cfg.embedding_host or "localhost:11434",
        )
    else:
        return NoneProvider()


# ---------------------------------------------------------------------------
# Permitted uses (semantic assistance only)
# ---------------------------------------------------------------------------


def suggest_policy_templates(
    natural_language: str,
    known_templates: list[dict[str, Any]] | None = None,
    provider: EmbeddingProvider | None = None,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Suggest policy templates by semantically matching natural language intent.

    This is ASSISTANCE ONLY — it suggests templates for a human to review.
    It NEVER creates, activates, or enforces a policy.

    Args:
        natural_language: Human intent, e.g. "never delete production data"
        known_templates: List of template dicts with 'description' and 'template' keys
        provider: Embedding provider (uses configured default if None)
        top_k: Maximum number of suggestions

    Returns:
        List of template dicts with similarity scores, sorted by relevance.
        Returns empty list if provider is None or no templates.
    """
    if provider is None:
        provider = get_embedding_provider()

    if not known_templates or provider.model_name == "none":
        return []

    query_embedding = provider.embed(natural_language)
    if not query_embedding:
        return []

    scored: list[tuple[float, dict[str, Any]]] = []
    for template in known_templates:
        desc = template.get("description", "")
        template_embedding = provider.embed(desc)
        score = _cosine_similarity(query_embedding, template_embedding)
        scored.append((score, {**template, "similarity_score": score}))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [t for _, t in scored[:top_k]]


def find_related_policies(
    action_description: str,
    policies: list[dict[str, Any]],
    provider: EmbeddingProvider | None = None,
    threshold: float = 0.5,
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """Find possibly related policies for a proposed action.

    This is DISCOVERY ONLY — it suggests policies for the agent to review.
    The enforcement decision is ALWAYS deterministic (from the policy engine).

    Args:
        action_description: Description of the proposed action
        policies: List of policy dicts with 'description' field
        provider: Embedding provider
        threshold: Minimum similarity score (0.0 to 1.0)
        top_k: Maximum results

    Returns:
        List of policies with similarity scores above threshold, sorted by relevance.
    """
    if provider is None:
        provider = get_embedding_provider()

    if not policies or provider.model_name == "none":
        return []

    query_embedding = provider.embed(action_description)
    if not query_embedding:
        return []

    scored: list[tuple[float, dict[str, Any]]] = []
    for policy in policies:
        desc = policy.get("description", "")
        policy_embedding = provider.embed(desc)
        score = _cosine_similarity(query_embedding, policy_embedding)
        if score >= threshold:
            scored.append((score, {**policy, "similarity_score": score}))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in scored[:top_k]]


def semantic_audit_search(
    query: str,
    audit_events: list[dict[str, Any]],
    provider: EmbeddingProvider | None = None,
    threshold: float = 0.3,
    top_k: int = 20,
) -> list[dict[str, Any]]:
    """Search audit events by semantic similarity.

    This is SEARCH ONLY — it finds events for review.
    It does NOT modify, delete, or authenticate audit events.

    Args:
        query: Search query, e.g. "actions that modified production database"
        audit_events: List of audit event dicts with 'event_data' or 'event_type'
        provider: Embedding provider
        threshold: Minimum similarity
        top_k: Maximum results

    Returns:
        List of audit events with similarity scores above threshold.
    """
    if provider is None:
        provider = get_embedding_provider()

    if not audit_events or provider.model_name == "none":
        return []

    query_embedding = provider.embed(query)
    if not query_embedding:
        return []

    scored: list[tuple[float, dict[str, Any]]] = []
    for event in audit_events:
        # Embed the event type and data description
        event_text = event.get("event_type", "")
        event_data = event.get("event_data", {})
        if isinstance(event_data, dict):
            event_text += " " + json.dumps(event_data, default=str)
        event_embedding = provider.embed(event_text)
        score = _cosine_similarity(query_embedding, event_embedding)
        if score >= threshold:
            scored.append((score, {**event, "similarity_score": score}))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [e for _, e in scored[:top_k]]
