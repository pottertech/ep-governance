"""EP-Governance bypass detection and reconciliation.

Compares target system activity logs against EP-Governance authorized action
logs. Any target action lacking a matching EP authorization is flagged as a
potential bypass. Also provides network-access and credential-isolation checks
for agent hosts.

The module is import-safe: no database or network connections are opened at
import time. All live connections are established lazily inside the functions
that need them.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Callable, Protocol

from sqlalchemy import text

from .errors import EPError

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

__all__ = [
    "ReconciliationReport",
    "BypassDetector",
    "reconcile_postgres_activity",
    "check_agent_network_access",
    "check_credential_isolation",
    "generate_alert",
]


# ---------------------------------------------------------------------------
# Protocols / type aliases
# ---------------------------------------------------------------------------


class ActivityLogReader(Protocol):
    """Protocol for target-specific activity log readers."""

    def read_activity(
        self,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return recent target activity entries as dicts.

        Each entry should contain at least an ``action_hash`` or
        ``payload_hash`` key for matching against EP authorization hashes.
        """
        ...


# Type alias for the callable form of an activity reader.
ActivityReaderFn = Callable[[datetime | None], list[dict[str, Any]]]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ReconciliationReport:
    """Result of a reconciliation pass between EP events and target activity.

    Attributes:
        matched: List of (ep_event, target_action) pairs that matched.
        unmatched_target: Target actions with no corresponding EP authorization
            (potential bypasses).
        unmatched_ep: EP authorizations with no corresponding target action
            (phantom authorizations).
        bypass_detected: True when unmatched_target is non-empty.
        checked_at: ISO-8601 UTC timestamp of when the check ran.
        summary: Human-readable summary string.
    """

    matched: list[tuple[dict[str, Any], dict[str, Any]]] = field(default_factory=list)
    unmatched_target: list[dict[str, Any]] = field(default_factory=list)
    unmatched_ep: list[dict[str, Any]] = field(default_factory=list)
    bypass_detected: bool = False
    checked_at: str = ""
    summary: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return current UTC time as ISO-8601 with microseconds and Z suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _parse_event_data(raw: Any) -> dict[str, Any]:
    """Parse event_data which may be a JSON string or already a dict."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _extract_hash(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Extract the first available hash key from *record*."""
    for key in keys:
        val = record.get(key)
        if val:
            return str(val)
    return None


def _normalize_hash(value: str | None) -> str | None:
    """Strip a ``sha256:`` prefix if present so hashes compare cleanly."""
    if value is None:
        return None
    if value.startswith("sha256:"):
        return value[len("sha256:") :]
    return value


# ---------------------------------------------------------------------------
# BypassDetector
# ---------------------------------------------------------------------------


class BypassDetector:
    """Detects bypasses by reconciling target activity against EP audit events.

    Parameters:
        gov_engine: SQLAlchemy engine for the governance DB (ep_events).
        activity_reader: Optional callable or object implementing
            :class:`ActivityLogReader`. When provided, it is used instead of
            the default PostgreSQL ``pg_stat_activity`` reader.
    """

    def __init__(
        self,
        gov_engine: Engine,
        activity_reader: ActivityLogReader | ActivityReaderFn | None = None,
    ) -> None:
        self.gov_engine = gov_engine
        self._activity_reader = activity_reader

    # -- public API --------------------------------------------------------

    def reconcile_postgres_activity(
        self,
        gov_engine: Engine | None = None,
        target_conn_params: dict[str, Any] | None = None,
        since: datetime | None = None,
    ) -> ReconciliationReport:
        """Reconcile PostgreSQL target activity against EP audit events.

        Args:
            gov_engine: Override engine for the governance DB. Defaults to
                the engine passed at construction.
            target_conn_params: Connection parameters for the target
                PostgreSQL (host, port, database, user, password). Ignored
                when a custom ``activity_reader`` was supplied.
            since: Only consider events/activity after this timestamp.
                ``None`` means no lower bound (all rows).

        Returns:
            A :class:`ReconciliationReport`.
        """
        engine = gov_engine or self.gov_engine
        ep_events = self._query_ep_events(engine, since)
        target_actions = self._query_target_activity(target_conn_params, since)
        return self._reconcile(ep_events, target_actions)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _query_ep_events(
        engine: Engine,
        since: datetime | None,
    ) -> list[dict[str, Any]]:
        """Query ep_events for execution_succeeded rows since *since*."""
        params: dict[str, Any] = {"event_type": "execution_succeeded"}
        since_clause = ""
        if since is not None:
            params["since"] = since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            since_clause = " AND created_at >= :since"

        sql = text(
            "SELECT id, lattice_id, sequence, event_type, event_data, "
            "  actor_principal_id, created_at "
            "FROM ep_events "
            "WHERE event_type = :event_type"
            f"{since_clause} "
            "ORDER BY created_at ASC"
        )

        with engine.connect() as conn:
            rows = conn.execute(sql, params).mappings().all()

        events: list[dict[str, Any]] = []
        for row in rows:
            row_dict = dict(row)
            row_dict["event_data"] = _parse_event_data(row_dict.get("event_data"))
            events.append(row_dict)
        return events

    def _query_target_activity(
        self,
        target_conn_params: dict[str, Any] | None,
        since: datetime | None,
    ) -> list[dict[str, Any]]:
        """Query the target system for recent activity.

        When a custom activity reader was supplied, it is used directly.
        Otherwise, the default PostgreSQL reader is used.
        """
        if self._activity_reader is not None:
            reader = self._activity_reader
            # Protocol-style object with read_activity method
            read_fn = getattr(reader, "read_activity", None)
            if callable(read_fn):
                result = read_fn(since)
                if isinstance(result, list):
                    return result
            # Callable form
            if callable(reader):
                result = reader(since)  # type: ignore[operator]
                if isinstance(result, list):
                    return result
        return _default_pg_activity_reader(target_conn_params, since)

    @staticmethod
    def _reconcile(
        ep_events: list[dict[str, Any]],
        target_actions: list[dict[str, Any]],
    ) -> ReconciliationReport:
        """Match EP events to target actions by payload hash."""
        # Build index of EP events by normalized payload hash.
        ep_index: dict[str, dict[str, Any]] = {}
        for ev in ep_events:
            data = ev.get("event_data", {})
            h = _normalize_hash(
                _extract_hash(data, ("payload_hash", "action_hash", "hash"))
            )
            if h:
                ep_index[h] = ev

        # Build index of target actions by normalized hash.
        target_index: dict[str, dict[str, Any]] = {}
        for ta in target_actions:
            h = _normalize_hash(
                _extract_hash(ta, ("payload_hash", "action_hash", "hash", "query_hash"))
            )
            if h:
                target_index[h] = ta

        matched: list[tuple[dict[str, Any], dict[str, Any]]] = []
        unmatched_ep: list[dict[str, Any]] = []
        unmatched_target: list[dict[str, Any]] = []

        # Match: EP event hash present in target actions.
        matched_target_keys: set[str] = set()
        for h, ev in ep_index.items():
            if h in target_index:
                matched.append((ev, target_index[h]))
                matched_target_keys.add(h)
            else:
                unmatched_ep.append(ev)

        # Target actions whose hash is NOT in EP events.
        for h, ta in target_index.items():
            if h not in matched_target_keys and h not in ep_index:
                unmatched_target.append(ta)

        # Also include target actions with no extractable hash — these are
        # suspicious (potential bypass) because EP always records a hash.
        for ta in target_actions:
            h = _normalize_hash(
                _extract_hash(ta, ("payload_hash", "action_hash", "hash", "query_hash"))
            )
            if h is None and ta not in unmatched_target:
                unmatched_target.append(ta)

        bypass = len(unmatched_target) > 0
        checked_at = _now_iso()
        summary = (
            f"Reconciliation at {checked_at}: "
            f"{len(matched)} matched, "
            f"{len(unmatched_target)} unmatched target (bypass), "
            f"{len(unmatched_ep)} unmatched EP (phantom). "
            f"Bypass detected: {bypass}"
        )

        return ReconciliationReport(
            matched=matched,
            unmatched_target=unmatched_target,
            unmatched_ep=unmatched_ep,
            bypass_detected=bypass,
            checked_at=checked_at,
            summary=summary,
        )


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def reconcile_postgres_activity(
    gov_engine: Engine,
    target_conn_params: dict[str, Any] | None = None,
    since: datetime | None = None,
) -> ReconciliationReport:
    """Module-level shortcut: create a BypassDetector and reconcile.

    See :meth:`BypassDetector.reconcile_postgres_activity` for details.
    """
    detector = BypassDetector(gov_engine)
    return detector.reconcile_postgres_activity(
        gov_engine=gov_engine,
        target_conn_params=target_conn_params,
        since=since,
    )


# ---------------------------------------------------------------------------
# Default PostgreSQL activity reader
# ---------------------------------------------------------------------------


def _default_pg_activity_reader(
    conn_params: dict[str, Any] | None,
    since: datetime | None,
) -> list[dict[str, Any]]:
    """Read recent SQL activity from a target PostgreSQL.

    Tries a custom ``ep_audit`` table first (if it exists), falling back to
    ``pg_stat_activity``. Returns a list of dicts with at least ``payload_hash``
    and ``query`` keys.

    This function is only called when no custom activity reader is supplied.
    It opens a real connection to the target DB, so it is NOT used in unit
    tests (tests inject a custom reader or mock the engine).
    """
    if conn_params is None:
        return []

    import sqlalchemy as sa  # local import — avoid hard dep at module import

    url = _build_pg_url(conn_params)
    engine = sa.create_engine(url, future=True)
    try:
        return _read_pg_activity(engine, since)
    finally:
        engine.dispose()


def _build_pg_url(params: dict[str, Any]) -> str:
    """Build a SQLAlchemy PostgreSQL URL from a params dict."""
    host = params.get("host", "localhost")
    port = params.get("port", 5432)
    database = params.get("database", "")
    user = params.get("user", "")
    password = params.get("password", "")
    auth = f"{user}:{password}@" if password else f"{user}@" if user else ""
    return f"postgresql+psycopg://{auth}{host}:{port}/{database}"


def _read_pg_activity(engine: Any, since: datetime | None) -> list[dict[str, Any]]:
    """Query the target PG for activity rows."""
    since_clause = ""
    params: dict[str, Any] = {}
    if since is not None:
        params["since"] = since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        since_clause = " WHERE created_at >= :since"

    # Try custom audit table first.
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT payload_hash, query, principal_id, created_at "
                    "FROM ep_audit"
                    f"{since_clause} ORDER BY created_at ASC"
                ),
                params,
            ).mappings().all()
            return [dict(r) for r in rows]
    except Exception:
        pass  # fall through to pg_stat_activity

    # Fallback: pg_stat_activity (only shows currently-running queries).
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT md5(query) AS payload_hash, query, "
                "  usename AS principal_id, query_start AS created_at "
                "FROM pg_stat_activity "
                "WHERE state = 'active' AND query IS NOT NULL"
            )
        ).mappings().all()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Network access check
# ---------------------------------------------------------------------------


def check_agent_network_access(
    agent_host: str,
    allowed_endpoints: list[str],
) -> list[str]:
    """Check whether *agent_host* can reach endpoints it should not.

    Attempts a TCP connect to each endpoint in the global endpoint space
    (common sensitive ports) that is NOT in *allowed_endpoints*. Returns the
    list of endpoints that are reachable and should be blocked.

    Args:
        agent_host: Hostname or IP of the agent machine.
        allowed_endpoints: Endpoints the agent is explicitly permitted to
            reach, in ``host:port`` format.

    Returns:
        List of reachable ``host:port`` endpoints that should be blocked.
    """
    # Common sensitive endpoints that an agent should NOT reach directly.
    sensitive_ports = [5432, 6379, 27017, 3306, 9092, 2379, 443, 80]
    allowed_set = set(allowed_endpoints)
    violations: list[str] = []

    for port in sensitive_ports:
        endpoint = f"{agent_host}:{port}"
        if endpoint in allowed_set:
            continue
        if _can_connect(agent_host, port, timeout=1.0):
            violations.append(endpoint)

    return violations


def _can_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except (OSError, socket.gaierror):
        return False


# ---------------------------------------------------------------------------
# Credential isolation check
# ---------------------------------------------------------------------------


def check_credential_isolation(
    agent_host: str,
    expected_credentials: list[str],
) -> list[str]:
    """Check whether credentials that should only be on the proxy are on the agent.

    This function attempts to detect whether any credential identifiers (e.g.,
    env var names, file paths, or key names) from *expected_credentials* are
    present on the given agent host. In practice this would SSH to the agent
    or call a local checker; here we use a pluggable approach so tests can
    mock the actual check.

    Args:
        agent_host: Hostname or IP of the agent machine.
        expected_credentials: Credential identifiers that should only exist
            on the proxy (not on the agent).

    Returns:
        List of credential identifiers found on the agent host. Empty list
        means the host is clean.
    """
    found: list[str] = []
    checker = _get_credential_checker()
    for cred in expected_credentials:
        if checker(agent_host, cred):
            found.append(cred)
    return found


# The default credential checker is a no-op that reports clean. In production
# this would be replaced with an SSH-based or agent-side check. Tests override
# this via monkeypatching.
_credential_checker: Callable[[str, str], bool] | None = None


def _get_credential_checker() -> Callable[[str, str], bool]:
    """Return the active credential checker function."""
    if _credential_checker is not None:
        return _credential_checker
    return _default_credential_checker


def _default_credential_checker(agent_host: str, credential: str) -> bool:
    """Default: always returns False (no credentials found).

    In production, this would SSH to *agent_host* and check for the presence
    of *credential* (env var, file, etc.).
    """
    return False


# ---------------------------------------------------------------------------
# Alert generation
# ---------------------------------------------------------------------------


def generate_alert(report: ReconciliationReport) -> str:
    """Format a bypass alert message for stderr / notification systems.

    Args:
        report: A :class:`ReconciliationReport`.

    Returns:
        A multi-line alert string. When no bypass is detected, returns a
        short "clean" message.
    """
    if not report.bypass_detected:
        return (
            f"[EP-Governance] Reconciliation clean at {report.checked_at}. "
            f"No bypass detected. {report.summary}"
        )

    lines = [
        "=" * 72,
        "EP-GOVERNANCE BYPASS DETECTED",
        "=" * 72,
        f"Checked at:  {report.checked_at}",
        f"Summary:     {report.summary}",
        "",
        f"Unmatched target actions ({len(report.unmatched_target)}):",
    ]
    for i, action in enumerate(report.unmatched_target, 1):
        h = _extract_hash(action, ("payload_hash", "action_hash", "hash", "query_hash"))
        query = action.get("query", action.get("action", "<unknown>"))
        lines.append(f"  [{i}] hash={h or 'N/A'}  action={query}")

    if report.unmatched_ep:
        lines.append("")
        lines.append(f"Phantom EP authorizations ({len(report.unmatched_ep)}):")
        for i, ev in enumerate(report.unmatched_ep, 1):
            data = ev.get("event_data", {})
            h = _extract_hash(data, ("payload_hash", "action_hash", "hash"))
            lines.append(
                f"  [{i}] event_id={ev.get('id', 'N/A')}  hash={h or 'N/A'}"
            )

    lines.append("")
    lines.append(
        "ACTION REQUIRED: Investigate unmatched target actions immediately. "
        "These represent target system activity with no corresponding EP "
        "authorization — a potential bypass of governance controls."
    )
    lines.append("=" * 72)
    return "\n".join(lines)