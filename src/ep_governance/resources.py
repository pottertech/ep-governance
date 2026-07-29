"""Resource canonicalization for EP-Governance.

Converts raw resource identifiers (URIs, paths, hostnames) into a canonical
form so that policies can be matched deterministically regardless of how the
resource was originally expressed.

Canonical URI schemes:
  postgres://  — PostgreSQL database/schema/table
  host://      — A network host
  container:// — A running container
  file://      — An absolute file path
  email://     — An email recipient
  git://       — A git remote/branch

Examples::

    postgres://cloudhub/gbrain_pilot/public/memory_items
    host://cloudhub.pottersquill.com
    container://cloudhub/open-webui
    file://cloudhub/etc/open-webui/config.yaml
    email://recipient/example@example.com
    git://github.com/pottertech/ep-governance/branch/main
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC
from urllib.parse import quote, unquote, urlparse

from .errors import ResourceCanonicalizationError

__all__ = [
    "CanonicalResource",
    "canonicalize_resource",
    "match_glob",
]

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

_DEFAULT_PORTS: dict[str, int] = {
    "postgres": 5432,
    "postgresql": 5432,
}

_SUPPORTED_SCHEMES: frozenset[str] = frozenset(
    {"postgres", "postgresql", "host", "container", "file", "email", "git"}
)

# Hostname aliases that we normalise to a single canonical hostname.
_HOSTNAME_ALIASES: dict[str, str] = {
    # Add alias mappings here as needed, e.g.:
    # "db": "cloudhub",
    # "localhost": "cloudhub",
}

# Regex for a valid hostname label.
_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# Known symlink indicators in paths.
_SYMLINK_INDICATORS = {"..", "."}

# Regex for a valid email local-part and domain.
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# Regex for XID-like git branch names (permissive but bounded).
_GIT_BRANCH_RE = re.compile(r"^[a-zA-Z0-9._/\-]+$")


# --------------------------------------------------------------------------- #
# Dataclass
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CanonicalResource:
    """A canonicalized resource.

    Attributes:
        scheme:    Lowercase scheme (postgres, host, container, file, email, git).
        path:      Scheme-specific path component (decoded, normalized).
        raw:       The original raw resource string.
        canonical: The fully canonical URI string.
    """

    scheme: str
    path: str
    raw: str
    canonical: str


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


def _now_iso() -> str:
    """Return current UTC timestamp (not used currently but reserved)."""
    from datetime import datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_hostname(host: str) -> str:
    """Lowercase and resolve known aliases for a hostname.

    If the host is an IP literal (v4 or v6), return its canonical compressed form.
    """
    host = host.strip().lower().rstrip(".")
    if not host:
        raise ResourceCanonicalizationError("Empty hostname")

    # IP literal
    try:
        ip = ipaddress.ip_address(host)
        return str(ip)  # compressed form
    except ValueError:
        pass

    # Check alias table
    host = _HOSTNAME_ALIASES.get(host, host)

    # Validate DNS hostname labels
    labels = host.split(".") if "." in host else [host]
    for label in labels:
        if not _HOSTNAME_LABEL_RE.match(label):
            raise ResourceCanonicalizationError(f"Invalid hostname label {label!r} in {host!r}")
    return host


def _normalize_port(scheme: str, port: int | None) -> int | None:
    """Return the canonical port, applying defaults where appropriate."""
    if port is None or port == 0:
        return _DEFAULT_PORTS.get(scheme)
    return port


def _normalize_path(path: str) -> str:
    """Normalize a file path: decode percent-encoding, reject symlinks, strip
    trailing separators, collapse duplicate slashes."""
    # Decode percent-encoded characters
    decoded = unquote(path)

    # Reject symlink traversal segments
    parts = decoded.split("/")
    for seg in parts:
        if seg in _SYMLINK_INDICATORS:
            raise ResourceCanonicalizationError(
                f"Path contains symlink/relative segment: {decoded!r}"
            )

    # Collapse duplicate slashes and remove empty segments
    filtered = [seg for seg in parts if seg != ""]
    normalized = "/" + "/".join(filtered) if filtered else "/"
    return normalized


def _percent_encode_path(path: str) -> str:
    """Percent-encode a normalized path for the canonical URI, preserving
    forward slashes as path separators."""
    # Encode each segment separately so "/" remains a separator
    segments = path.split("/")
    encoded = [quote(seg, safe="") for seg in segments]
    return "/".join(encoded)


def _parse_generic_uri(raw: str) -> tuple[str, str, int | None, str]:
    """Parse raw as a generic URI.  Returns (scheme, host, port, path).

    Raises ResourceCanonicalizationError if parsing fails.
    """
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if not scheme:
        raise ResourceCanonicalizationError(f"Cannot determine scheme from {raw!r}")
    if scheme not in _SUPPORTED_SCHEMES:
        raise ResourceCanonicalizationError(f"Unsupported scheme {scheme!r} in {raw!r}")

    host = parsed.hostname or ""
    port = parsed.port  # None if absent or invalid
    path = parsed.path or ""

    return scheme, host, port, path


# --------------------------------------------------------------------------- #
# Scheme-specific canonicalizers
# --------------------------------------------------------------------------- #


def _canonicalize_postgres(raw: str, parsed: tuple) -> CanonicalResource:
    """Canonicalize a postgres:// URI.

    Format: postgres://<host>[:port]/<db>/<schema>/<table>
    """
    scheme, host, port, path = parsed

    host = _normalize_hostname(host)
    port = _normalize_port("postgres", port)

    # path should be /<db>/<schema>/<table>
    path = _normalize_path(path)
    segments = [s for s in path.split("/") if s != ""]
    if len(segments) < 1:
        raise ResourceCanonicalizationError(f"postgres URI must include database: {raw!r}")
    if len(segments) > 3:
        raise ResourceCanonicalizationError(f"postgres URI has too many path segments: {raw!r}")
    # db/schema/table — lowercase identifiers (Postgres is case-insensitive
    # for unquoted identifiers, and we canonicalize to lowercase)
    segments = [s.lower() for s in segments]
    canonical_path = "/" + "/".join(segments)

    canonical = f"postgres://{host}"
    if port and port != _DEFAULT_PORTS.get("postgres"):
        canonical += f":{port}"
    canonical += canonical_path

    return CanonicalResource(
        scheme="postgres",
        path=canonical_path,
        raw=raw,
        canonical=canonical,
    )


def _canonicalize_host(raw: str, parsed: tuple) -> CanonicalResource:
    """Canonicalize a host:// URI.

    Format: host://<host>[:port]
    """
    scheme, host, port, path = parsed

    host = _normalize_hostname(host)

    # host scheme has no path; reject if one is present
    if path and path != "/":
        raise ResourceCanonicalizationError(f"host URI must not have a path: {raw!r}")

    canonical = f"host://{host}"
    if port:
        canonical += f":{port}"

    return CanonicalResource(
        scheme="host",
        path="",
        raw=raw,
        canonical=canonical,
    )


def _canonicalize_container(raw: str, parsed: tuple) -> CanonicalResource:
    """Canonicalize a container:// URI.

    Format: container://<host>/<container-name>
    """
    scheme, host, port, path = parsed

    host = _normalize_hostname(host)
    path = _normalize_path(path)

    segments = [s for s in path.split("/") if s != ""]
    if len(segments) != 1:
        raise ResourceCanonicalizationError(
            f"container URI must have exactly one path segment (container name): {raw!r}"
        )
    container_name = segments[0].lower()
    # Validate container name characters (DNS-like)
    if not re.match(r"^[a-z0-9][a-z0-9._\-]*$", container_name):
        raise ResourceCanonicalizationError(f"Invalid container name {container_name!r}")

    canonical_path = "/" + container_name
    canonical = f"container://{host}{canonical_path}"

    return CanonicalResource(
        scheme="container",
        path=canonical_path,
        raw=raw,
        canonical=canonical,
    )


def _canonicalize_file(raw: str, parsed: tuple) -> CanonicalResource:
    """Canonicalize a file:// URI.

    Format: file://<host>/<absolute-path>
    """
    scheme, host, port, path = parsed

    # For file URIs, host may be empty (localhost) or a real host.
    host = _normalize_hostname(host) if host else "localhost"

    path = _normalize_path(path)
    if not path.startswith("/"):
        raise ResourceCanonicalizationError(f"file URI path must be absolute: {raw!r}")
    if path == "/":
        raise ResourceCanonicalizationError(f"file URI path must not be root: {raw!r}")

    encoded_path = _percent_encode_path(path)
    canonical = f"file://{host}{encoded_path}"

    return CanonicalResource(
        scheme="file",
        path=path,
        raw=raw,
        canonical=canonical,
    )


def _canonicalize_email(raw: str, parsed: tuple) -> CanonicalResource:
    """Canonicalize an email:// URI.

    Format: email://<type>/<address>
    Where <type> is e.g. "recipient", "sender", "bcc".
    The address part is lowercased.
    """
    scheme, host, port, path = parsed

    # Reconstruct the remainder after scheme://
    remainder = raw.split("://", 1)[1] if "://" in raw else ""
    parts = remainder.split("/", 1)
    if len(parts) != 2:
        raise ResourceCanonicalizationError(f"email URI must be email://<type>/<address>: {raw!r}")
    email_type = parts[0].lower().strip("/")
    address = parts[1].strip().lower()

    if not email_type:
        raise ResourceCanonicalizationError(f"email URI missing type segment: {raw!r}")
    if not _EMAIL_RE.match(address):
        raise ResourceCanonicalizationError(f"Invalid email address {address!r}")

    canonical_path = f"/{email_type}/{address}"
    canonical = f"email://{email_type}/{address}"

    return CanonicalResource(
        scheme="email",
        path=canonical_path,
        raw=raw,
        canonical=canonical,
    )


def _canonicalize_git(raw: str, parsed: tuple) -> CanonicalResource:
    """Canonicalize a git:// URI.

    Format: git://<host>/<owner>/<repo>/branch/<branch>
    """
    scheme, host, port, path = parsed

    host = _normalize_hostname(host)
    path = _normalize_path(path)

    segments = [s for s in path.split("/") if s != ""]
    if len(segments) < 3:
        raise ResourceCanonicalizationError(
            f"git URI too short; expected git://<host>/<owner>/<repo>/branch/<branch>: {raw!r}"
        )
    if segments[-2] != "branch":
        raise ResourceCanonicalizationError(f"git URI must contain '/branch/' segment: {raw!r}")

    branch = segments[-1]
    if not _GIT_BRANCH_RE.match(branch):
        raise ResourceCanonicalizationError(f"Invalid git branch name {branch!r}")

    canonical_path = "/" + "/".join(segments)
    canonical = f"git://{host}{canonical_path}"

    return CanonicalResource(
        scheme="git",
        path=canonical_path,
        raw=raw,
        canonical=canonical,
    )


# Dispatch table
_CANONICALIZERS: dict[str, callable] = {
    "postgres": _canonicalize_postgres,
    "postgresql": _canonicalize_postgres,
    "host": _canonicalize_host,
    "container": _canonicalize_container,
    "file": _canonicalize_file,
    "email": _canonicalize_email,
    "git": _canonicalize_git,
}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def canonicalize_resource(raw: str, scheme_hint: str | None = None) -> CanonicalResource:
    """Canonicalize a raw resource identifier into a :class:`CanonicalResource`.

    If *scheme_hint* is provided and the raw string has no scheme, the hint
    is used to determine the canonicalization path.

    Args:
        raw:         The raw resource string (URI, path, etc.).
        scheme_hint: Optional scheme hint when the raw string lacks a scheme.

    Returns:
        A :class:`CanonicalResource`.

    Raises:
        ResourceCanonicalizationError: If the resource cannot be canonicalized
            with sufficient confidence.
    """
    if not raw or not raw.strip():
        raise ResourceCanonicalizationError("Empty resource string")

    raw = raw.strip()

    # Apply scheme hint if no scheme present
    if "://" not in raw and scheme_hint:
        scheme_hint = scheme_hint.lower()
        if scheme_hint not in _SUPPORTED_SCHEMES:
            raise ResourceCanonicalizationError(f"Unsupported scheme hint {scheme_hint!r}")
        raw = f"{scheme_hint}://{raw}"

    if "://" not in raw:
        raise ResourceCanonicalizationError(
            f"Cannot determine scheme for {raw!r} and no hint provided"
        )

    parsed = _parse_generic_uri(raw)
    scheme = parsed[0]

    # Normalize postgresql -> postgres for storage
    if scheme == "postgresql":
        scheme = "postgres"

    canonicalizer = _CANONICALIZERS.get(scheme)
    if canonicalizer is None:
        raise ResourceCanonicalizationError(f"No canonicalizer for scheme {scheme!r}")

    result = canonicalizer(raw, parsed)

    # Ensure scheme is stored as 'postgres' not 'postgresql'
    if result.scheme == "postgresql":
        result = CanonicalResource(
            scheme="postgres",
            path=result.path,
            raw=result.raw,
            canonical=result.canonical.replace("postgresql://", "postgres://", 1),
        )

    return result


def match_glob(pattern: str, canonical: str) -> bool:
    """Match a glob pattern against a canonical resource URI.

    Uses :func:`fnmatch.fnmatchcase` (case-sensitive, since canonical URIs
    are already lowercased where appropriate).

    Args:
        pattern:  Glob pattern, e.g. ``postgres://cloudhub/*``.
        canonical: Canonical resource URI string.

    Returns:
        True if *canonical* matches *pattern*.
    """
    if not pattern or not canonical:
        return False
    return fnmatch.fnmatchcase(canonical, pattern)
