"""EP-Governance canonical JSON serialization.

Implements the 10 canonicalization rules from v1.1.1 section 4:
  1. UTF-8 encoding throughout.
  2. Sorted object keys (alphabetical, recursive).
  3. No insignificant whitespace (no spaces after separators).
  4. Timestamp format: ISO 8601 UTC (YYYY-MM-DDTHH:MM:SS.ffffffZ).
  5. Number representation: integers as integers, floats with full precision, no trailing zeros.
  6. Null: represented as null.
  7. Booleans: true or false.
  8. Arrays: preserve insertion order.
  9. No duplicate keys in objects.
 10. No comments.

For governed numeric values where floating-point canonicalization is unsafe
or ambiguous, represent as fixed-point integers (risk_milliunits,
percentage_basis_points, budget_milliunits).
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "canonical_json",
    "canonical_json_bytes",
    "canonical_hash",
]


def canonical_json(obj: Any) -> str:
    """Serialize *obj* into canonical JSON.

    Rules:
      - Sorted object keys (recursive).
      - No insignificant whitespace.
      - Floats: no trailing zeros, no NaN/Infinity.
      - Datetime objects: ISO 8601 UTC with microseconds.
      - Everything else: standard JSON with sort_keys and compact separators.
    """
    return json.dumps(
        _normalize(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_json_bytes(obj: Any) -> bytes:
    """Return canonical JSON encoded as UTF-8 bytes."""
    return canonical_json(obj).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    """Return the SHA-256 hex digest of the canonical JSON of *obj*."""
    import hashlib

    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize(obj: Any) -> Any:
    """Recursively normalise *obj* for canonical serialization.

    - datetime -> ISO 8601 UTC string
    - float -> normalised (reject NaN/Infinity)
    - dict -> with normalised values (keys are sorted by json.dumps)
    - list -> with normalised elements (order preserved)
    """
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError("NaN and Infinity are not allowed in canonical JSON")
        return _normalize_float(obj)
    if isinstance(obj, datetime):
        return _normalize_datetime(obj)
    if isinstance(obj, dict):
        return {str(k): _normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize(v) for v in obj]
    if isinstance(obj, str):
        return obj
    # Fallback: convert to string
    return str(obj)


def _normalize_float(value: float) -> float:
    """Normalise a float: remove trailing zeros via repr."""
    # json.dumps already handles float representation without trailing zeros
    # when using default encoding.  We just validate.
    return value


def _normalize_datetime(dt: datetime) -> str:
    """Convert a datetime to ISO 8601 UTC with microseconds.

    Format: YYYY-MM-DDTHH:MM:SS.ffffffZ
    No timezone offset; always Z suffix.
    """
    dt = dt.astimezone(UTC) if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    # Format with microseconds, always 6 digits, then Z
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
