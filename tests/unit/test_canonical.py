"""Unit tests for EP-Governance canonical JSON serialization.

References: v1.1.1 section 4, ADR-0002-canonical-json.md
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ep_governance.canonical import canonical_json, canonical_json_bytes, canonical_hash


class TestCanonicalJSON:
    def test_sorted_keys(self):
        result = canonical_json({"b": 1, "a": 2})
        assert result == '{"a":2,"b":1}'

    def test_nested_sorted_keys(self):
        result = canonical_json({"b": {"d": 1, "c": 2}, "a": 3})
        assert result == '{"a":3,"b":{"c":2,"d":1}}'

    def test_no_whitespace(self):
        result = canonical_json({"a": 1, "b": [1, 2]})
        assert " " not in result

    def test_null(self):
        result = canonical_json({"a": None})
        assert result == '{"a":null}'

    def test_booleans(self):
        result = canonical_json({"a": True, "b": False})
        assert result == '{"a":true,"b":false}'

    def test_arrays_preserve_order(self):
        result = canonical_json({"arr": [3, 1, 2]})
        assert result == '{"arr":[3,1,2]}'

    def test_deterministic_same_input_different_key_order(self):
        r1 = canonical_json({"b": 2, "a": 1})
        r2 = canonical_json({"a": 1, "b": 2})
        assert r1 == r2

    def test_nan_rejected(self):
        with pytest.raises(ValueError):
            canonical_json(float("nan"))

    def test_infinity_rejected(self):
        with pytest.raises(ValueError):
            canonical_json(float("inf"))

    def test_integer_preserved(self):
        result = canonical_json({"a": 42})
        assert result == '{"a":42}'

    def test_string_escaped(self):
        result = canonical_json({"a": 'hello "world"'})
        assert r'"hello \"world\""' in result

    def test_datetime_iso8601_utc(self):
        dt = datetime(2026, 7, 29, 12, 0, 0, 0, tzinfo=timezone.utc)
        result = canonical_json({"ts": dt})
        assert '"2026-07-29T12:00:00.000000Z"' in result

    def test_datetime_with_timezone_converted_to_utc(self):
        from datetime import timedelta

        dt = datetime(2026, 7, 29, 14, 0, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        result = canonical_json({"ts": dt})
        assert '"2026-07-29T12:00:00.000000Z"' in result

    def test_naive_datetime_treated_as_utc(self):
        dt = datetime(2026, 7, 29, 12, 0, 0, 0)
        result = canonical_json({"ts": dt})
        assert '"2026-07-29T12:00:00.000000Z"' in result


class TestCanonicalJSONBytes:
    def test_bytes_are_utf8(self):
        b = canonical_json_bytes({"a": 1})
        assert isinstance(b, bytes)
        assert b == b'{"a":1}'


class TestCanonicalHash:
    def test_hash_is_64_hex(self):
        h = canonical_hash({"a": 1})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_same_input_same_hash(self):
        h1 = canonical_hash({"a": 1})
        h2 = canonical_hash({"a": 1})
        assert h1 == h2

    def test_different_input_different_hash(self):
        h1 = canonical_hash({"a": 1})
        h2 = canonical_hash({"a": 2})
        assert h1 != h2

    def test_key_order_doesnt_change_hash(self):
        h1 = canonical_hash({"b": 2, "a": 1})
        h2 = canonical_hash({"a": 1, "b": 2})
        assert h1 == h2

    def test_tamper_detected(self):
        h1 = canonical_hash({"event": "proposed", "id": "001"})
        h2 = canonical_hash({"event": "DENIED", "id": "001"})
        assert h1 != h2
