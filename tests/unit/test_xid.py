"""Unit tests for EP-Governance XID generator.

References: v1.1 section 14, EP contract test_xid_format.py
"""

from __future__ import annotations

import re
import threading

import pytest

from ep_governance.xid import XID, new, fork_safe_reseed


XID_RE = re.compile(r"^[0-9a-v]{20}$")


class TestXIDGeneration:
    def test_new_returns_valid_xid(self):
        xid = new()
        assert XID_RE.match(str(xid)) is not None

    def test_new_returns_xid_instance(self):
        xid = new()
        assert isinstance(xid, XID)

    def test_xid_is_20_chars(self):
        xid = new()
        assert len(str(xid)) == 20

    def test_xid_uses_base32hex_alphabet(self):
        xid = new()
        for c in str(xid):
            assert c in "0123456789abcdefghijklmnopqrstuv"

    def test_xid_is_unique_across_many_calls(self):
        xids = {str(new()) for _ in range(10000)}
        assert len(xids) == 10000

    def test_xid_is_time_sortable(self):
        xid1 = new()
        xid2 = new()
        assert xid1 < xid2

    def test_xid_timestamp_is_positive(self):
        xid = new()
        assert xid.timestamp > 0

    def test_xid_machine_is_3_bytes(self):
        xid = new()
        assert len(xid.machine) == 3

    def test_xid_counter_is_24_bit(self):
        xid = new()
        assert 0 <= xid.counter <= 0xFFFFFF

    def test_xid_bytes_is_12_bytes(self):
        xid = new()
        assert len(xid.bytes) == 12


class TestXIDParsing:
    def test_from_string_roundtrip(self):
        xid = new()
        s = str(xid)
        parsed = XID.from_string(s)
        assert str(parsed) == s
        assert parsed == xid

    def test_from_string_invalid_length(self):
        from ep_governance.errors import XIDError

        with pytest.raises(XIDError):
            XID.from_string("too-short")

    def test_from_string_invalid_char(self):
        from ep_governance.errors import XIDError

        with pytest.raises(XIDError):
            XID.from_string("w" * 20)

    def test_from_string_uppercase_rejected(self):
        from ep_governance.errors import XIDError

        with pytest.raises(XIDError):
            XID.from_string("A" * 20)


class TestXIDComparison:
    def test_equality(self):
        x1 = new()
        x2 = XID(x1.bytes)
        assert x1 == x2

    def test_inequality(self):
        x1 = new()
        x2 = new()
        assert x1 != x2

    def test_hashable(self):
        x1 = new()
        x2 = XID(x1.bytes)
        assert hash(x1) == hash(x2)

    def test_less_than(self):
        x1 = new()
        x2 = new()
        assert x1 < x2

    def test_repr(self):
        x = new()
        assert repr(x).startswith("XID('")


class TestXIDForkSafety:
    def test_fork_safe_reseed_changes_counter(self):
        x1 = new()
        fork_safe_reseed()
        x2 = new()
        assert x1.counter != x2.counter


class TestXIDThreadSafety:
    def test_concurrent_generation_is_unique(self):
        results: list[str] = []
        barrier = threading.Barrier(10)

        def generate():
            barrier.wait()
            for _ in range(1000):
                results.append(str(new()))

        threads = [threading.Thread(target=generate) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 10000
        assert len(set(results)) == 10000