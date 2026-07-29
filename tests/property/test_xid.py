"""Property-based tests for EP-Governance XID generator.

Uses Hypothesis to verify:
  - Generated XIDs are always 20 chars
  - Generated XIDs only use base32hex alphabet (0-9, a-v)
  - XID.from_string(str(x)) == x for any generated XID (roundtrip)
  - Generated XIDs are monotonically increasing (timestamp component)

References: EP contracts, v1.1 section 14
"""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from ep_governance.xid import XID, new


# base32hex alphabet: 0-9, a-v
ALPHABET = "0123456789abcdefghijklmnopqrstuv"
XID_RE = re.compile(r"^[0-9a-v]{20}$")


# --------------------------------------------------------------------------- #
# Property: generated XIDs are always 20 chars
# --------------------------------------------------------------------------- #


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=200)
def test_xid_always_20_chars(_n):
    """Every generated XID is exactly 20 characters long."""
    xid = new()
    assert len(str(xid)) == 20


# --------------------------------------------------------------------------- #
# Property: generated XIDs only use base32hex alphabet
# --------------------------------------------------------------------------- #


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=200)
def test_xid_uses_base32hex_alphabet(_n):
    """Every character in a generated XID is in the base32hex alphabet (0-9, a-v)."""
    xid = new()
    s = str(xid)
    for c in s:
        assert c in ALPHABET, f"Character '{c}' not in base32hex alphabet"


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=200)
def test_xid_matches_regex(_n):
    """Generated XID matches the ^[0-9a-v]{20}$ regex."""
    xid = new()
    assert XID_RE.match(str(xid)) is not None


# --------------------------------------------------------------------------- #
# Property: XID.from_string(str(x)) == x (roundtrip)
# --------------------------------------------------------------------------- #


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=200)
def test_xid_roundtrip(_n):
    """XID.from_string(str(x)) == x for any generated XID."""
    xid = new()
    s = str(xid)
    parsed = XID.from_string(s)
    assert parsed == xid
    assert str(parsed) == s


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=200)
def test_xid_roundtrip_bytes_preserved(_n):
    """Roundtrip preserves the underlying bytes."""
    xid = new()
    parsed = XID.from_string(str(xid))
    assert parsed.bytes == xid.bytes


# --------------------------------------------------------------------------- #
# Property: generated XIDs are monotonically increasing (timestamp component)
# --------------------------------------------------------------------------- #


@given(st.integers(min_value=1, max_value=50))
@settings(max_examples=100)
def test_xid_timestamp_monotonically_increasing(_n):
    """Successive XIDs have non-decreasing timestamps (monotonicity)."""
    xid1 = new()
    xid2 = new()
    assert xid2.timestamp >= xid1.timestamp


@given(st.integers(min_value=2, max_value=100))
@settings(max_examples=100)
def test_xid_lexicographic_order(_n):
    """Successive XIDs are lexicographically non-decreasing (time-sortable)."""
    xid1 = new()
    xid2 = new()
    assert str(xid1) <= str(xid2)


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=100)
def test_xid_timestamp_positive(_n):
    """Generated XID timestamp is always positive."""
    xid = new()
    assert xid.timestamp > 0


# --------------------------------------------------------------------------- #
# Additional properties
# --------------------------------------------------------------------------- #


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=200)
def test_xid_bytes_length(_n):
    """Generated XID is backed by exactly 12 bytes."""
    xid = new()
    assert len(xid.bytes) == 12


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=200)
def test_xid_machine_3_bytes(_n):
    """Machine ID component is 3 bytes."""
    xid = new()
    assert len(xid.machine) == 3


@given(st.integers(min_value=1, max_value=100))
@settings(max_examples=200)
def test_xid_counter_24bit(_n):
    """Counter component fits in 24 bits."""
    xid = new()
    assert 0 <= xid.counter <= 0xFFFFFF


@given(st.integers(min_value=1, max_value=200))
@settings(max_examples=100)
def test_xid_uniqueness_batch(n):
    """A batch of n XIDs are all unique."""
    xids = [str(new()) for _ in range(n)]
    assert len(xids) == len(set(xids))