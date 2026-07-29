"""EP-Governance XID generator — pure Python rs/xid-compatible implementation.

Format: 12 bytes -> 20-char lowercase base32hex string
  Bytes 0-3:   timestamp (seconds since epoch, big-endian)
  Bytes 4-6:   machine ID (MD5 hash of hostname, first 3 bytes)
  Bytes 7-8:   PID (big-endian, lower 2 bytes)
  Bytes 9-11:  counter (thread-safe incrementing, big-endian)

The PyPI xid package is broken on Python 3, so we implement our own.
"""

from __future__ import annotations

import hashlib
import os
import socket
import threading
import time

from .errors import XIDError

__all__ = ["XID", "new"]

# base32hex alphabet: 0123456789abcdefghijklmnopqrstuv
_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
_ENCODING = b"0123456789abcdefghijklmnopqrstuv"

# Module-level state (seeded once at import time)
_machine_id: bytes
_pid_bytes: bytes
_counter: int
_last_timestamp: int
_lock: threading.Lock


def _init_machine_id() -> bytes:
    """Return 3 bytes derived from MD5(hostname)."""
    hostname = socket.gethostname().encode("utf-8")
    digest = hashlib.md5(hostname).digest()
    return digest[:3]


def _init_pid() -> bytes:
    """Return 2 bytes for the PID (big-endian, lower 2 bytes)."""
    pid = os.getpid()
    return pid.to_bytes(4, "big")[-2:]


def _seed_counter() -> int:
    """Seed the counter with a random value to avoid fork collision."""
    return int.from_bytes(os.urandom(3), "big")


# Initialise at import time
_machine_id = _init_machine_id()
_pid_bytes = _init_pid()
_counter = _seed_counter()
_last_timestamp = 0
_lock = threading.Lock()


class XID:
    """A 20-char lowercase base32hex identifier backed by 12 bytes.

    Properties:
      - Probabilistically unique (not guaranteed)
      - Time-sortable (lexicographic order approximates chronological order)
      - 20 chars (vs 36 for UUID)
      - No central coordinator needed
    """

    __slots__ = ("_bytes",)

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 12:
            raise XIDError(f"XID requires 12 bytes, got {len(raw)}")
        self._bytes = bytes(raw)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def new(cls) -> XID:
        """Generate a new XID."""
        global _counter, _last_timestamp
        with _lock:
            now = int(time.time())
            if now < _last_timestamp:
                # Clock rollback: use last + 1 for monotonicity
                now = _last_timestamp + 1
            _last_timestamp = now
            _counter = (_counter + 1) & 0xFFFFFF  # 24-bit wrap
            raw = now.to_bytes(4, "big") + _machine_id + _pid_bytes + _counter.to_bytes(3, "big")
        return cls(raw)

    @classmethod
    def from_string(cls, s: str) -> XID:
        """Parse a 20-char base32hex string into an XID."""
        if len(s) != 20:
            raise XIDError(f"XID string must be 20 chars, got {len(s)}")
        # Decode base32hex (5 bits per char, no padding)
        bits = 0
        value = 0
        raw = bytearray()
        for c in s:
            try:
                idx = _ALPHABET.index(c)
            except ValueError:
                raise XIDError(f"Invalid base32hex character '{c}' in '{s}'") from None
            value = (value << 5) | idx
            bits += 5
            while bits >= 8:
                raw.append((value >> (bits - 8)) & 0xFF)
                bits -= 8
        return cls(bytes(raw))

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------

    def string(self) -> str:
        """Return the 20-char base32hex representation.

        Uses standard base32hex (5 bits per char, no padding).
        12 bytes = 96 bits -> ceil(96/5) = 20 chars (4 padding bits).
        """
        result: list[str] = []
        bits = 0
        value = 0
        for byte in self._bytes:
            value = (value << 8) | byte
            bits += 8
            while bits >= 5:
                result.append(_ALPHABET[(value >> (bits - 5)) & 0x1F])
                bits -= 5
        if bits > 0:
            result.append(_ALPHABET[(value << (5 - bits)) & 0x1F])
        return "".join(result)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def bytes(self) -> bytes:
        return self._bytes

    @property
    def timestamp(self) -> int:
        """Unix timestamp embedded in the XID."""
        return int.from_bytes(self._bytes[:4], "big")

    @property
    def machine(self) -> bytes:
        return self._bytes[4:7]

    @property
    def pid(self) -> int:
        return int.from_bytes(self._bytes[7:9], "big")

    @property
    def counter(self) -> int:
        return int.from_bytes(self._bytes[9:12], "big")

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        return self.string()

    def __repr__(self) -> str:
        return f"XID('{self.string()}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, XID):
            return self._bytes == other._bytes
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._bytes)

    def __lt__(self, other: XID) -> bool:
        return self._bytes < other._bytes

    def __le__(self, other: XID) -> bool:
        return self._bytes <= other._bytes

    def __gt__(self, other: XID) -> bool:
        return self._bytes > other._bytes

    def __ge__(self, other: XID) -> bool:
        return self._bytes >= other._bytes


def new() -> XID:
    """Convenience function to generate a new XID."""
    return XID.new()


def fork_safe_reseed() -> None:
    """Re-seed the counter after a fork to avoid XID collision.

    Call this in the child process immediately after fork().
    """
    global _counter, _pid_bytes
    with _lock:
        _counter = _seed_counter()
        _pid_bytes = _init_pid()
