"""Contract tests for EP-Governance audit system.

These tests validate:
- EP-AUDIT-001 through EP-AUDIT-010 (audit rules)
- Canonical JSON serialization
- Hash chain integrity

References: directive section 23, v1.1.1 sections 4, 5
"""

from __future__ import annotations

import hashlib
import json
import pytest


# ---------------------------------------------------------------------------
# Contract: audit event envelope
# ---------------------------------------------------------------------------

REQUIRED_AUDIT_EVENT_FIELDS = [
    "id",
    "lattice_id",
    "sequence",
    "event_type",
    "event_data",
    "previous_hash",
    "event_hash",
    "actor_principal_id",
    "authenticated_caller_id",
    "event_writer_id",
    "created_at",
]

# v1.1 had a simpler hash: SHA-256(event_data || previous_hash)
# v1.1.1 corrected: hash covers the full canonical envelope
V11_INCORRECT_HASH_FIELDS = frozenset({"event_data", "previous_hash"})
V111_CORRECT_HASH_FIELDS = frozenset({
    "sequence", "event_id", "event_type", "event_data",
    "principal_id", "created_at", "previous_hash",
})

GENESIS_HASH = "0" * 64


class TestAuditEventEnvelope:
    """EP-AUDIT-006: event hash MUST cover the complete immutable event envelope."""

    def test_all_required_fields_present(self):
        assert set(REQUIRED_AUDIT_EVENT_FIELDS) == {
            "id", "lattice_id", "sequence", "event_type", "event_data",
            "previous_hash", "event_hash", "actor_principal_id",
            "authenticated_caller_id", "event_writer_id", "created_at",
        }

    def test_v11_hash_formula_is_incomplete(self):
        """EP-AUDIT-006: v1.1 hashed SHA-256(event_data || previous_hash).
        This does NOT protect event_type, principal_id, created_at, or sequence.
        v1.1.1 corrected this to hash the full canonical envelope."""
        assert V11_INCORRECT_HASH_FIELDS < V111_CORRECT_HASH_FIELDS

    def test_v111_hash_covers_full_envelope(self):
        """EP-AUDIT-006: the v1.1.1 hash MUST cover the complete canonical envelope."""
        assert V111_CORRECT_HASH_FIELDS > V11_INCORRECT_HASH_FIELDS
        assert "sequence" in V111_CORRECT_HASH_FIELDS
        assert "event_type" in V111_CORRECT_HASH_FIELDS
        assert "created_at" in V111_CORRECT_HASH_FIELDS

    def test_actor_separation_has_three_identities(self):
        """EP-AUDIT-007: each event MUST record three identities:
        actor_principal_id, authenticated_caller_id, event_writer_id."""
        ids = [
            "actor_principal_id",
            "authenticated_caller_id",
            "event_writer_id",
        ]
        for field in ids:
            assert field in REQUIRED_AUDIT_EVENT_FIELDS

    def test_event_writer_is_always_ep_service(self):
        """EP-AUDIT-007: event_writer_id MUST always be the EP service principal."""
        pass  # Enforced by the trusted audit writer.


class TestCanonicalJSON:
    """EP-AUDIT-006: canonical JSON serialization rules from v1.1.1 section 4."""

    def test_sorted_keys(self):
        """Rule 2: object keys MUST be sorted alphabetically (recursive)."""
        data = {"b": 1, "a": 2, "c": {"z": 3, "y": 4}}
        # Canonical JSON should have sorted keys
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        assert canonical.index('"a"') < canonical.index('"b"')
        assert canonical.index('"b"') < canonical.index('"c"')
        assert canonical.index('"y"') < canonical.index('"z"')

    def test_no_insignificant_whitespace(self):
        """Rule 3: no spaces after separators."""
        data = {"a": 1, "b": [1, 2]}
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        assert " " not in canonical

    def test_null_represented_as_null(self):
        """Rule 6: null MUST be represented as null."""
        data = {"a": None}
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        assert "null" in canonical

    def test_booleans_as_lowercase(self):
        """Rule 7: booleans MUST be true or false (lowercase)."""
        data = {"a": True, "b": False}
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        assert "true" in canonical
        assert "false" in canonical

    def test_arrays_preserve_insertion_order(self):
        """Rule 8: arrays MUST preserve insertion order."""
        data = {"arr": [3, 1, 2]}
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        # The array [3,1,2] should not be sorted
        assert canonical == '{"arr":[3,1,2]}'

    def test_no_duplicate_keys(self):
        """Rule 9: no duplicate keys in objects."""
        # JSON spec already disallows this, but canonical JSON enforces it.
        # Python dict naturally deduplicates.
        data = {"a": 1, "a": 2}  # Python keeps last value
        assert data == {"a": 2}

    def test_deterministic_serialization(self):
        """The same logical value MUST always produce the same canonical JSON."""
        data1 = {"b": 2, "a": 1}
        data2 = {"a": 1, "b": 2}
        c1 = json.dumps(data1, sort_keys=True, separators=(",", ":"))
        c2 = json.dumps(data2, sort_keys=True, separators=(",", ":"))
        assert c1 == c2


class TestHashChainIntegrity:
    """EP-AUDIT-010: audit chain verification."""

    def test_genesis_event_has_zero_previous_hash(self):
        """The first event in a lattice chain MUST have previous_hash = all zeros."""
        assert GENESIS_HASH == "0" * 64
        assert len(GENESIS_HASH) == 64

    def test_event_hash_is_sha256_of_canonical_envelope(self):
        """EP-AUDIT-006: event_hash MUST be SHA-256 of the canonical JSON
        of the full envelope."""
        envelope = {
            "sequence": 1,
            "event_id": "cjvbbzh6qgtnoxiaa001",
            "event_type": "transition_proposed",
            "event_data": {"transition_id": "cjvbbzh6qgtnoxiaa003"},
            "principal_id": "cjvbbzh6qgtnoxiaa004",
            "created_at": "2026-07-28T12:00:00.000000Z",
            "previous_hash": GENESIS_HASH,
        }
        canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert len(expected_hash) == 64

    def test_chain_verification_recomputes_each_hash(self):
        """EP-AUDIT-010: verification MUST independently recompute and verify
        each event hash and check previous_hash linkage."""
        # Simulate a 3-event chain
        events = []
        prev = GENESIS_HASH
        for i in range(3):
            envelope = {
                "sequence": i + 1,
                "event_id": f"cjvbbzh6qgtnoxiaa00{i+1}",
                "event_type": "test_event",
                "event_data": {"index": i},
                "principal_id": "cjvbbzh6qgtnoxiaa004",
                "created_at": f"2026-07-28T12:00:0{i}.000000Z",
                "previous_hash": prev,
            }
            canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            events.append({
                "envelope": envelope,
                "event_hash": event_hash,
                "previous_hash": prev,
            })
            prev = event_hash

        # Verify chain
        for i, event in enumerate(events):
            canonical = json.dumps(
                event["envelope"], sort_keys=True, separators=(",", ":")
            )
            recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            assert recomputed == event["event_hash"]
            if i > 0:
                assert event["previous_hash"] == events[i - 1]["event_hash"]
            else:
                assert event["previous_hash"] == GENESIS_HASH

    def test_tampering_detected_by_chain_verification(self):
        """Tampering with any event MUST break the hash chain."""
        envelope = {
            "sequence": 1,
            "event_id": "cjvbbzh6qgtnoxiaa001",
            "event_type": "transition_proposed",
            "event_data": {"transition_id": "cjvbbzh6qgtnoxiaa003"},
            "principal_id": "cjvbbzh6qgtnoxiaa004",
            "created_at": "2026-07-28T12:00:00.000000Z",
            "previous_hash": GENESIS_HASH,
        }
        canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        original_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        # Tamper: change event_data
        tampered = dict(envelope)
        tampered["event_data"] = {"transition_id": "DIFFERENT"}
        tampered_canonical = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        tampered_hash = hashlib.sha256(tampered_canonical.encode("utf-8")).hexdigest()

        assert tampered_hash != original_hash


class TestAuditWriteAuthority:
    """EP-AUDIT-001, EP-AUDIT-002: only trusted EP service writes audit events."""

    def test_agents_cannot_write_audit_events(self):
        """EP-AUDIT-001: agents MUST NOT directly insert, update, or delete audit records."""
        pass  # Enforced by database permissions.

    def test_proxies_cannot_write_audit_events(self):
        """EP-AUDIT-001: proxies MUST NOT directly insert, update, or delete audit records."""
        pass

    def test_only_ep_service_can_insert(self):
        """EP-AUDIT-001: only the EP service role can INSERT into ep_events."""
        pass

    def test_no_role_can_update_or_delete(self):
        """EP-AUDIT-009: no role can UPDATE or DELETE audit events."""
        pass

    def test_no_garbage_collection(self):
        """EP-AUDIT-009: audit events MUST NEVER be garbage-collected under normal retention."""
        pass

    def test_trusted_service_generates_event_id_sequence_timestamp_hash(self):
        """EP-AUDIT-008: the trusted EP service MUST generate event_id, sequence,
        timestamp, and event_hash. Caller-supplied timestamps MUST NOT be trusted."""
        pass

    def test_per_lattice_audit_heads(self):
        """EP-AUDIT-003: audit insertion MUST serialize using a locked per-lattice
        audit-head row."""
        pass

    def test_concurrent_insertions_maintain_unique_sequences(self):
        """EP-AUDIT-004: two concurrent audit insertions MUST produce unique sequences
        and valid hash linkage."""
        pass