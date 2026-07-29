# ADR-0002: Canonical JSON Serialization

## Status

Accepted

## Context

EP-Governance requires canonical JSON serialization for:
- audit event hash computation
- authorization token payload hashing
- policy-set hashing
- transfer package content hashing

The audit hash chain depends on deterministic serialization. If two parties serialize the same logical value differently, hash verification fails.

## Decision

Adopt the canonical JSON serialization rules from v1.1.1 section 4:

1. UTF-8 encoding throughout.
2. Sorted object keys (alphabetical, recursive).
3. No insignificant whitespace (no spaces after separators).
4. Timestamp format: ISO 8601 UTC (YYYY-MM-DDTHH:MM:SS.ffffffZ), no timezone offset.
5. Number representation: integers as integers, floats with full precision, no trailing zeros.
6. Null: represented as null.
7. Booleans: true or false.
8. Arrays: preserve insertion order (arrays are ordered, objects are not).
9. No duplicate keys in objects.
10. No comments.

For governed numeric values where floating-point canonicalization is unsafe or ambiguous, represent as fixed-point integers:
- risk_milliunits (risk * 1000)
- percentage_basis_points (percentage * 100)
- budget_milliunits (budget * 1000)

## Rationale

RFC 8785 (JSON Canonicalization Scheme) was evaluated. The v1.1.1 rules are compatible with RFC 8785's core principles but add explicit timestamp and numeric representation rules needed for governance semantics. The fixed-point representation eliminates floating-point ambiguity for risk and budget values.

## Consequences

- All hash computations must use the canonical JSON function, not ad-hoc serialization.
- The canonical JSON implementation must be tested with property-based tests.
- Floating-point values in governed data must be converted to fixed-point before serialization.