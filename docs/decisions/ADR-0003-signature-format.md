# ADR-0003: Authorization Signature Format

## Status

Accepted

## Context

v1.1 specified HMAC-SHA256 for authorization token signing (shared key between EP and proxy). v1.1.1 corrected this to Ed25519 asymmetric signatures.

The conflict: with HMAC-SHA256, both EP and the proxy share the same signing key. A compromised proxy can mint authorizations. With Ed25519, EP holds the private signing key and proxies hold only the public verification key. A compromised proxy cannot mint authorizations.

## Decision

Adopt Ed25519 asymmetric signatures as specified in v1.1.1.

- EP holds the private signing key.
- Proxies hold only the public verification key.
- Agents never receive either key.
- The signature covers the canonical token payload (canonical JSON of the authorization token fields, excluding the signature itself).
- The database stores the authorization record and token hash, not a reusable private token.

Token contents (from directive section 17):
- authorization_id, transition_id, agent_id, project_id, branch_id
- proxy_audience, tool
- payload_hash (sha256), policy_set_hash (sha256)
- matched_policy_versions (mapping)
- issued_at, expires_at, nonce

## Rationale

Ed25519 prevents a compromised proxy from minting authorizations, which is a critical security property. The asymmetric design also allows third-party verification of tokens without sharing the signing key.

## Consequences

- EP must securely store the Ed25519 private key.
- Key rotation must be supported (signing with new key, verification accepting old key during transition).
- The `PyNaCl` library provides Ed25519 in Python.
- Token verification is slightly more complex than HMAC but the security gain is essential.