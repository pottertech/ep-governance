# Security Policy

## Reporting a Vulnerability

Report security vulnerabilities to skip.potter.va@gmail.com. Do not open public issues for security vulnerabilities.

## Security Review Boundaries

The following components require independent security review before production deployment:

- Ed25519 key handling
- Canonical token format
- Signature verification
- Audit canonicalization
- Hash-chain design
- Credential storage
- Role enforcement
- Policy override logic
- SQL classification
- Network isolation
- Proxy deployment
- Key rotation
- Import trust handling

## Threat Model

The full threat model is documented in `docs/threat-model.md`. It covers:

Compromised agent, compromised proxy, compromised agent credential, compromised proxy credential, malicious policy author, malicious approver, replayed token, altered payload, stale authorization, duplicate callback, direct infrastructure bypass, database tampering, audit-log tampering, imported malicious policy, SQL parser evasion, opaque shell behavior, network partition, proxy crash, EP service crash, partial transaction, clock skew, key rotation, insider threat.

## What Is Enforced

- Deterministic policy evaluation before action authorization
- Signed, payload-bound, short-lived, single-use authorization tokens
- Atomic token claiming with row-level locking
- Append-only hash-chained audit events
- Optimistic concurrency for branch transitions
- Node creation only after successful execution
- Separation of duties (requester cannot approve own action)

## What Is Detected

- Audit chain tampering (via verification command)
- Stale authorizations (via policy-set hash comparison)
- Duplicate callback attempts (via execution-attempt ID)
- Policy conflicts (at policy creation time)

## Residual Risks

- Database administrator with direct access can modify tables (detected by audit chain verification, but not prevented)
- Network partition between EP and proxy can leave transitions in `execution_uncertain`
- Clock skew can affect token expiry validation
- Agent with direct infrastructure access in enforced mode invalidates enforcement (deployment must prevent this)
- Shell classification cannot achieve complete semantic understanding (opaque shell classified as high-risk)

## Not a Cryptographic Guarantee

EP-Governance makes bypassing constraints structurally difficult, not cryptographically impossible. The audit chain is detect-tamper, not prevent-tamper, against someone with direct database write access.