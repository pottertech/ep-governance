# EP-Governance Security Review Package

**Date:** July 30, 2026
**Reviewer needed:** Independent security review (not the implementer)
**Repo:** https://github.com/pottertech/ep-governance

## Purpose

The design spec (Section 34) requires that the following components be reviewed by someone other than the implementer before production deployment. This document identifies the specific files, line ranges, and review questions for each component.

## Components Requiring Review

### 1. Ed25519 Key Handling
**File:** `src/ep_governance/authorizations.py`, lines 63-146
**Class:** `KeyManager`

**Review questions:**
- Is the private key properly protected in memory? (It's a PyNaCl SigningKey object)
- Is `save_private_key` writing with restrictive permissions (0600)?
- Is `load_private_key` validating the file is exactly 32 bytes?
- Is `from_private_key` safe to use?
- Can the private key leak through Python's garbage collector or memory dumps?
- Is the key generation cryptographically secure? (PyNaCl uses libsodium)

### 2. Canonical Token Format
**File:** `src/ep_governance/authorizations.py`, lines 154-258
**Class:** `AuthorizationToken`

**Review questions:**
- Does `to_canonical_payload` exclude the signature field from the signed payload?
- Is `canonical_json_bytes` deterministic (sorted keys, no whitespace)?
- Is the signature over the canonical bytes, not the JSON string with potential encoding differences?
- Can an attacker modify any field without invalidating the signature?
- Are all 14 directive fields present and signed? (authorization_id, transition_id, agent_id, project_id, branch_id, proxy_audience, tool, payload_hash, policy_set_hash, matched_policy_versions, issued_at, expires_at, nonce, signature)

### 3. Signature Verification
**File:** `src/ep_governance/authorizations.py`, lines 241-258
**Method:** `verify_signature`

**Review questions:**
- Is the verification using the correct public key?
- Is the signature comparison constant-time? (PyNaCl VerifyKey.verify uses constant-time comparison)
- What happens if the signature is empty? (Returns False — verified)
- What happens if the signature is malformed hex? (Catches exception, returns False — verified)
- Can an attacker forge a signature without the private key?

### 4. Audit Canonicalization
**File:** `src/ep_governance/audit.py`, lines 1-100 (AuditEvent class), lines 400-419 (_dump_json, _load_json)
**Also:** `src/ep_governance/canonical.py`

**Review questions:**
- Is `canonical_json` deterministic across Python versions and platforms?
- Does it handle Unicode correctly?
- Are floating-point numbers handled safely? (The spec recommends fixed-point for governed values)
- Is the hash computation over the complete immutable envelope?
- Does `_load_json` handle JSONB dict input from PostgreSQL correctly? (Fixed in this deployment)

### 5. Hash-Chain Design
**File:** `src/ep_governance/audit.py`, lines 220-350 (AuditWriter)

**Review questions:**
- Is each event's `previous_hash` correctly set to the previous event's `event_hash`?
- Is the sequence number per-lattice and monotonically increasing?
- Is the audit head row locked during insertion to serialize concurrent writes?
- Can an attacker reorder events without breaking the chain?
- Can an attacker insert a fake event in the middle of the chain?
- Is the hash chain verifiable by an independent party? (`AuditVerifier.verify`)

### 6. Credential Storage
**File:** `migrations/postgres/001_init.sql` (ep_credentials table)
**File:** `src/ep_governance/db/repositories.py` (CredentialRepository)

**Review questions:**
- Are credentials stored as hashes, not plaintext?
- Is constant-time comparison used for credential verification?
- Can credentials be revoked?
- Is the ep_agent role denied access to ep_credentials? (002_roles.sql)

### 7. Role Enforcement
**File:** `migrations/postgres/002_roles.sql`
**File:** `migrations/postgres/003_proxy_role.sql`

**Review questions:**
- Is `ep_service` the only role that can INSERT into `ep_events`?
- Can `ep_agent` UPDATE or DELETE audit events? (Must not be able to)
- Is `ep_agent` denied access to `ep_authorizations`, `ep_audit_heads`, `ep_credentials`?
- Is `ep_proxy` denied access to the `ep_governance` schema?
- Are roles created with NOLOGIN (no static passwords in migrations)?

### 8. Policy Override Logic
**File:** `src/ep_governance/policy_engine.py`

**Review questions:**
- Can an allow policy override a deny without listing it in `exception_to`? (Must not be able to)
- Does the override require narrower scope, time limit, and justification?
- Is priority alone never sufficient to override a deny?
- Are equal-priority contradictions detected as conflicts?
- Is the resolution order correct: deny > require_approval > warn > allow?

### 9. SQL Classification
**File:** `src/ep_governance/classification.py` (SQLClassifier)

**Review questions:**
- Are multi-statement payloads detected and marked opaque?
- Are transaction control commands (BEGIN, COMMIT, ROLLBACK) classified?
- Does parser failure result in opaque classification (fail closed)?
- Can an attacker evade classification with comments, encoding, or Unicode tricks?
- Are DDL operations (DROP, ALTER, TRUNCATE) always marked requires_approval?

### 10. Network Isolation
**Deployment:** Proxy on NAS Docker, port 8201
**File:** `docker/proxy/docker-compose.proxy.yml`

**Review questions:**
- Does the proxy run as a separate process from the agent?
- Does the proxy hold credentials the agent cannot access?
- Can the agent reach the target database without going through the proxy?
- Is the proxy listening on the right interface? (Currently 0.0.0.0:8201 — should this be restricted?)
- Is the Docker container using security_opt no-new-privileges and cap_drop ALL?

### 11. Proxy Token Claim
**File:** `src/ep_governance/proxy/base.py`, lines 108-491 (GovernedProxy.execute)

**Review questions:**
- Is the atomic claim using UPDATE...WHERE used=FALSE...RETURNING?
- Is the payload hash computed from the actual payload, not caller-supplied?
- Is the policy_set_hash checked before execution (stale authorization detection)?
- Is the claim + transition advancement in a single serializable transaction?
- Can a TOCTOU race allow execution under a stale policy?

### 12. Key Rotation
**File:** `src/ep_governance/authorizations.py` (KeyManager)

**Review questions:**
- Can keys be rotated without downtime?
- Do old tokens remain verifiable during the transition window?
- Is there a documented key rotation procedure?

## Automated Security Scans (First Pass)

Run these tools against the repo for an automated first pass:

```bash
# Static analysis
pip install semgrep bandit pip-audit
semgrep scan --config=p/python .
bandit -r src/ -f json -o bandit-report.json
pip-audit

# Dependency audit
pip-audit --strict
```

## Reviewer Instructions

1. Clone the repo: `git clone https://github.com/pottertech/ep-governance.git`
2. Read the governing design documents in ~/Downloads (v1.1 and v1.1.1)
3. Review each component listed above using the review questions
4. Run the automated security scans
5. Document findings as: CRITICAL / HIGH / MEDIUM / LOW / INFO
6. For each finding, identify: file, line, description, risk, recommended fix
7. Sign off on each component as: APPROVED / APPROVED WITH CONDITIONS / REJECTED

## Current Test Coverage

972 tests pass (0 failures):
- 342 unit tests (core library modules)
- 54 property tests (fuzz: SQL/shell/JSON/XID)
- 127 contract tests (executable spec contracts)
- 415 integration tests (DB, proxy, CLI, MCP, PG, migrations)
- 50 security tests (hardening, adversarial, fault injection, network partition)
- 4 concurrency stress tests
- 4 end-to-end enforced mode tests

## Automated Security Scan Results (July 30, 2026)

### pip-audit
No known vulnerabilities found in dependencies.

### Bandit (12 findings)

| Severity | Confidence | File:Line | Description | Action |
|----------|-----------|-----------|-------------|--------|
| HIGH | HIGH | xid.py:39 | MD5 hash used in XID generation | XID uses MD5 for machine fingerprint + timestamp, not for security. Acceptable — XIDs are probabilistically unique IDs, not cryptographic primitives. |
| MEDIUM | MEDIUM | proxy_service.py:254 | Binding to 0.0.0.0 (all interfaces) | Proxy listens on all interfaces for Tailscale access. Should restrict to Tailscale interface in production. |
| MEDIUM | LOW | db/repositories.py:824,839 | SQL injection via string-based query | These use parameterized queries with SQLAlchemy text() — false positive. |
| MEDIUM | LOW | transfer.py:307,320 | SQL injection via string-based query | Same — parameterized queries. False positive. |
| MEDIUM | HIGH | embeddings.py:104 | URL open for permitted schemes | Embeddings module allows URL fetching. Not used in enforcement path. Acceptable. |
| LOW | MEDIUM | docker_proxy.py:184,207 | Hardcoded password 'docker' | These are proxy audience strings, not passwords. False positive. |
| LOW | MEDIUM | git_proxy.py:233 | Hardcoded password 'git' | Same — audience string, not password. False positive. |
| LOW | HIGH | classification.py:308 | Try/Except/Continue | Exception handling in table extraction. Acceptable — fails closed. |
| LOW | HIGH | proxy_service.py:192 | Try/Except/Continue | Exception handling in policy loading. Acceptable. |

**Summary:** 1 HIGH finding (XID MD5 — acceptable, not a security primitive), 1 MEDIUM finding (proxy binding to 0.0.0.0 — should restrict in production), 10 LOW/false positives.

## Deployment State

- Governance DB: NAS PostgreSQL (Synology DS1817+, port 5433)
- Proxy: NAS Docker container, port 8201, ep_proxy_user credentials
- EP service: Mac (Mary Wise's Hermes session)
- Agents: Mary Wise (Mac), Brodie (cloudhub)
- Mode: enforced
- Signing key: ep_signing_test.key (test key — must be replaced for production)