# EP-Governance Transfer Package Format

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** v1.1 §12; v1.1.1 additional corrections.

---

## 1. Three Operations

EP-Governance supports three transfer operations for model switching and project portability:

| Operation | Description | Modifies Source? | Creates New Entity? |
|-----------|-------------|-----------------|---------------------|
| **Resume** | Connect a new model to the existing database. No import needed. The new model reads the same graph. | No | No |
| **Export** | Create a portable, immutable, signed snapshot of the lattice state. | No (creates a new transfer package record) | Yes (transfer package) |
| **Import-as-fork** | Create a new lattice and project from a snapshot. Never import blindly into the authoritative live lattice. | No | Yes (new lattice + project) |

### 1.1 Resume

```
ep-governance resume --project <id> --branch <id>
```

- Connects the current model to the existing database.
- No export/import needed.
- The model reads the current graph state, loads active policies, and begins operating.
- This is the normal case for model switching when the database is shared.
- Bootstrap loads: active policies, branch head, BT planning budget, risk ledger, quarantines, work claims, pending approvals.

### 1.2 Export

```
ep-governance export --project <id> --branch <id> > transfer.json
```

- Creates an immutable, signed snapshot of the lattice state.
- The snapshot is a JSON document containing the full serialized lattice.
- The snapshot is signed with the EP service Ed25519 key.
- The original lattice is untouched.
- A transfer package record is stored in `ep_transfer_packages`.

### 1.3 Import-as-fork

```
ep-governance import transfer.json --project-name "OpenCut rewrite fork"
```

- Creates a **new** lattice and project from the snapshot.
- Generates new XIDs for all imported entities (no ID collision).
- The original lattice is untouched.
- Imported policies start as `draft` with `trust_status=pending_review`.
- Never imports active auth tokens, credentials, private keys, live sessions, or unexpired approvals.

---

## 2. Transfer Package Fields

### 2.1 Package Structure

```json
{
  "schema_version": "1.0",
  "package_version": "1.0",
  "source_lattice_id": "cjvbbzh6qgtnoxiaa001",
  "source_project_id": "cjvbbzh6qgtnoxiaa002",
  "snapshot_sequence": 42,
  "created_at": "2026-07-28T12:00:00.000000Z",
  "content_hash": "sha256:abc123def456...",
  "signature": "ed25519:...",
  "signer_id": "cjvbbzh6qgtnoxiaa003",
  "trust_status": "untrusted",
  "lattice_state": {
    "lattice": {
      "id": "cjvbbzh6qgtnoxiaa001",
      "project_id": "cjvbbzh6qgtnoxiaa002",
      "name": "NAS Migration",
      "created_at": "2026-07-20T10:00:00.000000Z"
    },
    "project": {
      "id": "cjvbbzh6qgtnoxiaa002",
      "name": "NAS Migration",
      "description": "Migrating GBrain to NAS",
      "status": "active",
      "created_at": "2026-07-20T10:00:00.000000Z"
    },
    "branches": [...],
    "nodes": [...],
    "edges": [...],
    "policies": [...],
    "risk_ledger": [...],
    "risk_mitigations": [...],
    "branch_heads": [...],
    "policy_versions": [...],
    "audit_events": [...],
    "principals": [...],
    "sessions": [...]
  }
}
```

### 2.2 Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | TEXT | Schema version at export time (e.g., "1.0") |
| `package_version` | TEXT | Transfer package format version (e.g., "1.0") |
| `source_lattice_id` | TEXT (XID) | XID of the source lattice |
| `source_project_id` | TEXT (XID) | XID of the source project |
| `snapshot_sequence` | INTEGER | Monotonic snapshot number for this lattice |
| `created_at` | TIMESTAMPTZ | When the export was created (ISO 8601 UTC) |
| `content_hash` | TEXT | SHA-256 hash of the canonical JSON of `lattice_state` |
| `signature` | TEXT | Ed25519 signature of the `content_hash` |
| `signer_id` | TEXT (XID) | FK to `ep_principals` — who signed it (EP service principal) |
| `trust_status` | TEXT | `trusted`, `untrusted`, or `imported` |
| `lattice_state` | JSONB | Full serialized lattice: nodes, edges, policies, risk ledger, branch heads, policy versions, audit events |

### 2.3 Content Hash Computation

```python
canonical_lattice_state = canonical_json(lattice_state)
content_hash = "sha256:" + sha256(canonical_lattice_state.encode("utf-8")).hexdigest()
```

The canonical JSON rules from `audit-format.md` §1 apply. All governed numeric values are serialized as fixed-point integers.

### 2.4 Signature

```python
signature = "ed25519:" + base64_encode(
    ed25519_sign(private_key, content_hash.encode("utf-8"))
)
```

The signature covers the `content_hash` string (including the `sha256:` prefix). The EP service signs with its Ed25519 private key. Any party with the public key can verify.

### 2.5 `lattice_state` Contents

The `lattice_state` object contains a complete snapshot of the lattice:

| Component | Contents |
|-----------|---------|
| `lattice` | Lattice metadata |
| `project` | Project metadata |
| `branches` | All branches with head_node_id, version, status |
| `nodes` | All nodes with status, metadata, committed_at |
| `edges` | All edges with upstream/downstream, edge_type |
| `policies` | All policies with full fields (status, effect, actions, resources, conditions, priority, scope, etc.) |
| `risk_ledger` | All risk ledger entries per domain |
| `risk_mitigations` | All risk mitigations with evidence |
| `branch_heads` | Current branch heads (redundant with branches but explicit for verification) |
| `policy_versions` | Policy version history |
| `audit_events` | Full audit chain for this lattice |
| `principals` | Principal metadata (names, types, machines — NOT credentials) |
| `sessions` | Session metadata (NOT live session tokens) |

### 2.6 What Is Excluded from `lattice_state`

The following are **NOT** included in the transfer package:

- ❌ Active authorization tokens
- ❌ Credentials (API keys, hashes, enrollment tokens)
- ❌ Private keys (Ed25519 signing key)
- ❌ Live session tokens
- ❌ Unexpired approvals (without accompanying policy context)
- ❌ Target infrastructure credentials (these belong to the proxy, not EP)
- ❌ Credential hashes (security-sensitive, not transferable)

---

## 3. Import ID Mapping

### 3.1 Purpose

When importing a transfer package, all imported entities receive new local XIDs. The mapping between source and imported IDs is stored for provenance tracking.

### 3.2 Mapping Table

```sql
CREATE TABLE ep_import_mappings (
    id                  TEXT (XID) PRIMARY KEY,
    source_entity_id    TEXT NOT NULL,    -- XID from source lattice
    imported_entity_id  TEXT NOT NULL,    -- New local XID
    source_lattice_id   TEXT NOT NULL,    -- Source lattice XID
    source_package_id   TEXT NOT NULL,    -- Transfer package XID
    entity_type         TEXT NOT NULL,    -- 'node', 'edge', 'policy', 'branch', 'principal', etc.
    imported_at         TIMESTAMPTZ NOT NULL
);
```

### 3.3 Fields

| Field | Type | Description |
|-------|------|-------------|
| `source_entity_id` | TEXT (XID) | The entity's XID in the source lattice |
| `imported_entity_id` | TEXT (XID) | The new local XID assigned during import |
| `source_lattice_id` | TEXT (XID) | The source lattice's XID |
| `source_package_id` | TEXT (XID) | The transfer package's XID |
| `entity_type` | TEXT | The type of entity: `node`, `edge`, `policy`, `branch`, `principal`, `risk_ledger`, `risk_mitigation`, `audit_event` |
| `imported_at` | TIMESTAMPTZ | When the import occurred |

### 3.4 Mapping Process

1. For each entity in `lattice_state`, generate a new local XID.
2. Insert the entity with the new XID into the appropriate table.
3. Record the mapping in `ep_import_mappings`.
4. For edges, update `upstream_node_id` and `downstream_node_id` to the new imported node XIDs using the mapping.
5. For branch heads, update `head_node_id` to the new imported node XID.
6. For policies, update `supersedes` references using the mapping.
7. For audit events, update `previous_hash` to maintain the chain (the first event in the imported chain gets `previous_hash = '0000...'`).

### 3.5 Provenance

The mapping table allows:
- Tracing any imported entity back to its source.
- Verifying the import chain (which package, which source lattice).
- Detecting duplicate imports (same source entity imported twice).

---

## 4. Imported Policy Quarantine

### 4.1 Entry State

Imported policies enter the system in a quarantined state:

| Field | Value |
|-------|-------|
| `status` | `draft` |
| `origin` | `imported` |
| `trust_status` | `pending_review` |
| `source_entity_id` | XID from source lattice |
| `imported_entity_id` | New local XID |
| `source_lattice_id` | Source lattice XID |
| `source_package_id` | Transfer package XID |

### 4.2 No Automatic Activation

Imported policies MUST NOT be automatically active. They have no enforcement effect while in `draft` status with `trust_status=pending_review`.

### 4.3 Activation Requirements

An imported policy can be activated only when ALL of the following are true:

1. **Trusted signer.** The `signer_id` of the transfer package must be explicitly trusted by the importing deployment. Trust is established through:
   - Explicit configuration: `EP_TRUSTED_SIGNERS=cjvb...,...`
   - Or manual verification by an administrator.

2. **Trusted source.** The `source_lattice_id` must be explicitly trusted. Trust is established through:
   - Explicit configuration: `EP_TRUSTED_SOURCES=cjvb...,...`
   - Or manual verification by an administrator.

3. **Normal approval workflow.** The policy must go through the standard approval workflow:
   - `draft` → `pending_approval` (via `submit-policy`)
   - `pending_approval` → `active` (via approval by `policy_approver`, with human co-approval for global policies)

4. **Tension check.** The policy must not create tensions with existing active policies (EP-POLICY-013).

### 4.4 Review Process

1. An operator or administrator reviews the imported policy.
2. The operator verifies the policy content matches expectations.
3. The operator verifies the signer and source trust.
4. If trusted: the operator submits the policy for approval.
5. If untrusted: the policy remains in `draft` with `trust_status=pending_review` until trust is established or the policy is retired.

### 4.5 Trust Status Values

| `trust_status` | Meaning |
|----------------|---------|
| `pending_review` | Newly imported, awaiting trust verification |
| `trusted` | Signer and source verified as trusted |
| `untrusted` | Signer or source determined to be untrusted; policy should be retired |

---

## 5. Prohibited Imports

### 5.1 Never Imported

The following items MUST NOT be included in transfer packages and MUST NOT be imported:

| Prohibited Item | Reason |
|-----------------|--------|
| **Active authorization tokens** | Tokens are single-use, short-lived, and bound to the source deployment. Importing them would allow replay attacks. |
| **Credentials** (API keys, credential hashes) | Credentials are deployment-specific. Importing them would leak secrets across deployments. |
| **Private keys** (Ed25519 signing key) | The signing key is deployment-specific. Importing it would allow cross-deployment token forgery. |
| **Live sessions** | Session tokens are deployment-specific and time-bound. |
| **Unexpired approvals** (without policy context) | Approvals are bound to the source deployment's policies. Importing an approval without the full policy context could authorize unintended actions. |

### 5.2 Verification

During import, the system MUST verify that the transfer package does not contain any prohibited items:

1. Parse the `lattice_state` JSON.
2. Check for presence of:
   - `authorizations` or `tokens` fields → reject
   - `credentials` field → reject
   - `private_keys` field → reject
   - `sessions` with active tokens → reject (session metadata is OK, live tokens are not)
   - `approvals` without corresponding policies → reject
3. If any prohibited item is found, the import MUST fail with an error listing the prohibited items.

### 5.3 Audit Record

The import operation MUST be recorded in the audit log:

```
Event type: transfer_imported
Event data: {
  "package_id": "...",
  "source_lattice_id": "...",
  "imported_lattice_id": "...",
  "imported_entity_count": {
    "nodes": 42,
    "edges": 41,
    "policies": 5,
    "branches": 2,
    ...
  },
  "prohibited_items_found": [],
  "signer_id": "...",
  "signer_trusted": true/false,
  "source_trusted": true/false
}
```

---

## 6. Signing and Verification

### 6.1 Signing (Export)

1. **Serialize lattice state.** The `lattice_state` object is serialized using canonical JSON rules (from `audit-format.md` §1).

2. **Compute content hash.**
   ```python
   canonical_state = canonical_json(lattice_state)
   content_hash = "sha256:" + sha256(canonical_state.encode("utf-8")).hexdigest()
   ```

3. **Sign the content hash.**
   ```python
   signature_bytes = ed25519_sign(ep_private_key, content_hash.encode("utf-8"))
   signature = "ed25519:" + base64_encode(signature_bytes)
   ```

4. **Assemble the package.** Include all fields from §2.1.

5. **Store the transfer package record.** Insert a row into `ep_transfer_packages` with the content hash, signature, signer ID, and lattice state.

### 6.2 Verification (Import)

1. **Parse the transfer package.** Read the JSON document.

2. **Verify content hash.**
   ```python
   canonical_state = canonical_json(lattice_state)
   expected_hash = "sha256:" + sha256(canonical_state.encode("utf-8")).hexdigest()
   assert content_hash == expected_hash, "Content hash mismatch"
   ```

3. **Verify signature.**
   ```python
   signature_bytes = base64_decode(signature.remove_prefix("ed25519:"))
   is_valid = ed25519_verify(ep_public_key, signature_bytes, content_hash.encode("utf-8"))
   assert is_valid, "Signature verification failed"
   ```

4. **Check signer trust.** Verify that `signer_id` is in the trusted signers list.

5. **Check source trust.** Verify that `source_lattice_id` is in the trusted sources list.

6. **Check for prohibited items.** Verify no prohibited items are present (§5).

7. **If all checks pass:** proceed with import (create new lattice, generate new XIDs, store mappings, quarantine policies).

8. **If any check fails:** reject the import with an error listing the specific failure.

### 6.3 Key Used for Signing

The transfer package is signed with the EP service's Ed25519 private key — the same key used for authorization token signing. This ensures:
- The package is authentic (signed by the EP service that created it).
- Any party with the EP public key can verify the package.
- A compromised proxy cannot forge transfer packages (it does not have the private key).

### 6.4 Model Info

The transfer package includes `model_info` — the LLM model running at export time. This is for audit trail purposes only and does not affect governance semantics.

```
"model_info": "gpt-4-2024-04-09"
```