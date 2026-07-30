# EP-Governance Policy Resolution Semantics

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** v1.1 §4.3, §4.4, §8.4; v1.1.1 §6. Where they conflict, v1.1.1 governs.

---

## 1. Matching Rules

A policy is considered to **match** a proposed action when all of the following conditions are satisfied:

### 1.1 Active and In-Force

- The policy's `status` MUST be `active`.
- The policy MUST be in-force: `valid_from` (if set) MUST be ≤ current time, and `valid_until` (if set) MUST be > current time.
- Policies with `status` in `draft`, `pending_approval`, `rejected`, `superseded`, or `retired` MUST NOT be considered for matching.
- Imported policies with `trust_status != trusted` MUST NOT be considered for matching.

### 1.2 Canonical Action Type Matching

- The action type from server-side classification (e.g., `db.drop`, `shell.exec`, `email.send`) MUST match one of the entries in the policy's `actions` array.
- Matching is exact string equality on canonical action type strings.
- Glob patterns in action type selectors are not supported (action types are enum-like, not glob-matched).
- The classified action type is authoritative; agent-supplied action categories are hints and MUST NOT be used for matching.

### 1.3 Canonical Resource Identity Matching

- The classified target resource MUST match at least one entry in the policy's `resources` array.
- Resource selectors use glob patterns: `env:production/**`, `host:prod-server`, `db:production_db`, `container:app-container`.
- Matching is performed against the **canonical** resource identity, not raw agent-supplied strings.
- Canonical resource formats are defined in `normative-spec.md` EP-RESOURCE-001 through EP-RESOURCE-006.
- A resource selector matches if:
  - The selector exactly equals the canonical resource string, OR
  - The selector is a prefix match with `/**` glob expansion (e.g., `db:production_db/**` matches `db:production_db/public/memory_items`).

### 1.4 Deterministic Condition Evaluation

- If the policy has a `conditions` field, the conditions MUST be evaluated against the action context.
- Condition evaluation MUST be deterministic (see §5 below).
- A policy matches only if its conditions evaluate to `true`.
- If condition evaluation fails (error, timeout, undefined behavior), the policy MUST be treated as matching with effect `require_approval` (fail-closed).

### 1.5 Scope Matching

- `scope=global` policies match all agents.
- `scope=agent` policies match only when `agent_scope` equals the proposing agent's principal ID.

---

## 2. Effect Precedence

### 2.1 Effect Values

| Effect | Behavior |
|--------|----------|
| `deny` | Action is blocked. Transition is denied. Logged. |
| `require_approval` | Action requires human approval. EP creates an approval request. |
| `warn` | Action proceeds but a warning is logged. Agent is notified. |
| `allow` | Explicitly permitted. May override lower-priority `deny`/`warn` with proper override controls. |

### 2.2 Precedence Order

At equal priority, effects resolve in the following order (highest precedence first):

```
deny > require_approval > warn > allow
```

- If two matching policies have the same priority, the one with the higher-precedence effect wins.
- Example: at priority 100, a `deny` policy beats a `require_approval` policy, which beats a `warn` policy, which beats an `allow` policy.

---

## 3. Priority Resolution

### 3.1 Higher Priority Wins

- If two matching policies have different priorities, the one with the higher `priority` value wins.
- Example: priority 100 `allow` beats priority 50 `deny`.
- BUT: see §4 Override Rules — priority alone does not authorize an exception to `deny` without explicit override controls.

### 3.2 Equal Priority Resolution

- If two matching policies have the same priority:
  1. Apply effect precedence: `deny > require_approval > warn > allow`.
  2. If both policies have the same effect, the result is that effect.

### 3.3 Equal-Priority Contradictions

- If two matching policies have the same priority and **conflicting** effects (e.g., one `deny`, one `allow`), the system MUST:
  1. Produce a **policy conflict** (tension).
  2. Return `require_approval` as the resolved effect.
  3. Log the conflict with both policy IDs, effects, and priorities.
- This applies at action proposal time when both policies match.
- Tension detection at policy creation time (EP-POLICY-013) should catch most of these before they reach action evaluation.

### 3.4 Resolution Algorithm

```
Given: matching_policies = [all active, in-force policies matching action + resource + conditions]

1. If matching_policies is empty:
   → Result: allow (no policy restricts this action)
   → Note: this is the default-allow behavior when no policies match

2. Group by priority (descending).

3. For the highest priority group:
   a. Collect all effects in the group.
   b. If all effects are the same:
      → Result: that effect
   c. If effects differ:
      i. If any effect is `deny` and no `allow` with exception_to override exists:
         → Result: deny
      ii. If any effect is `require_approval`:
         → Result: require_approval (policy conflict)
      iii. If effects include `warn` and `allow` (no deny, no require_approval):
         → Result: warn (warn takes precedence over allow at equal priority)
      iv. If only `allow` effects:
         → Result: allow

4. If the highest priority group has a single policy:
   → Result: that policy's effect
```

---

## 4. Override Rules

### 4.1 Override Conditions

An `allow` policy overrides a `deny` policy **only** when ALL of the following conditions are met:

| # | Condition | Requirement |
|---|-----------|-------------|
| 1 | `exception_to` explicitly lists the deny policy | The `allow` policy's `exception_to` field MUST contain the XID of the `deny` policy being overridden. |
| 2 | Narrower scope | The override policy MUST be more narrowly scoped than the overridden policy (fewer resources or more specific actions). |
| 3 | Time-limited | `valid_until` MUST be set (the override is not permanent). |
| 4 | Justification | A `justification` field MUST be non-empty. |
| 5 | Approved authority | The creating principal MUST have `policy_author` role or higher, and the original policy's approval requirements MUST be satisfied (if the original required human approval, the override requires human approval). |

### 4.2 Priority Does Not Confer Authority

- A policy with `priority: 101` and `effect: allow` does **NOT** automatically override a policy with `priority: 100` and `effect: deny`.
- The override conditions in §4.1 MUST all be satisfied.
- Without `exception_to`, narrower scope, time-limit, justification, and approved authority, the `deny` at priority 100 wins.

### 4.3 Override for Sensitive Operations

For especially sensitive operations:
- Overrides of `deny` policies with `priority >= 100` require a `human` principal as the approver.
- The payload MUST be frozen and hashed before approval (the approver sees exactly what they are approving).
- The override is logged to the audit trail with principal, justification, and expiry.

### 4.4 Override Audit

Every override MUST be recorded in:
- `ep_override_records`: `policy_id`, `transition_id`, `overridden_by`, `justification`, `expires_at`, `created_at`.
- The audit log: event type `override_granted` with full context.

---

## 5. Condition Language Requirements

### 5.1 Determinism Requirements

The condition language MUST satisfy:

| Requirement | Description |
|-------------|-------------|
| **Type behavior** | Every value has a well-defined type. Type coercion rules are explicit and documented. |
| **Missing fields** | Accessing a missing field produces a defined result (either `null` or an evaluation error, not undefined behavior). |
| **Null behavior** | `null` comparisons are defined: `null == null` is `true`; `null` compared to any non-null value is `false`; arithmetic on `null` is an evaluation error. |
| **String comparison** | String comparison is case-sensitive, lexicographic, UTF-8 byte order. |
| **Numeric comparison** | Numeric comparison uses standard ordering. Integers and floats compare by value. Mixed integer/float comparison is permitted. |
| **Time evaluation** | Time values are compared as UTC instants. Time arithmetic operates in seconds (or documented granularity). |
| **Timezone** | All timestamps in conditions are evaluated as UTC. No timezone offsets in condition expressions. Timestamps from data are ISO 8601 UTC. |
| **Error handling** | Evaluation errors (undefined functions, type mismatches, timeout) MUST fail closed: the policy is treated as `require_approval`. |
| **External function restrictions** | No network calls, filesystem access, shell access, or any side effects. The evaluation sandbox has no I/O capabilities. |
| **Deterministic execution limits** | Evaluation has a maximum instruction count and time limit. Exceeding limits is an evaluation error (fail closed). No nondeterministic functions (e.g., `random()`, `now()` with wall-clock, `uuid()`). |
| **Evaluation errors fail closed** | If condition evaluation fails for any reason, the policy MUST be treated as matching with effect `require_approval`. |

### 5.2 Prohibited Capabilities

The condition language MUST NOT support:
- Network calls (HTTP, TCP, DNS, etc.)
- Filesystem access (read or write)
- Shell execution
- Process spawning
- Nondeterministic functions (`random`, `uuid`, `now` as wall-clock, `hash` of external data)
- Unbounded loops (or loops with a configurable maximum iteration count)
- Global state mutation
- Access to the policy database or any external system

### 5.3 Required Capabilities

The condition language MUST support:
- Equality and inequality comparisons
- Numeric comparisons (<, >, <=, >=)
- Boolean logic (AND, OR, NOT)
- String operations (equality, prefix/suffix matching, contains)
- Array membership (contains, in)
- Time comparisons (before, after, between)
- Null checks (is null, is not null)
- Field access on nested objects

---

## 6. Condition Language Evaluation Directive

### 6.1 Evaluation Before Selection

Per v1.1.1 additional corrections and ADR-0001:

- The project MUST evaluate **CEL** (Common Expression Language) and **Cedar** before selecting a condition language.
- A custom general-purpose policy language MUST NOT be created unless a written decision record demonstrates that CEL, Cedar, and Rego are all unsuitable.
- The evaluation MUST be performed in Phase 2 before implementing policy conditions.

### 6.2 Selection Criteria

The chosen language MUST satisfy:
- Deterministic evaluation (no side effects, no I/O)
- Sandboxed execution (no network, filesystem, shell)
- Type safety with explicit null handling
- Time comparison support in UTC
- Bounded execution (instruction/time limits)
- Python bindings for integration

### 6.3 Decision Record

- An Architecture Decision Record (ADR) MUST be written documenting the evaluation and selection.
- ADR-0001 (Condition Language Selection) currently has status "Proposed — pending evaluation."
- The ADR MUST be updated to "Accepted" with the chosen language and rationale before Phase 2 implementation begins.

### 6.4 Preferred Direction

The design documents suggest selecting the **smallest deterministic language** that satisfies the requirements. The evaluation should favor:
1. Simplicity of sandboxing
2. Determinism guarantees
3. Python integration maturity
4. Community support and maintenance
5. Minimal attack surface

---

## 7. Effect Resolution Summary

```
INPUT: classified_action, canonical_resource, action_context, agent_id

1. Collect matching policies:
   - status = 'active'
   - in-force (valid_from <= now < valid_until)
   - actions array contains classified_action.action_type
   - resources array has at least one match against canonical_resource
   - scope = 'global' OR (scope = 'agent' AND agent_scope = agent_id)
   - conditions evaluate to true (or conditions is empty)

2. If no policies match:
   → allow (default)

3. If any matching policy has effect = 'deny' AND no valid allow-override exists:
   → deny

4. If any matching policy has effect = 'require_approval' (and no deny without override):
   → require_approval

5. If any matching policy has effect = 'warn' (and no deny, no require_approval):
   → warn

6. If all matching policies have effect = 'allow':
   → allow

7. If there are conflicting effects at the same priority:
   → require_approval (policy conflict)

8. Return: resolved_effect, matched_policies (with IDs, effects, priorities), classification_details
```