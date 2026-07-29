# ADR-0001: Condition Language Selection

## Status

Proposed — pending evaluation

## Context

EP-Governance requires a deterministic condition language for policy evaluation. The design documents (v1.1 section 4.4 and v1.1.1 additional corrections) require that we evaluate CEL and Cedar before selecting a condition language.

The chosen language must define:
- type behavior
- missing fields
- null behavior
- string comparison
- numeric comparison
- time evaluation
- timezone behavior
- error handling
- external function restrictions
- deterministic execution limits

Policy evaluation must not permit arbitrary network calls, filesystem access, shell access, or nondeterministic functions. Evaluation errors must fail closed.

## Options Under Evaluation

### CEL (Common Expression Language)

- Used by Google Cloud IAM, Kubernetes, Envoy
- Deterministic, side-effect-free
- Type system with protobuf support
- Time handling via CEL macros
- Python bindings via `cel-python` or `pycel`

### Cedar

- Used by Amazon Verified Permissions
- Domain-specific for authorization
- Schema-typed entities
- Deterministic evaluation
- Python bindings less mature

### Rego (OPA)

- General-purpose policy language
- Can be complex to sandbox
- Strong Python integration via `opa` binary

## Decision

Pending. Evaluation will be performed in Phase 2 before implementing policy conditions. The smallest deterministic language that satisfies the design requirements will be selected.

A custom general-purpose policy language will not be created unless a written decision record demonstrates that CEL, Cedar, and Rego are all unsuitable.

## Consequences

- Phase 2 policy engine implementation depends on this decision.
- The chosen language must be sandboxed: no network, filesystem, shell, or nondeterministic functions.
- Evaluation errors must fail closed (return require_approval or deny).