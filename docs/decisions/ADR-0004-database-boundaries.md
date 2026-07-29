# ADR-0004: Database Backend Boundaries

## Status

Accepted

## Context

v1.1 specified PostgreSQL for production and SQLite for development. v1.1.1 did not change this but clarified that the v1.1 schema (particularly the ep_nodes status constraint and ep_transitions stage constraint) needed correction.

The v1.1 document claimed SQLite could work as an equal backend, but listed it as development-only with documented limitations. The directive requires separate PostgreSQL and SQLite migrations.

## Decision

PostgreSQL is the authoritative production backend. SQLite is supported only for:
- local development
- demonstrations
- single-agent testing

Do not claim that SQLite provides production-equivalent concurrency, notifications, locking, or cross-machine behavior.

Use separate migration directories:
- migrations/postgres/
- migrations/sqlite/

Key differences documented:
- PostgreSQL: LISTEN/NOTIFY, FOR UPDATE row locking, partial indexes (WHERE status = 'active'), pgvector (optional), cross-machine multi-agent
- SQLite: BEGIN IMMEDIATE for serialization, no LISTEN/NOTIFY, no pgvector, single-machine single-agent only, WAL mode for concurrent reads

The v1.1.1 schema corrections apply to both backends:
- ep_nodes.status CHECK: ('committed', 'quarantined', 'at_risk', 'superseded', 'archived')
- ep_transitions.stage CHECK: ('proposed', 'pending_approval', 'authorized', 'executing', 'succeeded', 'failed', 'execution_uncertain', 'cancelled', 'expired', 'denied')

## Rationale

SQLite is useful for rapid local development and testing. PostgreSQL is required for production features: row-level locking for atomic token claims, LISTEN/NOTIFY for notifications, partial indexes for work-claim uniqueness, and pgvector for optional embeddings.

## Consequences

- All integration and concurrency tests must run against PostgreSQL (via Testcontainers).
- SQLite-only tests are labeled and do not substitute for PostgreSQL integration tests.
- Migration up/down tests must pass for both backends.
- The atomic claim SQL uses FOR UPDATE in PostgreSQL and BEGIN IMMEDIATE in SQLite.