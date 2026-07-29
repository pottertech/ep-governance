# Contributing to EP-Governance

## Phase Discipline

EP-Governance is built in bounded phases. Each phase has a defined scope and a gate.

- Do not implement runtime behaviour during Phase 0/1.
- Do not begin a new phase without external approval of the previous phase.
- Do not combine unrelated phases in one commit.

## Commit Discipline

1. Begin from a clean working tree.
2. Create a dedicated branch for each phase.
3. Implement only the approved scope.
4. Run all required verification (`./scripts/verify.sh`).
5. Inspect the diff.
6. Remove accidental files and secrets.
7. Update documentation.
8. Create a deliberate commit.
9. Record the commit hash.
10. Confirm the working tree is clean.

## Testing

- Write tests before or alongside implementation (test-driven).
- Reference normative rule identifiers (e.g., `EP-BRANCH-001`) in test docstrings.
- Never weaken or delete a valid test to make the suite pass.
- Never rely only on mocks for database concurrency or authorization claiming.
- Use disposable PostgreSQL instances for integration tests.
- Never connect to production databases.

## Code Style

- Ruff for linting and formatting (line-length 100).
- Mypy strict mode for type checking.
- Python 3.12+.

## Normative Vocabulary

- **MUST**: required for correctness or security.
- **MUST NOT**: prohibited.
- **SHOULD**: expected unless a documented reason exists.
- **SHOULD NOT**: discouraged unless justified.
- **MAY**: optional.

## Security

- Never expose production credentials to an agent.
- Never test destructive operations against production systems.
- Scrub secrets from logs and test artifacts.
- Flag cryptographic and authorization components for independent review.
- Do not describe the system as cryptographically guaranteed.