Documentation Integration Notes

Add these files to the repository:

docs/reference/database-schema.md
docs/architecture/diagrams.md

Recommended navigation additions:

README

- [Architecture diagrams](docs/architecture/diagrams.md)
- [Database schema reference](docs/reference/database-schema.md)

Architecture document

See [Architecture Diagrams](architecture/diagrams.md) for rendered system,
trust-boundary, policy, identity, transition, and deployment views.

Configuration or database section

The complete logical schema, table inventory, relationships, constraints,
access model, and migration notes are documented in the
[Database Schema Reference](reference/database-schema.md).

CI recommendation

Add a documentation check that:

renders or validates Mermaid syntax;

verifies internal Markdown links;

fails if a migration changes without a corresponding schema-reference update;

generates an actual PostgreSQL schema dump in CI for comparison.
