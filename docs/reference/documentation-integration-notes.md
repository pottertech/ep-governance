# Documentation Integration Notes

Add these files to the repository:

```text
docs/reference/database-schema.md
docs/architecture/diagrams.md
```

Recommended navigation additions:

## README

```markdown
- [Architecture diagrams](docs/architecture/diagrams.md)
- [Database schema reference](docs/reference/database-schema.md)
```

## Architecture document

```markdown
See [Architecture Diagrams](architecture/diagrams.md) for rendered system,
trust-boundary, policy, identity, transition, and deployment views.
```

## Configuration or database section

```markdown
The complete logical schema, table inventory, relationships, constraints,
access model, and migration notes are documented in the
[Database Schema Reference](reference/database-schema.md).
```

## CI recommendation

Add a documentation check that:

1. renders or validates Mermaid syntax;
2. verifies internal Markdown links;
3. fails if a migration changes without a corresponding schema-reference update;
4. generates an actual PostgreSQL schema dump in CI for comparison.
