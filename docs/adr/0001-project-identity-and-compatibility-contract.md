# ADR-0001 — Project Identity, Scope and Compatibility Contract

## Status

**Status:** Active

## Context

pySysPass is a Python-native reimplementation of sysPass PHP, the open-source password vault. The project must balance two competing objectives:

1. **Modernization**: leverage Python's strengths (type safety, async I/O, rich ecosystem) to improve maintainability, testability, and security posture.
2. **Compatibility**: preserve existing users' investments in data, integrations, and operational procedures.

## Decision

pySysPass adopts the **"Modernization with Compatibility"** model:

- **Python-native architecture**: Use FastAPI, SQLAlchemy, and Pydantic instead of PHP. This is not a line-by-line port but a domain-driven reconstruction.
- **Backward compatibility contract**: Existing sysPass databases must remain accessible without data loss or security compromise.
- **Semantic preservation**: Accounts, users, groups, profiles, permissions, categories, tags, and their relationships must retain their meaning and functionality.
- **Cryptographic parity**: Encryption formats (AES-256-CTR for accounts, bcrypt for users) and master password mechanisms must be supported for compatibility.
- **API stability**: Existing API clients and integrations should continue working without modification.
- **Workflow continuity**: Existing user and administrator workflows must remain familiar.

### Compatibility matrix (to be completed)

| Dimension | Required Level | Supported Versions | Verification Method | Known Limitations |
|-----------|----------------|---------------------|---------------------|-------------------|
| Database structural | 100% | sysPass 1.x | Alembic migrations | — |
| Database semantic | TBD | sysPass 1.x | Manual review + tests | — |
| Cryptographic | 100% | sysPass 1.x | Unit tests + compatibility harness | — |
| Authentication | TBD | sysPass 1.x | Manual review + tests | — |
| Authorization | TBD | sysPass 1.x | Manual review + tests | — |
| API contract | TBD | sysPass 1.x | Contract tests | — |
| Functional | TBD | sysPass 1.x | E2E tests | — |
| User workflow | TBD | sysPass 1.x | Manual review + tests | — |
| Deployment | TBD | sysPass 1.x | Container images | — |
| Migration | 100% | sysPass 1.x | Import/export tests | — |
| Rollback | TBD | sysPass 1.x | Restore tests | — |

**Note**: The matrix above is aspirational; not all dimensions are currently implemented or verified.

## Consequences

### Operational

- New development must consult the compatibility matrix before introducing breaking changes.
- Any deviation from the contract requires an ADR explaining the rationale and impact.
- Security-critical deviations take precedence over compatibility (see "Security takes precedence" below).

### Development

- Developers must verify compatibility against the PHP schema in `schemas/` before committing changes.
- The `app/models/php_compatibility.py` and related helpers must be consulted for compatibility-sensitive operations.
- AI agents must treat compatibility as a hard requirement, not a best-effort goal.

### Testing

- Compatibility tests must exist for each dimension in the matrix.
- E2E tests must cover migration from PHP to pySysPass and back (where applicable).

### Deprecation

- Legacy behaviour that conflicts with security requirements must be documented with a deprecation path.
- Deprecations are communicated via API responses, logs, and documentation.
- Removal of deprecated features requires a minimum deprecation window (to be specified).

## References

- `docs/project/php-compatibility-checklist.md`: Detailed compatibility goals and parity checklist.
- `AGENTS.md`: Development rules and AI agent instructions (includes compatibility constraints).
- `schemas/`: SQL schema snapshots for PHP compatibility reference.
