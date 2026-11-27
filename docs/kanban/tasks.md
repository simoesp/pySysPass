# Kanban Tasks - Documentation and Security Implementation

This Kanban board tracks all tasks from the documentation reconciliation and security implementation work.

**Operational Hermes Kanban board (`pysyspass`): 30 tasks total**
- 6 ADR tasks (ADR-0015 through ADR-0020)
- 14 Implementation tasks (IMPL-001 through IMPL-014)
- 10 Testing tasks (TEST-001 through TEST-010)

The previous documentation inventory reported 20 implementation tasks; these were consolidated into 14 during architectural review. No requirements were dropped — they were re-scoped with clearer acceptance criteria.

---

## Columns

- **Backlog** - Not yet started (architectural review incomplete)
- **Ready** - Ready to start, dependencies met
- **Active** - Currently being worked on
- **Review** - Complete, awaiting review
- **Done** - Complete and verified

---

## ADR Investigation Tasks (Architectural Discovery)

| ID | Task | Column | Priority | Dependencies | Notes |
|----|------|--------|----------|--------------|-------|
| ADR-0015 | Deployment Architecture and Infrastructure Requirements | **Active** | Critical | None | **In progress** - see ADR-0015 document |
| ADR-0016 | Database Migration Governance | **Ready** | High | ADR-0015 | Schema ownership, migration locking, PHP compatibility |
| ADR-0017 | Configuration and Secret Management | **Ready** | High | ADR-0015, ADR-0016 | Secret precedence, mounted secrets, rotation |
| ADR-0018 | API and Integration Governance | **Ready** | Medium | ADR-0015, ADR-0017 | Proxy trust, API compatibility, versioning |
| ADR-0019 | Testing and CI/CD | **Ready** | Medium | ADR-0015, ADR-0018 | Deployment verification, contract tests |
| ADR-0020 | Documentation Governance | **Ready** | Low | ADR-0015-0019 | Ongoing lifecycle, glossary maintenance |

---

## Implementation Tasks (From ADR Register — Consolidated)

| ID | Task | Column | Priority | ADR | Effort | Acceptance Criteria |
|----|------|--------|----------|-----|--------|---------------------|
| IMPL-001 | Remove LDAP fallback to local auth | **Ready** | Critical | ADR-0004 | Medium | `authenticate_ldap_login` fails closed; no local fallback; unit + integration tests pass |
| IMPL-002 | Enforce MFA before vault unlock | **Ready** | High | ADR-0003 | Medium | Vault unlock endpoint requires valid MFA claim; bypass returns 403; tests cover bypass attempts |
| IMPL-003 | Prevent master password identity fallback | **Ready** | High | ADR-0003 | Medium | Master password cannot authenticate without identity provider; tests verify |
| IMPL-004 | Implement emergency credentials table | **Ready** | Critical | ADR-0014 | Medium | `emergency_credentials` table created via Alembic; independent of User table; PHP-compatible |
| IMPL-005 | Implement emergency authentication endpoint | **Ready** | Critical | ADR-0014 | Medium | `POST /api/v1/auth/emergency` validates MFA, checks activation flag, returns JWT with vault claim |
| IMPL-006 | Implement emergency activation script | **Ready** | Critical | ADR-0014 | Medium | `activate-emergency-auth.sh` creates flag file, logs to audit, requires operator auth |
| IMPL-007 | Make backup encryption mandatory | **Ready** | Critical | ADR-0013 | High | Backup creation fails without encryption key; unencrypted requires explicit admin exception + audit |
| IMPL-008 | Implement backup integrity verification | **Ready** | High | ADR-0013 | Medium | HMAC-SHA256 on backup manifest; verification on restore; tampering detected |
| IMPL-009 | Implement backup authenticity verification | **Ready** | High | ADR-0013 | Medium | Ed25519 signature on manifest; signing key rotation; verification on restore |
| IMPL-010 | Implement service vault contexts | **Ready** | High | ADR-0010 | High | Service tokens get independent vault contexts; bound to token scope; revocable without master pwd rotation |
| IMPL-011 | Implement audit logging framework | **Ready** | High | ADR-0011 | High | All security events logged with actor/resource/operation/result; redaction; append-only; retention config |
| IMPL-012 | Add backup key rotation procedures | **Ready** | Medium | ADR-0013 | Medium | CLI command rotates backup encryption key; old keys retained for historical restore; audit logged |
| IMPL-013 | Implement cryptographic bootstrap for service vault contexts | **Ready** | High | ADR-0010 | High | Service vault key provisioned via operator; wrapped for each service identity; no secret-zero exposure |
| IMPL-014 | Implement service-specific key hierarchy | **Ready** | High | ADR-0010 | High | Per-service DEKs wrapped by service vault key; independent rotation; AAD binding to service identity |

---

## Testing Tasks

| ID | Task | Column | Priority | ADR | Effort | Acceptance Criteria |
|----|------|--------|----------|-----|--------|---------------------|
| TEST-001 | LDAP fallback rejection test | **Active** | Critical | ADR-0004 | Medium | LDAP-bound user with valid local password denied; only break-glass or emergency mode succeeds |
| TEST-002 | MFA before vault unlock test | **Ready** | High | ADR-0003 | Medium | Vault unlock without MFA claim → 403; with valid MFA → 200; token without MFA scope rejected |
| TEST-003 | Master password not identity test | **Ready** | High | ADR-0003 | Medium | Login with only master password (no identity) → 401; requires valid identity provider auth first |
| TEST-004 | Emergency mode test suite | **Ready** | Critical | ADR-0014 | High | Activation script works; emergency endpoint validates MFA+flag; 2hr timeout; sessions terminated on deactivation |
| TEST-005 | Backup encryption mandatory test | **Ready** | Critical | ADR-0013 | High | Backup without key → 400; with key → encrypted; unencrypted exception requires admin + audit event |
| TEST-006 | Backup integrity and authenticity tests | **Ready** | High | ADR-0013 | Medium | Tampered backup → restore fails verification; unsigned backup → restore fails; valid backup → restores |
| TEST-007 | Service vault context tests | **Ready** | High | ADR-0010 | High | Service token gets vault context; context bound to token scope; revoked on token rotation; no master pwd exposure |
| TEST-008 | Audit logging immutability test | **Ready** | High | ADR-0011 | Medium | Log entries cannot be modified; WORM or cryptographic signing verified; retention enforced |
| TEST-009 | PHP interoperability regression tests | **Ready** | Critical | ADR-0001, ADR-0002 | High | PHP sysPass reads/writes database created by pySysPass; XML import/export round-trip; schema guard blocks DDL |
| TEST-010 | Security regression test suite | **Ready** | High | ADR-0012 | Medium | All 40 threat mitigations tested; known vulnerabilities (AES-CTR, LDAP fallback, etc.) have regression tests |

---

## Verification Checklist

### Documentation Completeness

- [x] GLOSSARY.md updated with all concepts from ADR-0010 through ADR-0015
- [x] docs/security/policy.md reconciled against all ADRs
- [x] docs/runbooks/disaster-recovery.md created with all 14 scenarios
- [x] docs/deployment.md created with all 16 deployment topics
- [x] ADR-0014 clarifications added for three identity categories
- [x] ADR-0013 backup authenticity verification added
- [x] docs/adr/REGISTER.md created with all ADR statuses including ADR-0015
- [x] ADR-0015 Deployment Architecture document created

### Architecture Consistency

- [x] No ADR presented as implemented when it's only proposed
- [x] PHP compatibility limitations explicitly documented
- [x] Security control status (implemented vs proposed) distinguished
- [x] Threat identifiers referenced throughout
- [x] Recovery material storage requirements documented
- [x] Deployment verification matrix with 5 statuses

### Security Policy Alignment

- [x] Implemented controls listed with ADR references
- [x] Verified guarantees documented
- [x] Target architecture described
- [x] Proposed mechanisms distinguished from implemented
- [x] Known vulnerabilities listed
- [x] Remediation tasks prioritized
- [x] Residual risks accepted (only with explicit authorization)
- [x] PHP compatibility limitations documented

---

## Notes

1. **Phases 1-6 Complete:** All documentation work is complete (GLOSSARY, security policy, DR runbook, deployment docs, ADR-0014 clarifications, ADR register, ADR-0015).
2. **Implementation Work Remaining:** 14 implementation tasks and 10 testing tasks in Ready/Backlog.
3. **Critical Path:** IMPL-001, IMPL-004 through IMPL-007 (LDAP fallback + backup encryption + emergency auth).
4. **ADR Dependencies:** IMPL-004/IMPL-005/IMPL-006 depend on ADR-0014; IMPL-007/IMPL-008/IMPL-009 depend on ADR-0013; IMPL-010/IMPL-013/IMPL-014 depend on ADR-0010.
5. **PHP Compatibility:** All implementation tasks must maintain PHP compatibility per ADR-0001 and ADR-0002.
6. **Architecture Implementation Readiness Review:** Required before any implementation task moves to Active. Review gates: ADR-0015 through ADR-0020 complete, glossary current, threat model updated, Kanban reconciled.

---

## Next Steps

1. Complete ADR-0015 investigation (in progress)
2. Begin ADR-0016 investigation (Database Migration Governance)
3. Complete ADR-0017 through ADR-0020 in dependency order
4. Conduct Architecture Implementation Readiness Review
5. Move critical implementation tasks to Active after review approval
6. Begin implementation of backup encryption mandatory enforcement (IMPL-007)
7. Begin implementation of emergency authentication (IMPL-004 through IMPL-006)
8. Schedule disaster recovery testing (TEST-003 equivalent)
9. Verify PHP compatibility after each implementation