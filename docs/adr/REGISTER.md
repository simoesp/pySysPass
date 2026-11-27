# ADR Decision Register

This register tracks all Architectural Decision Records for pySysPass.

## ADR Status Summary

| ADR | Title | Status | Implementation | Verification | Related Threats |
|-----|-------|--------|----------------|--------------|-----------------|
| ADR-0001 | Project Identity and Compatibility Contract | **Accepted** | ✅ Implemented | ✅ Verified | - |
| ADR-0002 | Bidirectional Database Interoperability and Extension Isolation | **Accepted** | ✅ Implemented | ✅ Verified | - |
| ADR-0003 | Identity Authentication, MFA and Cryptographic Unlocking Boundaries | **Active** | ⚠️ Partially Implemented | ❌ Not Verified | T-EVP-06 |
| ADR-0004 | Identity Provider Binding, Administrator Provisioning and Break-Glass Access | **Active** | ⚠️ Partially Implemented | ❌ Not Verified | T-EVP-05 |
| ADR-0005 | Authorization, Access Control and Administrator Privilege Boundaries | **Accepted** | ✅ Implemented | ✅ Verified | T-EVP-01, T-EVP-02, T-EVP-03, T-EVP-04, T-EVP-07 |
| ADR-0006 | Account Ownership, Credential Sharing and Group-Based Access | **Accepted** | ✅ Implemented | ✅ Verified | T-EVP-04 |
| ADR-0007 | Effective Permissions, ACL Precedence and Conflict Resolution | **Accepted** | ✅ Implemented | ✅ Verified | T-EVP-04, T-EVP-07 |
| ADR-0008 | Encryption Architecture, Master Password and Cryptographic Key Lifecycle | **Accepted** | ✅ Implemented | ⚠️ Partially Verified | T-IDI-01, T-IDI-02, T-IDI-03 |
| ADR-0009 | Session Architecture, API Token Lifecycle and Server-Side Vault Context | **Accepted** | ✅ Implemented | ✅ Verified | T-SPA-01, T-SPA-02, T-SPA-03, T-IDI-03 |
| ADR-0010 | Service Accounts, Workload Identity and Automated Credential Retrieval | **Accepted** | ⚠️ Partially Implemented | ❌ Not Verified | T-SPA-02, T-EVP-02, T-EVP-03, T-IDI-04, T-IDI-08 |
| ADR-0011 | Audit Logging and Accountability | **Active** | ⚠️ Partially Implemented | ❌ Not Verified | T-REP-01, T-REP-02, T-REP-03, T-PDB-02 |
| ADR-0012 | Threat Model and Trust Boundaries | **Proposed** | ⚠️ Partially Implemented | ❌ Not Verified | All threats |
| ADR-0013 | Backup, Disaster Recovery and Cryptographic Recoverability | **Proposed** | ❌ Not Implemented | ❌ Not Verified | T-IDI-07 |
| ADR-0014 | Emergency Authentication and Offline Recovery Access | **Proposed** | ❌ Not Implemented | ❌ Not Verified | T-EVP-08, T-PM-07, T-EAM-01, T-EAM-02, T-EAM-03 |
| ADR-0015 | Deployment Architecture and Infrastructure Requirements | **Active** | ⚠️ Partially Implemented | ⚠️ Partially Verified | T-DEP-01 to T-DEP-12 |
| ADR-0016 | Database Schema Ownership and Migration Governance | **Active** | ⚠️ Partially Implemented | ⚠️ Partially Verified | T-MIG-01 to T-MIG-05 |
| ADR-0017 | Configuration and Secret Management | **Active** | ⚠️ Partially Implemented | ✅ Discovery Verified | T-CFG-01 to T-CFG-05 |

## Detailed ADR Status

### ADR-0001: Project Identity and Compatibility Contract
- **Status:** Accepted
- **Decision:** Modernization with strong backward compatibility (Option 2)
- **Implementation:** Complete - pySysPass maintains PHP compatibility
- **Verification:** Verified - database schema compatible, import/export working
- **Dependencies:** None
- **Related Security Findings:** None

### ADR-0002: Bidirectional Database Interoperability and Extension Isolation
- **Status:** Accepted
- **Decision:** Bidirectional database-level + import/export with namespace isolation (Option 1)
- **Implementation:** Complete - Python extension data in shared tables with JSON blobs
- **Verification:** Verified - PHP ignores unknown fields, MySQL dumps preserve blobs
- **Dependencies:** ADR-0001
- **Related Security Findings:** None

### ADR-0003: Identity Authentication, MFA and Cryptographic Unlocking Boundaries
- **Status:** Active
- **Decision:** Layered authentication model - Identity → MFA → Cryptographic unlock
- **Implementation:** Partially implemented - 4 documented deviations:
  1. Vault unlock before MFA (current order reversed)
  2. LDAP fallback to local auth (violates fail-closed)
  3. Master password can unlock vault without identity auth
  4. Emergency admin auto-provisioning risk
- **Verification:** Not verified - deviations block verification
- **Dependencies:** ADR-0001
- **Related Security Findings:** AES-256-CTR without authenticated encryption (runtime)

### ADR-0004: Identity Provider Binding, Administrator Provisioning and Break-Glass Access
- **Status:** Active
- **Decision:** Fail-closed authentication with mandatory identity provider binding (Option B)
- **Implementation:** Partially implemented - LDAP-to-local fallback still exists in `authenticate_ldap_login` (app/api/v1/auth.py:165-168)
- **Verification:** Not verified - fallback blocks fail-closed verification
- **Dependencies:** ADR-0003
- **Related Security Findings:** LDAP-to-local fallback present in current code

### ADR-0005: Authorization, Access Control and Administrator Privilege Boundaries
- **Status:** Accepted
- **Decision:** PHP-compatible ACL with admin/credential access separation (Option 3)
- **Implementation:** Complete - admin flags separate from profile permissions
- **Verification:** Verified - admin does not bypass resource-level checks
- **Dependencies:** ADR-0003, ADR-0006
- **Related Security Findings:** None

### ADR-0006: Account Ownership, Credential Sharing and Group-Based Access
- **Status:** Accepted
- **Decision:** PHP-compatible ownership and ACL semantics (Option 3)
- **Implementation:** Complete - userId=owner, userEditId=last editor, sharing additive
- **Verification:** Verified - ownership and sharing tested
- **Dependencies:** ADR-0005
- **Related Security Findings:** None

### ADR-0007: Effective Permissions, ACL Precedence and Conflict Resolution
- **Status:** Accepted
- **Decision:** Additive grants ∩ profile permissions ∩ mandatory restrictions
- **Implementation:** Complete - effective permissions calculation
- **Verification:** Verified - test matrix 76 scenarios
- **Dependencies:** ADR-0005, ADR-0006
- **Related Security Findings:** None

### ADR-0008: Encryption Architecture, Master Password and Cryptographic Key Lifecycle
- **Status:** Accepted
- **Decision:** Defuse V2 format for database, AES-256-GCM for runtime, PBKDF2-SHA256 (100k)
- **Implementation:** Complete - encryption compatibility with PHP
- **Verification:** Partially verified - round-trip tests pass but AES-256-CTR used in runtime without authenticated encryption
- **Dependencies:** ADR-0001, ADR-0002
- **Related Security Findings:** AES-256-CTR without authenticated encryption in runtime

### ADR-0009: Session Architecture, API Token Lifecycle and Server-Side Vault Context
- **Status:** Accepted
- **Decision:** Hybrid JWT + server-side sessions + independent vault contexts (Option C)
- **Implementation:** Complete - 15min JWT, 12hr session, 4hr vault
- **Verification:** Verified - session management tested
- **Dependencies:** ADR-0003, ADR-0008
- **Related Security Findings:** None

### ADR-0010: Service Accounts, Workload Identity and Automated Credential Retrieval
- **Status:** Accepted (decision record completed by the ADR-0010 key-hierarchy amendment, §17)
- **Decision:** Hybrid model with dedicated service identities and hardened service tokens (Option D). The service vault key hierarchy and authoritative-key precedence are recorded in ADR-0010 §17 (amendment).
- **Implementation:** Partially implemented - service vault keyring, per-service DEK wrapping/rotation, and vault-context cryptography implemented (`app/core/service_vault_keyring.py`, `app/core/service_vault_crypto.py`, `app/core/service_vault_key.py`). However, an existing keyring file silently overrides `SERVICE_VAULT_KEY` in `resolve_service_vault_key()` — a precedence divergence from the §17 decision, recorded explicitly there as unresolved.
- **Verification:** Not verified - IMPL-010 probe (`tests/test_impl010_probe.py`) executes but fails with a documented DEK-lookup error; not green. Verification must not be claimed from documentation alone.
- **Dependencies:** ADR-0003, ADR-0008, ADR-0009
- **Outstanding Decisions:**
  - Context lifetime separation
- **Related Threats:** T-SPA-02, T-EVP-02, T-EVP-03, T-IDI-04, T-IDI-08
- **Related Security Findings:** Service vault contexts partially implemented (keyring hierarchy present); keyring-vs-env precedence divergence recorded in §17, unresolved

### ADR-0011: Audit Logging and Accountability
- **Status:** Active
- **Decision:** Mandatory security event coverage, redaction, append-only, configurable retention, Security Auditor role
- **Implementation:** Partially implemented - basic event logging exists but full audit framework pending
- **Verification:** Not verified
- **Dependencies:** ADR-0005, ADR-0012
- **Outstanding Decisions:**
  - Audit log storage backend
  - Retention configuration
  - Redaction rules implementation
- **Related Threats:** T-REP-01, T-REP-02, T-REP-03, T-PDB-02

### ADR-0012: Threat Model and Trust Boundaries
- **Status:** Proposed
- **Decision:** 40 threats identified across 7 categories with prioritized remediation
- **Implementation:** Partially - some controls implemented, many gaps
- **Verification:** Not verified
- **Dependencies:** All previous ADRs
- **Outstanding Decisions:**
  - Emergency authentication controls (ADR-0014)
  - Backup encryption mandatory (ADR-0013)
  - Service vault contexts (ADR-0010)
- **Related Threats:** All 40 threats

### ADR-0013: Backup, Disaster Recovery and Cryptographic Recoverability
- **Status:** Proposed
- **Decision:** Mandatory backup encryption (AES-256-GCM), independent recovery storage, 2-hour emergency window
- **Implementation:** Not implemented
- **Verification:** Not verified
- **Dependencies:** ADR-0008, ADR-0010, ADR-0014
- **Outstanding Decisions:**
  - Asymmetric backup encryption investigation
  - Backup key rotation procedures
  - Recovery testing automation
- **Related Threats:** T-IDI-07
- **Related Security Findings:** Backup encryption not mandatory, no integrity verification

### ADR-0014: Emergency Authentication and Offline Recovery Access
- **Status:** Proposed
- **Decision:** Separate emergency_credentials table, 2-hour window, explicit activation, MFA mandatory
- **Implementation:** Not implemented
- **Verification:** Not verified
- **Dependencies:** ADR-0004, ADR-0013
- **Outstanding Decisions:**
  - Emergency credentials table creation
  - CLI activation script
  - Emergency authentication endpoint
  - Audit logging integration
- **Related Threats:** T-EVP-08, T-PM-07, T-EAM-01, T-EAM-02, T-EAM-03
- **Related Security Findings:** LDAP-to-local fallback removed, emergency mode needed

### ADR-0015: Deployment Architecture and Infrastructure Requirements
- **Status:** Active
- **Decision:** Multi-profile deployment (dev, standalone, compose, external DB, Portainer) with HA as opt-in; simple self-hosted without mandatory Redis/K8s; target native OpenShift compatibility via UBI base image; server-side sessions per ADR-0009
- **Implementation:** Partially implemented - Docker Compose, Podman, external DB, Portainer verified; Kubernetes/OpenShift/HA proposed
- **Verification:** Partially verified - container security, health checks, bootstrap locking, proxy trust verified; HA, K8s, OpenShift not verified
- **Dependencies:** ADR-0003, ADR-0008, ADR-0009, ADR-0010, ADR-0011, ADR-0013, ADR-0014
- **Outstanding Decisions:**
  - Kubernetes manifests and Helm chart
  - UBI base image for native arbitrary UID
  - Database-backed session storage (ADR-0009 target)
  - Graceful shutdown handling
  - Rolling upgrade procedures
- **Related Threats:** T-DEP-01 through T-DEP-12
- **Related Security Findings:** HA session/vault/scheduler gaps; file-based sessions transitional; JWT-embedded mpass transitional

### ADR-0016: Database Schema Ownership and Migration Governance
- **Status:** Active
- **Decision:** Bootstrap owns PHP base schema creation (IF NOT EXISTS); Alembic owns Python extensions (003-005+); runtime DDL blocked by schema guard; Alembic version check required at readiness; migration lock required for Alembic
- **Implementation:** Partially implemented — bootstrap + schema guard verified; Alembic exists but not invoked at startup; migration locking only for bootstrap; `python_init.sql` dead code; PHP `.sql` migration files unused
- **Verification:** Partially verified — table existence check verified; shape validation missing; Alembic idempotency risk documented
- **Dependencies:** ADR-0002 (PHP compat contract), ADR-0013 (backup prerequisites), ADR-0015 (deployment)
- **Outstanding Decisions:**
  - Alembic GET_LOCK in env.py
  - Extension schema version validation at readiness
  - AUTO_INIT_DB_ON_STARTUP default for production
  - Remove `python_init.sql` dead code
  - Database-backed session migration path (ADR-0009)
- **Related Threats:** T-MIG-01 through T-MIG-05
- **Related Security Findings:** No Alembic check at startup; concurrent migration without lock; schema guard correct for runtime

### ADR-0017: Configuration and Secret Management
- **Status:** Active
- **Decision:** 8-layer configuration precedence; mounted secrets (Docker/K8s) + optional external providers; secret lifecycle with rotation schedules and overlapping validity; fail-fast startup validation; consolidated recovery material
- **Implementation:** Partially implemented — layers 2/4/5/6/7/8 implemented and verified; layers 1 (mounted secrets) and 3 (external providers) not implemented; 9+ secrets bypass Settings via raw `os.environ.get()`
- **Verification:** Discovery verified (V-01–V-08); 8 findings documented against codebase
- **Dependencies:** ADR-0008, ADR-0009, ADR-0013, ADR-0014, ADR-0015, ADR-0016
- **Outstanding Decisions:**
  - `AUDIT_HMAC_KEY` and backup keyring vars: add to Settings or document as operator-level env only
  - `SYSPASS_PASSWORD_SALT` production validation (V-04)
  - `SERVICE_VAULT_KEY` startup validation (V-08)
  - `SECRET_KEY_PREVIOUS` overlapping rotation field (V-05)
  - `secrets_dir` configuration (V-02)
- **Related Threats:** T-CFG-01 through T-CFG-05
- **Related Security Findings:** Raw env var secrets bypass validation (V-03); salt not validated at startup (V-07); JWT rotation without overlap invalidates sessions

## Outstanding Decisions

| Decision | ADR | Status | Priority |
|----------|-----|--------|----------|
| Audit log storage backend | ADR-0011 | Pending | High |
| Backup encryption mandatory enforcement | ADR-0013 | Pending | Critical |
| Asymmetric backup encryption | ADR-0013 | Pending | Medium |
| Emergency authentication implementation | ADR-0014 | Pending | Critical |
| Emergency credentials table creation | ADR-0014 | Pending | Critical |
| LDAP fallback removal | ADR-0004 | Pending | Critical |
| MFA before vault unlock | ADR-0003 | Pending | High |
| Master password not identity fallback | ADR-0003 | Pending | High |

## Dependencies

```
ADR-0001 (Project Identity)
    ↓
ADR-0002 (Interoperability) ← ADR-0008 (Encryption)
    ↓
ADR-0003 (Auth Hierarchy) ← ADR-0004 (LDAP)
    ↓
ADR-0005 (Authorization) ← ADR-0006 (Ownership)
    ↓
ADR-0007 (Effective Permissions)
    ↓
ADR-0009 (Sessions) ← ADR-0008
    ↓
ADR-0010 (Service Accounts) ← ADR-0009
    ↓
ADR-0011 (Audit) ← ADR-0012 (Threats)
    ↓
ADR-0013 (Backup) ← ADR-0010, ADR-0014
    ↓
ADR-0014 (Emergency Auth) ← ADR-0004, ADR-0013
    ↓
ADR-0015 (Deployment) ← ADR-0003, ADR-0008, ADR-0009, ADR-0010, ADR-0011, ADR-0013, ADR-0014
    ↓
ADR-0016 (Schema/Migration) ← ADR-0002, ADR-0008, ADR-0013, ADR-0015
    ↓
ADR-0017 (Configuration & Secrets) ← ADR-0008, ADR-0009, ADR-0013, ADR-0014, ADR-0015, ADR-0016
    ↓
ADR-0018 (API/Integration) ← ADR-0002, ADR-0005, ADR-0009, ADR-0010, ADR-0015, ADR-0017
    ↓
ADR-0019 (Testing/CI-CD) ← All ADRs (verification matrix)
    ↓
ADR-0020 (Docs/Governance) ← All ADRs (documentation requirements)
```

## Security Findings Index

| Finding | Severity | ADR | Status |
|---------|----------|-----|--------|
| AES-256-CTR without authenticated encryption | Medium | ADR-0008 | Documented, not remediated |
| LDAP-to-local fallback | Critical | ADR-0004 | Not remediated (deviation) |
| Backup encryption not mandatory | High | ADR-0013 | Not implemented |
| Backup integrity verification missing | Medium | ADR-0013 | Not implemented |
| Audit logging not implemented | High | ADR-0011 | Not implemented |
| Service vault contexts partially implemented (keyring hierarchy present); keyring silently overrides SERVICE_VAULT_KEY — divergence recorded in ADR-0010 §17, unresolved | Medium | ADR-0010 | Partially implemented, not verified |
| Emergency authentication not implemented | High | ADR-0014 | Not implemented |
| Vault unlock before MFA | Medium | ADR-0003 | Not remediated (deviation) |
| Master password as identity fallback | Medium | ADR-0003 | Not remediated (deviation) |
| Emergency admin auto-provisioning | Medium | ADR-0003 | Not remediated (deviation) |
| Uncontrolled schema mutations | High | ADR-0016 | Not implemented |
| Missing migration locking | High | ADR-0016 | Not implemented |
| No backup prerequisite enforcement | Medium | ADR-0016 | Not implemented |
| Untested rollback procedures | Medium | ADR-0016 | Not implemented |
| Auto-generated secrets accepted in production | High | ADR-0017 | Not implemented |
| No mounted secret file support | Medium | ADR-0017 | Not implemented |
| No secret rotation policy | High | ADR-0017 | Not implemented |
| No external secret provider support | Medium | ADR-0017 | Not implemented |
| Secret age not validated at startup | Medium | ADR-0017 | Not implemented |

## Implementation Priority

| Priority | Task | ADR | Effort |
|----------|------|-----|--------|
| Critical | Remove LDAP fallback to local auth | ADR-0004 | Medium |
| Critical | Make backup encryption mandatory | ADR-0013 | High |
| Critical | Implement emergency authentication | ADR-0014 | High |
| Critical | Store emergency credentials independently | ADR-0014 | High |
| High | Enforce MFA before vault unlock | ADR-0003 | Medium |
| High | Prevent master password identity fallback | ADR-0003 | Medium |
| High | Verify service vault contexts and resolve the keyring/env precedence divergence (ADR-0010 §17) | ADR-0010 | High |
| High | Add audit log immutability | ADR-0011 | Medium |
| High | Implement migration locking | ADR-0016 | Medium |
| High | Add schema ownership registry | ADR-0016 | Medium |
| High | Enforce backup prerequisites for BREAKING migrations | ADR-0016 | Medium |
| Medium | Add migration classification + rollback tests | ADR-0016 | Medium |
| Medium | Implement PHP compatibility test gate | ADR-0016 | Medium |
| Medium | Add export limits | ADR-0012 | Low |
| Medium | Protect config files | ADR-0012 | Low |
| Medium | Implement backup key rotation | ADR-0013 | Medium |
| High | Add mounted secret file support (`/run/secrets/`) | ADR-0017 | Medium |
| High | Implement external secret provider abstraction (Vault, AWS, Azure, GCP) | ADR-0017 | High |
| High | Add secret rotation policy with overlapping validity (SECRET_KEY, ENCRYPTION_KEY) | ADR-0017 | Medium |
| High | Enforce secret age validation at startup (production) | ADR-0017 | Medium |
| High | Consolidate recovery material (temporary master, emergency token, DR shares) | ADR-0017 | Medium |
| Medium | Add 8-layer configuration precedence documentation and tests | ADR-0017 | Low |
| Medium | Implement secret provider health check in readiness probe | ADR-0017 | Low |

## Kanban Task Tracking

See `docs/kanban/tasks.md` for detailed task breakdown.

## Related Documentation

- `docs/GLOSSARY.md` - Domain dictionary
- `docs/security/policy.md` - Security policy
- `docs/runbooks/disaster-recovery.md` - Recovery procedures
- `docs/deployment.md` - Deployment guide