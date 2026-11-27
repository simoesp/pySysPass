# Security Policy

This document describes the security requirements and guarantees for pySysPass, the Python rewrite of sysPass.

## Document Status

| Aspect | Status |
|--------|--------|
| Implemented Controls | See "Implemented Security Controls" section |
| Target Architecture | See "Accepted Target Architecture" section |
| Known Vulnerabilities | See "Known Vulnerabilities" section |
| Outstanding Remediation | See "Remediation Tasks" section |
| PHP Compatibility Limitations | See "PHP Compatibility Limitations" section |

**Important:** This document does NOT claim that security controls described in ADRs have been implemented. ADRs represent architectural decisions; implementation status is indicated separately.

---

## Implemented Security Controls

| Control | ADR | Status | Threats Mitigated |
|---------|-----|--------|-------------------|
| TLS 1.2+ everywhere | ADR-0012 | ✅ Implemented | T-PA-01, T-PA-02, T-IDI-01 |
| MFA for all users | ADR-0003 | ✅ Implemented | T-EVP-06 |
| Token hash verification | ADR-0009 | ✅ Implemented | T-SPA-02, T-SPA-03 |
| Rate limiting | ADR-0012 | ✅ Implemented | T-PM-04, T-IDS-03 |
| Account lockout | ADR-0012 | ✅ Implemented | T-PM-04 |
| Encryption at rest | ADR-0008 | ✅ Implemented | T-IDI-01, T-IDI-02 |
| Private account protection | ADR-0007 | ✅ Implemented | T-EVP-07 |
| ACL enforcement | ADR-0007 | ✅ Implemented | T-EVP-04 |
| Session management | ADR-0009 | ✅ Implemented | T-IDI-03 |
| Service token validation | ADR-0010 | ❌ Not Implemented | T-SPA-02, T-EVP-02 |
| LDAP fail-safe (fail-closed) | ADR-0004 | ❌ Not Implemented | T-EVP-05 |

---

## Verified Security Guarantees

| Guarantee | Description | ADR Reference |
|-----------|-------------|---------------|
| No LDAP fallback | LDAP-bound identities never fall back to local auth on failure | ADR-0004 (target, not verified) |
| Layered authentication | Identity → MFA → Vault unlock as distinct responsibilities | ADR-0003 (target, not verified) |
| Token security | API tokens hashed for storage; service tokens hashed | ADR-0009, ADR-0010 (target) |
| Session isolation | Server-side session state; short-lived JWTs | ADR-0009 |
| Private accounts | Owner-exclusive access; admin bypass removed | ADR-0007 |
| Profile permissions | Admin flag does not bypass resource-level checks | ADR-0005 |
| Credential access | Requires master_pass parameter for decryption | ADR-0003 |
| Extension isolation | Python-exclusive data in shared tables with namespace isolation | ADR-0002 |
| PHP compatibility | Database schema compatible with sysPass PHP | ADR-0001 |

---

## Accepted Target Architecture

### Authentication Model

**Layered authentication with backward compatibility:**

1. **Identity authentication** → Verify credentials against identity provider
2. **MFA verification** → TOTP second factor
3. **Cryptographic unlocking** → Decrypt vault contents using master password

**Supported authentication paths:**

- **Human users:** Short-lived JWTs (15min) + server-side sessions (12hr) + independent vault contexts (4hr)
- **Service accounts:** Dedicated, scoped, revocable service credentials
- **Legacy integrations:** Original PHP-compatible API authentication within documented compatibility boundaries

**ADR Reference:** ADR-0003, ADR-0009, ADR-0010

### Authorization Model

**PHP-compatible ACL with admin/credential access separation:**

- Users have additive grants intersected with profile permissions and mandatory restrictions
- Admin flags (isUserAdmin, isAdminApp, isAdminAcc) are separate from profile permissions
- Admin flag does NOT bypass resource-level checks
- Credential access requires master_pass parameter

**ADR Reference:** ADR-0005, ADR-0006, ADR-0007

### Service Accounts and Workload Identities

**Hybrid model with dedicated service identities:**

- Service accounts have unique identity, descriptive name, documented purpose, responsible owner
- Service tokens: cryptographically random secrets, hashed for storage, one-time disclosure
- Service vault contexts: encrypted with SERVICE_VAULT_KEY, bounded lifetime
- Dedicated service token permissions (never exceed identity permissions)
- Hash-based token verification (opaque tokens)

**ADR Reference:** ADR-0010

### Emergency Authentication Mode

**Time-limited emergency access for disaster recovery:**

- Break-glass accounts stored in separate `emergency_credentials` table (NOT User table)
- Independent MFA required for all break-glass accounts
- 2-hour default activation window (configurable)
- Explicit operator authorization required
- Multi-factor verification for activation
- Recovery tokens do NOT bypass MFA
- Automatic deactivation and session revocation
- Independent recovery credentials (NOT stored in pySysPass)

**ADR Reference:** ADR-0014

### Backup and Disaster Recovery

**Mandatory backup encryption with integrity verification:**

- Backup encryption mandatory by default (AES-256-GCM)
- Integrity verification via HMAC-SHA256
- Authenticity verification via digital signatures (asymmetric encryption)
- Backup minimization (exclude disposable runtime files)
- Independent recovery storage for keys and credentials
- Recovery procedures documented and tested

**ADR Reference:** ADR-0013

### Secret Management

**Mounted secret files with optional external managers:**

- Default: Mounted secret files with restrictive permissions (0400)
- Optional: External secrets manager for enterprise deployments
- Not supported: Environment variables as primary storage
- Backup encryption key lifecycle independent of application secrets

**ADR Reference:** ADR-0013

### Audit Logging

**Mandatory coverage for security events:**

- Security events require mandatory audit logging
- Redaction rules for sensitive information
- Append-only integrity
- Configurable retention
- Explicit Security Auditor role (read-only)
- Fail-open only for non-security events

**ADR Reference:** ADR-0011

### Threat Boundaries

**Trust zones and boundaries:**

- Client → Server: TLS 1.2+, mutual TLS (future)
- Server → Database: Encrypted connection, access control
- Server → LDAP: LDAP over TLS, bind authentication
- Server → Backup: Encrypted transfer, access control
- Server → SIEM: Encrypted transport, API auth

**ADR Reference:** ADR-0012

---

## Proposed Security Mechanisms

| Mechanism | Status | ADR Reference | Implementation Status |
|-----------|--------|---------------|----------------------|
| Service vault contexts | Proposed | ADR-0010 | Not implemented |
| Audit logging | Proposed | ADR-0011 | Not implemented |
| Access control roles | Proposed | ADR-0012 | Not implemented |
| Emergency authentication controls | Proposed | ADR-0014 | Not implemented |
| Backup encryption mandatory enforcement | Proposed | ADR-0013 | Not implemented |
| Backup authenticity verification (digital signatures) | Proposed | ADR-0013 | Not implemented |
| Asymmetric backup encryption | Proposed | ADR-0013 | Not implemented |
| Service token rotation | Proposed | ADR-0010 | Not implemented |
| Cryptographic bootstrap provisioning | Proposed | ADR-0010 | Not implemented |
| WAF/DDoS protection | Proposed | ADR-0012 | Not implemented |
| SIEM integration | Proposed | ADR-0012 | Not implemented |
| OIDC workload identity | Proposed | ADR-0012 | Not implemented |
| Audit log immutability (WORM storage) | Proposed | ADR-0012 | Not implemented |
| Key rotation | Proposed | ADR-0013 | Not implemented |

**Important:** These mechanisms are documented in ADRs but have NOT been implemented in code.

---

## Known Vulnerabilities

| Vulnerability | Severity | Status | ADR Reference |
|---------------|----------|--------|---------------|
| AES-256-CTR without authenticated encryption | Medium | Documented, not remediated | Security audit finding |
| Backup encryption not mandatory | High | Documented, not implemented | ADR-0013 |
| Backup integrity verification not implemented | Medium | Documented, not implemented | ADR-0013 |
| Backup authenticity verification not implemented | Medium | Documented, not implemented | ADR-0013 |
| Audit logging not implemented | High | Documented, not implemented | ADR-0011 |
| Emergency authentication not implemented | High | Documented, not implemented | ADR-0014 |
| Service vault contexts not implemented | Medium | Documented, not implemented | ADR-0010 |
| LDAP-to-local fallback present | Critical | Documented, not remediated | ADR-0004 |
| Vault unlock before MFA | Medium | Documented, not remediated | ADR-0003 |
| Master password as identity fallback | Medium | Documented, not remediated | ADR-0003 |

---

## Remediation Tasks

### Priority 1 (Immediate)

| Task | ADR Reference | Threat |
|------|---------------|--------|
| Remove LDAP fallback to local auth | ADR-0004 | T-EVP-05 |
| Add credential export limits | ADR-0012 | T-PM-01 |
| Protect config files | ADR-0012 | T-IDI-06 |
| Implement emergency authentication | ADR-0014 | T-EVP-08 |
| Store emergency credentials independently | ADR-0014 | T-EVP-08 |

### Priority 2 (Short-term)

| Task | ADR Reference | Threat |
|------|---------------|--------|
| Implement service vault contexts | ADR-0010 | T-IDI-04, T-IDI-08 |
| Add audit log immutability | ADR-0012 | T-PDB-02 |
| Implement backup key rotation | ADR-0013 | T-IDI-07 |
| Make backup encryption mandatory | ADR-0013 | T-IDI-07 |
| Enforce MFA before vault unlock | ADR-0003 | T-EVP-06 |
| Prevent master password identity fallback | ADR-0003 | T-EVP-06 |

### Priority 3 (Long-term)

| Task | ADR Reference | Threat |
|------|---------------|--------|
| Implement WAF | ADR-0012 | T-IDS-01 |
| Implement SIEM integration | ADR-0012 | T-PDB-02 |
| Implement OIDC workload identity | ADR-0012 | T-SPA-02 |

---

## Accepted Residual Risks

| Risk | Description | Mitigation | ADR Reference |
|------|-------------|------------|---------------|
| T-EVP-05 | LDAP-to-local fallback bypass | Secure LDAP config, monitoring; fail-closed NOT YET enforced | ADR-0012 |
| T-PM-01 | Unrestricted credential export | Export limits, approval; not implemented yet | ADR-0012 |
| T-PM-04 | Offline password guessing | Rate limiting, account lockout | ADR-0012 |
| T-IDI-02 | Master password compromise | Encryption at rest; independent storage | ADR-0012 |
| T-PM-03 | Vault unlock access | Short vault lifetime; not implemented yet | ADR-0012 |
| T-EVP-08 | Emergency mode abuse | MFA enforcement, automatic deactivation; not implemented yet | ADR-0012 |
| T-IDI-07 | Backup data theft | Backup encryption mandatory; not implemented yet | ADR-0013 |
| T-EVP-05 residual | LDAP availability failure | Emergency authentication mode; not implemented yet | ADR-0014 |

---

## PHP Compatibility Limitations

| Limitation | Description | Impact | ADR Reference |
|------------|-------------|--------|---------------|
| Service vault contexts | Python-only, not understood by PHP | PHP rollback may lose service contexts | ADR-0002 |
| Python extension metadata | JSON blobs not visible to PHP | PHP rollback may lose extension data | ADR-0002 |
| API tokens | Plaintext in DB for PHP compatibility | Contains plaintext tokens (SECURITY RISK) | ADR-0002 |
| Encryption formats | Defuse V2 format for database | PHP can read encrypted data | ADR-0003 |
| Password hashes | bcrypt for login passwords | PHP can read password hashes | ADR-0001 |
| Schema columns | Same columns as PHP | Full database compatibility | ADR-0001 |
| LDAP-to-local fallback removal | Security improvement over PHP | PHP rollback weakens auth guarantees | ADR-0004 |
| Private account enforcement | Hardened model vs PHP admin bypass | PHP rollback may weaken access control | ADR-0007 |

---

## Security Control Gaps

| Gap | Affected Threats | Severity | Priority | ADR Reference |
|-----|------------------|----------|----------|---------------|
| LDAP-to-local fallback | T-EVP-05 | Critical | High | ADR-0012 |
| Credential export limits | T-PM-01 | High | High | ADR-0012 |
| Audit log immutability | T-PDB-02 | Medium | Medium | ADR-0012 |
| Service context rotation | T-IDI-08 | Medium | Medium | ADR-0012 |
| WAF/DDoS protection | T-IDS-01 | Medium | Medium | ADR-0012 |
| Backup key management | T-IDI-07 | High | High | ADR-0013 |
| Backup encryption mandatory | T-IDI-07 | High | High | ADR-0013 |
| Emergency authentication implementation | T-EVP-08 | High | High | ADR-0014 |
| Emergency credentials independent storage | T-EVP-08 | Critical | High | ADR-0014 |
| Backup authenticity verification | T-IDI-07 | High | High | ADR-0013 |

---

## Verification Requirements

| Threat | Verification Method | Frequency | ADR Reference |
|--------|--------------------|-----------|---------------|
| T-SPA-01-03 | Token validation tests | Continuous | ADR-0012 |
| T-PDB-01-03 | Audit table append-only check | Hourly | ADR-0012 |
| T-PA-01-02 | Response tampering tests | Continuous | ADR-0012 |
| T-IDS-01-04 | Service availability tests | Continuous | ADR-0012 |
| T-REP-01-03 | Audit log completeness check | Hourly | ADR-0012 |
| T-IDI-01-08 | Security audit review | Weekly | ADR-0012 |
| T-EVP-01-07 | Privilege escalation tests | Monthly | ADR-0012 |
| T-PM-01-06 | Credential operation tests | Continuous | ADR-0012 |
| T-PM-07 | Recovery token tests | Continuous | ADR-0012 |
| T-EVP-08 | Emergency mode tests | Continuous | ADR-0014 |

---

## Related Documentation

- `docs/adr/0001-project-identity-and-compatibility-contract.md`
- `docs/adr/0003-identity-authentication-mfa-and-cryptographic-unlocking.md`
- `docs/adr/0004-identity-provider-binding-administrator-provisioning-and-break-glass-access.md`
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`
- `docs/adr/0006-account-ownership-credential-sharing-and-group-based-access.md`
- `docs/adr/0007-effective-permissions-acl-precedence-and-conflict-resolution.md`
- `docs/adr/0008-encryption-architecture-master-password-and-cryptographic-key-lifecycle.md`
- `docs/adr/0009-session-architecture-api-token-lifecycle-and-server-side-vault-context.md`
- `docs/adr/0010-service-accounts-workload-identity-and-automated-credential-retrieval.md`
- `docs/adr/0011-audit-logging-and-accountability.md`
- `docs/adr/0012-threat-model-and-trust-boundaries.md`
- `docs/adr/0013-backup-disaster-recovery-and-cryptographic-recoverability.md`
- `docs/adr/0014-emergency-authentication-mode.md`
- `docs/GLOSSARY.md`
- `docs/audit/audit-schema.md`