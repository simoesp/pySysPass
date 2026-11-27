# ADR-0012 — Threat Model and Trust Boundaries

## Status

**Status:** **Proposed** (Initial threat model; requires implementation verification)

---

## Context

This threat model documents the security threats, trust boundaries, and control requirements for pySysPass. It uses STRIDE methodology as a structured starting point, supplemented with password-manager-specific abuse cases. The model is based on approved architectural decisions from ADR-0001 through ADR-0011.

---

## Decision

### 1. Asset Inventory

**Classified Assets:**

| Asset Class | Examples | Sensitivity | Location |
|-------------|----------|-------------|----------|
| **Stored Credentials** | Account passwords, keys | Critical | Database |
| **Global Master Password** | Master password (encrypted) | Critical | Database |
| **User Auth Passwords** | User login passwords (bcrypt) | High | Database |
| **User Master Password** | User vault master password (encrypted) | Critical | Database |
| **Account Encryption Keys** | Account pass/key (encrypted) | Critical | Database |
| **Application Root Secrets** | JWT secret, encryption key | Critical | Config/Env |
| **Service Vault Contexts** | Service cryptographic material | High | Database |
| **JWTs** | User access/refresh tokens | High | Client/Session |
| **API Tokens** | Legacy API tokens | Medium | Database |
| **Service Tokens** | Service authentication tokens | Medium | Database |
| **TOTP Secrets** | 2FA secrets | High | Database |
| **RSA Private Keys** | RSA keys for encryption/signing | Critical | Config/Env |
| **Database Backups** | MySQL dumps | Critical | Backup Storage |
| **Audit Records** | Security audit logs | Medium | Audit Storage |
| **Configuration Files** | App config, secrets | High | Config |
| **Integration Credentials** | External service credentials | High | Config/Env |

**Asset Sensitivity:**

| Level | Assets | Compromise Impact |
|-------|--------|-------------------|
| **Critical** | Master passwords, encryption keys, backups | Full system compromise |
| **High** | User credentials, TOTP secrets, audit logs | Account takeover, data exposure |
| **Medium** | Tokens, service contexts | Limited access, potential escalation |
| **Low** | Config files, operational logs | Information disclosure |

### 2. Actor Model

**Threat Actors:**

| Actor | Capability | Motivation | Trust Level |
|-------|------------|------------|-------------|
| **Unauthenticated External** | Network access, public API | Reconnaissance, exploitation | Untrusted |
| **Authenticated User** | API access, vault unlock | Account management, data access | Trusted (limited) |
| **Malicious User** | Same as above | Data theft, account takeover | Untrusted |
| **Malicious Account Owner** | Own account access | Data theft, privilege escalation | Untrusted |
| **Malicious System Admin** | Full system access | Data theft, system compromise | Untrusted |
| **Malicious Account Admin** | Admin permissions | Data theft, privilege escalation | Untrusted |
| **Compromised Service Account** | Service token access | Data theft, automation abuse | Untrusted |
| **Database Admin** | DB read/write access | Data theft, audit tampering | Semi-trusted |
| **Infrastructure Admin** | Full host access | System compromise | Semi-trusted |
| **Backup Operator** | Backup access | Backup theft | Semi-trusted |
| **Security Auditor** | Audit read access | Compliance verification | Trusted |
| **Compromised Identity Provider** | SSO access | Mass account takeover | Untrusted |
| **Compromised CI/CD Pipeline** | Deployment access | Supply chain compromise | Untrusted |
| **Compromised Dependency** | Code execution | System compromise | Untrusted |
| **Attacker with Stolen JWT** | Valid JWT presentation | Session hijacking | Untrusted |
| **Attacker with Stolen Token** | Valid token presentation | Account access | Untrusted |
| **Attacker with DB Dump** | Full DB read | Data theft, offline attacks | Untrusted |
| **Attacker with Config Access** | Secret retrieval | Credential theft | Untrusted |

### 3. Trust Boundaries

**Boundary Diagram:**

```
┌─────────────────────────────────────────────────────────────────┐
│ TRUST ZONE: Untrusted (External)                                 │
│  └─ Internet                                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TRUST ZONE: Client (Browser/Client App)                          │
│  ├─ User credentials (in transit)                                │
│  ├─ JWTs (in transit)                                            │
│  ├─ Decrypted credentials (in memory)                            │
│  └─ XSS, CSRF, MITM risks                                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TRUST ZONE: Application Server (pySysPass)                       │
│  ├─ Authentication layer                                         │
│  ├─ Authorization layer                                           │
│  ├─ Cryptographic operations                                     │
│  ├─ Service vault context management                             │
│  └─ Session management                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TRUST ZONE: Database (MySQL)                                     │
│  ├─ User credentials (bcrypt)                                    │
│  ├─ Master passwords (encrypted)                                 │
│  ├─ Account credentials (encrypted)                              │
│  ├─ Audit logs                                                   │
│  ├─ Service vault contexts                                       │
│  └─ Python-exclusive data (JSON blobs)                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TRUST ZONE: External Systems                                     │
│  ├─ LDAP/AD (identity provider)                                  │
│  ├─ Backup storage                                               │
│  ├─ External logging (SIEM, syslog)                              │
│  └─ PHP interoperability layer                                   │
└─────────────────────────────────────────────────────────────────┘
```

**Boundary Properties:**

| Boundary | Protection Mechanism |
|----------|---------------------|
| Client → Server | TLS 1.2+, mutual TLS (future) |
| Server → Database | Encrypted connection, access control |
| Server → LDAP | LDAP over TLS, bind authentication |
| Server → Backup | Encrypted transfer, access control |
| Server → SIEM | Encrypted transport, API auth |
| Server → PHP | Shared schema, isolation |

### 4. STRIDE Threat Analysis

#### STRIDE: S - Spoofing

| Threat | Asset | Actor | Boundary | Prerequisites | Impact | Existing Controls | Effectiveness | Residual Risk | Mitigation |
|--------|-------|-------|----------|---------------|--------|-------------------|---------------|---------------|------------|
| T-SPA-01 | User account | External attacker | Client→Server | Valid credentials | Impersonate user | MFA, session management | High | Low | None required |
| T-SPA-02 | Service account | Compromised service | Server→DB | Stolen service token | Impersonate service | Token hash verification | High | None | None required |
| T-SPA-03 | Admin identity | Attacker with admin token | Server→DB | Stolen admin token | Impersonate admin | Token validation | High | None | None required |

#### STRIDE: P - Tampering

| Threat | Asset | Actor | Boundary | Prerequisites | Impact | Existing Controls | Effectiveness | Residual Risk | Mitigation |
|--------|-------|-------|----------|---------------|--------|-------------------|---------------|---------------|------------|
| T-PDB-01 | Database credentials | DB admin | Database→Storage | DB access | Credential theft | Encryption at rest | Medium | Low | Encrypt at rest |
| T-PDB-02 | Audit logs | DB admin | Database→Storage | DB access | Audit tampering | Append-only semantics | Medium | Medium | WORM storage (optional) |
| T-PDB-03 | Service vault context | DB admin | Database→Storage | DB access | Context tampering | Encrypted storage | Medium | Low | Key rotation |
| T-PA-01 | API responses | External attacker | Server→Client | Valid session | Response tampering | HTTPS, origin validation | High | None | CORS, CSRF protection |
| T-PA-02 | Client-side code | External attacker | Client→Server | Browser access | Code injection | CSP, SRI | Medium | Low | Content Security Policy |

#### STRIDE: I - Denial of Service

| Threat | Asset | Actor | Boundary | Prerequisites | Impact | Existing Controls | Effectiveness | Residual Risk | Mitigation |
|--------|-------|-------|----------|---------------|--------|-------------------|---------------|---------------|------------|
| T-IDS-01 | Application server | External attacker | Client→Server | Network access | Service unavailable | Rate limiting, WAF | Medium | Medium | DDoS mitigation |
| T-IDS-02 | Database | DB admin | Server→DB | DB access | Data unavailability | Replication, backup | High | Low | Failover, backup restore |
| T-IDS-03 | Session storage | External attacker | Server→Session | Network access | Mass session invalidation | Session limits | Medium | Medium | Rate limiting |
| T-IDS-04 | Audit storage | External attacker | Server→Audit | Network access | Audit availability | Log rotation | High | Low | Log aggregation |

#### STRIDE: R - Repudiation

| Threat | Asset | Actor | Boundary | Prerequisites | Impact | Existing Controls | Effectiveness | Residual Risk | Mitigation |
|--------|-------|-------|----------|---------------|--------|-------------------|---------------|---------------|------------|
| T-REP-01 | User actions | Malicious user | Client→Server | User session | Deny action | Audit logging | High | None | None required |
| T-REP-02 | Admin actions | Malicious admin | Server→DB | Admin session | Deny action | Admin audit log | High | None | None required |
| T-REP-03 | Service actions | Compromised service | Server→DB | Service token | Deny action | Service audit log | High | None | None required |

#### STRIDE: D - Information Disclosure

| Threat | Asset | Actor | Boundary | Prerequisites | Impact | Existing Controls | Effectiveness | Residual Risk | Mitigation |
|--------|-------|-------|----------|---------------|--------|-------------------|---------------|---------------|------------|
| T-IDI-01 | Stored credentials | External attacker | Database | DB access | Credential theft | Encryption at rest | Medium | Low | Key management |
| T-IDI-02 | Master password | Malicious admin | Database | DB access | System compromise | Encrypted storage | Medium | Low | Key rotation, access control |
| T-IDI-03 | User credentials | Malicious user | Server→User | User session | Credential theft | Session management | High | Low | Session timeout |
| T-IDI-04 | Decrypted credentials | Malicious user | Server→DB | User session | Credential theft | Vault context lifetime | Medium | Medium | Short vault lifetime |
| T-IDI-05 | Audit logs | Unauthorized user | Audit | Audit access | Sensitive info disclosure | Access control | High | None | Role-based access |
| T-IDI-06 | JWT secrets | External attacker | Config | Config access | JWT forgery | Secret protection | High | Low | Secure config storage |
| T-IDI-07 | Backup data | Backup operator | Backup Storage | Backup access | Data theft | Backup encryption | Medium | Low | Backup key management |
| T-CFG-01 | Application secrets | External attacker | Process memory / `/proc` | `ps aux` or `docker inspect` | Secret exposure via env vars | Mounted secret files (`/run/secrets/`) | High | Medium | Not implemented (V-02) |
| T-CFG-02 | JWT signing key | Malicious operator | Client token | `SECRET_KEY` rotation without overlap | All sessions invalidated on rotation | Overlapping validity window (`SECRET_KEY_PREVIOUS`) | High | Medium | Not implemented (V-05) |
| T-CFG-03 | PHP password salt | Misconfigured deployment | `User.mPass` decryption | Empty `SYSPASS_PASSWORD_SALT` | All PHP-created credentials unreadable | Startup validation + runtime config fallback | **Critical** | Low | Partially mitigated (V-07) |
| T-CFG-04 | Audit HMAC key | Internal attacker | Audit log integrity | Raw `AUDIT_HMAC_KEY` env var (no rotation) | Unsigned/forged audit entries | Add to Settings + rotation policy | Medium | Low | Gap (V-03) |
| T-CFG-05 | Service vault key | Misconfigured deployment | Service API tokens | `SERVICE_VAULT_KEY` unset (no startup check) | Service vault operations fail at runtime, not startup | Add to `validate_production_settings` | Medium | Low | Gap (V-08) |
| T-API-01 | PHP AuthToken | External attacker | API | Token guessing (64-hex = 2^256 space) | Unauthorized account access | Action scope enforcement + rate limiting at nginx | Low | Low | Action scoping implemented; rate limiting deployment-level only |
| T-API-02 | Service account tokens | External attacker | API | Token replay / no overlap window | Credential vault exposure | Token rotation with grace period (ADR-0010) | Medium | Medium | No HTTP surface (V-02) |
| T-API-03 | Extension table absence | Misconfigured deployment | `POST /api/v1/auth/emergency` | Alembic not run; `emergency_credentials` absent | 500 instead of 401 on emergency auth | Readiness check validates extension tables (IMPL-016) | Medium | Low | Gap (V-03) |
| T-API-04 | API version confusion | Integration consumer | Clients | Inconsistent version metadata (2.2.2 vs 1.0.0) | Incorrect client version checks / migration timing | Single `__version__` source of truth (IMPL-026) | Low | Medium | Gap (V-01) |
| T-TEST-01 | Feature branch regressions | Developer workflow | CI pipeline | CI runs only on `main`; feature branches untested | Regressions reach main undetected | Enable feature branch CI triggers (IMPL-028) | **High** | Medium | Gap (V-01) |
| T-TEST-02 | Migration path untested | Operator | Alembic upgrade path | Alembic never exercised on populated PHP database in CI | Incompatible migration discovers at deploy time, not CI | Alembic-on-populated-DB integration test (IMPL-028) | Medium | Low | Gap (V-02) |
| T-IDI-08 | Service vault context | Compromised service | Server→DB | Service access | Context theft | Encrypted storage | Medium | Low | Key management |

#### STRIDE: E - Elevation of Privilege

|| Threat | Asset | Actor | Boundary | Prerequisites | Impact | Existing Controls | Effectiveness | Residual Risk | Mitigation |
|--------|-------|-------|----------|---------------|--------|-------------------|----------------|---------------|------------|------------|
| T-EVP-01 | User → Admin | Malicious user | Server→DB | Vulnerability | Admin access | Admin separation | High | Medium | Secure coding, input validation |
| T-EVP-02 | User → Service | Malicious user | Server→DB | Vulnerability | Service impersonation | Service token validation | High | Low | Token verification |
| T-EVP-03 | Service → Admin | Compromised service | Server→DB | Privilege escalation | Admin access | Admin separation | High | Medium | Least privilege, monitoring |
| T-EVP-04 | Account Owner → Other Accounts | Malicious owner | Server→DB | ACL vulnerability | Cross-account access | ACL enforcement | High | Low | Strict ACL checks |
| T-EVP-05 | LDAP → Local | External attacker | LDAP→Local | LDAP failure | Local account access | LDAP fail-safe | Medium | None | Secure LDAP config, monitoring |
| T-EVP-06 | MFA bypass | Malicious user | Client→Server | MFA vulnerability | Session access | MFA enforcement | High | Low | MFA implementation |
| T-EVP-07 | Private account bypass | Malicious user | Server→DB | Authorization bypass | Private data access | Private account check | High | Low | Strict private check |
| T-EVP-08 | Emergency mode abuse | Attacker | Server→DB | Server access | Emergency access | Time-limited, MFA, audit | High | Low | MFA enforcement, automatic deactivation |

---

### 5. Password Manager Specific Threats

|| Threat | Asset | Actor | Boundary | Prerequisites | Impact | Existing Controls | Effectiveness | Residual Risk | Mitigation |
|--------|-------|-------|----------|---------------|--------|-------------------|----------------|---------------|------------|------------|
| T-PM-01 | Credential export | Malicious user | Server→DB | Export permission | Mass credential theft | Export authorization | High | Low | Export limits, approval |
| T-PM-02 | Credential modification | Malicious user | Server→DB | Write permission | Credential tampering | Write authorization | High | Low | Write authorization |
| T-PM-03 | Vault unlock | Malicious user | Client→Server | Vault unlock access | Credential access | Vault context lifetime | Medium | Medium | Short vault lifetime |
| T-PM-04 | Offline password guessing | External attacker | Database | DB access | Offline brute force | Rate limiting | High | Medium | Rate limiting, account lockout |
| T-PM-05 | Credential rotation | Malicious user | Server→DB | Write permission | Credential tampering | Rotation authorization | High | Low | Rotation authorization |
| T-PM-06 | Credential deletion | Malicious user | Server→DB | Delete permission | Permanent loss | Delete authorization | High | Low | Delete authorization |
| T-PM-07 | Recovery token abuse | Attacker | Server→DB | Server access | Recovery login | Token expiry, MFA | High | Low | Token expiry, MFA enforcement |

---

### 6. Threat Classification Summary

**Threat Count by Category:**

| Category | Count | Most Critical |
|----------|-------|---------------|
| Spoofing | 3 | None (well controlled) |
| Tampering | 6 | T-PDB-02 (audit logs) |
| DoS | 4 | T-IDS-01 (service availability) |
| Repudiation | 3 | None (well controlled) |
| Information Disclosure | 8 | T-IDI-02 (master password) |
| Elevation of Privilege | 9 | T-EVP-05 (LDAP fallback), T-EVP-08 (emergency abuse) |
| Password Manager Specific | 7 | T-PM-01 (credential export) |

**Total: 40 threats identified**

**Top 5 Risks by Impact:**

1. **T-IDI-02**: Master password compromise → Full system compromise
2. **T-EVP-05**: LDAP-to-local fallback bypass → Admin access bypass
3. **T-EVP-08**: Emergency mode abuse → Unauthorized emergency access
4. **T-PM-01**: Unrestricted credential export → Mass credential theft
5. **T-PM-04**: Offline password guessing → Account takeover

---

### 7. Control Matrix

| Control | Threats Mitigated | Implementation Status | Effectiveness |
|---------|-------------------|----------------------|---------------|
| **TLS 1.2+ everywhere** | T-PA-01, T-PA-02, T-IDI-01 | Implemented | High |
| **MFA for all users** | T-EVP-06 | Implemented | High |
| **Token hash verification** | T-SPA-02, T-SPA-03 | Implemented | High |
| **Service vault contexts** | T-IDI-04 | Proposed | Medium |
| **Audit logging** | T-REP-01-03, T-PDB-02 | Proposed | High |
| **Access control roles** | T-IDI-05 | Proposed | High |
| **Rate limiting** | T-PM-04, T-IDS-03 | Implemented | Medium |
| **Account lockout** | T-PM-04 | Implemented | Medium |
| **Encryption at rest** | T-IDI-01, T-IDI-02 | Implemented | High |
| **Backup encryption** | T-IDI-07 | Implemented | High |
| **Private account protection** | T-EVP-07 | Implemented | High |
| **ACL enforcement** | T-EVP-04 | Implemented | High |
| **Session management** | T-IDI-03 | Implemented | High |
| **Service token validation** | T-SPA-02, T-EVP-02 | Implemented | High |
| **Emergency authentication controls** | T-EVP-08 | Proposed | High |

---

### 8. Security Control Gaps

**Identified Gaps:**

| Gap | Affected Threats | Severity | Priority |
|-----|------------------|----------|----------|
| **LDAP-to-local fallback** | T-EVP-05 | Critical | High |
| **Credential export limits** | T-PM-01 | High | High |
| **Audit log immutability** | T-PDB-02 | Medium | Medium |
| **Service context rotation** | T-IDI-08 | Medium | Medium |
| **WAF/DDoS protection** | T-IDS-01 | Medium | Medium |
| **Backup key management** | T-IDI-07 | High | High |
| **Backup encryption mandatory** | T-IDI-07 | High | High |
| **Emergency authentication implementation** | T-EVP-08 | High | High |
| **Emergency credentials independent storage** | T-EVP-08 | Critical | High |

---

### 9. Remediation Tasks

**Priority 1 (Immediate):**

| Task | Threat | Effort | Implementation |
|------|--------|--------|----------------|
| Implement LDAP fail-safe | T-EVP-05 | Medium | Fix LDAP service |
| Add export limits | T-PM-01 | Low | API rate limiting |
| Protect config files | T-IDI-06 | Low | File permissions |
| Implement emergency authentication | T-EVP-08 | High | ADR-0014 |
| Store emergency credentials independently | T-EVP-08 | High | Separate storage |

**Priority 2 (Short-term):**

| Task | Threat | Effort | Implementation |
|------|--------|--------|----------------|
| Implement service vault contexts | T-IDI-04, T-IDI-08 | High | ADR-0010 |
| Add audit log immutability | T-PDB-02 | Medium | WORM storage |
| Implement backup key rotation | T-IDI-07 | Medium | Key management |
| Make backup encryption mandatory | T-IDI-07 | Low | Policy enforcement |

**Priority 3 (Long-term):**

| Task | Threat | Effort | Implementation |
|------|--------|--------|----------------|
| Implement WAF | T-IDS-01 | High | External service |
| Implement SIEM integration | T-PDB-02 | Medium | External service |
| Implement OIDC workload identity | T-SPA-02 | High | External service |

---

### 10. Verification Requirements

| Threat | Verification Method | Frequency |
|--------|--------------------|-----------|
| T-SPA-01-03 | Token validation tests | Continuous |
| T-PDB-01-03 | Audit table append-only check | Hourly |
| T-PA-01-02 | Response tampering tests | Continuous |
| T-IDS-01-04 | Service availability tests | Continuous |
| T-REP-01-03 | Audit log completeness check | Hourly |
| T-IDI-01-08 | Security audit review | Weekly |
| T-EVP-01-07 | Privilege escalation tests | Monthly |
| T-PM-01-06 | Credential operation tests | Continuous |

---

### 11. Related Documentation

- `docs/security/policy.md`: Security requirements
- `docs/audit/audit-schema.md`: Audit log schema
- `docs/backup-recovery.md`: Backup procedures
- `docs/installation.md`: Environment setup
- `docs/adr/0014-emergency-authentication-mode.md`: Emergency authentication controls

---

### 12. Consequences

### Security

- Comprehensive threat identification
- Prioritized remediation roadmap
- Clear control effectiveness assessment
- Ongoing verification requirements
- Emergency authentication controls documented

### Development

- Threat-informed security coding
- Security testing requirements
- Continuous security monitoring
- Emergency authentication implementation

### Operations

- Security incident response procedures
- Regular security audits
- Threat monitoring and alerting
- Emergency authentication procedures

---

## References

- `docs/adr/0001-project-identity-and-compatibility-contract.md`
- `docs/adr/0003-identity-authentication-mfa-and-cryptographic-unlocking.md`
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`
- `docs/adr/0006-account-ownership-credential-sharing-and-group-based-access.md`
- `docs/adr/0007-effective-permissions-acl-precedence-and-conflict-resolution.md`
- `docs/adr/0008-encryption-architecture-master-password-and-cryptographic-key-lifecycle.md`
- `docs/adr/0009-session-architecture-api-token-lifecycle-and-server-side-vault-context.md`
- `docs/adr/0010-revised.md`
- `docs/adr/0011-revised.md`
- `docs/adr/0013-backup-disaster-recovery-and-cryptographic-recoverability.md`
- `docs/adr/0014-emergency-authentication-mode.md`
