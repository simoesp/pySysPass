# GLOSSARY — pySysPass Domain Dictionary

This glossary defines all approved domain concepts from ADR-0001 through ADR-0014. Each term has a single canonical definition.

## Service Accounts and Workload Identities

| Term | Definition | Source |
|------|------------|--------|
| **Service Account** | A dedicated machine identity for non-interactive integrations. Has unique identity, descriptive name, documented purpose, responsible owner, explicit permissions, enabled/disabled state, creation/modification timestamps, credential lifecycle policies, and audit history. Does NOT automatically inherit administrative privileges from creators. By default, does not support interactive UI authentication. | ADR-0010 |
| **Service Identity** | The machine identity of a service account. Distinct domain concept from authentication tokens and cryptographic contexts. | ADR-0010 |
| **Workload Identity** | Synonym for service identity in Kubernetes/OpenShift contexts. Refers to non-interactive machine identity. | ADR-0010 |
| **Service Token** | An authentication credential belonging to a service identity. Cryptographically random secret, hashed for storage, one-time secret disclosure during creation, configurable expiration, explicit operation scopes, optional account/group/resource restrictions, independent revocation, last-used timestamps, and credential rotation support. Multiple tokens may exist per service identity. | ADR-0010 |
| **Service Vault Context** | Cryptographic authorization associated with an approved service authentication context. Bound to a service identity and authorized token, has explicit cryptographic authorization, bounded lifetime, independently revocable, respects account-level authorization, invalidated after master password rotation, never exposes global master password to integration. | ADR-0010 |
| **Credential Retrieval** | The process of obtaining credentials from a vault context. Requires valid service token and authorized vault context. | ADR-0010 |
| **Token Scope** | The explicit operation permissions granted to a service token (e.g., read, write, delete, export). | ADR-0010 |
| **Token Rotation** | The process of issuing a new service token and invalidating the old one. Preserves service identity and associated permissions. | ADR-0010 |
| **Cryptographic Bootstrap** | The process of provisioning initial cryptographic material (keys, nonces, AAD binding) for a service vault context. Includes authorization verification and secure material transfer. | ADR-0010 |
| **Secret Zero** | The initial cryptographic material required before any service can operate. Provisioned by operator during initial setup. | ADR-0010 |
| **Non-Interactive Authentication** | Authentication mechanism that does not require human interaction (e.g., service accounts). Has its own security policy rather than being treated as an exception to human authentication requirements. | ADR-0010 |

## Cryptographic Provisioning

| Term | Definition | Source |
|------|------------|--------|
| **Cryptographic Bootstrap** | The process of provisioning initial cryptographic material (keys, nonces, AAD binding) for a service vault context. Includes authorization verification and secure material transfer. | ADR-0010 |
| **Service Vault Key** | The root encryption key for service vault contexts: `SERVICE_VAULT_KEY` from environment/settings when no keyring is explicitly configured, otherwise the keyring's current master key (keyring additive and opt-in per ADR-0010 §17). Never stored in the database. | ADR-0010 §§3, 5, 17 |
| **Wrapped Key** | A data encryption key encrypted with a recipient's public key. Stored in backup manifest for restoration. | ADR-0013 |
| **Data Encryption Key (DEK)** | A randomly generated key used to encrypt backup contents. Wrapped with the backup encryption key for storage. | ADR-0013 |
| **Key Wrapping** | The process of encrypting a DEK with a master key for secure storage. Uses authenticated encryption. | ADR-0013 |
| **Key Versioning** | The practice of assigning unique identifiers to cryptographic keys and maintaining historical keys for old backup recovery. | ADR-0013 |
| **Key Retirement** | The documented procedure for deprecating a cryptographic key while preserving recovery capability for old backups. | ADR-0013 |
| **Master Password** | The user-provided secret that decrypts the vault key (User.mPass/User.mKey). Used for cryptographic vault unlocking, not identity authentication. | ADR-0003 |
| **Vault Key** | The cryptographic key that encrypts account credentials. Stored encrypted as User.mPass with User.mKey. | ADR-0008 |
| **Data Encryption Key (DEK)** | A randomly generated key used to encrypt data at rest. Wrapped with the master key for storage. | ADR-0008 |
| **Key Encryption Key (KEK)** | A key used to encrypt other keys. In pySysPass, the master password acts as a KEK for the vault key. | ADR-0008 |
| **Key Derivation** | The process of deriving cryptographic keys from passwords using PBKDF2/Argon2. | ADR-0008 |
| **Key Rotation** | The process of replacing cryptographic keys while preserving access to historical data. | ADR-0008 |
| **Authenticated Encryption** | Encryption that provides both confidentiality and integrity (e.g., AES-256-GCM). | ADR-0008 |

## Service Vault Contexts

| Term | Definition | Source |
|------|------------|--------|
| **Service Vault Context** | Cryptographic authorization associated with an approved service authentication context. Bound to a service identity and authorized token, has explicit cryptographic authorization, bounded lifetime, independently revocable, respects account-level authorization, invalidated after master password rotation, never exposes global master password to integration. | ADR-0010 |
| **Service Vault Key** | The root encryption key for service vault contexts: `SERVICE_VAULT_KEY` from environment/settings when no keyring is explicitly configured, otherwise the keyring's current master key (keyring additive and opt-in per ADR-0010 §17). Never stored in the database. | ADR-0010 §§3, 5, 17 |
| **Service Vault Context Lifetime** | The bounded authorization lifetime of a service vault context. Includes absolute expiration and inactivity timeout. | ADR-0010 |
| **Service Vault Context Renewal** | Automatic creation of new vault context on valid request within lifetime bounds. Does not extend absolute lifetime. | ADR-0010 |

## Service Vault Key Hierarchy
|
| Term | Definition | Source |
|------|------------|--------|
| **Service Vault Keyring (keyring)** | Versioned JSON keyring holding the master `SERVICE_VAULT_KEY` root key and per-service DEKs wrapped by the master key. Located via `SERVICE_VAULT_KEYRING_PATH` or the default paths (`/etc/syspass/service-vault-keyring.json`, `<BASE_DIR>/config/service-vault-keyring.json`); protected with 0400 permissions. Additive and opt-in: authoritative only when explicitly configured. | ADR-0010 §17 |
| **Service-Specific Key Hierarchy** | Versioned master keyring plus per-service Data Encryption Keys (DEKs): each DEK randomly generated, wrapped with AES-256-GCM under a master key version, HKDF domain separation salted by the service ID, and AAD bound to the service id. DEKs are independently rotatable; historical master key versions are retained for decrypting old contexts. | ADR-0010 §17 |
| **DEK Wrapping** | Encrypting a per-service DEK with a master key version using AES-256-GCM; the wrapped DEK is stored next to the `wrapped_with_key_id` of the master key version that wrapped it. | ADR-0010 §17 |
|
## Security Auditing

| Term | Definition | Source |
|------|------------|--------|
| **Audit Logging** | The systematic recording of security-relevant events for accountability and incident response. Mandatory coverage for security events, with redaction rules, append-only integrity, configurable retention, and explicit Security Auditor role. | ADR-0011 |
| **Security Event** | An event that has security implications (auth failures, privilege changes, data access, etc.). Requires mandatory audit logging. | ADR-0011 |
| **Security Auditor** | A role with read-only access to audit logs for compliance verification. Does not have write access. | ADR-0011 |
| **Audit Integrity** | The property that audit logs cannot be modified after creation. Achieved through append-only storage, WORM storage, or cryptographic signing. | ADR-0011 |
| **Audit Retention** | The configurable duration for which audit logs are retained. | ADR-0011 |
| **Audit Redaction** | The removal of sensitive information from audit log entries. Mandatory for security events. | ADR-0011 |
| **Fail-Open** | The behavior of allowing access when audit logging cannot be verified. Only for non-security events. | ADR-0011 |
| **Audit Event** | A structured record of a security-relevant operation with actor, resource, operation, result, and metadata. | ADR-0011 |
| **Audit Category** | Classification of audit events: Security, Admin, Credential Access, Operational, Infrastructure. | ADR-0011 |

## Threat Modeling and Residual Risk

| Term | Definition | Source |
|------|------------|--------|
| **Threat Modeling** | The structured process of identifying, analyzing, and mitigating security threats. Uses STRIDE methodology supplemented with password-manager-specific abuse cases. | ADR-0012 |
| **Threat** | A potential security incident identified through threat modeling. Each threat has an identifier (e.g., T-IDI-01), affected assets, actor model, boundary, prerequisites, impact, existing controls, effectiveness, residual risk, and mitigation. | ADR-0012 |
| **Residual Risk** | The risk that remains after existing controls are applied. Assessed as None, Low, Medium, or High. | ADR-0012 |
| **Trust Boundary** | A boundary between zones of different trust levels. Each boundary has protection mechanisms and properties. | ADR-0012 |
| **Trust Zone** | A region with consistent trust assumptions. Examples: Untrusted (External), Client, Application Server, Database, External Systems. | ADR-0012 |
| **Threat Actor** | A modeled entity that may attempt security attacks. Examples: Unauthenticated External, Authenticated User, Malicious User, Database Admin, Infrastructure Admin, etc. | ADR-0012 |
| **Control Effectiveness** | The assessed effectiveness of a security control. High, Medium, or Low. | ADR-0012 |
| **STRIDE** | Threat classification methodology: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. | ADR-0012 |
| **Attack Surface** | The set of all possible points where an unauthorized user can try to enter or extract data from the system. | ADR-0012 |

## Backup Encryption

| Term | Definition | Source |
|------|------------|--------|
| **Backup Encryption** | The mandatory encryption of backup files using established cryptographic algorithms (AES-256-GCM). Mandatory by default; unencrypted backups require explicit administrative exception with security warning and audit event. | ADR-0013 |
| **Backup Encryption Key** | An independently generated key for encrypting backups. Stored in separate location (mounted file or secrets manager). Has lifecycle independent of ordinary application secrets. | ADR-0013 |
| **Symmetric Backup Encryption** | Backup encryption using a single key (symmetric algorithm). Suitable for straightforward self-hosted deployments. | ADR-0013 |
| **Asymmetric Backup Encryption** | Backup encryption using hybrid encryption: DEK per backup, wrapped with public key. Preferred for security-sensitive deployments. | ADR-0013 |
| **Backup Key Rotation** | The process of rotating backup encryption keys while preserving recovery capability for old backups. | ADR-0013 |
| **Backup Minimization** | The practice of excluding disposable runtime files (sessions, caches, temporary vault contexts) from backups. | ADR-0013 |
| **Backup Manifest** | Metadata describing backup contents, including version, application version, schema version, encryption key ID, integrity verification information, and sensitivity classification. | ADR-0013 |
| **Backup Integrity Verification** | Cryptographic verification of backup integrity using HMAC-SHA256. | ADR-0013 |
| **Backup Authenticity Verification** | Verification that a backup originated from an authorized production instance. Achieved through digital signatures. | ADR-0013 |
| **Backup Compliance** | Verification that backup procedures meet organizational and regulatory requirements. | ADR-0013 |

## Recovery Material

| Term | Definition | Source |
|------|------------|--------|
| **Recovery Material** | All material required to restore pySysPass: database backups, backup encryption keys, master password recovery material, emergency administrator credentials, recovery instructions, persistent cryptographic keys. Must NOT exist exclusively inside pySysPass or the production application host. | ADR-0013 |
| **Backup Decryption Key** | The key required to decrypt backup files. Must be stored independently of backups. | ADR-0013 |
| **Master Password Recovery Material** | The material required to recover the global master password. Must be stored independently of pySysPass. | ADR-0013 |
| **Emergency Administrator Credentials** | The credentials of break-glass administrators. Must be stored independently of pySysPass. | ADR-0013 |
| **Recovery Instructions** | The documented procedures for restoring pySysPass. Must be stored separately from pySysPass. | ADR-0013 |
| **Persistent Cryptographic Keys** | Keys required for credential restoration. Must be stored independently of pySysPass. | ADR-0013 |
| **Dual-Control Recovery** | A recovery mechanism requiring two independent authorities for authorization. Optional for organizations that require it. | ADR-0013 |

## Disaster Recovery

| Term | Definition | Source |
|------|------------|--------|
| **Disaster Recovery** | The process of restoring pySysPass after catastrophic failure. Includes complete host loss, database loss, master password loss, encryption key loss, backup key loss, and infrastructure loss. | ADR-0013 |
| **Recovery Point** | The point in time represented by a backup. | ADR-0013 |
| **Recovery Time** | The time required to restore pySysPass. Measured in minutes for full restore procedures. | ADR-0013 |
| **Complete Host Loss** | Disaster scenario where the entire application host is unavailable. Requires full restore from backup. | ADR-0013 |
| **Database Loss** | Disaster scenario where only the database is unavailable. Requires database restore. | ADR-0013 |
| **Master Password Loss** | Disaster scenario where the master password is unavailable. Requires password rotation. | ADR-0013 |
| **Encryption Key Loss** | Disaster scenario where the encryption key is unavailable. Requires credential reset. | ADR-0013 |
| **Backup Key Loss** | Disaster scenario where the backup encryption key is unavailable. Requires alternative recovery. | ADR-0013 |
| **Infrastructure Loss** | Disaster scenario where the entire infrastructure is unavailable. Requires full disaster recovery. | ADR-0013 |
| **External Secret Manager Outage** | Disaster scenario where the external secret manager is unavailable. Requires fallback to mounted secrets. | ADR-0013 |

## Break-Glass Identities

| Term | Definition | Source |
|------|------------|--------|
| **Break-Glass Administrator** | A local administrator account that can authenticate without LDAP. Independent of Active Directory, with independent MFA and explicit access to infrastructure recovery credentials. | ADR-0014 |
| **Break-Glass Account** | A local administrator account for emergency access. Stored in separate `emergency_credentials` table (NOT User table). | ADR-0014 |
| **Break-Glass Account Properties** | Username (unique, not in LDAP), password hash (bcrypt), password salt, MFA secret (TOTP, required), MFA enabled (mandatory TRUE), enabled (FALSE until activated), is_recovery_account (for LDAP recovery personnel), created_by (admin who created account). NOT linked to LDAP (independent identity). | ADR-0014 |
| **Emergency Credentials Table** | A separate table for break-glass administrator accounts. Preserves ADR-0002 interoperability requirements. Python-native extension metadata cannot represent emergency identity classification without modifying the original PHP schema. | ADR-0014 |
| **Emergency Credentials** | The credentials stored in the emergency_credentials table. Independent of LDAP, independent of PHP schema. | ADR-0014 |
| **Offline Recovery Credentials** | Credentials for pre-enrolled LDAP recovery personnel. Can authenticate offline only when emergency mode has been explicitly activated. | ADR-0014 |
| **Securely Cached Password Verifiers** | Password verification material that can be used for offline authentication. | ADR-0014 |
| **Separately Provisioned Offline Credentials** | Credentials provisioned separately from the application for offline use. | ADR-0014 |
| **Independent Recovery Credentials** | Credentials that can be used for recovery when normal infrastructure is unavailable. Must be stored independently of pySysPass. | ADR-0014 |
| **Independent Local Break-Glass Administrators** | Local admin accounts that authenticate without LDAP and WITHOUT requiring emergency mode activation. Always available for host-level recovery. | ADR-0014 |
| **Designated LDAP Recovery Personnel** | LDAP users pre-enrolled for offline authentication. Can ONLY authenticate offline when emergency mode has been explicitly activated. | ADR-0014 |
| **Ordinary LDAP Users** | Standard LDAP-bound users who are fail-closed and have NO offline fallback under any circumstances. | ADR-0014 |

## Emergency Authentication Mode

| Term | Definition | Source |
|------|------------|--------|
| **Emergency Authentication Mode** | A time-limited mode that permits offline authentication for pre-enrolled recovery personnel using securely cached password verifiers or separately provisioned offline credentials. Requires explicit authorization, recent MFA, justification, durable audit logging, automatic expiration, and restricted resource access. Does NOT enable local password fallback for every LDAP user. | ADR-0014 |
| **Emergency Mode Activation** | The process of enabling emergency authentication mode. Requires server host access, out-of-band activation script, multi-factor verification, and operator authorization. | ADR-0014 |
| **Emergency Mode Deactivation** | The process of disabling emergency authentication mode. Can occur automatically (timeout) or manually. Emergency sessions are terminated on deactivation. | ADR-0014 |
| **Emergency Mode Activation Window** | The time period during which emergency authentication is enabled. Default: 2 hours (configurable). | ADR-0014 |
| **Emergency Mode Timeout** | The duration of emergency mode before automatic deactivation. Default: 2 hours. | ADR-0014 |
| **Emergency Mode Extension** | An extension of the emergency mode activation window. Requires audit and justification. | ADR-0014 |
| **Emergency Authentication Endpoint** | The API endpoint for emergency authentication: `/api/v1/auth/emergency`. Requires MFA verification. | ADR-0014 |
| **Emergency Session** | A session created during emergency authentication. Terminated on emergency mode deactivation. | ADR-0014 |
| **Emergency Mode Authorization** | The requirement for explicit operator authorization before activating emergency mode. | ADR-0014 |
| **Emergency Mode Revocation** | The automatic termination of all emergency sessions when emergency mode is deactivated. | ADR-0014 |
| **Emergency Mode Resource Restriction** | The limitation of emergency mode access to vault operations only. Cannot modify system configuration. | ADR-0014 |
| **Emergency Mode Audit** | The logging of all emergency mode operations as CRITICAL severity. | ADR-0014 |
| **Emergency Activation Flag** | File-based flag at `/etc/syspass/emergency-auth-enabled` that enables emergency mode. | ADR-0014 |
| **Emergency Activation Script** | The script `activate-emergency-auth.sh` used to enable emergency mode with out-of-band authorization. | ADR-0014 |

## Offline Authentication

| Term | Definition | Source |
|------|------------|--------|
| **Offline Authentication** | Authentication without LDAP connectivity. Permitted only during emergency mode for pre-enrolled recovery personnel. | ADR-0014 |
| **Cached Password Verifier** | Password verification material cached for offline authentication. | ADR-0014 |
| **Offline Recovery Personnel** | Designated LDAP recovery personnel who can authenticate offline only when emergency mode has been explicitly activated. | ADR-0014 |
| **Offline Recovery Credentials** | Credentials for pre-enrolled LDAP recovery personnel. Can authenticate offline only when emergency mode has been explicitly activated. | ADR-0014 |

## Emergency Activation and Revocation

| Term | Definition | Source |
|------|------------|--------|
| **Emergency Activation** | The process of enabling emergency authentication mode. Requires server host access, out-of-band activation script, multi-factor verification, and operator authorization. | ADR-0014 |
| **Emergency Revocation** | The process of disabling emergency authentication mode. Can occur automatically (timeout) or manually. | ADR-0014 |
| **Emergency Mode Termination** | The automatic termination of all emergency sessions when emergency mode is deactivated. | ADR-0014 |
| **Emergency Mode Deactivation** | The process of disabling emergency authentication mode. Emergency sessions are terminated on deactivation. | ADR-0014 |
| **Emergency Mode Automatic Expiration** | The automatic deactivation of emergency mode after the timeout period (default 2 hours). | ADR-0014 |

## Authentication and Authorization

| Term | Definition | Source |
|------|------------|--------|
| **LDAP Fail-Safe** | LDAP authentication failures must never trigger local authentication for LDAP-bound identities. Result in denial of LDAP authentication. | ADR-0004 |
| **Emergency Credentials** | Credentials stored in the emergency_credentials table for break-glass authentication. Independent of LDAP, independent of PHP schema. | ADR-0014 |
| **Break-Glass Authentication** | Authentication using break-glass administrator accounts. Independent of LDAP availability. | ADR-0014 |
| **Emergency Authentication** | Authentication during emergency mode using break-glass accounts or recovery credentials. | ADR-0014 |
| **Service Account Authentication** | Non-interactive authentication using service tokens. Distinct from human authentication. | ADR-0010 |
| **Human Authentication** | Interactive authentication requiring MFA and vault unlock. | ADR-0003 |
| **Layered Authentication** | The layered authentication model: Identity → MFA → Vault unlock as distinct responsibilities. | ADR-0003 |
| **Authentication Hierarchy** | The layered authentication model with backward compatibility. | ADR-0003 |
| **MFA Verification** | Two-factor authentication verification. Required before vault unlock. | ADR-0003 |
| **Cryptographic Unlocking** | The process of decrypting vault contents using the master password. Distinct from authentication. | ADR-0003 |
| **Vault Unlock** | The process of decrypting vault contents using the master password. Requires MFA verification. | ADR-0003 |
| **Identity Provider** | The system responsible for identity verification (local database or LDAP server). | ADR-0004 |
| **Provider Binding** | The explicit assignment of a user to exactly one authentication provider (local or LDAP). | ADR-0004 |
| **Fail-Closed** | Security policy where access is denied when the primary authentication mechanism is unavailable. | ADR-0004 |
| **Authorization** | The process of determining what an authenticated identity is permitted to do. | ADR-0005 |
| **ACL (Access Control List)** | The list of permissions attached to a resource specifying which identities can perform which operations. | ADR-0007 |
| **Effective Permissions** | The computed permissions after applying ACL precedence and conflict resolution rules. | ADR-0007 |
| **Private Account** | An account restricted to its owner only, with no sharing or group access permitted. | ADR-0006 |
| **Credential Sharing** | The mechanism for granting access to account credentials to other users or groups. | ADR-0006 |

## Backup and Recovery Operations

| Term | Definition | Source |
|------|------------|--------|
| **Backup Encryption Mandatory** | The policy that backup encryption is required by default. Unencrypted backups require explicit administrative exception with security warning and audit event. | ADR-0013 |
| **Backup Integrity Verification** | Cryptographic verification of backup integrity using HMAC-SHA256. | ADR-0013 |
| **Backup Authenticity Verification** | Verification that a backup originated from an authorized production instance. Achieved through digital signatures. | ADR-0013 |
| **Historical Backup Recovery** | Recovery using old backups encrypted with previous backup encryption keys. | ADR-0013 |
| **Security State Reconciliation** | The process of validating security state after restoration (sessions invalidated, tokens revoked, emergency mode reset, vault contexts re-provisioned). | ADR-0013 |
| **Controlled Recovery Mode** | A recovery mode that prevents ordinary production access until security state reconciliation is complete. | ADR-0013 |
| **Recovery Checklist** | The validation steps required after database restore. | ADR-0013 |
| **Backup Verification** | The process of verifying backup integrity and authenticity before restoration. | ADR-0013 |
| **Test Restore** | Periodic test restoration of backups to verify recoverability. | ADR-0013 |

## Threat Identifiers

| Term | Definition | Source |
|------|------------|--------|
| **T-EVP-01** | User → Admin privilege escalation threat. | ADR-0012 |
| **T-EVP-02** | User → Service impersonation threat. | ADR-0012 |
| **T-EVP-03** | Service → Admin privilege escalation threat. | ADR-0012 |
| **T-EVP-04** | Account owner → other accounts cross-access threat. | ADR-0012 |
| **T-EVP-05** | LDAP → Local fallback bypass threat. | ADR-0012 |
| **T-EVP-06** | MFA bypass threat. | ADR-0012 |
| **T-EVP-07** | Private account bypass threat. | ADR-0012 |
| **T-EVP-08** | Emergency mode abuse threat. | ADR-0012 |
| **T-EVP-09** | Audit log tampering threat. | ADR-0012 |
| **T-EVP-10** | Secret rotation failure threat. | ADR-0012 |
| **T-EVP-11** | Brute-force attack threat. | ADR-0012 |
| **T-EVP-12** | Session hijacking threat. | ADR-0012 |
| **T-EVP-13** | Algorithm agility failure threat. | ADR-0012 |
| **T-EVP-14** | Backup verification failure threat. | ADR-0012 |
| **T-PM-01** | Credential export threat. | ADR-0012 |
| **T-PM-02** | Credential modification threat. | ADR-0012 |
| **T-PM-03** | Vault unlock threat. | ADR-0012 |
| **T-PM-04** | Offline password guessing threat. | ADR-0012 |
| **T-PM-05** | Credential rotation threat. | ADR-0012 |
| **T-PM-06** | Credential deletion threat. | ADR-0012 |
| **T-PM-07** | Recovery token abuse threat. | ADR-0012 |
| **T-IDI-01** | Stored credentials theft threat. | ADR-0012 |
| **T-IDI-02** | Master password theft threat. | ADR-0012 |
| **T-IDI-03** | User credentials theft threat. | ADR-0012 |
| **T-IDI-04** | Decrypted credentials theft threat. | ADR-0012 |
| **T-IDI-05** | Audit logs disclosure threat. | ADR-0012 |
| **T-IDI-06** | JWT secrets theft threat. | ADR-0012 |
| **T-IDI-07** | Backup data theft threat. | ADR-0012 |
| **T-IDI-08** | Service vault context theft threat. | ADR-0012 |

## Security Control Statuses

| Term | Definition | Source |
|------|------------|--------|
| **Implemented** | The security control has been implemented in code. | ADR-0012 |
| **Proposed** | The security control is documented but not yet implemented. | ADR-0012 |
| **Verified** | The security control has been tested and verified operational. | ADR-0012 |

## Related ADRs

| ADR | Title |
|-----|-------|
| ADR-0001 | Project Identity and Compatibility Contract |
| ADR-0002 | Bidirectional Database Interoperability and Extension Isolation |
| ADR-0003 | Identity Authentication, MFA and Cryptographic Unlocking Boundaries |
| ADR-0004 | Identity Provider Binding, Administrator Provisioning and Break-Glass Access |
| ADR-0005 | Authorization, Access Control and Administrator Privilege Boundaries |
| ADR-0006 | Account Ownership, Credential Sharing and Group-Based Access |
| ADR-0007 | Effective Permissions, ACL Precedence and Conflict Resolution |
| ADR-0008 | Encryption Architecture, Master Password and Cryptographic Key Lifecycle |
| ADR-0009 | Session Architecture, API Token Lifecycle and Server-Side Vault Context |
| ADR-0010 | Service Accounts, Workload Identity and Automated Credential Retrieval |
| ADR-0011 | Audit Logging and Accountability |
| ADR-0012 | Threat Model and Trust Boundaries |
| ADR-0013 | Backup, Disaster Recovery and Cryptographic Recoverability |
| ADR-0014 | Emergency Authentication and Offline Recovery Access |
| ADR-0015 | Deployment Architecture and Infrastructure Requirements |

## Deployment Architecture

| Term | Definition | Source |
|------|------------|--------|
| **Deployment Profile** | A named configuration pattern (Development, Standalone, Production Compose, External DB, Portainer, Kubernetes, OpenShift, HA, DR) sharing the same application architecture with infrastructure differences configured via environment and volume mounts. | ADR-0015 |
| **Bootstrap Lock** | MySQL `GET_LOCK('pysyspass_bootstrap', 300)` or `fcntl` file lock serializing schema initialization across workers and containers. | ADR-0015 |
| **Schema Guard** | Runtime `SQLALCHEMY_SCHEMA_GUARD=true` preventing unintended DDL mutations (`CREATE TABLE`, `ALTER TABLE`) at application runtime. | ADR-0015 |
| **PHP-Owned Schema** | Core sysPass tables managed by PHP migrations; Python treats as immutable contract and only adds additive extension tables. | ADR-0015 |
| **Python-Native Extensions** | Additive tables created by Python (e.g., `emergency_credentials`) with Alembic migrations; not present in PHP schema. | ADR-0015 |
| **Trusted Proxy Hosts** | `TRUSTED_PROXY_HOSTS` allowlist (JSON array of IPs/CIDRs) validating `X-Forwarded-*` headers. Untrusted proxies cannot spoof forwarded headers. | ADR-0015 |
| **Vault Claim** | Encrypted master password embedded in JWT token (`mpass` field, AES-256-GCM under key derived from `ENCRYPTION_KEY` + user ID). Per-session, stateless distribution. | ADR-0015 |
| **Deployment Verification Status** | One of: **Supported and Verified** (tested and operational), **Supported but Not Verified** (config exists, not tested), **Partially Supported** (some features work), **Proposed** (designed, not implemented), **Unsupported** (explicitly not supported). | ADR-0015 |
| **Writable Directory** | A container filesystem path that must be a mounted volume for persistence: `/app/data`, `/app/backups`, `/var/lib/mysql`. | ADR-0015 |
| **Disposable Directory** | A container filesystem path that is ephemeral and excluded from backups: `/tmp`, `/var/cache`, `/var/run`. | ADR-0015 |
| **Arbitrary UID Compatibility** | Container image ability to run with any UID assigned by OpenShift SCC `runAsUser: RunAsAny`. Requires writable directories to be pre-provisioned with correct permissions or init container. | ADR-0015 |
| **Rootless Container** | Container runtime without root privileges (Podman rootless, Docker rootless). Supported for pySysPass. | ADR-0015 |
| **Read-Only Root Filesystem** | Container with root filesystem mounted read-only. pySysPass backend supports with `/app/data` and `/app/backups` as writable volumes. | ADR-0015 |
| **Health Endpoint** | `/health` (liveness) and `/health/ready` (readiness) endpoints returning no sensitive configuration or cryptographic material. | ADR-0015 |
| **Readiness Probe** | `GET /health/ready` checking database connectivity, schema version, configuration validity, and storage writability. | ADR-0015 |
| **Liveness Probe** | `GET /health` returning simple "healthy" indicating process is alive. | ADR-0015 |
| **Graceful Shutdown** | SIGTERM handling that drains connections, stops accepting new requests, completes in-flight operations, and exits cleanly. **Not yet implemented.** | ADR-0015 |
| **Rolling Upgrade** | Deployment strategy where new replicas start and pass readiness before old replicas terminate. Requires backward-compatible schema and shared session store. | ADR-0015 |
| **Session Store Backend** | Storage mechanism for session revocation state. Default: file-based (`/app/data/sessions.json`). HA option: Redis (optional, not mandatory). | ADR-0015 |
| **Scheduler Lock** | File-based lock (`/app/data/scheduler.lock`) ensuring only one worker runs background tasks. **Not distributed** — requires Redis for HA. | ADR-0015 |
| **Alembic Version** | The revision identifier stored in `alembic_version` table indicating which migrations have been applied. pySysPass requires extension schema >= version 003 for production. | ADR-0016 |
| **Extension Schema** | Python-native tables added by Alembic migrations (003–005+): `emergency_credentials`, `audit_*`, `service_*`. PHP ignores these tables entirely. | ADR-0016 |
| **Bootstrap Schema** | The PHP base table definitions applied by `CREATE TABLE IF NOT EXISTS` from `schemas/dbstructure.sql` on first startup. Idempotent; does not modify existing tables. | ADR-0016 |
| **Schema Superset** | The property that pySysPass tables must be a superset of what PHP expects. No PHP table may be renamed, dropped, or have columns removed by Python migrations. | ADR-0016 |
| **Migration Lock** | `GET_LOCK('pysyspass_alembic', 600)` serializing Alembic across processes. Prevents concurrent migration on shared MySQL server. Proposed per ADR-0016; not yet implemented. | ADR-0016 |
| **Schema Guard** | `before_cursor_execute` SQLAlchemy event blocking DDL (CREATE/ALTER/DROP/TRUNCATE/RENAME/GRANT/REVOKE) at application runtime. Bypassed by bootstrap and Alembic (by design). | ADR-0016 |
| **Shared Schema** | The 18 PHP base tables + 2 views that constitute the bidirectional compatibility contract between pySysPass and sysPass PHP. Owned by PHP schema definition; pySysPass mirrors but does not mutate. | ADR-0016, ADR-0002 |
| **Extension Tables** | Python-native tables not present in PHP: `emergency_credentials`, `audit_events`, `audit_archives`, `audit_retention_policies`, `audit_access_logs`, `service_accounts`, `service_auth_tokens`, `service_vault_contexts`. Alembic owns these. | ADR-0016 |
| **Configuration Layer** | One of the 8 ordered sources that can supply a setting. Higher layers override lower. See ADR-0017 §1 for the full precedence order. | ADR-0017 |
| **Mounted Secret** | A secret provided as a file (typically `/run/secrets/<name>`) by the container runtime. Layer 1 in ADR-0017 precedence. Not yet implemented. | ADR-0017 |
| **Secret Provider** | An abstraction for external secret storage (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager). Layer 3 in ADR-0017 precedence. Not yet implemented. | ADR-0017 |
| **Overlapping Validity Window** | A key rotation pattern where both the current and previous key are accepted for decryption/verification during a grace period, preventing immediate session/data loss. Implemented via `SECRET_KEY_PREVIOUS` (proposed) and `ENCRYPTION_KEY_PREVIOUS` (proposed). | ADR-0017 |
| **Breaking Rotation** | Key rotation without an overlapping validity window — all existing JWTs or encrypted data become unreadable immediately. Current risk for `SECRET_KEY` (T-CFG-02). | ADR-0017 |
| **Runtime JSON Config** | Mutable application settings stored in `/app/data/runtime-config.json`. Layer 6 in ADR-0017 precedence. Used for mail, LDAP, general, and wiki settings. | ADR-0017, ADR-0002 |
| **PHP config.xml** | Legacy sysPass PHP configuration file. Layer 8 in ADR-0017 precedence. Read by `syspass_runtime_config.py` for `passwordSalt` and other PHP-owned values. | ADR-0017, ADR-0002 |
| **Secret Age** | Time since a secret was last rotated. When exceeding the configured `*_MAX_AGE_DAYS` threshold, a warning is logged (or readiness degraded). Not yet enforced. | ADR-0017 |

## Deprecated Terms

| Term | Reason | Replacement |
|------|--------|-------------|
| EmergencyAdmin table | Contradicts ADR-0002 (PHP compatibility) | emergency_credentials table |
| User.isEmergency | Contradicts ADR-0002 (PHP compatibility) | emergency_credentials table |
| 24-hour emergency window | Contradicts user decision | 2-hour default window |
| LDAP-to-local fallback | Contradicts ADR-0004 (fail-closed) | Emergency authentication mode |
| Environment variable backup keys | Contradicts backup encryption policy | Mounted secret files (Option B) |
| Local auth fallback | Violates fail-closed policy | Explicit break-glass accounts |
| Implicit admin provisioning | Security hardening | Explicit admin assignment |
| Master password as identity | Violates separation of concerns | Master password as crypto unlock only |