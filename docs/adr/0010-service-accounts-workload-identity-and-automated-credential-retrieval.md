# ADR-0010 — Service Accounts, Workload Identity and Automated Credential Retrieval

## Status

**Status:** Accepted

## Context

pySysPass must support non-interactive integrations (CI/CD, Ansible, monitoring, backup automation) while maintaining strict authorization boundaries. This ADR establishes a hybrid model with dedicated service identities, scoped service tokens, and encrypted service vault contexts.

## Decision

### 1. Service Account Model

**Service Account as Distinct Identity Type:**

Service accounts are distinct from human users, intended for non-interactive integrations.

**Service Account Properties:**
- `service_id`: UUID (hashed, not secret)
- `service_name`: Human-readable name
- `owner_id`: Human user or team managing the service account
- `purpose`: Documented use case
- `scopes`: Array of permitted operations
- `enabled/disabled`: State flag
- `created_at`, `updated_at`: Timestamps
- `last_used_at`: Last request timestamp
- `audit_history`: Log of operations

**Not Automatic:**
- ❌ No inherited admin privileges
- ❌ No interactive UI authentication
- ❌ No default credential disclosure access

### 2. Authentication Paths

**Three Distinct Paths:**

| Path | Actor | Mechanism | JWT Claims |
|------|-------|-----------|------------|
| **Human User** | Interactive users | Username/password + MFA | `sub`, `sid`, `jti`, `exp`, `azp` |
| **Service Account** | Non-interactive integrations | Service token | `sub`, `sid`, `jti`, `exp`, `svc` |
| **Legacy PHP** | PHP integrations | Original API auth | `user_id`, `username`, `mpass` |

**Service Token:**
- Cryptographically random 64-char hex secret
- Hashed in database (bcrypt)
- One-time disclosure on creation
- Configurable expiration (90 days default)
- Scope-limited (read, write, delete, export, admin)
- Resource-restricted (optional)

### 3. Cryptographic Bootstrap

**Service Vault Context Model:**

```
┌─────────────────────────────────────────────────────────────┐
│ Service Token (AuthTokenMetadata)                            │
│   ├─ service_id (hashed)                                     │
│   ├─ owner_id                                                │
│   ├─ scopes, resource_restrictions                           │
│   ├─ created_at, expires_at                                  │
│   └─ last_used_at                                            │
├─────────────────────────────────────────────────────────────┤
│ Service Vault Context (encrypted, server-side)               │
│   └─ Encrypted with: SERVICE_VAULT_KEY (env var)              │
│       ├─ service_id                                          │
│       ├─ master_password (encrypted)                         │
│       ├─ service_key (encrypted)                             │
│       └─ vault_context_version                               │
├─────────────────────────────────────────────────────────────┤
│ Authorization Check (per request)                            │
│   ├─ Validate service token (signature + expiration)         │
│   ├─ Check service identity (not expired/revoked)            │
│   ├─ Verify scopes match operation                           │
│   ├─ Check resource restrictions                              │
│   ├─ Verify authorization (ACL, private accounts)            │
│   └─ Decrypt service vault context (if needed)               │
└─────────────────────────────────────────────────────────────┘
```

**Key Properties:**
- ✅ Service vault context encrypted separately (no master password exposure)
- ✅ Service key stored in environment variable (not database)
- ✅ On-demand decryption (no persistent plaintext)
- ✅ Time-bound access (context expires)
- ✅ Revocable (service context can be invalidated)
- ✅ Audit trail for all service operations

### 4. Service Account Permissions

**Capability Matrix:**

| Capability | Default | Description |
|------------|---------|-------------|
| Account discovery | ✅ Allow | List/search accounts (metadata only) |
| Account metadata retrieval | ✅ Allow | View account details (no password) |
| Credential disclosure | ❌ Deny | Requires explicit scope |
| Credential creation | ❌ Deny | Requires write scope |
| Credential modification | ❌ Deny | Requires write scope |
| Credential rotation | ❌ Deny | Requires write scope |
| Credential deletion | ❌ Deny | Requires delete scope |
| Credential export | ❌ Deny | Requires export scope |
| Administrative operations | ❌ Deny | Requires admin scope |

**Scope Definitions:**

| Scope | Permissions | Use Case |
|-------|-------------|----------|
| `read` | Account metadata only | Monitoring, discovery |
| `write` | Create/edit/delete accounts | Automation, bulk operations |
| `export` | Read + export credentials | Backup, migration |
| `admin` | All operations + token management | Service administration |

**Private Account Protection:**
- Service accounts obey ADR-0007 private account restrictions
- No bypass of owner/ACL requirements
- Service context does not override authorization

### 5. Service Vault Context Lifecycle

**Context Storage:**
- Server-side encrypted storage (`data/service_vaults.json` or DB-backed)
- Encrypted with `SERVICE_VAULT_KEY` (env var, never DB)
- Per-service context (not shared)

**Context Expiration:**
- Absolute lifetime: 8 hours (configurable per service)
- Inactivity timeout: 4 hours (configurable)
- Revoked on: Service token expiration, service context revocation, master password rotation

**Context Renewal:**
- Automatic renewal on request (within lifetime)
- Requires valid service token and authorization
- Does not extend absolute lifetime
- No indefinite access

### 6. Legacy Master Password API (Compatibility Mode)

**Restricted Legacy Mechanism:**

Legacy PHP integrations may use master password parameter, but:

- ❌ Disabled by default for new integrations
- ✅ Explicit administrative enablement required
- ✅ TLS-protected transport mandatory
- ✅ No secrets in URLs or query strings
- ✅ No logging of master password
- ✅ Strict request validation
- ✅ Rate limiting (10 requests/minute)
- ✅ Documented security warnings
- ✅ Auditable usage
- ✅ Migration path documented

**Requirements:**
- `master_password` parameter in request body
- TLS 1.2+ required
- Request body only (not URL)
- No master password in logs or telemetry
- Clear deprecation warnings

### 7. Secret Zero Problem

**Explicit Documentation:**

> **The secret-zero problem:** An automated integration needs an initial trusted credential to authenticate to pySysPass. pySysPass can reduce the number of credentials distributed (service tokens instead of master passwords), but it cannot eliminate the need for initial trust establishment.

**Mitigation Strategies:**
1. **Service token distribution**: One-time secret disclosure, secure channel required
2. **Service key management**: `SERVICE_VAULT_KEY` in environment, not code
3. **Credential rotation**: Service tokens rotated periodically
4. **Strong initial secrets**: Minimum 32 characters, cryptographically random
5. **Secure storage**: Environment variables, secret management tools

**Future Enhancements (Optional):**
- Mutual TLS authentication
- OIDC workload identity
- Short-lived federated credentials
- CI/CD identity federation
- External identity providers

### 8. Failure Handling

**Fail Securely:**

| Condition | Action |
|-----------|--------|
| Service identity disabled | Reject request |
| Token expired or revoked | Reject request |
| Insufficient scope | Reject request |
| Missing resource authorization | Reject request |
| Service vault context expired | Reject request |
| Master password rotation | Invalidate service context |
| Session/token state unavailable | Reject request (no fallback) |
| Cryptographic verification failure | Reject request |

**No fallback to:**
- ❌ Unrestricted access
- ❌ Legacy authentication
- ❌ Global administrator context
- ❌ Plaintext master password retrieval

### 9. Audit Requirements

**Required Audit Events:**

| Event | Fields |
|-------|--------|
| Service account creation | `service_id`, `owner_id`, `purpose`, `scopes`, `created_at`, `actor` |
| Service account deletion | `service_id`, `owner_id`, `reason`, `deleted_at`, `actor` |
| Service account disable | `service_id`, `owner_id`, `reason`, `disabled_at`, `actor` |
| Token creation | `service_id`, `token_id`, `scopes`, `expires_at`, `created_at`, `actor` |
| Token revocation | `service_id`, `token_id`, `reason`, `revoked_at`, `actor` |
| Token rotation | `service_id`, `token_id`, `old_token_id`, `new_token_id`, `rotated_at`, `actor` |
| Scope modification | `service_id`, `token_id`, `scopes_before`, `scopes_after`, `modified_at`, `actor` |
| Resource permission change | `service_id`, `token_id`, `resource_id`, `permission_before`, `permission_after`, `modified_at`, `actor` |
| Cryptographic context provisioning | `service_id`, `context_id`, `provisioned_at`, `expires_at`, `actor` |
| Vault context renewal | `service_id`, `context_id`, `renewed_at`, `expires_at`, `actor` |
| Credential retrieval | `service_id`, `token_id`, `credentials_count`, `retrieved_at`, `outcome` |
| Credential modification | `service_id`, `token_id`, `credential_id`, `modified_at`, `outcome` |
| Failed authentication | `service_id`, `token_id`, `attempted_at`, `error` |
| Failed authorization | `service_id`, `token_id`, `resource_id`, `requested_operation`, `attempted_at`, `error` |
| Legacy master password API usage | `service_id`, `token_id`, `usage_count`, `last_used_at`, `actor` |

**Audit Properties:**
- ✅ Identify service account (never secret token)
- ✅ Non-secret token identifier
- ✅ Requested operation
- ✅ Affected resource
- ✅ Timestamp
- ✅ Outcome
- ❌ Never record credential values
- ❌ Never record token secrets
- ❌ Never record master passwords

### 10. Implementation Tables

**New Tables (Python-native only):**

**`AuthTokenMetadata`**: Service token metadata
```sql
CREATE TABLE AuthTokenMetadata (
    id INT PRIMARY KEY AUTO_INCREMENT,
    service_id VARCHAR(64) NOT NULL,
    token_id VARCHAR(64) NOT NULL,
    owner_id INT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    scopes JSON NOT NULL,
    resource_restrictions JSON,
    last_used_at DATETIME,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at DATETIME,
    revoker_id INT,
    revocation_reason TEXT,
    UNIQUE KEY uk_service_token (service_id, token_id),
    INDEX idx_owner_id (owner_id),
    INDEX idx_created_at (created_at),
    INDEX idx_expires_at (expires_at),
    INDEX idx_revoked (revoked),
    CONSTRAINT fk_owner FOREIGN KEY (owner_id) REFERENCES User(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**`AuthTokenMetadataRevocationLog`**: Token revocation history
```sql
CREATE TABLE AuthTokenMetadataRevocationLog (
    id INT PRIMARY KEY AUTO_INCREMENT,
    service_id VARCHAR(64) NOT NULL,
    token_id VARCHAR(64) NOT NULL,
    revoked_at DATETIME NOT NULL,
    revoker_id INT NOT NULL,
    revocation_reason TEXT,
    INDEX idx_service_id (service_id),
    INDEX idx_revoked_at (revoked_at),
    CONSTRAINT fk_revoker FOREIGN KEY (revoker_id) REFERENCES User(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**`ServiceVaultContext`**: Encrypted service vault context (stored encrypted in DB)
```sql
CREATE TABLE ServiceVaultContext (
    id INT PRIMARY KEY AUTO_INCREMENT,
    service_id VARCHAR(64) NOT NULL,
    context_id VARCHAR(64) NOT NULL,
    encrypted_context VARBINARY(8192) NOT NULL,
    encrypted_with_key VARBINARY(64) NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    last_used_at DATETIME,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at DATETIME,
    UNIQUE KEY uk_service_context (service_id, context_id),
    INDEX idx_service_id (service_id),
    INDEX idx_created_at (created_at),
    INDEX idx_expires_at (expires_at),
    INDEX idx_revoked (revoked)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Existing Tables (Modified):**

**`Config`**: Add service vault key
```sql
ALTER TABLE Config ADD COLUMN service_vault_key VARBINARY(128);
ALTER TABLE Config ADD COLUMN service_vault_key_encrypted BOOLEAN DEFAULT FALSE;
```

**`AuthToken`**: Legacy tokens remain unchanged
```sql
-- No changes to legacy PHP-compatible tokens
-- New service tokens stored in AuthTokenMetadata
```

### 11. Service Account Creation Flow

```
1. Admin creates service account via API:
   POST /api/v1/service-accounts
   {
     "service_name": "ci-cd-pipeline",
     "owner_id": 5,
     "purpose": "GitHub Actions CI/CD integration",
     "scopes": ["read", "write"],
     "resource_restrictions": {
       "groups": ["developers"],
       "exclude_private": true
     }
   }

2. Server creates AuthTokenMetadata entry:
   - Generates service_id (UUID)
   - Creates service token (64-char hex)
   - Hashes token for storage
   - Stores in AuthTokenMetadata

3. Server creates ServiceVaultContext:
   - Encrypts master password with SERVICE_VAULT_KEY
   - Encrypts service key with SERVICE_VAULT_KEY
   - Stores in ServiceVaultContext

4. Server sends response:
   {
     "service_id": "svc_abc123",
     "service_token": "5f3a8b2c9d1e4f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a"
   }
   (one-time disclosure only)

5. Admin distributes service token via secure channel:
   - Secure file transfer
   - Password manager
   - Encrypted message
   - Not in email/logs

6. Integration uses service token:
   Authorization: Bearer {service_token}
   All subsequent requests validated server-side
```

### 12. Service Token Usage Flow

```
1. Integration makes request:
   POST /api/v1/accounts
   Authorization: Bearer {service_token}
   {
     "action": "read_accounts",
     "scope": "read"
   }

2. Server validates:
   a. JWT signature (SECRET_KEY)
   b. Token not expired
   c. Service identity valid (not revoked/expired)
   d. Scopes match requested operation
   e. Resource restrictions checked
   f. Private account restrictions enforced

3. Server checks service vault context:
   a. Context not expired
   b. Context not revoked
   c. Decrypt context with SERVICE_VAULT_KEY
   d. Verify authorization

4. Server processes request:
   a. Read credentials from database
   b. Decrypt with service vault context
   c. Return to client

5. Server logs audit event:
   - service_id, token_id, operation, resource, outcome
   - Updates last_used_at
   - Checks context expiration
```

### 13. Service Vault Context Rotation

**On Master Password Rotation:**
1. Mark all service vault contexts as invalid
2. Service tokens remain valid (identity unchanged)
3. Service context must be re-established
4. Next request: New context created with new master password
5. Context expires after 4 hours of inactivity

**On Service Key Change:**
1. Re-encrypt all service vault contexts with new key
2. Rotate SERVICE_VAULT_KEY environment variable
3. Old key deprecated (not deleted immediately)
4. Grace period for key rotation

**On Context Expiration:**
1. Context invalidated automatically
2. Next request creates new context
3. Old context not reused
4. Audit log records new context creation

### 14. Security Properties

| Property | Status | Description |
|----------|--------|-------------|
| Service identity authentication | ✅ | Token validates service identity |
| Scope enforcement | ✅ | Scopes checked per request |
| Resource restrictions | ✅ | Resource-level ACL enforced |
| Private account protection | ✅ | ADR-0007 restrictions apply |
| Time-bound access | ✅ | Context expires, no indefinite access |
| Revocation | ✅ | Immediate revocation supported |
| Audit trail | ✅ | All operations logged |
| No master password exposure | ✅ | Encrypted vault context |
| Secure failure | ✅ | Fail securely on all errors |
| Legacy compatibility | ✅ | Original PHP integrations supported |

### 15. Known Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| Secret-zero problem | Initial credential required | Secure distribution procedures |
| SERVICE_VAULT_KEY exposure | Key in environment | Secure environment management |
| Context encryption key | Same key for all services | Domain separation via service_id |
| Legacy token plaintext | Legacy tokens in plaintext | Migration to Python-native tokens |

### 16. Consequences

### Operational

- Service accounts require initial secure setup
- SERVICE_VAULT_KEY must be managed securely
- Service tokens distributed via secure channel
- Regular rotation of service tokens required
- Audit logs reviewed regularly

### Development

- Service account API endpoints created
- Service vault context management implemented
- Token hashing and verification added
- Scope enforcement in authorization layer
- Audit logging integrated

### Security

- Reduced credential exposure (service tokens vs master passwords)
- Better audit trail for service operations
- Time-bound service access
- Independent revocation capability
- Private account protection maintained

## References

- `docs/adr/0003-identity-authentication-mfa-and-cryptographic-unlocking.md`
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`
- `docs/adr/0007-effective-permissions-acl-precedence-and-conflict-resolution.md`
- `docs/adr/0008-encryption-architecture-master-password-and-cryptographic-key-lifecycle.md`
- `docs/adr/0009-session-architecture-api-token-lifecycle-and-server-side-vault-context.md`
- `app/models/account.py`: AuthToken model
- `app/services/auth_service.py`: Authentication logic

## Related Documents

- `docs/security/policy.md`: Security requirements
- `docs/backup-recovery.md`: Recovery procedures
- `docs/installation.md`: Environment setup
- `scripts/php-interop-stack.sh`: PHP interoperability tests

## 17. Amendment — Service Vault Key Hierarchy and Authoritative-Key Precedence

**Status of this amendment:** Accepted. Records the coordinator decision posted on IMPL-010 (2026-11-27 05:2x WET) and the implemented key hierarchy (IMPL-013/IMPL-014). This amendment supersedes the key-management statements in ADR-0010 §§3, 5, 12c and 13 as shown below; those sections remain in force for everything else, and are not renumbered or silently rewritten.

### 17.1 Why this amendment

IMPL-013/IMPL-014 implemented a versioned service vault keyring with per-service DEKs (`app/core/service_vault_keyring.py`), but ADR-0010 §§3, 5, 12c and 13 mention only `SERVICE_VAULT_KEY` (env var) and contain no keyring language. The code comment "per ADR-0010 §3/§13" therefore overstated the accepted text. This amendment closes the gap explicitly with before/after text, rather than silently rewriting the accepted sections.

### 17.2 Authoritative-key precedence (decision)

- `SERVICE_VAULT_KEY` from environment or settings is authoritative when no keyring is explicitly configured.
- A keyring is additive and opt-in only: it is used only when explicitly configured (`SERVICE_VAULT_KEYRING_PATH` or a keyring file at a default path), and it must not silently override `SERVICE_VAULT_KEY`.
- No silent precedence override: the resolution order and which source won must be observable, not implicit.

### 17.3 Implemented resolution order (observed in code)

`app/core/service_vault_crypto.resolve_service_vault_key()` resolves: explicit `key` override → keyring current master key (when a keyring file exists and is readable) → settings `SERVICE_VAULT_KEY` → environment `SERVICE_VAULT_KEY`.

**Divergence (unresolved — recorded explicitly, not silently reconciled):** the implementation gives an existing keyring file precedence over `SERVICE_VAULT_KEY`, i.e. a silent precedence override contrary to the decision in 17.2. Owner: IMPL-010 / key-hierarchy owner. Verification status: Not Verified (see 17.6).

### 17.4 Before / After

**§3 Cryptographic Bootstrap (diagram):**
- Before: `│   └─ Encrypted with: SERVICE_VAULT_KEY (env var)`
- After: `│   └─ Encrypted with the service vault root key: SERVICE_VAULT_KEY (env var/settings) when no keyring is explicitly configured; otherwise the keyring's current master key. Keyring is additive and opt-in; never stored in the database.`

**§5 Service Vault Context Lifecycle — Context Storage:**
- Before: `- Encrypted with \`SERVICE_VAULT_KEY\` (env var, never DB)`
- After: `- Encrypted with the service vault root key: \`SERVICE_VAULT_KEY\` from environment/settings when no keyring is explicitly configured; otherwise the keyring's current master key (keyring additive and opt-in). Never stored in the database.`

**§12 Service Token Usage Flow (step c):**
- Before: `c. Decrypt context with SERVICE_VAULT_KEY`
- After: `c. Decrypt context with the service vault root key (SERVICE_VAULT_KEY env/settings, or the keyring's current master key when a keyring is explicitly configured)`

**§13 Service Vault Context Rotation — On Service Key Change:**
- Before: `2. Rotate SERVICE_VAULT_KEY environment variable`
- After: `2. Rotate the service vault root key: add a new master key version to the keyring and rewrap all per-service DEKs with it (`rotate_master_key` + `rewrap_all_service_deks`); the old key is retained for historical context decryption. When no keyring is configured, rotate the SERVICE_VAULT_KEY environment variable.`

### 17.5 Rotation / DEK wrapping semantics

- Root key: versioned keyring (JSON), current plus retained historical key versions; keyring file protected with 0400 permissions.
- Per-service DEK: randomly generated 32-byte DEK wrapped with AES-256-GCM under a master key version; HKDF domain separation (`pysyspass-service-dek-wrap-v1`, salt = service ID); AAD `dek-wrap|<service_id>`; wrapping key recorded as `wrapped_with_key_id`.
- Independent rotation: per-service DEKs rotatable independently of the master key; master key rotation rewraps all DEKs and retains old versions.
- Single-shot seals: nonce-sealed contexts are one-time readable; the seal nonce registry is consumed on first open.

### 17.6 Test-isolation requirement

Tests must use a private keyring path (`SERVICE_VAULT_KEYRING_PATH` pointed at a temp file), reset the keyring/path module caches, and clear the single-shot seal nonce registry between tests, so an ambient deployment keyring cannot silently override the `SERVICE_VAULT_KEY` under test and DEK/seal state cannot leak across tests. Implemented in `tests/conftest.py` (`isolated_service_vault_state`).

### 17.7 Evidence (executed-test receipt; verification not claimed from documentation alone)

- `tests/test_impl010_probe.py` (IMPL-010 probe against IMPL-014's hierarchy): runs and fails with `ServiceVaultDecryptError: No DEK found for service` on the oneshot round-trip — the empty-id lookup failure mode documented in the probe's own docstring. The probe is not green; the precedence path is therefore **not verified**.
- Service-vault test files run this cycle (`test_impl010_probe.py`, `test_service_vault_context.py`, `test_service_vault_forward_security.py`, `test_service_vault_operator_bootstrap.py`): not green in this environment (53 failed, 2 passed), including fixture-setup failures in `isolated_service_vault_state`. Verification status: **Not Verified**.

### 17.8 References

- `app/core/service_vault_crypto.resolve_service_vault_key` (implemented resolution order)
- `app/core/service_vault_keyring` (keyring, DEK wrap/rotate)
- `tests/conftest.py` `isolated_service_vault_state` (test isolation)
- Coordinator decision on IMPL-010 (2026-11-27 05:2x WET)

---

## Owner decisions — AIRR Wave 1 (2026-11-27)

### GOV-002 Q1 — APPROVED (option a)

`SERVICE_VAULT_KEY` is mandatory whenever persistent service vault
functionality is enabled: explicit startup validation; clear remediation
message; no insecure default; **no silent key generation when persistent
encrypted contexts already exist**; no fallback to `SECRET_KEY` or
`ENCRYPTION_KEY`; independent lifecycle and key versioning; secure
mounted-file support; optional external secret provider. Disabled vault →
key optional. Undecryptable existing contexts → affected operations stay
unavailable; startup must **not destroy or overwrite** them.

### GOV-002 Q2 — APPROVED (modified option a): root secret vs mutable keyring state

Root encryption keys are supplied via read-only mounted secret files,
Docker secrets, Kubernetes/OpenShift secret volumes, environment variables
(compatibility), or optional external secret managers, and are **never
written back** during routine operation. Mutable keyring state sits behind
a **keyring storage abstraction** with three backends: (1) file-backed
(single-instance; restrictive permissions, atomic updates, filesystem
locking, explicit key versions, corruption detection, recovery); (2)
database-backed wrapped keyring (distributed; authenticated encryption of
wrapped key material, transactional metadata, rotation coordination,
concurrency safety, consistent active-key selection, revocation
propagation, recovery after interrupted rotation); (3) read-only keyring +
controlled redeployment. A shared writable volume is **not** a safe
distributed backend until its locking/consistency semantics are verified.
No plaintext master password or plaintext persistent service key material
in the database. Root-key rotation and operational-key rotation are
distinct procedures. Redis stays optional.

### Open security requirement (AIRR §4) — provisioning/bootstrap

Key-storage approval does not close cryptographic provisioning. Before
GOV-002 completes, establish and document: provisioning authority; master
material acquisition; persisted cryptographic authorization; derivation of
operational contexts from provisioning grants; renewal authorization;
absolute provisioning expiration; service-token revocation; service
identity disabling; master-password rotation; root-key rotation; restart
recovery; compromise containment. **Documented limitation:** a
service-specific key does not limit the blast radius of exposing the
global master password held in that service's decrypted context.
Tracked as IMPL-044.
