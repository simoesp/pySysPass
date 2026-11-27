# ADR-0013 — Backup, Disaster Recovery and Cryptographic Recoverability

## Status

**Status:** **Proposed** (Backup encryption mandatory pending approval)

---

## Context

pySysPass must support comprehensive backup and disaster recovery while maintaining cryptographic recoverability, PHP compatibility, and security. The existing backup implementation backs up database and runtime files, but recovery procedures for various failure scenarios need explicit documentation and testing.

---

## Investigation Results

### Current Backup Implementation

**What is Backed Up:**

From `app/services/backup_service.py`:

1. **Database (`database.sql`):**
   - All MySQL tables including User, Account, Plugin, PluginData, Config
   - Contains: password hashes, mPass/mKey material, API tokens, LDAP settings
   - Encrypted credentials remain encrypted

2. **Runtime Data (`data/` directory):**
   - RSA keys (if configured)
   - Session store (`sessions.json`)
   - Service vault contexts (`service_vaults.json` if implemented)
   - Two-factor pending secrets (`two-factor-pending.json`)
   - Backup codes (`backup-codes.json`)
   - Runtime config (`runtime-config.json`)

3. **What is NOT Backed Up:**
   - Application code (git repository)
   - Audit logs (separate storage)
   - Docker volumes not included in backup

### Backup Contents Analysis

| Component | Sensitive? | Recovery Required | PHP Compatible |
|-----------|------------|-------------------|----------------|
| User password hashes | Medium | Yes (bcrypt) | Yes |
| User mPass/mKey | Critical | Yes (encrypted) | Yes |
| Account credentials | Critical | Yes (encrypted) | Yes |
| API tokens | Medium | Yes (plaintext in DB) | Yes |
| Master password hash | Critical | Yes (bcrypt) | Yes |
| Service vault contexts | Critical | Yes (encrypted) | No (Python-only) |
| RSA keys | Critical | Yes | Yes |
| Session tokens | Low | No (regenerated) | N/A |
| LDAP settings | Medium | Yes | Yes |

### Backup Security Assessment

**Current State:**
- Backups stored in `./backups/` directory
- File permissions: `0o600` (owner read/write only)
- No encryption at rest
- Backup key stored in same location as backups (SECURITY RISK)

**Security Issues:**
1. Backups contain plaintext API tokens (for PHP compatibility)
2. Password hashes readable by offline attackers
3. Encrypted credentials require key recovery
4. No backup encryption key management
5. No integrity verification

---

## Decision

### 1. Backup Encryption: Mandatory by Default

**Policy:**

- **Backup encryption mandatory by default**
- Unencrypted backups require explicit administrative exception
- Security warning and audit event required for unencrypted backups
- Use established cryptographic libraries (not custom algorithms)

**Encryption Mechanisms:**

#### Option A: Symmetric Encryption (Default for Self-Hosted)

**Requirements:**
- Independently generated backup encryption key
- Authenticated encryption (AES-256-GCM)
- Secure mounted key file
- Restrictive filesystem permissions (0400)
- Explicit key versioning
- Secure key rotation
- Independent recovery copy of encryption key

**Key Management:**
- Key stored in `/etc/syspass/backup-key`
- File permissions: `0400` (owner read-only)
- Separate from application secrets
- Independent lifecycle from application

**Key Rotation:**
- Backup encryption key identifiers (version numbers)
- Historical key retention (old keys remain for old backups)
- Key retirement procedures (documented, not automatic)
- Compromised key handling (re-encrypt with new key, preserve old)
- Never silently replace missing encryption key

#### Option B: Asymmetric Encryption (Security-Sensitive Deployments)

**Hybrid Encryption Architecture:**

```
Backup Creation:
1. Generate random data encryption key (DEK) per backup
2. Encrypt backup contents with DEK (AES-256-GCM)
3. Wrap DEK with recipient's public key (RSA-OAEP or X25519-KEYWRAP)
4. Store DEK + wrapped key in backup manifest
5. Backup manifest signed for authenticity

Restoration:
1. Verify backup signature (authenticity)
2. Retrieve wrapped DEK from backup
3. Decrypt DEK with private key
4. Decrypt backup contents with DEK
```

**Tools:**
- Use established tools: `age`, `GPG`, or `openssl`
- Do not design custom encrypted backup format
- Private key in independently secured recovery storage
- Public key in production application

**Key Management:**
- Production: Only public key required
- Recovery: Private key in secure storage (NOT in pySysPass)
- Key rotation: Generate new key pair, re-encrypt affected backups

### 2. Secret Storage

**Supported Mechanisms:**

| Mechanism | Use Case | Permissions | Rotation |
|-----------|----------|-------------|----------|
| Mounted secret files | Docker Compose, self-hosted | 0400 | Restart required |
| Docker secrets | Docker Swarm/Kubernetes | Managed by platform | Managed by platform |
| Kubernetes/OpenShift volumes | Container orchestrators | RBAC controlled | Platform-managed |
| External secrets manager | Enterprise | Platform-managed | Platform-managed |
| Environment variables | Compatibility only | Process inspection risk | Restart required |

**Key Policy:**
- Backup encryption key lifecycle independent of ordinary application secrets
- Never assume mounted files or environment variables encrypted at rest
- Do not claim automatic encryption without verification
- Environment variables for compatibility only (document exposure risks)

### 3. Backup Contents and Minimization

**Backup Manifest:**

```json
{
  "backup_version": "1.0",
  "application_version": "1.0.0",
  "schema_version": "30018083002",
  "encryption_key_id": "v1",
  "encrypted": true,
  "algorithm": "AES-256-GCM",
  "created_at": "2026-11-27T00:00:00Z",
  "schema": {
    "database": {
      "mandatory": ["User", "Account", "UserGroup", "UserProfile", "Plugin", "PluginData", "Config", "AuthTokenMetadata", "ServiceAccounts"],
      "optional": ["AccountHistory", "AccountSearchView"],
      "sensitive": ["password", "mPass", "mKey", "pass", "key", "vault", "token"]
    },
    "runtime": {
      "mandatory": ["RSA keys", "runtime-config.json"],
      "optional": ["sessions.json", "service_vaults.json", "two-factor-pending.json", "backup-codes.json"],
      "disposable": ["sessions.json", "service_vaults.json", "cache files"]
    }
  }
}
```

**Policy:**
- Exclude active session files (sessions.json) - disposable
- Exclude temporary vault contexts (service_vaults.json) - disposable
- Exclude caches - disposable
- Include all persistent data - mandatory
- Include sensitive cryptographic material - mandatory but encrypted
- Database backup treated as sensitive (contains plaintext API tokens)

### 4. Backup Integrity and Authenticity

**Required:**
- Cryptographic integrity verification (HMAC-SHA256)
- Detection of truncated or corrupted backups
- Validation of backup manifest
- Safe archive extraction (path traversal protection)
- Verification before restoration
- Backup signing for authenticity (optional)

### 5. Restoration Security

**Security Policy:**

- A restored database does NOT automatically restore security state trustworthiness
- All interactive sessions invalidated
- All refresh tokens invalidated
- Emergency auth mode reset to inactive
- Service vault contexts require explicit reauthorization
- API tokens revoked (must be re-created)
- Disabled users remain disabled (not auto-enabled)
- Changed permissions preserved

**Controlled Recovery Mode:**

- Recovery mode flags: `RECOVERY_MODE_ACTIVE`, `SECURITY_STATE_UNTRUSTED`
- Service vault contexts require re-provisioning
- API tokens must be re-created
- Verify recovery checklist before normalizing

### 6. Recovery Verification Tests

**Required Tests:**

| Test | Description | Success Criteria |
|------|-------------|------------------|
| Complete host loss | Restore from backup, application functional | All data intact, users can login |
| Database loss only | Restore database, runtime preserved | Data restored, no runtime loss |
| Backup key incorrect | Attempt restore with wrong key | Failure, no data exposed |
| Backup key missing | Attempt restore without key | Failure, error message |
| Corrupted backup | Attempt restore with corrupted archive | Failure, integrity check |
| Truncated backup | Attempt restore with incomplete archive | Failure, integrity check |
| Historical backup | Restore backup after key rotation | Failure (old key required) |
| Pre-rotation backup | Restore backup before MPASS rotation | Success (old MPASS works) |
| Service token revocation | Verify revoked tokens not usable | Access denied |
| PHP restoration | Restore to PHP system | PHP can read encrypted data |
| pySysPass restoration | Restore to pySysPass | pySysPass reads data correctly |


### 7. PHP Compatibility

**Verified:**
- Database schema compatible with sysPass PHP
- Password hashes readable by PHP (bcrypt)
- Encrypted credentials readable by PHP (Defuse V2)
- API tokens readable by PHP (plaintext)
- Import/export compatible

**Limitations:**
- Service vault contexts (Python-only) not understood by PHP
- Python extension metadata not visible to PHP
- PHP rollback may not preserve Python-only data

### 8. Backup Key Rotation

**Policy:**
- Backup encryption key identifiers (version numbers)
- Historical key retention (old keys remain for old backups)
- Key retirement procedures (documented, not automatic)
- Compromised key handling (re-encrypt with new key, preserve old)
- Never silently replace missing encryption key

**Rotation Procedure:**
1. Generate new backup encryption key
2. Store old key for historical backup recovery
3. Re-encrypt new backups with new key
4. Document key retirement procedures
5. Verify all affected backups are recoverable

### 9. Independent Recovery Storage

**Required:**
- Backup decryption keys must NOT exist exclusively inside pySysPass or production application host
- Global master password recovery material must be stored independently
- Emergency administrator credentials must be stored independently
- Recovery instructions must be documented separately
- Persistent cryptographic keys must be stored independently

**Recommended:**
- Store backup encryption keys in separate secure location
- Maintain recovery copy of encryption key
- Document offline recovery procedures
- Consider dual-control recovery for sensitive deployments

### 10. Backup Integrity and Authenticity

**Required:**
- Cryptographic integrity verification (HMAC-SHA256)
- Detection of truncated or corrupted backups
- Validation of backup manifest
- Safe archive extraction (path traversal protection)
- Verification before restoration
- Backup signing for authenticity (optional)

### 11. Restoration Security

**Security Policy:**

- A restored database does NOT automatically restore security state trustworthiness
- All interactive sessions invalidated
- All refresh tokens invalidated
- Emergency auth mode reset to inactive
- Service vault contexts require explicit reauthorization
- API tokens revoked (must be re-created)
- Disabled users remain disabled (not auto-enabled)
- Changed permissions preserved

**Controlled Recovery Mode:**
- Recovery mode flags: `RECOVERY_MODE_ACTIVE`, `SECURITY_STATE_UNTRUSTED`
- Service vault contexts require re-provisioning
- API tokens must be re-created
- Verify recovery checklist before normalizing

### 12. Recovery Verification Tests

**Required Tests:**

| Test | Description | Success Criteria |
|------|-------------|------------------|
| Complete host loss | Restore from backup, application functional | All data intact, users can login |
| Database loss only | Restore database, runtime preserved | Data restored, no runtime loss |
| Backup key incorrect | Attempt restore with wrong key | Failure, no data exposed |
| Backup key missing | Attempt restore without key | Failure, error message |
| Corrupted backup | Attempt restore with corrupted archive | Failure, integrity check |
| Truncated backup | Attempt restore with incomplete archive | Failure, integrity check |
| Historical backup | Restore backup after key rotation | Failure (old key required) |
| Pre-rotation backup | Restore backup before MPASS rotation | Success (old MPASS works) |
| Service token revocation | Verify revoked tokens not usable | Access denied |
| PHP restoration | Restore to PHP system | PHP can read encrypted data |
| pySysPass restoration | Restore to pySysPass | pySysPass reads data correctly |

### 13. Backup Authenticity Verification

**Cryptographic Authenticity Models:**

#### Option A: Symmetric HMAC (Current Approach)

**Mechanism:**
- HMAC-SHA256 computed over encrypted backup contents
- HMAC key stored separately from backup and encrypted data
- Backup manifest includes HMAC key identifier

**Pros:**
- Simple implementation
- Fast verification
- Established cryptographic primitive

**Cons:**
- Requires shared secret between production and recovery
- If backup key is compromised, attacker can forge backups
- Key must be stored securely in recovery environment

**Implementation:**
```python
# Create backup
backup = encrypt_backup(backup_data, dek)
hmac = compute_hmac(backup, backup_encryption_key)
manifest = {
    'version': '1.0',
    'hmac': base64.b64encode(hmac).decode(),
    'wrapped_dek': ...,
    'encrypted_data': backup
}

# Restore backup
hmac_in_manifest = read_manifest(manifest)['hmac']
computed_hmac = compute_hmac(encrypted_data, backup_encryption_key)
assert hmac_in_manifest == computed_hmac.hex()  # Authenticity verified
```

#### Option B: Asymmetric Digital Signatures (Alternative)

**Mechanism:**
- Production signs backup manifest with private key
- Recovery verifies signature with public key
- No shared secret required

**Pros:**
- No shared secret between environments
- Tamper-evident (signature verification)
- Established cryptographic primitive (RSA-PSS or Ed25519)

**Cons:**
- Requires key pair management
- Slightly slower than HMAC
- Public key must be in recovery environment

**Implementation:**
```python
# Create backup
backup = encrypt_backup(backup_data, dek)
signature = sign_manifest(manifest, private_key)
manifest = {
    'version': '1.0',
    'signature': base64.b64encode(signature).decode(),
    'wrapped_dek': ...,
    'encrypted_data': backup
}

# Restore backup
signature_in_manifest = read_manifest(manifest)['signature']
verified = verify_signature(manifest, public_key)
assert verified  # Authenticity verified
```

#### Option C: Hybrid Approach (Recommended for Production)

**Mechanism:**
- Use asymmetric signatures for authenticity
- Use HMAC for ciphertext integrity
- Both mechanisms complementary

**Pros:**
- Best of both worlds
- Authenticity AND integrity verified
- No shared secret required for authenticity

**Cons:**
- Slightly more complex
- Requires both key types

**Implementation:**
```python
# Create backup
backup = encrypt_backup(backup_data, dek)
hmac = compute_hmac(backup, backup_encryption_key)
signature = sign_manifest(manifest, private_key)
manifest = {
    'version': '1.0',
    'hmac': base64.b64encode(hmac).decode(),
    'signature': base64.b64encode(signature).decode(),
    'wrapped_dek': ...,
    'encrypted_data': backup
}

# Restore backup
hmac_in_manifest = read_manifest(manifest)['hmac']
signature_in_manifest = read_manifest(manifest)['signature']
computed_hmac = compute_hmac(encrypted_data, backup_encryption_key)
verified = verify_signature(manifest, public_key)
assert hmac_in_manifest == computed_hmac.hex()  # Integrity verified
assert verified  # Authenticity verified
```

**Recommendation:** Start with Option A (symmetric HMAC) for simplicity. Consider migrating to Option C (hybrid) for production deployments requiring higher security guarantees.

**Backup Manifest Structure:**

```json
{
  "version": "1.0",
  "algorithm": "AES-256-GCM",
  "created_at": "2026-11-27T00:00:00Z",
  "hmac": "abc123...",
  "signature": "def456...",
  "wrapped_dek": "ghi789...",
  "encrypted_data": "encrypted backup data...",
  "schema": {
    "database": "backup.sql",
    "runtime": "data.tar.gz"
  }
}
```

**Authenticity vs Integrity Distinction:**

| Concept | What it Verifies | Mechanism |
|---------|------------------|------------|
| **Ciphertext Integrity** | Backup data hasn't been corrupted during storage/transfer | HMAC over encrypted data |
| **Archive Integrity** | Entire archive is complete and uncorrupted | Archive checksum |
| **Backup Origin Authentication** | Backup was created by authorized production instance | Digital signature |
| **Manifest Authentication** | Manifest hasn't been tampered with | Signature over manifest |

**Implementation Priority:**

1. **Phase 1:** Implement HMAC-based integrity verification (Option A)
2. **Phase 2:** Add digital signatures for authenticity (Option C)
3. **Phase 3:** Document migration path to hybrid approach


**User Decision: Option B (Default) with optional Option C support**

- **Default:** Mounted secret files with restrictive permissions
- **Optional:** External secrets manager for enterprise deployments
- **Not supported:** Environment variables as primary storage
- **Key lifecycle:** Independent of ordinary application secrets

### 14. Asymmetric Encryption Investigation

**Status:** To be investigated

- **Hybrid encryption architecture:** Each backup receives DEK, wrapped with public key
- **Tools to evaluate:** `age`, `GPG`, `openssl`
- **Private key:** Must remain in independently secured recovery storage
- **Public key:** Can be in production application
- **Key rotation:** Generate new key pair, re-encrypt affected backups

