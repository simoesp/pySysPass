# ADR-0008 — Encryption Architecture, Master Password and Cryptographic Key Lifecycle

## Status

**Status:** Active

## Context

sysPass uses a server-trusted encryption architecture where the application server holds cryptographic keys for credential decryption. This ADR documents the intended cryptographic trust boundaries, key hierarchy, and compatibility requirements.

## Decision

### 1. Encryption Architecture Model

**Server-Trusted Architecture:**
- Application server is a trusted component responsible for encryption/decryption
- Infrastructure administrators (DB access, config access, backups) can potentially decrypt all credentials
- This is a known limitation, not a vulnerability

**No Cryptographic Owner Exclusivity:**
- Account ownership is authorization-based, not cryptographic
- Master password alone can decrypt all account passwords
- User passwords provide recovery context, not cryptographic isolation

**Shared Encryption Model:**
- All account passwords encrypted with same global master password
- User password required only for User.mPass/mKey decryption
- No per-user encryption keys

### 2. Master Password Architecture

**Global Master Password:**
- Single global master password for all credentials
- Stored hashed in `Config.masterPwd` (bcrypt)
- User-encrypted in `User.mPass/mKey` (Defuse V2)
- Used directly for account password encryption

**Decryption Flow:**
```
Account Password Decryption:
  1. User authenticates (login password verified)
  2. User unlocks User.mPass/mKey (requires user password)
  3. Unlocked master password decrypts account passwords
  4. Master password stored in session (encrypted in JWT)
```

**Key Relationships:**
- `Account.pass`: Encrypted with master password (Defuse V2)
- `Account.key`: Wrapped key (Defuse V2), encrypted with master password
- `User.mPass`: Master password encrypted with user credentials
- `User.mKey`: Key material encrypted with user credentials

**Implications:**
- Database dump + master password = full credential recovery
- User password change breaks User.mPass (requires migration)
- Master password rotation re-encrypts all credentials

### 3. Cryptographic Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│ SECRET_KEY (environment variable, not stored in DB)              │
│   ├─ JWT signing (HS256)                                         │
│   ├─ Session fingerprint (HMAC-SHA256)                           │
│   └─ Derived: vault_claim_key (HKDF)                              │
├─────────────────────────────────────────────────────────────────┤
│ ENCRYPTION_KEY (environment variable or Config)                   │
│   └─ Derived: vault_claim_key (HKDF)                              │
│       └─ AES-256-GCM for JWT mpass encryption                     │
├─────────────────────────────────────────────────────────────────┤
│ Master Password (global, never stored in plaintext)               │
│   ├─ Hashed: Config.masterPwd (bcrypt)                            │
│   ├─ User-encrypted: User.mPass/mKey (Defuse V2)                 │
│   └─ Used to encrypt: Account.pass/key (Defuse V2)                │
├─────────────────────────────────────────────────────────────────┤
│ User Login Password (per-user, hashed)                            │
│   ├─ Hashed: User.password (bcrypt)                               │
│   ├─ Derives: user_key for mPass decryption                       │
│   └─ Session fingerprint (HMAC)                                   │
├─────────────────────────────────────────────────────────────────┤
│ API Tokens (per-token, plaintext)                                 │
│   └─ 64-char hex secret (no hashing)                              │
└─────────────────────────────────────────────────────────────────┘
```

### 4. Cryptographic Inventory

| Mechanism | Algorithm | Key Size | Integrity | Storage | Purpose |
|-----------|-----------|----------|-----------|---------|---------|
| **Defuse V2** (account passwords) | AES-256-CTR + HMAC-SHA256 | 256-bit | HMAC | DB | Credential encryption |
| **Defuse V2** (user mPass/mKey) | AES-256-CTR + HMAC-SHA256 | 256-bit | HMAC | DB | Master password protection |
| **JWT signing** | HS256 (HMAC-SHA256) | 256-bit | Yes | JWT | Token authentication |
| **Session encryption** | AES-256-GCM | 256-bit | AEAD | JWT | Master password in token |
| **User password hash** | bcrypt $2y$10 | 64-bit (derived) | No | DB | Login authentication |
| **API tokens** | SHA256 (random) | 256-bit | No | DB | API authentication |
| **Session fingerprint** | HMAC-SHA256 | 256-bit | No | JWT | Token revocation |

### 5. Key Separation

**Purpose-Specific Keys:**
- `SECRET_KEY`: JWT signing and session fingerprinting
- `ENCRYPTION_KEY`: Session encryption and vault claims
- `Master Password`: Credential encryption
- `User Password`: User authentication and mPass decryption

**Key Derivation:**
- `vault_claim_key` = HKDF(ENCRYPTION_KEY, "pysyspass session vault claim v2")
- Domain separation through HKDF info strings
- No direct reuse of keys across unrelated purposes

### 6. Token Security Analysis

**JWT Claims:**
```json
{
  "user_id": <int>,
  "username": <str>,
  "iat": <float>,
  "auth_time": <float>,
  "jti": <session_id>,
  "sfp": <HMAC of password hash>,
  "is_admin": <bool>,
  "is_admin_app": <bool>,
  "is_admin_acc": <bool>,
  "mpass": <encrypted if provided>
}
```

**Security Properties:**
- ✅ Signed with SECRET_KEY (server-side key)
- ✅ mpass encrypted with AES-256-GCM
- ✅ mpass bound to user_id (cannot transfer)
- ✅ Signed JWT does NOT provide confidentiality
- ⚠️ Stolen JWT permits online credential disclosure (replay attacks)
- ⚠️ SECRET_KEY compromise exposes all tokens

**API Tokens:**
- 64-char hex secret (plaintext in DB)
- No expiration (unlike JWT sessions)
- Revoked on delete or admin action
- No cryptographic protection

### 7. Actor Trust Matrix

| Actor | Can Decrypt Credentials? | Requires: | Risk Level |
|-------|--------------------------|------------|------------|
| Ordinary user | ✅ Own accounts only | Own password + master password | Low |
| Account owner | ✅ All owned accounts | Own password + master password | Medium |
| System admin | ✅ ALL accounts (with master_pass) | Admin status + master password | Medium |
| Account admin | ✅ All accounts (with master_pass) | Admin status + master password | Medium |
| Database admin (DB only) | ❌ No | Cannot derive keys from DB | Low |
| App host admin | ✅ With DB + config access | SECRET_KEY + ENCRYPTION_KEY + master password | High |
| Backup admin | ✅ With backup files | SECRET_KEY + ENCRYPTION_KEY + master password | High |
| JWT theft (stolen token) | ❌ Cannot decrypt offline | Needs to replay before expiry | Medium |
| API token theft | ❌ Cannot decrypt | Token provides no crypto access | Low |

**Clarification:**
- "Can decrypt" means can read plaintext credentials
- "Requires" means must provide these secrets
- Database admin cannot derive encryption keys from encrypted data

### 8. Cryptographic Weaknesses

1. **SECRET_KEY compromise**: Single point of failure for all JWTs
2. **ENCRYPTION_KEY in DB**: If stored, anyone with DB access can read it
3. **No key separation**: SECRET_KEY and ENCRYPTION_KEY are single-purpose
4. **Master password in JWT**: Stored server-side, can be extracted by admins
5. **No cryptographic owner exclusivity**: All encryption uses master password
6. **API tokens in plaintext**: Bearer tokens without expiration

### 9. Python-Native Encryption Modernization

**Unauthenticated AES-256-CTR:**
- Location: `app/core/security.py`
- Used for runtime data encryption (not credentials)
- **No integrity check** (vulnerable to ciphertext tampering)
- **No authentication** (IV reuse possible)
- **Should be replaced with AES-GCM**

**Migration Plan:**
- Replace AES-CTR with AES-GCM
- Maintain unique nonces per encryption operation
- Add authentication tag verification
- Document format versioning
- Provide migration script for existing data

### 10. Master Password Rotation

**Rotation Process:**
1. Verify current master password
2. Re-encrypt all account credentials
3. Re-encrypt credential history
4. Re-encrypt user mPass/mKey
5. Update `Config.lastupdatempass`
6. Revoke all sessions
7. Retire temporary master password

**Requirements:**
- Must be run with both old and new master password
- All writes in single transaction
- Verify decryption with new master before commit
- Requires maintenance mode

**Failure Scenarios:**
- ❌ Rotation interrupted: Mixed encryption states possible
- ❌ Old master password wrong: Fails with clear error
- ❌ Concurrent writes: Blocked by maintenance mode
- ✅ Rollback: MySQL dump preserves old master

### 11. Recovery Requirements

**Database Recovery:**
- Database backup (MySQL dump)
- Global master password
- Application SECRET_KEY
- Application ENCRYPTION_KEY

**What Cannot Be Recovered Without:**
- ❌ Master password: Cannot decrypt credentials
- ❌ User passwords: Cannot unlock User.mPass
- ❌ SECRET_KEY: Cannot forge valid JWTs
- ❌ ENCRYPTION_KEY: Cannot decrypt JWT mpass claims

**What Can Be Recovered With:**
- ✅ Database backup + master password: Full recovery
- ✅ Database backup without keys: Cannot decrypt credentials
- ✅ Keys without master password: Cannot decrypt credentials

### 12. Compatibility Deviations

**PHP Compatibility Preserved:**
- ✅ Defuse V2 format for account passwords
- ✅ Defuse V2 format for user mPass/mKey
- ✅ bcrypt password hashing
- ✅ Master password hash in Config.masterPwd
- ✅ Database schema identical

**Intentional Security Deviations:**
- ❌ Admin bypasses private account restrictions (PHP permits this)
- ❌ API tokens stored in plaintext (PHP permits this)
- ❌ No cryptographic owner exclusivity (PHP permits this)
- ❌ Master password in JWT (PHP permits this)

**Modernizations:**
- ✅ AES-256-GCM for JWT mpass (vs PHP's AES-256-CTR)
- ✅ JWT-based sessions (vs PHP's file-based sessions)
- ✅ HMAC session fingerprint (vs PHP's session cookies)

### 13. Threat Model

**Threat Actors:**
- **Malicious user**: Can only access own credentials
- **Malicious admin**: Can access all credentials with master password
- **Attacker with DB dump**: Can recover with master password
- **Attacker with stolen JWT**: Can replay before expiry
- **Attacker with SECRET_KEY**: Can forge any JWT

**Mitigations:**
- Master password kept secret
- SECRET_KEY stored in environment, not DB
- JWTs have short lifetimes (24 hours default)
- Sessions revoked on logout/password change
- Maintenance mode for rotation

### 14. Security Recommendations

1. **Keep SECRET_KEY secure**: Store in environment, not DB
2. **Protect master password**: Never store in logs, use secure storage
3. **Rotate master password**: Periodically or after security incidents
4. **Monitor token usage**: Detect unusual API token access
5. **Use AES-GCM**: Replace unauthenticated AES-CTR
6. **Document admin access**: All admins need master password training

## Consequences

### Operational

- Administrators must secure master password
- Database dumps must be encrypted
- SECRET_KEY must be in environment variables
- Master password rotation requires maintenance mode

### Development

- Cryptographic code must follow this architecture
- No per-user encryption keys
- No client-side encryption of credentials
- JWT mpass encryption with AES-GCM

### Security

- Clear understanding of trust boundaries
- No cryptographic owner exclusivity guarantees
- Admin access requires master password
- Known limitations documented

## References

- `app/core/defuse_compat.py`: Defuse V2 implementation
- `app/core/security.py`: AES-256-CTR (to be modernized)
- `app/services/auth_service.py`: JWT and session handling
- `app/services/session_service.py`: Session revocation
- `app/services/master_password_rotation.py`: Rotation logic
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`
- `docs/adr/0006-account-ownership-credential-sharing-and-group-based-access.md`
- `docs/adr/0007-effective-permissions-acl-precedence-and-conflict-resolution.md`

## Related Documents

- `docs/security/policy.md`: Security requirements
- `docs/backup-recovery.md`: Recovery procedures
- `docs/installation.md`: SECRET_KEY setup
- `scripts/php-interop-stack.sh`: PHP interoperability tests
