# ADR-0002 — Bidirectional Database Interoperability and Extension Isolation

## Status

**Status:** Active

## Context

pySysPass must support bidirectional interoperability with sysPass PHP databases while allowing Python-native extensions. This ADR defines the architectural contract for:

- **Shared Compatibility Domain:** Core sysPass data (accounts, users, groups, permissions, categories, tags, encryption)
- **Python-Native Extension Domain:** Python-exclusive functionality stored in shared schema tables
- **Runtime Security Domain:** Python-exclusive encryption formats (AES-256-GCM) used for transient data

The goal is to allow users to transition between PHP and Python implementations without data loss or security compromise.

## Decision

### 1. Shared Compatibility Domain

**Definition:** All data that must remain bidirectionally compatible with sysPass PHP.

**Scope:**
- `User` table: login credentials, master password (Defuse V2 format), permissions
- `Account` table: vault credentials (Defuse V2 format), sharing, views
- `UserGroup`, `UserToUserGroup`: ACL and sharing
- `Category`, `Client`: organizational metadata
- `Config`: runtime configuration (master password salt, maintenance mode, etc.)

**Cryptographic Compatibility:**
- Account passwords: PHP Defuse V2 format (`defuse_compat.py`)
- User master passwords: PHP Defuse V2 format (`defuse_compat.py`)
- Key derivation: PBKDF2-SHA256 (100,000 iterations)

### 2. Python-Native Extension Domain

**Definition:** Python-exclusive functionality stored in shared schema tables using namespace isolation.

**Scope:**
- `PluginData` table: 2FA state, notification settings (stored as JSON blobs)
- `ItemPreset` table: password generator settings (stored as JSON blobs)
- `AuthToken` table: JWT sessions (stored as JSON blobs)
- `Notification` table: user notifications (stored as JSON blobs)

**Physical vs Logical Ownership:**
- **Physical schema ownership:** All tables are defined in sysPass PHP schema; PHP can read them
- **Logical record ownership:** PHP and Python share responsibility for table structure, but Python owns extension blobs
- **Isolation mechanism:** Python stores data as JSON blobs with Python-specific field names; PHP ignores unknown fields

**Isolation Guarantee:**
- PHP's `mysqli_query()` reads all columns but only interprets PHP-owned fields
- Python blobs are opaque to PHP (PHP doesn't crash on unknown JSON keys)
- PHP cleanup routines may delete Python blobs if they match PHP deletion criteria

**Extension Isolation Requirements:**
1. **Field name namespace:** Python-exclusive fields must use Python-prefixed names (e.g., `pluginData_2fa`, `pluginData_notification`)
2. **Type safety:** Python blobs must be valid JSON; PHP's loose typing tolerates JSON without error
3. **ID collision prevention:** Python uses UUIDs for blob identifiers where PHP uses integers
4. **Backup/restore compatibility:** MySQL dumps preserve Python blobs; PHP restore ignores them
5. **Migration safety:** Python-to-PHP migration can delete Python blobs safely (PHP ignores them)

**Verification:**
- PHP reads Python blobs without error (loose typing)
- PHP does not overwrite Python fields (field name mismatch)
- PHP does not delete Python blobs (no matching criteria)
- MySQL backups preserve both PHP and Python data

### 3. Runtime Security Domain

**Definition:** Python-exclusive encryption formats used for transient data.

**Scope:**
- JWT session tokens: AES-256-GCM (authenticated encryption)
- Vault claims: AES-256-GCM (authenticated encryption)
- 2FA backup codes: AES-256-CTR (unauthenticated, transient only)

**Isolation Guarantee:** These are stored in JWT tokens or ephemeral storage, NOT in the database. PHP cannot read these tokens because they're encrypted with Python-exclusive keys.

**Security Semantics:** Switching from PHP to Python does NOT introduce new attack vectors:
- Database-level data remains PHP-compatible
- Python-exclusive encryption is ephemeral (tokens, not stored)
- Rollback to PHP preserves all database data

### 4. Cryptographic Compatibility

| Data Type | PHP Format | Python Format | Compatible |
|-----------|------------|---------------|------------|
| Account passwords | Defuse V2 | Defuse V2 | ✓ Yes |
| User master passwords | Defuse V2 | Defuse V2 | ✓ Yes |
| User login passwords | bcrypt | bcrypt | ✓ Yes |
| JWT tokens | N/A | AES-256-GCM | ✗ No (ephemeral) |
| Vault claims | N/A | AES-256-GCM | ✗ No (ephemeral) |

### 5. Determinism Note

Encryption is **non-deterministic** (random salt/IV per operation). This is intentional for security:
- Prevents ciphertext pattern attacks
- PHP and Python will produce different ciphertexts for the same plaintext
- Interoperability is verified by decryption (not ciphertext comparison)

### 6. Rollback Compatibility

**Rollback Procedure:**
1. Stop Python application
2. Restore database from backup (MySQL dump, not Python archive)
3. Restart PHP application
4. Core data is fully compatible (accounts, users, groups, etc.)
5. Python-exclusive tables (`PluginData`, `AuthToken`, `Notification`, `ItemPreset`) are ignored by PHP

**Python-to-PHP Migration Path:**
- Delete Python-exclusive tables if needed (they're safe to drop)
- Or leave them (PHP ignores them)
- No data loss

**PHP-to-Python Migration Path:**
- Python reads all PHP-created data
- Creates Python-exclusive entries in shared tables
- No data loss

## Consequences

### Operational

- Users can switch between PHP and Python implementations without data loss
- Rollback is supported by restoring from MySQL dumps (not Python archives)
- Python-exclusive data is backward-compatible with PHP (opaque blobs)

### Development

- New Python features must use shared schema tables, not new tables (to maintain compatibility)
- Python-exclusive data must be stored as JSON blobs in existing PHP tables
- Cryptographic compatibility must be maintained for all database-stored data

### Security

- JWT tokens and vault claims are Python-exclusive (ephemeral, not stored in DB)
- No new attack vectors introduced by switching implementations
- Database-level data remains PHP-compatible

### Testing

- Compatibility tests exist in `tests/compatibility/`
- Round-trip tests require `PYSYSPASS_PHP_VERIFY_CMD` to be set
- Tests are skipped by default (not run in CI unless explicitly enabled)

## References

- `docs/adr/0001-project-identity-and-compatibility-contract.md`: Project identity and scope
- `app/core/defuse_compat.py`: PHP-compatible encryption implementation
- `tests/compatibility/`: Compatibility test suite
- `schemas/`: PHP schema reference for compatibility verification
