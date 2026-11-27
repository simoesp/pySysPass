# Security Audit Finding: Unauthenticated AES-256-CTR Encryption

## Status

**Status:** Open — Requires remediation

## Severity

**Severity:** High — Cryptographic weakness in runtime encryption

## Finding

`app/core/security.py` uses AES-256-CTR for runtime encryption without authenticated encryption:

```python
cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
```

This implementation:
- Uses CTR mode (authenticated encryption by accident)
- Does NOT include HMAC or AEAD authentication
- Does NOT verify ciphertext integrity on decryption

## Impact

An attacker who can modify ciphertext can:
- Tamper with encrypted data without detection
- Inject arbitrary plaintext into decrypted output
- Bypass confidentiality guarantees

## Scope

**Affected:**
- JWT session tokens (uses AES-256-GCM — SAFE)
- Vault claims (uses AES-256-GCM — SAFE)
- Runtime encryption in `app/core/security.py` (unsafe)

**Not Affected:**
- Database-stored credentials (Defuse V2 with HMAC)
- User login passwords (bcrypt)
- Account passwords (Defuse V2 with HMAC)

## Mitigation

**Option 1: Migrate to AES-256-GCM** (Recommended)
- Switch to authenticated encryption with associated data (AEAD)
- Maintains API compatibility
- Requires re-encrypting all existing data

**Option 2: Add HMAC verification** (Alternative)
- Add HMAC-SHA256 signature to ciphertext
- Verify on decryption before use
- Adds 64 bytes overhead per encrypted value

**Option 3: Keep CTR (Accept Risk)**
- Document the limitation
- Add security warning in documentation
- Consider acceptable for transient data only

## Decision Required

Choose one mitigation option. If Option 1 or 2:
- Create ADR documenting the migration
- Add compatibility task for existing data
- Update security policy

## References

- `app/core/security.py`: Lines 8-41 (encryption implementation)
- `app/core/defuse_compat.py`: Uses HMAC (safe, Defuse V2 format)
- `app/services/auth_service.py`: Uses AES-256-GCM (safe, vault claims)
