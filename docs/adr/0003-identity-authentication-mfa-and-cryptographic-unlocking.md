# ADR-0003 — Identity Authentication, MFA and Cryptographic Unlocking

## Status

**Status:** Active

## Context

sysPass supports three distinct security responsibilities that must remain architecturally separate:

1. **Identity authentication:** Proving who you are (username/password, LDAP)
2. **Multi-factor authentication (MFA):** Adding identity assurance (TOTP 2FA)
3. **Cryptographic vault unlocking:** Decrypting protected material (master password)

The current implementation conflates these responsibilities, particularly by unlocking the vault before MFA verification. This audit finding requires architectural separation.

## Decision

### 1. Authentication Hierarchy

The intended sequence is:

1. **Identify the user and authentication provider:**
   - Determine whether local authentication or LDAP applies
   - Do NOT silently fall back from LDAP to local authentication

2. **Authenticate identity:**
   - LDAP: Authenticate against LDAP server; reject on failure (don't fall back to local)
   - Local: Authenticate against `User.password` (bcrypt hash)
   - Disabled accounts: Reject immediately after identity verification

3. **Enforce MFA when enrolled or required:**
   - If `TwoFactorConfig.get_mode() != "disabled"` and user has 2FA enrolled
   - Require TOTP code or recovery code
   - Reject with `428 TWO_FACTOR_REQUIRED` if no code supplied
   - Lock IP on failed MFA attempts

4. **Establish cryptographic vault context:**
   - Decrypt `User.mPass` using login password
   - Verify master password hash against `Config.masterPwd`
   - If vault unlock fails, reject with `401 MASTER_PASSWORD_REQUIRED`

5. **Establish session:**
   - Issue JWT token with user identity and scopes
   - Embed master password in JWT only if requested (encrypted AES-256-GCM)

6. **Evaluate authorization:**
   - Check `User.isAdminApp`, `User.isAdminAcc`, `User.isUserEnabled`
   - Enforce ACL via `UserProfile` permissions

7. **Permit credential access:**
   - Vault is unlocked; credentials can be decrypted for display

### 2. Authentication Providers

**Local Authentication:**
- Primary mechanism for most users
- Stores bcrypt hash in `User.password`
- Supports master password vault unlocking via `User.mPass`/`User.mKey`

**LDAP Authentication:**
- Secondary provider for enterprise environments
- Requires explicit configuration in `Config`
- Must be explicitly enabled by administrator
- On failure: reject immediately (no fallback to local auth)
- On success: creates local `User` row with `isLdap=True`
- Disabled LDAP accounts are rejected (not auto-enabled)

**Emergency Administrator Accounts:**
- Pre-seeded admin accounts bypass MFA enforcement
- Can be used for recovery scenarios
- Must be explicitly created by administrator

### 3. Master Password Responsibilities

**Cryptographic Key, Not Identity:**
- The master password unlocks the vault (decrypts credentials)
- It does NOT substitute for identity authentication
- It is NOT an authentication factor by default

**Lifecycle:**
- Stored encrypted in `User.mPass`/`User.mKey` (Defuse V2 format)
- Hash stored in `Config.masterPwd` for verification
- Rotation requires old master password as input
- Never log or expose plaintext master password

**Security Invariants:**
- Master password verification happens AFTER identity auth and MFA
- Failed vault unlock does NOT establish an authenticated session
- Vault unlock failure is logged but does not trigger IP lock (different failure domain)

### 4. Session Establishment

**JWT Token:**
- Contains user identity (`user_id`, `username`)
- Contains session fingerprint (`sfp`) for revocation
- Contains admin scopes (`is_admin_app`, `is_admin_acc`)
- Master password embedded as encrypted blob (`g2:` prefix) only if requested
- Expires after 24 hours (configurable per user)

**Revocation:**
- Sessions are invalidated on password change
- Sessions are invalidated on 2FA enrollment changes
- Sessions are invalidated on LDAP account disable

### 5. Current Implementation Deviations

**Deviation 1: Vault Unlock Before MFA**
- Current order: vault unlock → MFA verification
- Issue: Master password material exists in memory before MFA succeeds
- Risk: If MFA fails, vault material is discarded but was exposed in memory
- Mitigation: Document as audit finding; consider refactoring to MFA-first

**Deviation 2: LDAP Fallback**
- Current code: If LDAP fails, falls back to local auth (line 328-337 in `ldap_service.py`)
- Issue: Violates "no silent fallback" security principle
- Risk: LDAP-disabled accounts could access via local credentials
- Mitigation: **Task:** Remove fallback logic; make LDAP failure a hard rejection

**Deviation 3: Master Password as Fallback**
- Current code: `mpass` can unlock vault even if identity auth fails
- Issue: `mpass` is vault unlock material, not identity
- Risk: Someone with master password could bypass identity auth
- Mitigation: Task to ensure master password is ONLY used AFTER identity auth

**Deviation 4: Emergency Admin Auto-Provisioning**
- Current code: LDAP login can provision new users into default group (line 351-364)
- Issue: If default group is Admins, LDAP users get admin privileges on first login
- Risk: Emergency admin access without explicit consent
- Mitigation: Task to require explicit admin group configuration

### 6. Security Invariants

| Invariant | Current | Required |
|-----------|---------|----------|
| Identity auth before MFA | Yes | Yes |
| MFA before vault unlock | No (deviation) | Yes |
| LDAP no fallback to local | No (deviation) | Yes |
| Master password not identity | Yes | Yes |
| Failed MFA discards vault material | Yes | Yes |
| Session token contains master password | Optional | Optional |

### 7. Compatibility Constraints

**PHP Compatibility:**
- PHP's `AuthProvider` tries LDAP before local auth when enabled
- PHP's `LoginService` allows master password vault unlock even without identity auth
- Our implementation MUST NOT replicate these behaviours (security hardening)

**Migration Path:**
- Existing users with 2FA enrolled must be able to log in (MFA enforced)
- Existing users without 2FA must be able to log in (identity auth only)
- LDAP users must NOT be able to fall back to local auth

### 8. Required Verification Tests

| Test | Description |
|------|-------------|
| TOTP-MFA-enforced | User with 2FA must supply code |
| TOTP-MFA-bypass-rejected | User without 2FA can't bypass MFA |
| LDAP-fallback-rejected | LDAP auth failure must not fall back to local |
| Master-password-not-identity | Master password alone cannot authenticate |
| MFA-failure-discards-vault | Failed MFA does not expose credentials |
| Session-revocation-on-password-change | Password change invalidates all sessions |

## Consequences

### Operational

- Users must complete MFA enrollment to enable enhanced security
- LDAP administrators must explicitly enable LDAP authentication
- Emergency admin accounts must be created manually

### Development

- New authentication features must respect the hierarchy
- Vault unlocking must occur AFTER MFA verification
- Master password handling must follow cryptographic best practices

### Security

- Reduced attack surface (no silent fallbacks)
- Clear separation of authentication and cryptographic responsibilities
- Audit trail of authentication failures at each stage

## References

- `docs/adr/0002-bidirectional-database-interoperability-and-extension-isolation.md`: Database compatibility contract
- `app/api/v1/auth.py`: Current authentication implementation
- `app/services/auth_service.py`: Authentication service functions
- `app/services/two_factor_service.py`: MFA implementation
