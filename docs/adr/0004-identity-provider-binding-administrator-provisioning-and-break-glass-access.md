# ADR-0004 — Identity Provider Binding, Administrator Provisioning and Break-Glass Access

## Status

**Status:** Active

## Context

sysPass must support explicit break-glass administrator accounts for emergency access when external identity providers (LDAP) are unavailable. The current implementation has an LDAP-to-local fallback that violates this architecture. This ADR establishes the intended identity provider binding and administrator provisioning model.

**Scope Clarification:** This ADR covers normal local administrator accounts that remain functional when LDAP fails. For disaster recovery scenarios requiring offline authentication when both LDAP AND normal local auth are compromised, see ADR-0014 (Emergency Authentication Mode) which defines a separate `emergency_credentials` table with independent storage and explicit activation.

## Decision

### 1. Emergency Access — Local Admin Accounts (Break-Glass)

**Definition:** Explicitly provisioned local administrator accounts that remain functional when external identity providers fail. These are NORMAL local users with `isUserAdmin=True` and `isLdap=False`, not the disaster recovery emergency accounts defined in ADR-0014.

**Characteristics:**
- **Explicit designation:** Must be created with `isUserAdmin=True` by authorized administrator
- **Local authentication:** Authenticate against `User.password` (bcrypt), independent of LDAP
- **Strong credentials:** Must use strong, independently managed passwords (not default)
- **MFA support:** Can be enrolled in TOTP 2FA independently of LDAP
- **Subject to crypto requirements:** Must satisfy master password vault unlock before accessing credentials
- **Audit events:** Logged with `auth.login.emergency` event type
- **Credential rotation:** Documented rotation and recovery procedures
- **Emergency-only:** Reserved for emergency access, not routine administration

**Initial Installation:**
- First-time installation creates one authorized local admin account
- Administrator must save credentials securely (not in code, not in logs)

**Additional Accounts:**
- Emergency accounts must be explicitly provisioned via `/api/v1/users` or admin interface
- Each account must be documented (who created it, why)

**Relationship to ADR-0014:** For disaster recovery scenarios where the entire application host or database is compromised, ADR-0014 defines a separate `emergency_credentials` table with independent storage. The accounts defined here are normal local admins; the ADR-0014 accounts are for when these normal local admins cannot be used (e.g., host loss, DB loss, master password loss).

### 2. Normal Administrator Provisioning

**Mechanism 1: Explicit Assignment**
- Existing authorized administrator creates new admin account
- Sets `isUserAdmin=True` explicitly
- Records creation in audit log

**Mechanism 2: LDAP Group Mapping**
- LDAP group membership determines admin privileges
- **Must be explicitly configured** (not implicit on first login)
- **Must be auditable** (group membership change → privilege change)
- **Must be revocable** (group removal → privilege loss)

**Prohibited:**
- Automatic admin provisioning on first LDAP login
- Admin privileges based on `isLdap=True` alone
- Group membership inference without explicit configuration

### 3. Authentication Provider Binding

**Identity Provider Types:**
- **Local Identity:** `isLdap=False`, authenticates against `User.password`
- **LDAP Identity:** `isLdap=True`, authenticates against LDAP server

**Binding Rules:**
- Each `User` has exactly one authentication provider (local OR LDAP)
- **No provider fallback:** LDAP failure → reject, no local auth attempt
- **Provider migration:** Must be explicit (LDAP→Local or vice versa)
- **Audit trail:** Provider change logged with reason and author

**Provider Switching:**
- Admin must explicitly change `User.isLdap` flag
- Old provider credentials invalidated (security boundary)
- Audit log entry required

### 4. LDAP Availability and Failure Handling

**LDAP Failure Scenarios:**

| Scenario | Expected Behavior |
|----------|-------------------|
| LDAP server unavailable | LDAP-bound accounts fail; local accounts work |
| Invalid LDAP credentials | LDAP-bound account fails; no local fallback |
| Disabled LDAP account | LDAP-bound account fails; no access |
| Revoked LDAP group membership | LDAP-bound account fails (group check fails) |
| LDAP timeout | LDAP-bound account fails after timeout |

**Emergency Access:**
- Break-glass admins can authenticate locally regardless of LDAP status
- Break-glass admins can access admin interface
- Break-glass admins must still satisfy MFA and crypto requirements

**Session Handling:**
- LDAP sessions expire when LDAP becomes unavailable
- Local sessions (break-glass) are unaffected
- Session revocation policy documented in ADR-0005

### 5. Master Password Restrictions

**What Master Password Does NOT Do:**
- **Never establishes identity:** Cannot authenticate on its own
- **Never grants admin privileges:** `isUserAdmin` must be set explicitly
- **Never substitutes for admin credentials:** Admin must have own password
- **Never bypasses MFA:** TOTP requirement still applies if enrolled
- **Never overrides authorization:** ACL still enforced via `UserProfile`
- **Never auto-grants all credentials:** Vault unlock only, not credential access

**What Master Password DOES Do:**
- Decrypts `User.mPass`/`User.mKey` to obtain vault key
- Enables decryption of account passwords
- Required before accessing any vaulted credentials

**Security Boundary:**
- Master password is cryptographic material, not identity factor
- Even admin must unlock vault with master password first
- Master password rotation requires explicit admin action

### 6. Security Invariants

| Invariant | Description |
|-----------|-------------|
| Provider binding | Each user has exactly one auth provider (local or LDAP) |
| No fallback | LDAP failure → reject, no local auth attempt |
| Break-glass independence | Local admins work when LDAP fails |
| Master password separation | Crypto unlock ≠ identity auth |
| Admin explicit | `isUserAdmin` must be set explicitly, not inferred |
| Audit trail | All provider changes logged |
| Emergency access | Break-glass admins can access admin interface when needed |

### 7. Compatibility Constraints

**PHP Compatibility:**
- PHP allows master password vault unlock without identity auth
- PHP allows implicit admin group mapping on LDAP login
- Our implementation MUST NOT replicate these (security hardening)

**Migration Path:**
- Existing LDAP users with local passwords: migrate to explicit provider
- Existing admin users: retain `isUserAdmin` flags
- Master password: keep as crypto unlock mechanism only

### 8. Required Verification Tests

| Test | Description |
|------|-------------|
| LDAP-failure-break-glass | Local admin works when LDAP fails |
| LDAP-failure-no-local-fallback | LDAP account fails without local fallback |
| Provider-explicit-only | Provider change requires explicit admin action |
| Master-password-not-admin | Master password alone cannot authenticate |
| Break-glass-MFA-supported | Break-glass admin can enroll in MFA |
| Group-mapping-explicit | LDAP group mapping must be configured explicitly |
| Disabled-account-rejected | Disabled accounts cannot authenticate |

## Consequences

### Operational

- Administrators must create emergency accounts explicitly
- Break-glass credentials must be documented and rotated
- LDAP administrators must configure group mappings explicitly

### Development

- New auth features must respect provider binding
- No code can assume LDAP fallback or master password identity

### Security

- Reduced attack surface (no silent fallbacks)
- Clear audit trail of provider changes
- Break-glass accounts are auditable and revocable

## References

- `docs/adr/0003-identity-authentication-mfa-and-cryptographic-unlocking.md`: Authentication hierarchy
- `docs/adr/0002-bidirectional-database-interoperability-and-extension-isolation.md`: Database compatibility
- `app/services/ldap_service.py`: Current LDAP implementation
- `app/models/account.py`: User model with provider flags
