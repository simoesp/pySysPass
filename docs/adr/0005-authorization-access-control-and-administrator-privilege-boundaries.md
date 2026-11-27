# ADR-0005 — Authorization, Access Control and Administrator Privilege Boundaries

## Status

**Status:** Active

## Context

sysPass distinguishes between administrative privileges (system management) and credential access capabilities. The current implementation conflates these roles. This ADR establishes the intended authorization model with explicit separation of duties.

## Decision

### 1. Authorization Model

**Hybrid RBAC + ACL Model:**

pySysPass uses a hybrid model:
- **RBAC (Role-Based Access Control):** Profile permissions grant functional capabilities
- **ACL (Access Control List):** User/group ACLs determine resource-level access
- **Admin privileges:** System-wide administrative capabilities

**Observable Behaviour:**
Must remain compatible with sysPass PHP's ACL semantics. Internal implementation may differ, but external behaviour must match.

### 2. Administrator Privilege Boundaries

**System Administrator (`isUserAdmin=True`):**

| Capability | Granted? |
|------------|----------|
| Create users/groups/profiles | Yes |
| Configure application settings | Yes |
| Manage authentication providers | Yes |
| Perform maintenance tasks | Yes |
| Review audit logs | Yes |
| Manage backups/restore | Yes |
| **View all stored passwords** | **No** |
| **Export all credentials** | **No** |

**Account Administrator (`is_admin_acc=True`):**

| Capability | Granted? |
|------------|----------|
| Create/delete accounts | Yes |
| Edit account metadata | Yes |
| **View account passwords** | **Yes** (with vault unlock) |
| Share accounts with others | Yes |
| Manage account permissions | Yes |

**Key Distinction:**
- System admin manages the platform
- Account admin manages accounts
- Neither automatically grants unrestricted password access

### 3. Credential Access Requirements

**All conditions required for credential access:**

1. **Valid authenticated identity** — Successful login or API token
2. **MFA verification** — TOTP code if enrolled and enforced
3. **Profile permissions** — User has `acc_view`/`acc_view_pass` permission
4. **Resource-level authorization** — ACL allows access to specific account
5. **Cryptographic vault context** — Master password provided for decryption

**All five conditions must be satisfied.** Missing any one results in access denial.

**Examples:**
- Admin without master password → cannot decrypt passwords
- User with master password but no `acc_view_pass` → cannot view passwords
- User with profile permission but not in ACL → cannot access account

### 4. Granular Permissions

**Permission Matrix:**

| Permission | Description |
|------------|-------------|
| `acc_view` | List/search accounts (metadata only) |
| `acc_view_pass` | View password (decrypted) |
| `acc_edit` | Modify account metadata |
| `acc_edit_pass` | Change account password |
| `acc_add` | Create new accounts |
| `acc_delete` | Delete accounts |
| `acc_permission` | Manage account sharing/ACLs |
| `acc_private` | Create private accounts |
| `acc_private_group` | Create group-shared accounts |
| `acc_copy` | Copy accounts |

**Scope:**
Each permission is resource-level (user or group ACL determines which accounts).

### 5. Privilege Escalation Prevention

**Prohibited Actions:**

| Action | Reason |
|--------|--------|
| Modify own profile permissions | Self-modification bypasses audit |
| Add to privileged groups without admin approval | Privilege escalation |
| Change own account ownership | Ownership transfer without audit |
| Create privileged API tokens | Token creation requires admin privileges |
| Reset own credentials | Credential reset requires admin privileges |
| Export credentials without authorization | Bulk disclosure prevention |

**Required:**
All administrative changes must be audited and logged.

### 6. Authorization Path Trace

**API Request Flow:**

1. **Dependency check** (`app/api/deps.py`):
   - `get_current_user()` validates JWT/API token
   - Returns user dict with `is_admin_app`, `is_admin_acc`, `master_pass`

2. **Permission check** (`require_any_permission`):
   - Checks profile permissions via `_profile_permissions()`
   - Admins bypass profile check if `account_admin=True`

3. **Service layer** (`AccountService.get_accounts()`):
   - Query scoped to `current_user["id"]`
   - Filters by user/group ACLs

4. **SQL execution**:
   - WHERE clause filters by ownership/sharing
   - Admins see more but still filtered by ACL

5. **Credential decryption**:
   - Requires `master_pass` from JWT
   - Uses Defuse V2 to decrypt account password
   - Returns plaintext only to authorized caller

### 7. Security Invariants

| Invariant | Description |
|-----------|-------------|
| Deny by default | Unauthenticated requests denied |
| Least privilege | Users granted minimum permissions needed |
| No implicit admin access | Admin flag doesn't bypass ACL |
| Resource-level checks | Each account checked independently |
| MFA before crypto | Vault unlock after MFA |
| Audit privileged ops | All admin changes logged |
| Fail securely | Missing ACL → deny, not error |

### 8. Compatibility Constraints

**PHP Compatibility:**
- PHP uses profile permissions + user ACLs
- PHP's `is_admin` flag grants broad permissions but not unlimited password access
- Our implementation must match PHP's observable behaviour

**Migration Path:**
- Existing `isUserAdmin=True` users retain admin capabilities
- Existing profile permissions remain valid
- ACL checks apply to all users (including admins)

### 9. Required Verification Tests

| Test | Description |
|------|-------------|
| Admin-no-password-access | Admin cannot view passwords without master password |
| Admin-ACL-enforced | Admin ACL-restricted accounts denied |
| Profile-permission-required | Users without permissions denied |
| MFA-before-crypto | MFA enforced before vault unlock |
| Privilege-escalation-blocked | Self-modification of permissions denied |
| API-token-no-vault | API tokens cannot decrypt passwords |

## Consequences

### Operational

- Administrators must use master password to access credentials
- Profile permissions still apply even to admins
- Audit logs show all permission changes

### Development

- New authorization logic must respect all five conditions
- Admin flag is a convenience, not a bypass

### Security

- Reduced risk of credential disclosure
- Clear audit trail of privilege usage
- Separation of duties enforced

## References

- `docs/adr/0004-identity-provider-binding-administrator-provisioning-and-break-glass-access.md`: Administrator provisioning
- `docs/adr/0003-identity-authentication-mfa-and-cryptographic-unlocking.md`: Authentication hierarchy
- `app/api/deps.py`: Authorization dependency chain
- `app/api/v1/accounts.py`: Account endpoints and permission gates
