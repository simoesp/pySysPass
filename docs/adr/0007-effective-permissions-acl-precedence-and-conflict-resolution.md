# ADR-0007 — Effective Permissions, ACL Precedence and Conflict Resolution

## Status

**Status:** Active

## Context

pySysPass must combine multiple permission sources into a single effective permission for each operation. The original PHP implementation uses `compileAccountAccess()` to determine edit/view permissions. This ADR establishes the intended resolution model.

## Decision

### 1. Permission Sources

| Source | Description | Grants |
|--------|-------------|--------|
| **Account Ownership** | `userId == current_user.id` | Full access (view/edit/delete) |
| **Primary Group Membership** | `userGroupId == account.userGroupId` | View + edit (for group accounts) |
| **Individual ACL** | `AccountToUser` entry | View/edit per `isEdit` flag |
| **Group ACL** | `AccountToUserGroup` entry | View/edit per `isEdit` flag |
| **Profile Permission** | `UserProfile.permissions` | Functional capabilities |
| **System Admin** | `isUserAdmin=True` | Bypass most checks (except listing private) |
| **Account Admin** | `is_admin_acc=True` | Account management capabilities |

### 2. Evaluation Model

**Two-phase evaluation:**

**Phase 1: Access Grant (can I access this account?)**

```
1. Admin bypass → True (except private listing)
2. Owner → True
3. Private filter → False (ADMIN BYPASS: can access but not list)
4. Primary group match → True
5. Individual ACL → True if `isEdit=True`
6. Group ACL → True if `isEdit=True`
7. Default → False
```

**Phase 2: Permission Level (what can I do?)**

```
1. Admin bypass → All permissions
2. Owner → Full permissions
3. ACL `isEdit=True` → Edit permissions
4. ACL `isEdit=False` → View-only permissions
5. Profile permission → Functional capability check
```

### 3. Permission Combination Rules

**Additive Model:**

Multiple permission sources are combined; the highest privilege wins.

| Scenario | Resolution | Rationale |
|----------|------------|-----------|
| Read-only via group A + Edit via group B | Edit | Highest privilege wins |
| Edit ACL + Profile view-only | Edit | ACL permission overrides profile |
| Owner + Profile restrict | Owner | Ownership overrides profile |
| Admin + Profile restrict | Admin | Admin bypasses profile |
| Group member + Individual share | Both apply | User can access via either path |

**Conflict Resolution:**

| Conflict Type | Resolution | Example |
|---------------|-------------|---------|
| Higher privilege path available | Use highest | Group A (read) + Group B (edit) → edit |
| ACL permission > Profile restriction | Use ACL | ACL edit > Profile view-only |
| Ownership > Profile restriction | Use ownership | Owner can edit despite profile |
| Admin > All restrictions | Use admin | Admin bypasses all |
| Individual share > Group membership | Use individual | Individual share takes precedence |

### 4. Specific Scenarios

**Scenario 1: Multiple Group Memberships**

```
User in:
  - Group A (primary): account's primary group → edit
  - Group B (secondary): account's primary group → edit (if accountFullGroupAccess)

Result: Edit access (both grant edit)
```

**Scenario 2: ACL Overrides Group Membership**

```
User in:
  - Group A (primary): account's primary group → would grant edit
  - Individual share: isEdit=False → view-only

Result: View-only (ACL short-circuits group)
```

**Scenario 3: Profile Restriction vs ACL Permission**

```
User has:
  - ACL: isEdit=True (can edit)
  - Profile: acc_edit=False (cannot edit)

Result: Edit (ACL permission overrides profile)
```

**Scenario 4: Owner with Restrictive Profile**

```
User is:
  - Account owner (userId == user.id)
  - Profile: acc_edit=False

Result: Edit (ownership overrides profile)
```

**Scenario 5: Admin with Profile Restriction**

```
User has:
  - isUserAdmin=True
  - Profile: acc_edit=False

Result: Edit (admin bypasses profile)
```

**Scenario 6: Group Member Loses Membership**

```
User was:
  - In Group A (primary group match)
  - Also has individual share (isEdit=True)

User removed from Group A:

Result: Still has access via individual share
```

**Scenario 7: Session Persistence After Revocation**

```
User has:
  - Active session with JWT
  - ACL revoked (share deleted)

Result: Session revoked on next request (no caching)
```

### 5. Private Account Special Case

```
User: Admin, isUserAdmin=True
Account: isPrivate=True

Phase 1 (Access Grant):
  - Admin bypass → Access granted

Phase 2 (Permission Level):
  - Admin → Full permissions (view/edit/delete)

Phase 3 (Listing):
  - Private filter → Account NOT shown in search/listing
```

### 6. Security Invariants

| Invariant | Description |
|-----------|-------------|
| Highest privilege wins | Multiple sources combine to highest |
| ACL overrides profile | Resource-level > functional |
| Ownership overrides profile | Ownership > profile restrictions |
| Admin bypasses restrictions | Admin > all profile/ACL limits |
| Individual share short-circuits group | Explicit share > group membership |
| ACL revocation immediate | No session caching |
| Private accounts admin-accessible | Admin can access but not list |

### 7. PHP Compatibility

**PHP `compileAccountAccess()` behavior:**

1. Admin bypass (view+edit)
2. Owner bypass
3. Private filter (kept for listing)
4. Primary group match
5. Individual share (`isEdit`)
6. Group share (`isEdit`)

**Our implementation mirrors this exactly.**

### 8. Required Tests

| Test | Description |
|------|-------------|
| T_EFFECTIVE_01 | Multiple groups: highest privilege wins |
| T_EFFECTIVE_02 | ACL overrides profile restriction |
| T_EFFECTIVE_03 | Owner overrides profile restriction |
| T_EFFECTIVE_04 | Admin overrides profile restriction |
| T_EFFECTIVE_05 | Individual share short-circuits group |
| T_EFFECTIVE_06 | ACL revocation revokes session |
| T_EFFECTIVE_07 | Admin can access private but not list |

## Consequences

### Operational

- Profile permissions are not the final word; ACLs and ownership matter more
- Admins have broad access but still need master_pass for credentials
- Revocation is immediate, not cached

### Development

- Code must evaluate all permission sources
- Don't assume profile permissions alone determine access
- ACL evaluation order must be preserved

### Security

- Clear precedence rules prevent ambiguity
- Admin bypass is documented and limited
- Revocation is immediate, reducing exposure window

## References

- `docs/adr/0006-account-ownership-credential-sharing-and-group-based-access.md`
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`
- `app/services/account_service.py`: `_can_edit_account()` implementation
- PHP's `compileAccountAccess()` (documented in compatibility notes)
