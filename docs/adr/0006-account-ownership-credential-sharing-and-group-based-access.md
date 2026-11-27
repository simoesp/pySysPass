# ADR-0006 — Account Ownership, Credential Sharing and Group-Based Access

## Status

**Status:** Active

## Context

sysPass uses multiple fields and tables to manage account ownership, sharing, and permissions. The current implementation conflates ownership (who created the account) with authorization (who can access it). This ADR clarifies the intended semantics.

## Decision

### 1. Account Ownership Semantics

**`Account.userId` — Account Owner**
- Represents the user who created the account
- Grants automatic view/edit access
- Subject to `isPrivate`/`isPrivateGroup` flags
- **Not** automatically transferable on edit

**`Account.userEditId` — Last Editor**
- Represents the user who last edited the account
- Updated on every `update_account()` call (line 645)
- **Does not** grant special privileges
- **Does not** imply ownership transfer

**Key Distinction:**
- `userId` = ownership (creator)
- `userEditId` = last modification (editor)
- These are **distinct concepts**; editing does not transfer ownership

### 2. Authorization Model

**Ownership Grants:**
- Owner (`userId == current_user.id`) can view/edit/delete own accounts
- Subject to `isPrivate` visibility rules
- Can add users/groups via sharing

**Group-Based Access:**
- User's primary group (`userGroupId`) can see all accounts in that group
- Secondary groups require `accountFullGroupAccess` config
- Group membership grants visibility, not ownership

**Individual Sharing:**
- `AccountToUser` table grants explicit sharing
- `isEdit` bit determines view-only vs edit access
- Revocable by owner or group admin

**Group Sharing:**
- `AccountToUserGroup` table grants group-based sharing
- `isEdit` bit determines view-only vs edit access
- Applies to all users in the shared group

**ACL Evaluation Order (Object-Level Access):**
1. Admin check (`isAdminApp`/`isAdminAcc`) — bypasses ALL checks (view/edit/delete)
2. Owner check (`userId == current_user.id`) — grants edit
3. Private check — reject private accounts (ADMIN BYPASS: admins can access but not list)
4. Primary group check — grants edit if in same group
5. Individual share check (`AccountToUser`) — grants access with `isEdit`
6. Group share check (`AccountToUserGroup`) — grants access if in shared group

**ACL Evaluation Order (Listing/Search):**
1. Admin check — admins can search if `accGlobalSearch` permission granted
2. Private check — private accounts filtered out
3. Primary group check — only show accounts in user's group
4. Global search config — when enabled, drops ownership/group filter

### 3. Sharing Semantics

**Individual Sharing Requirements:**
- Requires explicit authorization (owner or group admin)
- Must respect performer's profile permissions
- Creates `AccountToUser` entry with `isEdit` flag
- Revocable by owner or group admin

**Prohibited Actions by Shared Users:**
- Cannot transfer ownership
- Cannot modify ACL (add/remove other shared users)
- Cannot delete account
- Cannot share with additional users unless `isEdit=True`

**Group Sharing Requirements:**
- Requires explicit authorization
- Creates `AccountToUserGroup` entry with `isEdit` flag
- Applies to all group members
- Revocable by owner or group admin

### 4. Group-Based Access

**Primary Group Membership:**
- User's `userGroupId` grants access to all accounts in that group
- Applies to both `userId` and `userGroupId` columns

**Secondary Group Membership:**
- Applies only when `accountFullGroupAccess` is enabled
- Grants visibility but not edit access

**Membership Revocation:**
- User removed from group → immediate loss of group-based access
- Existing sessions are revoked (not cached)
- Audit log records revocation

**Group Deletion:**
- All accounts in group remain in database
- `userGroupId` becomes orphaned
- Accounts may become private (no group to share with)
- Audit log records group deletion

### 5. Ownership Lifecycle

**Owner Leaves Organization:**
- Account remains with original `userId`
- Owner can be removed from group
- Ownership cannot be auto-transferred

**Owner is Disabled:**
- Account remains accessible to other authorized users
- `isPrivate` flag still applies
- Owner cannot edit/delete own account while disabled

**Owner is Deleted:**
- **Prohibited:** Cannot delete user without handling their accounts
- **Required:** Transfer ownership or reassign accounts first
- Admin must explicitly handle orphaned accounts

**Ownership Transfer:**
- Requires explicit admin operation
- Admin updates `Account.userId` to new owner
- Audit log records transfer
- Old owner loses ownership privileges

**Orphaned Accounts:**
- Accounts with no authorized users
- `userId` points to non-existent user
- Admin can reassign to new owner
- Audit log required

### 6. Favorites

**Definition:** User-specific organizational preference

**Not Authorization:**
- Adding to favorites does NOT grant access
- Revoking access prevents disclosure through favorites
- Search results reflect current ACL, not favorites

**Storage:**
`AccountToFavorite` table (primary key: `accountId`, `userId`)

**Semantics:**
- Read-only user preference
- No edit bit (implicit view-only)
- Does not imply ownership

### 7. Security Invariants

| Invariant | Description |
|-----------|-------------|
| Ownership distinct from editing | `userId` ≠ `userEditId` |
| Ownership not auto-transfer | Edit doesn't change `userId` |
| Sharing requires authorization | Cannot share without permission |
| Group membership revocable | Removed users lose access immediately |
| Favorites are preferences | Not authorization mechanism |
| Admin bypass object-level ACL | Admins can access private accounts but not list them |
| Admin bypass requires master_pass | Admins need master_pass for credential decryption |
| Admin listing restricted | Admins need `accGlobalSearch` permission for global search |
| ACL enforced server-side | No client-side bypass |

### 8. Compatibility Constraints

**PHP Compatibility:**
- PHP uses same table structure
- PHP's `compileAccountAccess()` evaluates same conditions
- Our implementation mirrors PHP's ACL logic

**Migration Path:**
- Existing accounts retain original `userId` as owner
- `userEditId` updates on edit
- Sharing tables preserved

### 9. Required Verification Tests

| Test | Description |
|------|-------------|
| Ownership-not-transferred-on-edit | Editing account doesn't change `userId` |
| Owner-can-edit-own-account | `userId` owner has edit access |
| Non-owner-can-view-own-account | User can view accounts owned by others (if shared) |
| Sharing-revocation-immediate | Removed user loses access immediately |
| Group-deletion-preserves-accounts | Deleted group leaves accounts intact |
| Favorites-no-access-grant | Favorite doesn't grant view access |
| Admin-transfer-ownership | Admin can transfer ownership explicitly |
| Orphaned-account-handling | Admin must handle orphaned accounts |

## Consequences

### Operational

- Administrators must handle ownership transfers explicitly
- Group membership changes immediately affect access
- Favorites are purely organizational

### Development

- Code must distinguish ownership from editing
- ACL checks must follow evaluation order

### Security

- Clear separation of ownership and authorization
- Reduced risk of accidental privilege escalation

## References

- `app/services/account_service.py`: Account service implementation
- `app/models/account.py`: Account model definitions
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`: Authorization model
