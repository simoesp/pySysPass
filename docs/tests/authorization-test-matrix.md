# Account Ownership and Sharing Test Matrix

## Purpose

Document all authorization scenarios for account ownership, sharing, and permissions. This matrix serves as a contract for implementing and testing the authorization model.

## Test Cases

### Ownership Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_OWN_01 | User creates account | `userId=userEditId=current_user.id` | `create_account()` |
| T_OWN_02 | User edits own account | `userId` unchanged, `userEditId` updated | `update_account()` |
| T_OWN_03 | User edits other's account (via share) | `userId` unchanged, `userEditId` updated | `update_account()` |
| T_OWN_04 | User deletes own account | Account deleted, no error | `delete_account()` |
| T_OWN_05 | User deletes other's account | Error: not owner | `delete_account()` |
| T_OWN_06 | Non-owner views own-account | Visible (if shared or global search) | `get_accounts()` |
| T_OWN_07 | Owner views own accounts | All visible, including private | `get_accounts()` |
| T_OWN_08 | Owner copies own account | New account with `userId=copying_user.id` | `copy_account()` |

### Sharing Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_SHARE_01 | Owner shares with user | `AccountToUser` entry created | `set_user_access()` |
| T_SHARE_02 | Owner shares with group | `AccountToUserGroup` entry created | `set_group_access()` |
| T_SHARE_03 | Owner removes user share | `AccountToUser` deleted | `remove_user_access()` |
| T_SHARE_04 | Owner removes group share | `AccountToUserGroup` deleted | `remove_group_access()` |
| T_SHARE_05 | Shared user edits account (isEdit=True) | Account edited, `userEditId` updated | `update_account()` |
| T_SHARE_06 | Shared user views account (isEdit=False) | Account visible, read-only | `get_account()` |
| T_SHARE_07 | Non-shared user views shared account | Not visible | `get_accounts()` |
| T_SHARE_08 | Shared user tries to transfer ownership | Error: requires admin | N/A |
| T_SHARE_09 | Shared user tries to delete account | Error: not owner | `delete_account()` |
| T_SHARE_10 | Shared user tries to add new shares | Error: not owner/admin | N/A |
| T_SHARE_11 | Shared user shares with additional user | Error: not owner/admin | N/A |
| T_SHARE_12 | Group member accesses via group share | Visible if in shared group | `get_accounts()` |

### Group-Based Access Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_GROUP_01 | User in primary group | All accounts in group visible | `get_accounts()` |
| T_GROUP_02 | User in secondary group (full access) | All accounts in all groups visible | `get_accounts()` |
| T_GROUP_03 | User removed from group | Immediate access loss | `get_accounts()` |
| T_GROUP_04 | Group deleted | Accounts remain, orphaned | N/A |
| T_GROUP_05 | User's group is account's group | Edit access granted | `_can_edit_account()` |
| T_GROUP_06 | User's group ≠ account's group | No edit access | `_can_edit_account()` |
| T_GROUP_07 | User in group with edit share | Edit access via `isEdit` | `_can_edit_account()` |
| T_GROUP_08 | Group share revocation | Access lost immediately | `remove_group_access()` |

### Ownership Transfer Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_TRANSFER_01 | Admin transfers ownership | `userId` updated, audit logged | Admin operation |
| T_TRANSFER_02 | Non-admin tries to transfer | Error: insufficient privilege | N/A |
| T_TRANSFER_03 | Owner tries to transfer | Error: owner cannot self-transfer | N/A |
| T_TRANSFER_04 | Old owner after transfer | Loses ownership privileges | N/A |
| T_TRANSFER_05 | New owner after transfer | Full ownership privileges | `get_accounts()` |
| T_TRANSFER_06 | Transfer to deleted user | Error: user must exist | N/A |

### Favorites Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_FAV_01 | User adds account to favorites | `AccountToFavorite` entry created | `toggle_favorite()` |
| T_FAV_02 | User removes favorite | `AccountToFavorite` deleted | `toggle_favorite()` |
| T_FAV_03 | Favorite grants access | Error: favorites not authorization | N/A |
| T_FAV_04 | Favorite visible to non-owner | Not visible | `get_accounts()` |
| T_FAV_05 | Favorite in search results | Not shown | `search_accounts()` |
| T_FAV_06 | Owner favorite | Visible to owner | `get_account()` |

### Admin Privilege Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_ADMIN_01 | Admin views all accounts | All accounts visible | `get_accounts()` |
| T_ADMIN_02 | Admin edits any account | Edit permitted | `update_account()` |
| T_ADMIN_03 | Admin deletes any account | Delete permitted | `delete_account()` |
| T_ADMIN_04 | Admin views private account | Visible | `get_account()` |
| T_ADMIN_05 | Admin creates account | Account created with `userId=admin.id` | `create_account()` |
| T_ADMIN_06 | Admin shares account | Share permitted | `set_user_access()` |
| T_ADMIN_07 | Admin transfers ownership | Ownership transfer permitted | Admin operation |
| T_ADMIN_08 | Admin without master_pass | Cannot decrypt passwords | `get_decrypted_password()` |

### Permission Combination Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_COMBINE_01 | Owner + ACL share | Owner privileges (ACL redundant) | `get_account()` |
| T_COMBINE_02 | Shared user + profile edit | Edit permitted (both satisfied) | `update_account()` |
| T_COMBINE_03 | Shared user + profile view-only | View permitted, edit denied | `get_account()` |
| T_COMBINE_04 | Group member + profile edit | Edit permitted | `update_account()` |
| T_COMBINE_05 | Group member + profile view-only | View permitted | `get_account()` |
| T_COMBINE_06 | Profile edit + no ACL access | Edit denied (ACL fails) | `update_account()` |
| T_COMBINE_07 | Profile view + no ACL access | View denied (ACL fails) | `get_accounts()` |
| T_COMBINE_08 | Admin + profile restriction | Admin overrides profile | `get_accounts()` |

### Private Account Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_PRIVATE_01 | Owner views private account | Visible | `get_account()` |
| T_PRIVATE_02 | Shared user views private account | Visible (if shared) | `get_account()` |
| T_PRIVATE_03 | Non-shared views private | Not visible | `get_accounts()` |
| T_PRIVATE_04 | Private group member views | Visible (if in group) | `get_accounts()` |
| T_PRIVATE_05 | Admin views private | Visible | `get_account()` |

### Security Tests

| Test ID | Scenario | Expected Behavior | Code Path |
|---------|----------|-------------------|-----------|
| T_SEC_01 | Shared user requests password | Requires master_pass | `get_decrypted_password()` |
| T_SEC_02 | Non-shared user requests password | Access denied | `get_decrypted_password()` |
| T_SEC_03 | Admin requests all passwords | Requires master_pass | `get_decrypted_password()` |
| T_SEC_04 | Shared user copies account | Error: not owner | `copy_account()` |
| T_SEC_05 | Shared user changes owner | Error: not owner | `update_account()` |
| T_SEC_06 | Shared user removes other shares | Error: not owner/admin | N/A |
| T_SEC_07 | Shared user shares with others | Error: not owner/admin | N/A |
| T_SEC_08 | Shared user deletes account | Error: not owner | `delete_account()` |

## Implementation Notes

### Authorization Check Order (Object-Level Access)

```python
# 1. Admin check (bypasses ALL checks)
if _is_admin(user_id):
    return True

# 2. Owner check
if account.userId == user_id:
    return True

# 3. Private check (admin bypass: can access but not list)
if account.isPrivate:
    if not _is_admin(user_id):
        return False

# 4. Primary group check
if account.userGroupId == user.userGroupId:
    return True

# 5. Individual share check
if shared_user and shared_user.isEdit:
    return True

# 6. Group share check
if shared_group.isEdit:
    return True

# 7. Default deny
return False
```

### ACL Evaluation Order (Listing/Search)

```python
# 1. Admin check (can search if accGlobalSearch permission)
if _is_admin(user_id) and global_search_enabled:
    return True

# 2. Private filter (exclude private accounts)
if account.isPrivate:
    return False

# 3. Primary group filter
if account.userGroupId != user.userGroupId:
    return False

# 4. Global search config
if global_search_enabled:
    return True

# 5. Default deny
return False
```

## Verification Requirements

- All test cases must pass in test suite
- Test coverage ≥ 90% for authorization paths
- Security tests must be run in isolated environment
- Admin operations require audit logging
- Effective permission tests must verify combination rules

## Test Summary

**Total unique test scenarios:** 69 (consolidated from 9 categories)

**Consolidated test IDs:**
- T_OWN_01 to T_OWN_08: Ownership tests (8 tests)
- T_SHARE_01 to T_SHARE_12: Sharing tests (12 tests)
- T_GROUP_01 to T_GROUP_08: Group-based access tests (8 tests)
- T_TRANSFER_01 to T_TRANSFER_06: Ownership transfer tests (6 tests)
- T_FAV_01 to T_FAV_06: Favorites tests (6 tests)
- T_ADMIN_01 to T_ADMIN_08: Admin privilege tests (8 tests)
- T_COMBINE_01 to T_COMBINE_08: Permission combination tests (8 tests)
- T_PRIVATE_01 to T_PRIVATE_05: Private account tests (5 tests)
- T_SEC_01 to T_SEC_08: Security tests (8 tests)

**Effective permission tests (new):**
- T_EFFECTIVE_01 to T_EFFECTIVE_07: Permission combination and conflict resolution

## Related Documents

- `docs/adr/0006-account-ownership-credential-sharing-and-group-based-access.md`
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`
- `app/services/account_service.py`
- `app/models/account.py`
