# Audit Event Dictionary

Complete reference of all audit event types and their meanings per ADR-0011.

## Authentication Events

### `AUTH_LOGIN_SUCCESS`
**Trigger:** Successful user authentication (password, SSO, or token)

**Fields:**
- `actor.id` - User ID
- `actor.username` - Username
- `ip_address` - Client IP
- `user_agent` - Client user agent
- `session_id` - Session identifier
- `metadata.mfa_verified` - Whether MFA was verified (boolean)
- `metadata.login_method` - Authentication method (password, sso, token)

**Severity:** `info`

---

### `AUTH_LOGIN_FAILURE`
**Trigger:** Failed authentication attempt

**Fields:**
- `actor.id` - User ID (if known)
- `actor.username` - Username attempted
- `ip_address` - Client IP
- `error_message` - Failure reason (invalid_password, user_not_found, account_disabled, mfa_failed, rate_limited)
- `metadata.attempt_count` - Consecutive failure count

**Severity:** `warn`

---

### `AUTH_MFA_ENROLL`
**Trigger:** User enrolls in multi-factor authentication

**Fields:**
- `actor.id` - User ID
- `actor.username` - Username
- `metadata.mfa_type` - MFA type (totp, webauthn, email)
- `metadata.enrolled_at` - Enrollment timestamp

**Severity:** `info`

---

### `AUTH_MFA_VERIFY`
**Trigger:** MFA verification attempt

**Fields:**
- `actor.id` - User ID
- `actor.username` - Username
- `metadata.mfa_type` - MFA type
- `metadata.verified` - Verification result (boolean)
- `metadata.failure_count` - Consecutive failures

**Severity:** `info` (success) / `warn` (failure)

---

### `AUTH_TOKEN_ISSUED`
**Trigger:** API token created for user or service

**Fields:**
- `actor.id` - Issuing user ID
- `actor.username` - Issuing username
- `resource.id` - Token ID
- `resource.name` - Token name
- `metadata.token_type` - Token type (user, service)
- `metadata.scopes` - Granted scopes array
- `metadata.expires_at` - Expiration timestamp

**Severity:** `info`

---

### `AUTH_TOKEN_REVOKED`
**Trigger:** API token revoked

**Fields:**
- `actor.id` - Revoking user ID
- `actor.username` - Revoking username
- `resource.id` - Token ID
- `metadata.reason` - Revocation reason
- `metadata.revoked_by` - Revoker username

**Severity:** `warn`

---

### `AUTH_SERVICE_CREATED`
**Trigger:** Service account created

**Fields:**
- `actor.id` - Creating user ID
- `actor.username` - Creating username
- `resource.id` - Service account ID
- `resource.name` - Service account name
- `metadata.owner_id` - Owner user ID
- `metadata.scopes` - Granted scopes array

**Severity:** `info`

---

### `AUTH_SERVICE_TOKEN_ISSUED`
**Trigger:** Service account token issued

**Fields:**
- `actor.id` - Issuing user ID
- `actor.username` - Issuing username
- `resource.id` - Token ID
- `resource.name` - Service account name
- `metadata.service_id` - Service account ID
- `metadata.expires_at` - Expiration timestamp

**Severity:** `info`

---

## Authorization Events

### `AUTHZ_CHECK`
**Trigger:** Permission evaluation for any protected resource

**Fields:**
- `actor.id` - Requesting user/service ID
- `actor.username` - Requesting username
- `resource.id` - Target resource ID
- `resource.name` - Target resource name
- `operation_action` - Operation attempted
- `metadata.granted` - Whether access was granted (boolean)
- `metadata.reason` - Grant/denial reason

**Severity:** `info`

---

### `AUTHZ_DENIED`
**Trigger:** Explicit permission denial

**Fields:**
- `actor.id` - Requesting user/service ID
- `actor.username` - Requesting username
- `resource.id` - Target resource ID
- `resource.name` - Target resource name
- `operation_action` - Operation attempted
- `metadata.denied_by` - Policy/rule that denied access
- `metadata.reason` - Denial reason

**Severity:** `warn`

---

### `AUTHZ_SCOPE_CHECK`
**Trigger:** OAuth/scope validation

**Fields:**
- `actor.id` - Requesting user/service ID
- `metadata.requested_scope` - Requested scope(s)
- `metadata.granted_scope` - Granted scope(s)
- `metadata.match` - Whether scopes match (boolean)

**Severity:** `info`

---

### `AUTHZ_RESOURCE_RESTRICTION`
**Trigger:** Resource-specific restriction check (ownership, group membership, etc.)

**Fields:**
- `actor.id` - Requesting user/service ID
- `resource.id` - Target resource ID
- `metadata.restriction_type` - Restriction type (ownership, group, private, etc.)
- `metadata.passed` - Whether restriction passed (boolean)

**Severity:** `info`

---

## Operation Events

### `OP_ACCOUNT_CREATED`
**Trigger:** New credential account created

**Fields:**
- `actor.id` - Creating user ID
- `actor.username` - Creating username
- `resource.id` - Account ID
- `resource.name` - Account name
- `metadata.owner_id` - Account owner ID

**Severity:** `info`

---

### `OP_ACCOUNT_UPDATED`
**Trigger:** Credential account modified

**Fields:**
- `actor.id` - Modifying user ID
- `actor.username` - Modifying username
- `resource.id` - Account ID
- `resource.name` - Account name
- `metadata.fields_changed` - Array of changed field names
- `metadata.previous_values` - Previous values (redacted for sensitive fields)

**Severity:** `info`

---

### `OP_ACCOUNT_DELETED`
**Trigger:** Credential account deleted

**Fields:**
- `actor.id` - Deleting user ID
- `actor.username` - Deleting username
- `resource.id` - Account ID
- `resource.name` - Account name
- `metadata.reason` - Deletion reason

**Severity:** `warn`

---

### `OP_ACCOUNT_SHARED`
**Trigger:** Account shared with user or group

**Fields:**
- `actor.id` - Sharing user ID
- `actor.username` - Sharing username
- `resource.id` - Account ID
- `resource.name` - Account name
- `metadata.shared_with` - Target user/group ID
- `metadata.is_edit` - Whether edit permission granted (boolean)

**Severity:** `info`

---

### `OP_CREDENTIAL_RETRIEVED`
**Trigger:** Credential (password, key) accessed/decrypted

**Fields:**
- `actor.id` - Accessing user ID
- `actor.username` - Accessing username
- `resource.id` - Account ID
- `resource.name` - Account name
- `metadata.method` - Retrieval method (api, ui, export)
- `metadata.vault_context_id` - Vault context identifier

**Severity:** `info`

---

### `OP_CREDENTIAL_MODIFIED`
**Trigger:** Credential value changed (password rotation, key update)

**Fields:**
- `actor.id` - Modifying user ID
- `actor.username` - Modifying username
- `resource.id` - Account ID
- `resource.name` - Account name
- `metadata.previous_hash` - Hash of previous credential (not the value)
- `metadata.new_hash` - Hash of new credential (not the value)

**Severity:** `warn`

---

### `OP_CREDENTIAL_EXPORTED`
**Trigger:** Credentials exported (bulk export)

**Fields:**
- `actor.id` - Exporting user ID
- `actor.username` - Exporting username
- `metadata.accounts_count` - Number of accounts exported
- `metadata.export_format` - Export format (csv, json, keepass, etc.)
- `metadata.exported_at` - Export timestamp

**Severity:** `warn`

---

### `OP_GROUP_CREATED`
**Trigger:** User group created

**Fields:**
- `actor.id` - Creating user ID
- `actor.username` - Creating username
- `resource.id` - Group ID
- `resource.name` - Group name
- `metadata.member_limit` - Member limit (if any)

**Severity:** `info`

---

### `OP_GROUP_MEMBER_ADDED`
**Trigger:** User added to group

**Fields:**
- `actor.id` - Adding user ID
- `actor.username` - Adding username
- `resource.id` - Group ID
- `resource.name` - Group name
- `metadata.user_id` - Added user ID
- `metadata.role` - Role in group (member, manager)

**Severity:** `info`

---

### `OP_GROUP_MEMBER_REMOVED`
**Trigger:** User removed from group

**Fields:**
- `actor.id` - Removing user ID
- `actor.username` - Removing username
- `resource.id` - Group ID
- `resource.name` - Group name
- `metadata.user_id` - Removed user ID
- `metadata.reason` - Removal reason

**Severity:** `info`

---

### `OP_PROFILE_MODIFIED`
**Trigger:** User profile updated

**Fields:**
- `actor.id` - Modifying user ID
- `actor.username` - Modifying username
- `resource.id` - Profile ID
- `resource.name` - User ID whose profile changed
- `metadata.fields_changed` - Array of changed field names

**Severity:** `info`

---

## Administrative Events

### `ADMIN_USER_CREATED`
**Trigger:** Administrator creates a new user

**Fields:**
- `actor.id` - Admin user ID
- `actor.username` - Admin username
- `resource.id` - Created user ID
- `resource.name` - Created username
- `metadata.is_admin` - Whether created user is admin (boolean)
- `metadata.admin_by` - Admin username who performed action

**Severity:** `warn`

---

### `ADMIN_USER_DISABLED`
**Trigger:** Administrator disables a user account

**Fields:**
- `actor.id` - Admin user ID
- `actor.username` - Admin username
- `resource.id` - Disabled user ID
- `resource.name` - Disabled username
- `metadata.reason` - Disablement reason
- `metadata.admin_by` - Admin username

**Severity:** `warn`

---

### `ADMIN_USER_ENABLED`
**Trigger:** Administrator enables a user account

**Fields:**
- `actor.id` - Admin user ID
- `actor.username` - Admin username
- `resource.id` - Enabled user ID
- `resource.name` - Enabled username
- `metadata.reason` - Enablement reason
- `metadata.admin_by` - Admin username

**Severity:** `info`

---

### `ADMIN_ADMIN_CREATED`
**Trigger:** Administrator grants admin privileges

**Fields:**
- `actor.id` - Granting admin ID
- `actor.username` - Granting admin username
- `resource.id` - User ID granted admin
- `resource.name` - Username granted admin
- `metadata.is_admin_acc` - Account admin flag
- `metadata.admin_by` - Granting admin username

**Severity:** `warn`

---

### `ADMIN_TOKEN_CREATED`
**Trigger:** Administrator creates an API token

**Fields:**
- `actor.id` - Admin user ID
- `actor.username` - Admin username
- `resource.id` - Token ID
- `resource.name` - Token name
- `metadata.scopes` - Token scopes array
- `metadata.admin_id` - Admin user ID

**Severity:** `warn`

---

### `ADMIN_CONFIG_CHANGED`
**Trigger:** System configuration modified

**Fields:**
- `actor.id` - Admin user ID
- `actor.username` - Admin username
- `resource.name` - Configuration key
- `metadata.config_key` - Configuration key
- `metadata.previous_value` - Previous value (redacted)
- `metadata.new_value` - New value (redacted)

**Severity:** `warn`

---

### `ADMIN_BACKUP_CREATED`
**Trigger:** Administrator initiates backup

**Fields:**
- `actor.id` - Admin user ID
- `actor.username` - Admin username
- `resource.id` - Backup ID
- `metadata.backup_type` - Backup type (full, incremental, config)
- `metadata.timestamp` - Backup timestamp

**Severity:** `info`

---

### `ADMIN_MASTER_PASSWORD_ROTATED`
**Trigger:** Master password rotated

**Fields:**
- `actor.id` - Rotating user ID
- `actor.username` - Rotating username
- `metadata.previous_hash` - Hash of previous master password
- `metadata.new_hash` - Hash of new master password
- `metadata.rotated_by` - Username who rotated

**Severity:** `warn`

---

## System Events

### `SYSTEM_ERROR`
**Trigger:** Application error/exception

**Fields:**
- `metadata.error_type` - Exception class name
- `metadata.error_message` - Error message
- `metadata.stack_trace` - Stack trace (truncated)
- `request_id` - Request identifier

**Severity:** `error`

---

### `SYSTEM_CONFIG_CHANGED`
**Trigger:** System-level configuration change (not admin-initiated)

**Fields:**
- `metadata.config_key` - Configuration key
- `metadata.previous_value` - Previous value
- `metadata.new_value` - New value
- `metadata.changed_by` - Process/service that changed it

**Severity:** `warn`

---

### `SYSTEM_SERVICE_STARTED`
**Trigger:** Service/process startup

**Fields:**
- `metadata.service_name` - Service name
- `metadata.version` - Version
- `metadata.started_at` - Start timestamp
- `metadata.started_by` - Process/user that started it

**Severity:** `info`

---

### `SYSTEM_SERVICE_STOPPED`
**Trigger:** Service/process shutdown

**Fields:**
- `metadata.service_name` - Service name
- `metadata.stopped_at` - Stop timestamp
- `metadata.stopped_by` - Process/user that stopped it
- `metadata.reason` - Shutdown reason

**Severity:** `info`

---

### `SYSTEM_MAINTENANCE_MODE`
**Trigger:** Maintenance mode toggled

**Fields:**
- `metadata.enabled` - Whether maintenance mode enabled (boolean)
- `metadata.enabled_by` - Username/process that toggled
- `metadata.reason` - Reason for maintenance

**Severity:** `warn`

---

### `SYSTEM_BACKUP_COMPLETED`
**Trigger:** Backup job completed successfully

**Fields:**
- `resource.id` - Backup ID
- `metadata.files_count` - Number of files backed up
- `metadata.size_bytes` - Backup size
- `metadata.duration_ms` - Backup duration

**Severity:** `info`

---

### `SYSTEM_BACKUP_FAILED`
**Trigger:** Backup job failed

**Fields:**
- `resource.id` - Backup ID
- `metadata.error_type` - Error type
- `metadata.error_message` - Error message

**Severity:** `error`