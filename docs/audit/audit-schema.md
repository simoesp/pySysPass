# Audit Log Schema

Complete event field definitions for the pySysPass audit logging system per ADR-0011.

## AuditEvent Table (`audit_events`)

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `event_id` | VARCHAR(64) | NO | Primary key, unique event identifier (format: `evt_<urlsafe>`) |
| `timestamp` | DATETIME | NO | Event timestamp in UTC |
| `event_type` | ENUM | NO | Event type from `AuditEventType` enum |
| `severity` | ENUM | NO | Severity: `info`, `warn`, `error` |
| `actor_type` | ENUM | NO | Actor type: `user`, `service`, `admin`, `unknown` |
| `actor_id` | INT UNSIGNED | YES | Actor user/service ID |
| `actor_username` | VARCHAR(255) | YES | Actor username |
| `token_type` | ENUM | YES | Token type: `jwt`, `service`, `api`, `unknown` |
| `resource_type` | ENUM | YES | Resource type: `account`, `user`, `group`, `config`, `token` |
| `resource_id` | INT UNSIGNED | YES | Resource ID |
| `resource_name` | VARCHAR(255) | YES | Resource name |
| `operation_action` | ENUM | YES | Operation: `read`, `write`, `delete`, `export`, `admin` |
| `operation_scope` | TEXT | YES | JSON array of scopes |
| `operation_params` | TEXT | YES | JSON object of parameters (redacted) |
| `result` | ENUM | NO | Result: `success`, `denied`, `error` |
| `error_message` | TEXT | YES | Error message if failed |
| `ip_address` | VARCHAR(45) | YES | Client IP address (IPv4 or IPv6) |
| `user_agent` | TEXT | YES | Client user agent string |
| `session_id` | VARCHAR(128) | YES | Session ID for traceability |
| `service_id` | VARCHAR(64) | YES | Service account ID |
| `request_id` | VARCHAR(64) | NO | Request ID for traceability (format: `req_<urlsafe>`) |
| `metadata` | TEXT | YES | JSON object of additional metadata (redacted) |
| `signature` | VARCHAR(128) | YES | HMAC-SHA256 signature for integrity |

## Indexes

| Index Name | Columns | Purpose |
|------------|---------|---------|
| `idx_audit_events_timestamp` | `timestamp` | Time-range queries |
| `idx_audit_events_event_type` | `event_type` | Filter by event type |
| `idx_audit_events_actor` | `actor_type`, `actor_id` | Actor-based queries |
| `idx_audit_events_resource` | `resource_type`, `resource_id` | Resource-based queries |
| `idx_audit_events_result` | `result` | Result-based filtering |
| `idx_audit_events_severity` | `severity` | Severity-based filtering |
| `idx_audit_events_session` | `session_id` | Session correlation |
| `idx_audit_events_request` | `request_id` | Request traceability |
| `idx_audit_events_ip` | `ip_address` | IP-based analysis |

## Integrity Protection

Each audit event includes an HMAC-SHA256 signature computed over the canonical JSON representation of the event data (excluding the signature field itself). The HMAC key is configured via the `AUDIT_HMAC_KEY` environment variable.

**Verification:**
```python
from app.services.audit_service import AuditService

audit = AuditService(db)
verified, failed = audit.verify_all_events(
    from_timestamp=datetime(2026, 11, 1),
    to_timestamp=datetime(2026, 11, 30)
)
```

## Redaction Rules

The following field patterns are automatically redacted (replaced with `[REDACTED]`) before storage:

- `password`, `pass`, `secret`, `token`, `key`, `hash`, `salt`
- `mfa_secret`, `mfa_code`, `totp`
- `private_key`, `api_key`, `access_token`, `refresh_token`
- `authorization`, `credential`, `master_password`
- `encryption_key`, `decryption_key`

Redaction is applied recursively to all JSON fields (`operation_params`, `metadata`).

## Event Type Enumeration

### Authentication Events
- `AUTH_LOGIN_SUCCESS` - Successful user login
- `AUTH_LOGIN_FAILURE` - Failed login attempt
- `AUTH_MFA_ENROLL` - MFA enrollment
- `AUTH_MFA_VERIFY` - MFA verification
- `AUTH_TOKEN_ISSUED` - API token issued
- `AUTH_TOKEN_REVOKED` - API token revoked
- `AUTH_SERVICE_CREATED` - Service account created
- `AUTH_SERVICE_TOKEN_ISSUED` - Service token issued

### Authorization Events
- `AUTHZ_CHECK` - Permission evaluation
- `AUTHZ_DENIED` - Permission denied
- `AUTHZ_SCOPE_CHECK` - Scope validation
- `AUTHZ_RESOURCE_RESTRICTION` - Resource restriction check

### Operation Events
- `OP_ACCOUNT_CREATED` - Account created
- `OP_ACCOUNT_UPDATED` - Account updated
- `OP_ACCOUNT_DELETED` - Account deleted
- `OP_ACCOUNT_SHARED` - Account shared
- `OP_CREDENTIAL_RETRIEVED` - Credential accessed
- `OP_CREDENTIAL_MODIFIED` - Credential changed
- `OP_CREDENTIAL_EXPORTED` - Credentials exported
- `OP_GROUP_CREATED` - Group created
- `OP_GROUP_MEMBER_ADDED` - Group member added
- `OP_GROUP_MEMBER_REMOVED` - Group member removed
- `OP_PROFILE_MODIFIED` - Profile updated

### Administrative Events
- `ADMIN_USER_CREATED` - User created by admin
- `ADMIN_USER_DISABLED` - User disabled by admin
- `ADMIN_USER_ENABLED` - User enabled by admin
- `ADMIN_ADMIN_CREATED` - Admin user created
- `ADMIN_TOKEN_CREATED` - Admin token created
- `ADMIN_CONFIG_CHANGED` - Configuration changed
- `ADMIN_BACKUP_CREATED` - Backup created
- `ADMIN_MASTER_PASSWORD_ROTATED` - Master password rotated

### System Events
- `SYSTEM_ERROR` - Application error
- `SYSTEM_CONFIG_CHANGED` - System configuration changed
- `SYSTEM_SERVICE_STARTED` - Service started
- `SYSTEM_SERVICE_STOPPED` - Service stopped
- `SYSTEM_MAINTENANCE_MODE` - Maintenance mode toggled
- `SYSTEM_BACKUP_COMPLETED` - Backup completed successfully
- `SYSTEM_BACKUP_FAILED` - Backup failed

## Example Event (JSON)

```json
{
  "event_id": "evt_abc123def456",
  "timestamp": "2026-11-27T10:30:00Z",
  "event_type": "AUTH_LOGIN_SUCCESS",
  "severity": "info",
  "actor_type": "user",
  "actor_id": 42,
  "actor_username": "jdoe",
  "token_type": "jwt",
  "resource_type": "user",
  "resource_id": 42,
  "resource_name": "jdoe",
  "operation_action": "read",
  "operation_scope": ["auth:login"],
  "operation_params": {"mfa_verified": true},
  "result": "success",
  "error_message": null,
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "session_id": "sess_xyz789",
  "service_id": null,
  "request_id": "req_abc123",
  "metadata": {"login_method": "password"},
  "signature": "a1b2c3d4e5f6..."
}
```