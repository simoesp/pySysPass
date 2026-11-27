# ADR-0011 — Audit Logging and Accountability

## Status

**Status:** Active

## Context

Audit logging is essential for security monitoring, incident response, compliance, and accountability. This ADR establishes comprehensive audit logging requirements, accountability mechanisms, and documentation for the pySysPass authorization and access control model.

## Decision

### 1. Audit Event Model

**Event Categories:**

| Category | Description | Frequency |
|----------|-------------|-----------|
| Authentication | Login attempts, MFA, token issuance | Per request |
| Authorization | Permission denials, scope checks | Per request |
| Operations | CRUD operations on accounts | Per operation |
| Cryptographic | Vault unlock, encryption operations | Per operation |
| Administrative | Admin actions, token management | Per admin action |
| System | Configuration changes, errors | Per event |
| Network | Connection events, IP changes | Per connection |

**Event Structure:**
```python
{
    "event_id": "uuid",
    "timestamp": "ISO8601",
    "event_type": "enum",
    "severity": "info|warn|error",
    "actor": {
        "type": "user|service|admin|unknown",
        "id": "user_id|service_id",
        "username": "string",
        "token_type": "jwt|service|api|unknown"
    },
    "resource": {
        "type": "account|user|group|config|token",
        "id": "resource_id",
        "name": "resource_name"
    },
    "operation": {
        "action": "read|write|delete|export|admin",
        "scope": "array",
        "parameters": {"key": "value"}
    },
    "result": "success|denied|error",
    "error_message": "string|null",
    "ip_address": "string|null",
    "user_agent": "string|null",
    "session_id": "string|null",
    "service_id": "string|null",
    "request_id": "string",
    "metadata": {"key": "value"}
}
```

### 2. Required Audit Events

**Authentication Events:**

| Event | Trigger | Fields |
|-------|---------|--------|
| `AUTH_LOGIN_SUCCESS` | Successful login | `actor.id`, `ip_address`, `user_agent`, `mfa_verified`, `session_id` |
| `AUTH_LOGIN_FAILURE` | Failed login attempt | `actor.id`, `ip_address`, `reason`, `attempt_count` |
| `AUTH_MFA_ENROLL` | MFA enrollment | `actor.id`, `mfa_type`, `enrolled_at` |
| `AUTH_MFA_VERIFY` | MFA verification | `actor.id`, `mfa_type`, `verified`, `failure_count` |
| `AUTH_TOKEN_ISSUED` | Token creation | `actor.id`, `token_type`, `scopes`, `expires_at` |
| `AUTH_TOKEN_REVOKED` | Token revocation | `actor.id`, `token_id`, `reason`, `revoked_by` |
| `AUTH_SERVICE_CREATED` | Service account creation | `actor.id`, `service_id`, `owner_id`, `scopes` |
| `AUTH_SERVICE_TOKEN_ISSUED` | Service token creation | `actor.id`, `service_id`, `token_id`, `expires_at` |

**Authorization Events:**

| Event | Trigger | Fields |
|-------|---------|--------|
| `AUTHZ_CHECK` | Permission evaluation | `actor.id`, `resource.id`, `operation`, `granted`, `reason` |
| `AUTHZ_DENIED` | Permission denied | `actor.id`, `resource.id`, `operation`, `denied_by`, `reason` |
| `AUTHZ_SCOPE_CHECK` | Scope validation | `actor.id`, `requested_scope`, `granted_scope`, `match` |
| `AUTHZ_RESOURCE_RESTRICTION` | Resource restriction check | `actor.id`, `resource.id`, `restriction_type`, `passed` |

**Operation Events:**

| Event | Trigger | Fields |
|-------|---------|--------|
| `OP_ACCOUNT_CREATED` | Account creation | `actor.id`, `account.id`, `account.name`, `owner_id` |
| `OP_ACCOUNT_UPDATED` | Account update | `actor.id`, `account.id`, `fields_changed`, `previous_values` |
| `OP_ACCOUNT_DELETED` | Account deletion | `actor.id`, `account.id`, `account.name`, `reason` |
| `OP_ACCOUNT_SHARED` | Account sharing | `actor.id`, `account.id`, `shared_with`, `is_edit` |
| `OP_CREDENTIAL_RETRIEVED` | Credential access | `actor.id`, `account.id`, `method`, `vault_context_id` |
| `OP_CREDENTIAL_MODIFIED` | Credential change | `actor.id`, `account.id`, `previous_hash`, `new_hash` |
| `OP_CREDENTIAL_EXPORTED` | Credential export | `actor.id`, `accounts_count`, `export_format`, `exported_at` |
| `OP_GROUP_CREATED` | Group creation | `actor.id`, `group.id`, `group.name`, `member_limit` |
| `OP_GROUP_MEMBER_ADDED` | Group member added | `actor.id`, `group.id`, `user_id`, `role` |
| `OP_GROUP_MEMBER_REMOVED` | Group member removed | `actor.id`, `group.id`, `user_id`, `reason` |
| `OP_PROFILE_MODIFIED` | Profile update | `actor.id`, `user_id`, `profile_id`, `fields_changed` |

**Administrative Events:**

| Event | Trigger | Fields |
|-------|---------|--------|
| `ADMIN_USER_CREATED` | User creation | `actor.id`, `user.id`, `is_admin`, `admin_by` |
| `ADMIN_USER_DISABLED` | User disabled | `actor.id`, `user.id`, `reason`, `admin_by` |
| `ADMIN_USER_ENABLED` | User enabled | `actor.id`, `user.id`, `reason`, `admin_by` |
| `ADMIN_ADMIN_CREATED` | Admin creation | `actor.id`, `user.id`, `is_admin_acc`, `admin_by` |
| `ADMIN_TOKEN_CREATED` | Admin token creation | `actor.id`, `token_id`, `scopes`, `admin_id` |
| `ADMIN_CONFIG_CHANGED` | Configuration change | `actor.id`, `config_key`, `previous_value`, `new_value` |
| `ADMIN_BACKUP_CREATED` | Backup creation | `actor.id`, `backup_id`, `backup_type`, `timestamp` |
| `ADMIN_MASTER_PASSWORD_ROTATED` | Master password rotation | `actor.id`, `previous_hash`, `new_hash`, `rotated_by` |

**System Events:**

| Event | Trigger | Fields |
|-------|---------|--------|
| `SYSTEM_ERROR` | Application error | `error_type`, `error_message`, `stack_trace`, `request_id` |
| `SYSTEM_CONFIG_CHANGED` | Configuration change | `config_key`, `previous_value`, `new_value`, `changed_by` |
| `SYSTEM_SERVICE_STARTED` | Service start | `service_name`, `version`, `started_at`, `started_by` |
| `SYSTEM_SERVICE_STOPPED` | Service stop | `service_name`, `stopped_at`, `stopped_by`, `reason` |
| `SYSTEM_MAINTENANCE_MODE` | Maintenance mode | `enabled`, `enabled_by`, `reason` |
| `SYSTEM_BACKUP_COMPLETED` | Backup success | `backup_id`, `files_count`, `size_bytes`, `duration_ms` |
| `SYSTEM_BACKUP_FAILED` | Backup failure | `backup_id`, `error_type`, `error_message` |

### 3. Accountability Mechanisms

**Accountability Principles:**

1. **Uniqueness**: Every action traced to unique actor identity
2. **Non-repudiation**: Actions cannot be denied (tamper-proof logs)
3. **Completeness**: All significant events captured
4. **Timeliness**: Events logged near real-time
5. **Accuracy**: Correct event data recorded
6. **Durability**: Logs survive system failures

**Implementation:**

**Actor Identification:**
- Human users: `user.id`, `user.username`
- Service accounts: `service_id`, `service_name`
- API tokens: `token_id`, `token_type`
- Admin actions: `admin_by` field

**Resource Identification:**
- Account: `account.id`, `account.name`
- User: `user.id`, `user.username`
- Group: `group.id`, `group.name`
- Profile: `profile.id`, `profile.name`
- Token: `token.id`, `token.name`

**Temporal Accountability:**
- Every event has `timestamp` (ISO8601)
- Every action has `request_id` (traceability)
- Session tracking for multi-operation actions

**Tamper Resistance:**
- Audit logs stored separately from application data
- Immutable storage (WORM, append-only)
- Regular integrity verification
- Separate access controls for audit logs

### 4. Audit Log Storage

**Storage Strategy:**

| Storage | Purpose | Retention |
|---------|---------|-----------|
| Application logs (JSON) | Detailed event data | 90 days |
| Database audit table | Queryable events | 1 year |
| Immutable archive | Compliance retention | 7 years |

**Application Logs:**
```python
# Location: app/logs/audit.jsonl (JSON Lines format)
# Format: One event per line, no truncation

{
    "event_id": "evt_abc123",
    "timestamp": "2026-11-27T00:00:00Z",
    "event_type": "AUTH_LOGIN_SUCCESS",
    ...
}

{
    "event_id": "evt_def456",
    "timestamp": "2026-11-27T00:01:00Z",
    "event_type": "OP_ACCOUNT_CREATED",
    ...
}
```

**Database Audit Table:**
```sql
CREATE TABLE audit_events (
    event_id VARCHAR(64) PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    severity ENUM('info', 'warn', 'error') NOT NULL,
    actor_type ENUM('user', 'service', 'admin', 'unknown') NOT NULL,
    actor_id INT UNSIGNED,
    actor_username VARCHAR(255),
    token_type ENUM('jwt', 'service', 'api', 'unknown'),
    resource_type ENUM('account', 'user', 'group', 'config', 'token'),
    resource_id INT UNSIGNED,
    resource_name VARCHAR(255),
    operation_action VARCHAR(32),
    operation_scope JSON,
    operation_params JSON,
    result ENUM('success', 'denied', 'error'),
    error_message TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    session_id VARCHAR(128),
    service_id VARCHAR(64),
    request_id VARCHAR(64),
    metadata JSON,
    INDEX idx_timestamp (timestamp),
    INDEX idx_event_type (event_type),
    INDEX idx_actor (actor_type, actor_id),
    INDEX idx_resource (resource_type, resource_id),
    INDEX idx_result (result),
    INDEX idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Archive Strategy:**
```bash
# Daily archival to immutable storage
python -m app.audit_archive --date 2026-11-27 --output /var/log/syspass/audit/2026-11-27.jsonl

# Weekly compression
python -m app.audit_compress --from 2026-11-01 --to 2026-11-07

# Monthly archival to WORM storage
python -m app.audit_worm --month 2026-11 --storage s3://audit-archive/monthly/
```

### 5. Audit Query API

**Query Interface:**

```python
# Example: Query for all failed login attempts
from app.audit_service import AuditService

audit = AuditService(db)

# Query: All failed logins from specific IP
events = audit.query(
    event_type="AUTH_LOGIN_FAILURE",
    ip_address="192.168.1.100",
    from_timestamp="2026-11-27T00:00:00Z",
    to_timestamp="2026-11-27T23:59:59Z",
    limit=100
)

# Query: All admin actions by specific admin
events = audit.query(
    actor_username="admin1",
    from_timestamp="2026-11-27T00:00:00Z",
    to_timestamp="2026-11-27T23:59:59Z",
    limit=100
)

# Query: All credential exports
events = audit.query(
    event_type="OP_CREDENTIAL_EXPORTED",
    from_timestamp="2026-11-27T00:00:00Z",
    to_timestamp="2026-11-27T23:59:59Z",
    limit=100
)
```

**REST API:**
```
GET /api/v1/audit/events
GET /api/v1/audit/events/{event_id}
GET /api/v1/audit/events/search
GET /api/v1/audit/events/export
GET /api/v1/audit/events/{event_id}/raw
```

**Query Parameters:**
- `event_type`: Filter by event type
- `actor_type`: user, service, admin, unknown
- `actor_id`: Filter by actor ID
- `actor_username`: Filter by username
- `resource_type`: account, user, group, config, token
- `resource_id`: Filter by resource ID
- `operation_action`: read, write, delete, export, admin
- `ip_address`: Filter by IP
- `from_timestamp`: ISO8601 start time
- `to_timestamp`: ISO8601 end time
- `severity`: info, warn, error
- `result`: success, denied, error
- `limit`: Max results (default 100, max 1000)
- `offset`: Pagination offset
- `sort`: timestamp, event_type, actor_id, resource_id
- `order`: ASC, DESC
- `format`: json, csv, jsonl
- `export`: Full export with all fields

### 6. Alerting and Monitoring

**Alert Types:**

| Alert | Trigger | Severity | Action |
|-------|---------|----------|--------|
| Brute force | >10 failed logins from same IP | High | Lock account, alert admin |
| Admin action | Admin creates/disables user | Medium | Log, notify admin |
| Credential export | Export >100 credentials | High | Alert admin, log |
| Service token misuse | Service token accessing restricted resources | Medium | Alert admin |
| Mass modification | >10 accounts modified by same actor | Medium | Alert admin |
| Privilege escalation | User gaining admin access | Critical | Alert admin, freeze |
| Configuration change | Critical config modified | Medium | Log, notify admin |
| Backup failure | Backup failed | High | Alert admin |
| Audit log tampering | Audit log integrity check fails | Critical | Alert admin |
| Unusual access pattern | Anomalous access detected | Medium | Alert admin |

**Alert Delivery:**
- Email notifications
- Slack/Teams webhook
- PagerDuty integration
- Syslog forwarding
- Audit log review

### 7. Compliance and Retention

**Retention Policies:**

| Data Type | Retention | Storage |
|-----------|-----------|---------|
| Application logs | 90 days | `/app/logs/audit.jsonl` |
| Database audit events | 1 year | `audit_events` table |
| Immutable archive | 7 years | WORM storage |
| Compliance reports | 7 years | `/var/log/syspass/compliance/` |

**Legal Hold:**
- Administrative freeze on deletion
- Immutable storage
- Access-controlled retrieval
- Audit trail of access

**Compliance Requirements:**
- GDPR: Right to explanation
- SOC 2: Audit trail requirements
- PCI-DSS: Cardholder data access logging
- HIPAA: Protected health information access
- Custom: Industry-specific requirements

### 8. Security Properties

**Audit Log Protection:**

| Property | Implementation |
|----------|---------------|
| Integrity | HMAC signature, checksums |
| Confidentiality | Read-only for admins, encrypted at rest |
| Availability | Replicated storage, backup |
| Non-repudiation | Immutable storage, append-only |
| Tamper detection | Cryptographic signing, checksums |
| Access control | Role-based, audit-only roles |

**Audit Log Access:**

| Role | Permissions |
|------|-------------|
| `audit_viewer` | Read audit logs only |
| `audit_analyst` | Read audit logs, export, query |
| `audit_admin` | Full audit access, configuration |
| `sysadmin` | All permissions |

### 9. Documentation

**Required Documentation:**

1. **Audit Log Schema**: Complete event field definitions
2. **Event Dictionary**: All event types and meanings
3. **Retention Policy**: Retention periods and procedures
4. **Access Control**: Roles and permissions for audit access
5. **Query Guide**: Example queries for common use cases
6. **Alerting Guide**: Alert thresholds and delivery
7. **Compliance Guide**: Regulatory requirements and procedures
8. **Incident Response**: Audit log usage in incidents

**Documentation Location:**
- `docs/audit/audit-schema.md`
- `docs/audit/event-dictionary.md`
- `docs/audit/retention-policy.md`
- `docs/audit/access-control.md`
- `docs/audit/query-guide.md`
- `docs/audit/alerting.md`
- `docs/audit/compliance.md`
- `docs/audit/incident-response.md`

### 10. Implementation

**Phase 1: Audit Logging Infrastructure**
1. Create audit event model
2. Implement audit logging middleware
3. Create audit database tables
4. Implement audit query API
5. Create audit archive service

**Phase 2: Service Account Audit**
1. Service account creation events
2. Service token lifecycle events
3. Service vault context events
4. Service operation audit

**Phase 3: Admin Audit**
1. Admin action events
2. Admin configuration changes
3. Admin backup operations
4. Admin user management

**Phase 4: Compliance**
1. Retention policy implementation
2. Immutable archive setup
3. Access control implementation
4. Compliance reporting

### 11. Security Implications

**Audit Logging Security:**

- Audit logs must not contain credentials
- Audit logs must not contain secrets
- Audit logs must be read-only for most users
- Audit logs must be protected from modification
- Audit logs must be regularly reviewed
- Audit logs must be retained for compliance

**Threat Mitigation:**

- Brute force detection and alerting
- Unusual access pattern detection
- Admin action monitoring
- Configuration change tracking
- Service account misuse detection
- Credential export monitoring

### 12. Consequences

### Operational

- Comprehensive audit trail for all operations
- Improved security monitoring and incident response
- Compliance with regulatory requirements
- Better accountability and non-repudiation
- Audit log review required for security operations

### Development

- Audit logging in all API endpoints
- Audit event generation in service layer
- Database audit table maintenance
- Audit query API implementation
- Archive and retention automation

### Security

- Stronger accountability and non-repudiation
- Better threat detection and response
- Compliance with audit requirements
- Reduced attack surface through monitoring
- Improved incident investigation capabilities

## References

- `docs/adr/0003-identity-authentication-mfa-and-cryptographic-unlocking.md`
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`
- `docs/adr/0007-effective-permissions-acl-precedence-and-conflict-resolution.md`
- `docs/adr/0008-encryption-architecture-master-password-and-cryptographic-key-lifecycle.md`
- `docs/adr/0009-session-architecture-api-token-lifecycle-and-server-side-vault-context.md`
- `docs/adr/0010-service-accounts-workload-identity-and-automated-credential-retrieval.md`
- `app/logs/audit.jsonl`: Audit log file
- `app/services/audit_service.py`: Audit service implementation

## Related Documents

- `docs/security/policy.md`: Security requirements
- `docs/backup-recovery.md`: Backup procedures
- `docs/installation.md`: Environment setup
- `scripts/php-interop-stack.sh`: PHP interoperability tests
