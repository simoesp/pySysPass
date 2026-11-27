# Audit Query Guide

Example queries for common audit log use cases per ADR-0011.

## API Query Examples

### Base URL
```
GET /api/v1/audit/events
POST /api/v1/audit/events/search
```

### Common Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | string | Filter by event type |
| `actor_type` | string | `user`, `service`, `admin`, `unknown` |
| `actor_id` | integer | Actor user/service ID |
| `actor_username` | string | Actor username |
| `resource_type` | string | `account`, `user`, `group`, `config`, `token` |
| `resource_id` | integer | Resource ID |
| `operation_action` | string | `read`, `write`, `delete`, `export`, `admin` |
| `ip_address` | string | Client IP address |
| `from_timestamp` | ISO8601 | Start time (e.g., `2026-11-27T00:00:00Z`) |
| `to_timestamp` | ISO8601 | End time |
| `severity` | string | `info`, `warn`, `error` |
| `result` | string | `success`, `denied`, `error` |
| `session_id` | string | Session ID |
| `request_id` | string | Request ID |
| `limit` | integer | Max results (1-1000, default 100) |
| `offset` | integer | Pagination offset |
| `sort` | string | Sort field |
| `order` | string | `ASC` or `DESC` |

---

## Common Use Cases

### 1. Failed Login Attempts (Brute Force Detection)

```bash
# All failed logins from specific IP
GET /api/v1/audit/events?event_type=AUTH_LOGIN_FAILURE&ip_address=192.168.1.100&from_timestamp=2026-11-27T00:00:00Z&to_timestamp=2026-11-27T23:59:59Z&limit=100

# Failed logins for specific user
GET /api/v1/audit/events?event_type=AUTH_LOGIN_FAILURE&actor_username=jdoe&from_timestamp=2026-11-20T00:00:00Z&limit=50

# All failed logins in last 24 hours (for alerting)
GET /api/v1/audit/events?event_type=AUTH_LOGIN_FAILURE&from_timestamp=2026-11-26T10:00:00Z&sort=timestamp&order=DESC&limit=200
```

### 2. Admin Actions by Specific Admin

```bash
# All admin actions by admin1
GET /api/v1/audit/events?actor_username=admin1&actor_type=admin&from_timestamp=2026-11-27T00:00:00Z&to_timestamp=2026-11-27T23:59:59Z&limit=100

# Admin user management actions
GET /api/v1/audit/events?event_type=ADMIN_USER_CREATED,ADMIN_USER_DISABLED,ADMIN_USER_ENABLED,ADMIN_ADMIN_CREATED&from_timestamp=2026-11-01T00:00:00Z&limit=200
```

### 3. Credential Exports (Data Exfiltration Detection)

```bash
# All credential exports
GET /api/v1/audit/events?event_type=OP_CREDENTIAL_EXPORTED&from_timestamp=2026-11-01T00:00:00Z&limit=100

# Large exports (>100 accounts)
POST /api/v1/audit/events/search
{
  "event_type": "OP_CREDENTIAL_EXPORTED",
  "from_timestamp": "2026-11-01T00:00:00Z",
  "limit": 100
}
# Then filter client-side for metadata.accounts_count > 100
```

### 4. Permission Denials (Access Control Issues)

```bash
# All denied authorizations
GET /api/v1/audit/events?result=denied&from_timestamp=2026-11-27T00:00:00Z&limit=200

# Denials for specific resource
GET /api/v1/audit/events?result=denied&resource_type=account&resource_id=123&limit=50

# Denials by specific user
GET /api/v1/audit/events?result=denied&actor_username=jdoe&from_timestamp=2026-11-01T00:00:00Z&limit=100
```

### 5. Configuration Changes

```bash
# All config changes
GET /api/v1/audit/events?event_type=ADMIN_CONFIG_CHANGED,SYSTEM_CONFIG_CHANGED&from_timestamp=2026-11-01T00:00:00Z&limit=100

# Critical config changes (master password, encryption)
GET /api/v1/audit/events?event_type=ADMIN_MASTER_PASSWORD_ROTATED,ADMIN_CONFIG_CHANGED&from_timestamp=2026-11-01T00:00:00Z&limit=50
```

### 6. Service Account Activity

```bash
# All service account actions
GET /api/v1/audit/events?actor_type=service&from_timestamp=2026-11-27T00:00:00Z&limit=200

# Service token usage
GET /api/v1/audit/events?event_type=AUTH_SERVICE_TOKEN_ISSUED&from_timestamp=2026-11-01T00:00:00Z&limit=50
```

### 7. Account Lifecycle

```bash
# Account created/deleted/modified
GET /api/v1/audit/events?event_type=OP_ACCOUNT_CREATED,OP_ACCOUNT_UPDATED,OP_ACCOUNT_DELETED&from_timestamp=2026-11-01T00:00:00Z&limit=200

# Specific account history
GET /api/v1/audit/events?resource_type=account&resource_id=456&from_timestamp=2026-11-01T00:00:00Z&limit=100
```

### 8. MFA Events

```bash
# All MFA enrollments
GET /api/v1/audit/events?event_type=AUTH_MFA_ENROLL&from_timestamp=2026-11-01T00:00:00Z&limit=50

# MFA verification failures
GET /api/v1/audit/events?event_type=AUTH_MFA_VERIFY&result=denied&from_timestamp=2026-11-27T00:00:00Z&limit=100
```

### 9. Backup Operations

```bash
# Backup created/completed/failed
GET /api/v1/audit/events?event_type=ADMIN_BACKUP_CREATED,SYSTEM_BACKUP_COMPLETED,SYSTEM_BACKUP_FAILED&from_timestamp=2026-11-01T00:00:00Z&limit=100
```

### 10. System Errors

```bash
# Application errors in last 24 hours
GET /api/v1/audit/events?event_type=SYSTEM_ERROR&from_timestamp=2026-11-26T10:00:00Z&sort=timestamp&order=DESC&limit=50

# Errors with specific type
GET /api/v1/audit/events?event_type=SYSTEM_ERROR&metadata.error_type=DatabaseError&limit=50
```

---

## Advanced Search (POST /api/v1/audit/events/search)

For complex queries, use the structured search endpoint:

```json
POST /api/v1/audit/events/search
{
  "event_type": "OP_CREDENTIAL_RETRIEVED",
  "actor_type": "user",
  "from_timestamp": "2026-11-27T00:00:00Z",
  "to_timestamp": "2026-11-27T23:59:59Z",
  "severity": "info",
  "result": "success",
  "limit": 100,
  "offset": 0,
  "sort": "timestamp",
  "order": "DESC"
}
```

### Combining Multiple Event Types

```json
{
  "from_timestamp": "2026-11-27T00:00:00Z",
  "to_timestamp": "2026-11-27T23:59:59Z",
  "limit": 500,
  "sort": "timestamp",
  "order": "DESC"
}
```
Note: Use `event_type` as comma-separated list in GET, or omit for all types in POST.

---

## Export Examples

### Export Failed Logins (CSV)
```bash
POST /api/v1/audit/events/export
{
  "event_type": "AUTH_LOGIN_FAILURE",
  "from_timestamp": "2026-11-01T00:00:00Z",
  "to_timestamp": "2026-11-30T23:59:59Z",
  "format": "csv"
}
```

### Export Admin Actions (JSONL)
```bash
POST /api/v1/audit/events/export
{
  "actor_type": "admin",
  "from_timestamp": "2026-11-01T00:00:00Z",
  "format": "jsonl"
}
```

### Export All Events for Compliance (JSON)
```bash
POST /api/v1/audit/events/export
{
  "from_timestamp": "2026-11-01T00:00:00Z",
  "to_timestamp": "2026-11-30T23:59:59Z",
  "format": "json",
  "export_all": true
}
```

---

## Direct Database Queries (SQL)

For advanced analysis, query the `audit_events` table directly:

### Failed Login Count by IP
```sql
SELECT ip_address, COUNT(*) as attempts
FROM audit_events
WHERE event_type = 'AUTH_LOGIN_FAILURE'
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY ip_address
HAVING attempts > 10
ORDER BY attempts DESC;
```

### Admin Actions Summary
```sql
SELECT 
  actor_username,
  event_type,
  COUNT(*) as count,
  MIN(timestamp) as first,
  MAX(timestamp) as last
FROM audit_events
WHERE actor_type = 'admin'
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY actor_username, event_type
ORDER BY count DESC;
```

### Credential Access by User
```sql
SELECT 
  actor_username,
  resource_name as account_name,
  COUNT(*) as access_count,
  MAX(timestamp) as last_access
FROM audit_events
WHERE event_type = 'OP_CREDENTIAL_RETRIEVED'
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY actor_username, resource_id
ORDER BY access_count DESC;
```

### Configuration Changes Detail
```sql
SELECT 
  timestamp,
  actor_username,
  resource_name as config_key,
  metadata->>'$.previous_value' as old_value,
  metadata->>'$.new_value' as new_value
FROM audit_events
WHERE event_type IN ('ADMIN_CONFIG_CHANGED', 'SYSTEM_CONFIG_CHANGED')
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 90 DAY)
ORDER BY timestamp DESC;
```

### Event Volume by Type (Last 30 Days)
```sql
SELECT 
  event_type,
  COUNT(*) as count,
  severity,
  result
FROM audit_events
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY event_type, severity, result
ORDER BY count DESC;
```

### Integrity Check Failures
```sql
-- Find events with invalid signatures (requires application-side verification)
SELECT event_id, timestamp, event_type
FROM audit_events
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
ORDER BY timestamp;
-- Then verify each with AuditService.verify_event_integrity()
```

---

## Pagination Best Practices

1. **Use `limit` and `offset`** for page-based pagination
2. **Max limit is 1000** - use multiple requests for large datasets
3. **Sort by `timestamp DESC`** for most recent first
4. **Use `from_timestamp`/`to_timestamp`** to narrow time windows
5. **Combine with `event_type`** to reduce result set size

```bash
# Page 1
GET /api/v1/audit/events?from_timestamp=2026-11-01T00:00:00Z&limit=100&offset=0&sort=timestamp&order=DESC

# Page 2
GET /api/v1/audit/events?from_timestamp=2026-11-01T00:00:00Z&limit=100&offset=100&sort=timestamp&order=DESC
```

---

## Performance Tips

1. **Always specify time range** - avoids full table scans
2. **Use indexed fields** - `timestamp`, `event_type`, `actor_type`, `actor_id`, `resource_type`, `result`, `severity`, `request_id`
3. **Limit result set** - use `limit` parameter
4. **Use POST search** for complex multi-field queries
5. **Export for large datasets** - more efficient than pagination

---

## Python Client Example

```python
import requests
from datetime import datetime, timedelta

BASE_URL = "https://syspass.example.com/api/v1/audit"
HEADERS = {"Authorization": "Bearer YOUR_JWT_TOKEN"}

def query_events(params):
    response = requests.get(f"{BASE_URL}/events", params=params, headers=HEADERS)
    response.raise_for_status()
    return response.json()

# Failed logins last 24 hours
events = query_events({
    "event_type": "AUTH_LOGIN_FAILURE",
    "from_timestamp": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
    "limit": 200,
    "sort": "timestamp",
    "order": "DESC"
})

# Admin actions this week
events = query_events({
    "actor_type": "admin",
    "from_timestamp": (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z",
    "limit": 500
})

# Export credential exports
export_response = requests.post(
    f"{BASE_URL}/events/export",
    json={
        "event_type": "OP_CREDENTIAL_EXPORTED",
        "from_timestamp": "2026-11-01T00:00:00Z",
        "format": "csv"
    },
    headers=HEADERS
)
with open("credential_exports.csv", "wb") as f:
    f.write(export_response.content)
```