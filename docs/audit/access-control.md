# Audit Access Control

Roles and permissions for audit log access per ADR-0011.

## Role Definitions

| Role | Description | Permissions |
|------|-------------|-------------|
| `audit_viewer` | Read-only audit log access | View events, basic queries |
| `audit_analyst` | Analyst-level access | View, export, advanced queries, raw events |
| `audit_admin` | Full audit administration | All permissions + configuration, retention, archives |
| `sysadmin` | System administrator | All permissions (implicit) |

## Permission Matrix

| Action | `audit_viewer` | `audit_analyst` | `audit_admin` | `sysadmin` |
|--------|----------------|-----------------|---------------|------------|
| List events (`GET /audit/events`) | ✓ | ✓ | ✓ | ✓ |
| Get event (`GET /audit/events/{id}`) | ✓ | ✓ | ✓ | ✓ |
| Search events (`POST /audit/events/search`) | ✓ | ✓ | ✓ | ✓ |
| Export events (`POST /audit/events/export`) | ✗ | ✓ | ✓ | ✓ |
| Raw event (`GET /audit/events/{id}/raw`) | ✗ | ✓ | ✓ | ✓ |
| Statistics (`GET /audit/events/stats`) | ✓ | ✓ | ✓ | ✓ |
| Verify integrity (`GET /audit/events/verify`) | ✗ | ✗ | ✓ | ✓ |
| List archives (`GET /audit/archives`) | ✓ | ✓ | ✓ | ✓ |
| Create archive (`POST /audit/archives`) | ✗ | ✗ | ✓ | ✓ |
| Retention policies (`GET/POST/PUT /audit/retention-policies`) | ✗ | ✗ | ✓ | ✓ |
| Access logs (`GET /audit/access-logs`) | ✗ | ✗ | ✓ | ✓ |
| Event types reference (`GET /audit/event-types`) | ✓ | ✓ | ✓ | ✓ |

## Role Assignment

Roles are assigned via user group membership or direct user attributes:

```sql
-- Via user group (recommended)
INSERT INTO UserToUserGroup (userId, userGroupId) VALUES (42, 5);
-- Group 5 has audit_analyst role via PluginData or config

-- Via direct user attribute (admin only)
UPDATE User SET isAdminAcc=1 WHERE id=42;  -- Implicit audit_admin
```

### Default Role Mapping

| User Type | Implicit Roles |
|-----------|----------------|
| Application Admin (`isAdminApp=1`) | `sysadmin`, `audit_admin` |
| Account Admin (`isAdminAcc=1`) | `audit_admin` |
| Regular User | None (must be granted explicitly) |
| Service Account | None (must be granted explicitly) |

## API Access Control

All audit endpoints require authentication via JWT. Permissions are checked via the `require_permission` dependency:

```python
from app.api.deps import require_permission

# In route definition
current_user = Depends(require_permission('audit_view'))
```

### Permission Strings

| Permission | Maps To |
|------------|---------|
| `audit_view` | `audit_viewer` |
| `audit_analyst` | `audit_analyst` |
| `audit_admin` | `audit_admin` |
| `evl` (legacy) | `audit_viewer` (backward compatibility) |

## Resource-Level Access

### Event Access
- Users can only view events where they are the actor OR
- Users with `audit_viewer`+ can view all events
- Admins see all events

### Export Restrictions
- Export requires `audit_analyst`+
- Exports are logged in `audit_access_logs`
- Large exports (>1000 events) require `audit_admin`

### Archive Access
- Archive listing: `audit_viewer`+
- Archive creation: `audit_admin`+
- Archive download: `audit_analyst`+

## Meta-Auditing

All access to audit logs is itself logged in `audit_access_logs`:

| Field | Description |
|-------|-------------|
| `user_id` | User who accessed audit logs |
| `action` | `view`, `export`, `query`, `configure`, `create_archive` |
| `accessed_event_id` | Specific event viewed (if applicable) |
| `query_params` | Query parameters used |
| `timestamp` | Access timestamp |
| `ip_address` | Client IP |
| `user_agent` | Client user agent |

### Access Log Retention
- **Retention:** 1 year (aligned with database events)
- **Access:** `audit_admin` only
- **Purpose:** Accountability for audit log access

## Implementation

### Permission Check (Python)
```python
from app.api.deps import require_permission
from app.models.account import User

# In route
async def list_events(
    current_user: User = Depends(require_permission('audit_view'))
):
    # User has audit_view permission
    pass
```

### Role Assignment via Groups
```python
# Create audit group
group = UserGroup(name="Auditors", description="Audit log access")
db.add(group)

# Assign role via plugin data
plugin_data = PluginData(
    name="RBAC",
    itemId=group.id,
    data=json.dumps({"roles": ["audit_analyst"]}).encode(),
    key=b"roles"
)
db.add(plugin_data)

# Add user to group
user_to_group = UserToUserGroup(userId=42, userGroupId=group.id)
db.add(user_to_group)
```

## Audit Log Protection

Per ADR-0011 security properties:

| Property | Implementation |
|----------|----------------|
| **Integrity** | HMAC-SHA256 signatures on each event |
| **Confidentiality** | Read-only for non-admins, encrypted at rest |
| **Availability** | Replicated database, automated backups |
| **Non-repudiation** | Immutable storage, append-only design |
| **Tamper detection** | Cryptographic signatures, periodic verification |
| **Access control** | Role-based, meta-audited |

## Compliance Notes

- **GDPR:** Audit logs contain personal data (usernames, IPs) - ensure lawful basis
- **SOC 2:** Access control review required quarterly
- **PCI-DSS:** Audit log access must be logged and reviewed
- **HIPAA:** Audit logs are part of the audit trail for PHI access

## Emergency Access

Break-glass procedure for emergency audit access:

```bash
# CLI command (requires physical server access)
python -m app.audit_emergency_access --user admin --reason "Incident response" --duration 3600
```

- Creates temporary `audit_admin` role for specified user
- Duration-limited (max 4 hours)
- All actions during emergency access are prominently flagged
- Requires post-incident review