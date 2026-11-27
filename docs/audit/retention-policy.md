# Audit Retention Policy

Retention periods and procedures for audit data per ADR-0011.

## Retention Tiers

| Data Type | Retention Period | Storage Location | Purpose |
|-----------|------------------|------------------|---------|
| Application Logs | 90 days | `/app/logs/audit.jsonl` (JSON Lines) | Detailed event data, real-time access |
| Database Events | 1 year | `audit_events` table | Queryable events, API access |
| Immutable Archive | 7 years | WORM storage (S3, Glacier, etc.) | Compliance retention, legal hold |
| Compliance Reports | 7 years | `/var/log/syspass/compliance/` | Generated compliance reports |

## Storage Strategy

### Application Logs (Tier 1)
- **Format:** JSON Lines (one event per line)
- **Location:** `/app/logs/audit.jsonl`
- **Rotation:** Daily at midnight UTC
- **Compression:** gzip after 7 days
- **Retention:** 90 days automatic cleanup

```bash
# Daily rotation (via logrotate or cron)
python -m app.audit_archive --date 2026-11-27 --output /var/log/syspass/audit/2026-11-27.jsonl

# Weekly compression
python -m app.audit_compress --from 2026-11-01 --to 2026-11-07
```

### Database Events (Tier 2)
- **Table:** `audit_events`
- **Indexes:** Optimized for time-range, actor, resource, and event-type queries
- **Retention:** 1 year (365 days)
- **Cleanup:** Automated via retention policy job

```sql
-- Manual cleanup (if needed)
DELETE FROM audit_events 
WHERE timestamp < DATE_SUB(NOW(), INTERVAL 365 DAY);
```

### Immutable Archive (Tier 3)
- **Format:** JSON Lines, compressed, signed
- **Storage:** WORM-compatible (S3 Object Lock, Azure Immutable Blob, Glacier Vault Lock)
- **Schedule:** Monthly archival
- **Verification:** Checksum + HMAC verification on write and read

```bash
# Monthly archival to WORM storage
python -m app.audit_worm --month 2026-11 --storage s3://audit-archive/monthly/

# Verification
python -m app.audit_verify --archive s3://audit-archive/monthly/2026-11.jsonl.gz
```

## Retention Policy Configuration

Policies are stored in `audit_retention_policies` table and managed via API:

```bash
# List policies
GET /api/v1/audit/retention-policies

# Create/update policy (admin only)
POST /api/v1/audit/retention-policies
{
  "data_type": "database_events",
  "retention_days": 365,
  "storage_location": "audit_events table",
  "enabled": true
}
```

### Default Policies

| Data Type | Retention Days | Enabled |
|-----------|----------------|---------|
| application_logs | 90 | Yes |
| database_events | 365 | Yes |
| immutable_archive | 2555 (7 years) | Yes |
| compliance_reports | 2555 (7 years) | Yes |

## Legal Hold

Legal hold freezes deletion for specific events or time ranges:

```python
# Apply legal hold (admin only)
audit_service.apply_legal_hold(
    event_ids=["evt_abc123", "evt_def456"],
    reason="Litigation hold - Case #2026-001",
    requested_by="legal@company.com"
)

# Remove legal hold
audit_service.remove_legal_hold(event_ids=["evt_abc123"])
```

**Legal Hold Effects:**
- Prevents automatic deletion by retention jobs
- Marks events as `legal_hold=true` in database
- Requires explicit admin action to release
- All hold actions are themselves audited

## Automated Retention Jobs

### Daily Cleanup Job
Runs at 02:00 UTC daily:
1. Identifies expired events per policy
2. Archives to immutable storage (if not already)
3. Deletes from `audit_events` table
4. Logs cleanup activity to `audit_access_logs`

### Weekly Archive Job
Runs Sunday 03:00 UTC:
1. Creates archive for previous week
2. Compresses and signs archive
3. Stores in configured archive location
4. Records in `audit_archives` table

### Monthly WORM Job
Runs 1st of month 04:00 UTC:
1. Creates monthly archive from weekly archives
2. Uploads to WORM storage
3. Verifies checksum and signature
4. Records in `audit_archives` with `storage_type=worm`

## Compliance Requirements

| Regulation | Requirement | Implementation |
|------------|-------------|----------------|
| GDPR | Right to explanation, data portability | Event export API, 7-year retention for accountability |
| SOC 2 | Audit trail for security events | Comprehensive event coverage, integrity verification |
| PCI-DSS | Cardholder data access logging | `OP_CREDENTIAL_RETRIEVED`, `OP_CREDENTIAL_EXPORTED` events |
| HIPAA | PHI access logging | All credential access events, immutable archive |
| Custom | Industry-specific | Configurable retention, custom event types |

## Recovery Procedures

### Point-in-Time Recovery
```bash
# Restore from database backup
pg_restore -d syspass -t audit_events backup.dump

# Restore from archive
gunzip -c audit-archive/2026-11.jsonl.gz | python -m app.audit_import
```

### Integrity Verification
```bash
# Verify all events in range
python -m app.audit_verify --from 2026-11-01 --to 2026-11-30

# Verify specific archive
python -m app.audit_verify --archive s3://audit-archive/monthly/2026-11.jsonl.gz
```

## Monitoring & Alerting

### Retention Compliance Alerts
- **Warning:** Events approaching retention limit (30 days before)
- **Critical:** Events past retention limit without archive
- **Critical:** Archive verification failure
- **Critical:** WORM storage upload failure

### Metrics
- `audit.events.total` - Total events in database
- `audit.events.by_age` - Event count by age buckets
- `audit.archive.size` - Archive storage size
- `audit.archive.verification_status` - Last verification result
- `audit.retention.compliance` - Compliance percentage