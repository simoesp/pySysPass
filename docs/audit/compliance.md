# Audit Compliance Guide

Regulatory requirements and procedures for audit logging per ADR-0011.

## Regulatory Mapping

| Regulation | Key Requirements | Audit Events | Retention | Evidence |
|------------|------------------|--------------|-----------|----------|
| **GDPR** | Art. 30 Records of processing, Art. 32 Security, Art. 33 Breach notification | All events (accountability) | 7 years | Event export, integrity verification |
| **SOC 2** | CC6.1 Logical access, CC7.2 System monitoring, CC7.3 Incident response | AUTH\*, AUTHZ\*, ADMIN\*, OP_CREDENTIAL\* | 1 year (DB), 7 years (archive) | Query API, archive verification |
| **PCI-DSS** | Req. 10 Track access, Req. 11 Test security | OP_CREDENTIAL_RETRIEVED, OP_CREDENTIAL_EXPORTED, AUTH_LOGIN\* | 1 year (available), 3 years (archive) | Export, access logs |
| **HIPAA** | §164.312 Audit controls, §164.308 Activity review | OP_CREDENTIAL_RETRIEVED, OP_CREDENTIAL_MODIFIED, OP_ACCOUNT\* | 6 years | Immutable archive, access control |
| **ISO 27001** | A.12.4 Logging, A.12.4.3 Admin logs, A.12.4.1 Event logging | All events | Per policy | Full audit trail |

---

## GDPR Compliance

### Lawful Basis for Audit Logging
- **Legitimate Interest (Art. 6(1)(f)):** Security monitoring, fraud prevention
- **Legal Obligation (Art. 6(1)(c)):** SOC 2, PCI-DSS, HIPAA requirements
- **Vital Interest (Art. 6(1)(d)):** Breach detection and response

### Data Subject Rights

#### Right of Access (Art. 15)
```bash
# Export all events for a user
GET /api/v1/audit/events?actor_username={username}&format=jsonl
```

#### Right to Rectification (Art. 16)
- Audit events are immutable by design
- Corrections via supplementary events with `metadata.correction_for`

#### Right to Erasure (Art. 17)
- **Exception:** Legal obligation retention (Art. 17(3)(b))
- Audit logs retained per regulatory requirements
- Personal data in events: username, IP address (pseudonymized where possible)

#### Right to Restriction (Art. 18)
- Legal hold mechanism prevents deletion during disputes

#### Right to Data Portability (Art. 20)
```bash
# Machine-readable export
POST /api/v1/audit/events/export
{
  "actor_username": "{username}",
  "format": "json",
  "export_all": true
}
```

#### Right to Object (Art. 21)
- Processing for security is overriding legitimate interest
- No opt-out for security audit logging

### DPIA (Data Protection Impact Assessment)
Required for systematic monitoring. Key points:
- **Purpose:** Security, compliance, accountability
- **Data:** Usernames, IPs, timestamps, actions (no credentials)
- **Retention:** Tiered (90d/1y/7y)
- **Safeguards:** Encryption, access control, integrity, minimization
- **Review:** Annual DPIA review

---

## SOC 2 Compliance

### Trust Services Criteria Mapping

| Criterion | Audit Events | Controls |
|-----------|--------------|----------|
| **CC6.1** Logical access | AUTH_LOGIN\*, AUTHZ\*, ADMIN_USER\* | MFA, RBAC, session management |
| **CC6.2** Credential management | AUTH_TOKEN\*, OP_CREDENTIAL\* | Token lifecycle, rotation |
| **CC6.3** Network segmentation | AUTH_LOGIN\* (IP tracking) | IP allowlists, geo-blocking |
| **CC6.6** Privileged access | ADMIN_ADMIN_CREATED, ADMIN_CONFIG_CHANGED | Admin approval, break-glass |
| **CC6.7** Data access | OP_CREDENTIAL_RETRIEVED, OP_CREDENTIAL_EXPORTED | Access logging, alerting |
| **CC7.2** System monitoring | SYSTEM_ERROR, SYSTEM_SERVICE\*, AUTH_LOGIN_FAILURE | Alerting, dashboards |
| **CC7.3** Incident response | All events (forensic) | Integrity, export, runbooks |
| **CC7.4** Recovery | SYSTEM_BACKUP\*, ADMIN_BACKUP_CREATED | Backup verification, DR testing |

### SOC 2 Evidence Package

For auditors, provide:
1. **Audit Log Schema** (`docs/audit/audit-schema.md`)
2. **Event Dictionary** (`docs/audit/event-dictionary.md`)
3. **Retention Policy** (`docs/audit/retention-policy.md`)
4. **Access Control** (`docs/audit/access-control.md`)
5. **Sample Exports** (JSONL, CSV for period)
6. **Integrity Verification Report** (monthly)
7. **Alert Configuration** (`docs/audit/alerting.md`)
8. **Access Logs** (meta-audit trail)

---

## PCI-DSS Compliance

### Requirement 10: Track and Monitor Access

| Sub-req | Implementation |
|---------|----------------|
| 10.1 Audit trails | All events in `audit_events` table |
| 10.2 User identification | `actor_id`, `actor_username` on all events |
| 10.3 Event capture | All event types in dictionary |
| 10.4 Timestamp | `timestamp` field (UTC, synchronized) |
| 10.5 Log protection | HMAC signatures, append-only, access control |
| 10.6 Log review | Daily automated, weekly manual, alerting |
| 10.7 Retention | 1 year available, 3 years archive |

### Cardholder Data Access Logging

```sql
-- PCI scope: All credential access
SELECT * FROM audit_events
WHERE event_type IN (
  'OP_CREDENTIAL_RETRIEVED',
  'OP_CREDENTIAL_MODIFIED', 
  'OP_CREDENTIAL_EXPORTED'
)
AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 YEAR);
```

### Requirement 11: Test Security

- **11.4** Intrusion detection: Brute force alerts, unusual access patterns
- **11.5** Change detection: `ADMIN_CONFIG_CHANGED`, `SYSTEM_CONFIG_CHANGED` with file integrity monitoring

---

## HIPAA Compliance

### §164.312(b) Audit Controls

| Requirement | Implementation |
|-------------|----------------|
| Hardware/software audit | `audit_events` table, immutable archive |
| Record activity | All PHI-access events logged |
| Audit log protection | HMAC, encryption at rest, access control |
| Audit log review | Daily automated, monthly manual |

### §164.308(a)(1)(ii)(D) Information System Activity Review

```bash
# Monthly review report
POST /api/v1/audit/events/export
{
  "from_timestamp": "2026-10-01T00:00:00Z",
  "to_timestamp": "2026-10-31T23:59:59Z",
  "event_type": "OP_CREDENTIAL_RETRIEVED,OP_CREDENTIAL_MODIFIED,OP_CREDENTIAL_EXPORTED,OP_ACCOUNT_CREATED,OP_ACCOUNT_UPDATED,OP_ACCOUNT_DELETED",
  "format": "csv"
}
```

### PHI Access Events

All credential operations are treated as potential PHI access:
- `OP_CREDENTIAL_RETRIEVED` - View/access
- `OP_CREDENTIAL_MODIFIED` - Change
- `OP_CREDENTIAL_EXPORTED` - Export
- `OP_ACCOUNT_SHARED` - Disclosure

### Breach Notification (§164.400-414)

Audit logs provide:
- **What happened:** Event types and details
- **When:** Precise timestamps
- **Who:** Actor identification
- **What data:** Resource identification
- **Evidence:** Immutable, signed logs

---

## ISO 27001 Compliance

### A.12.4 Logging and Monitoring

| Control | Implementation |
|---------|----------------|
| A.12.4.1 Event logging | Comprehensive event dictionary |
| A.12.4.2 Protection of log information | HMAC, encryption, access control, WORM |
| A.12.4.3 Administrator logging | `ADMIN_*`, `SYSTEM_*` events |
| A.12.4.4 Clock synchronization | NTP, UTC timestamps |

### A.12.6 Technical Vulnerability Management

- `SYSTEM_ERROR` events capture vulnerabilities
- `ADMIN_CONFIG_CHANGED` tracks patching
- Alerting on critical errors

### A.16.1 Information Security Incident Management

- Complete forensic trail in `audit_events`
- `audit_access_logs` for investigation tracking
- Export for evidence preservation

---

## Compliance Reporting

### Automated Reports

```python
# Monthly compliance report (scheduled job)
def generate_compliance_report(month: str):
    report = {
        "period": month,
        "total_events": audit.count(from_timestamp=start, to_timestamp=end),
        "by_category": {
            "authentication": audit.count(event_type="AUTH_*", ...),
            "authorization": audit.count(event_type="AUTHZ_*", ...),
            "operations": audit.count(event_type="OP_*", ...),
            "administrative": audit.count(event_type="ADMIN_*", ...),
            "system": audit.count(event_type="SYSTEM_*", ...),
        },
        "integrity": audit.verify_all_events(start, end),
        "alerts": alert_summary(month),
        "access_logs": audit.get_access_logs(...),
        "retention_compliance": check_retention_compliance(),
    }
    return report
```

### Report Schedule

| Report | Frequency | Recipients | Retention |
|--------|-----------|------------|-----------|
| Daily Security Summary | Daily | Security team | 90 days |
| Weekly Access Review | Weekly | Admins | 1 year |
| Monthly Compliance | Monthly | Compliance, Audit | 7 years |
| Quarterly SOC 2 Evidence | Quarterly | Auditors | 7 years |
| Annual GDPR DPIA | Annual | DPO, Legal | 7 years |

---

## Evidence Preservation

### Legal Hold Procedure

```python
# Apply legal hold
audit.apply_legal_hold(
    event_ids=["evt_abc123"],
    reason="Litigation: Case #2026-001",
    requested_by="legal@company.com"
)

# Verify hold
event = audit.get_event("evt_abc123")
assert event.metadata.get("legal_hold") == True
```

### Evidence Export for Legal

```bash
# Complete export with chain of custody
POST /api/v1/audit/events/export
{
  "from_timestamp": "2026-01-01T00:00:00Z",
  "to_timestamp": "2026-12-31T23:59:59Z",
  "format": "jsonl",
  "export_all": true
}

# Include access logs (who accessed the audit logs)
GET /api/v1/audit/access-logs?from_timestamp=2026-01-01T00:00:00Z
```

### Chain of Custody

Each export includes:
- Export timestamp and requester
- Query parameters used
- Hash of exported data
- Signature of export file

---

## Audit Program

### Internal Audit Checklist (Quarterly)

- [ ] Verify all event types are being generated
- [ ] Confirm retention policies enforced
- [ ] Test integrity verification (100% pass)
- [ ] Review access logs for unauthorized access
- [ ] Validate alert thresholds and notifications
- [ ] Check archive completeness and verification
- [ ] Review legal holds active
- [ ] Confirm backup of audit data
- [ ] Test export and restore procedures
- [ ] Update event dictionary for new features

### External Audit Preparation

1. **30 days before:** Generate compliance package
2. **14 days before:** Provide sample exports
3. **7 days before:** Schedule walkthrough
4. **During:** Real-time query access for auditors
5. **After:** Archive audit artifacts

---

## Continuous Compliance Monitoring

### Metrics Dashboard

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Event ingestion lag | < 1 second | > 5 seconds |
| Integrity verification pass rate | 100% | < 100% |
| Retention compliance | 100% | < 100% |
| Archive verification | 100% | < 100% |
| Alert delivery success | 100% | < 100% |
| Access log completeness | 100% | < 100% |

### Automated Compliance Checks

```python
# Daily compliance check (scheduled)
def daily_compliance_check():
    checks = {
        "integrity": audit.verify_all_events(yesterday_start, yesterday_end),
        "retention": check_retention_jobs_completed(),
        "archives": verify_archive_jobs(),
        "alerts": check_alert_delivery(),
        "access_logs": verify_access_logging(),
    }
    
    if any(not v for v in checks.values()):
        alert("compliance_check_failed", checks)
```

---

## Regulatory Change Management

When regulations change:

1. **Identify** new requirements
2. **Gap analysis** against current event dictionary
3. **Add** new event types if needed
4. **Update** retention policies
5. **Modify** alert rules
6. **Document** changes in CHANGELOG
7. **Train** team on new procedures
8. **Test** implementation