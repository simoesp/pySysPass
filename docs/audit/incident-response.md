# Audit Log Incident Response

Using audit logs for security incident investigation per ADR-0011.

## Incident Response Phases

### 1. Preparation (Continuous)

**Audit Log Readiness:**
- [ ] All event types configured and generating
- [ ] Retention policies active and tested
- [ ] Integrity verification passing (100%)
- [ ] Archives complete and verified
- [ ] Access controls configured (RBAC)
- [ ] Alerting rules tuned and tested
- [ ] Export procedures documented and tested
- [ ] Team trained on query procedures

**Runbooks Maintained:**
- [ ] `docs/runbooks/brute-force-response.md`
- [ ] `docs/runbooks/privilege-escalation.md`
- [ ] `docs/runbooks/data-exfiltration.md`
- [ ] `docs/runbooks/audit-tampering.md`
- [ ] `docs/runbooks/insider-threat.md`
- [ ] `docs/runbooks/compromised-credentials.md`

---

### 2. Detection

#### Alert Sources
| Source | Events | Response Time |
|--------|--------|---------------|
| Automated alerts | Brute force, export, privilege escalation | Immediate |
| Manual review | Daily log review, weekly access review | Hours |
| External reports | User reports, partner notifications | Varies |
| Threat intel | IOC matches in audit logs | Immediate |

#### Initial Triage Questions
1. **What** alert/event triggered?
2. **When** did it occur? (Precise timestamp)
3. **Who** is the actor? (User, service, admin, unknown)
4. **What** resource was targeted?
5. **What** was the result? (Success, denied, error)
6. **Is** this a known pattern or anomaly?

---

### 3. Analysis

#### Timeline Reconstruction

```bash
# Get all events for actor in time window
GET /api/v1/audit/events?actor_username=jdoe&from_timestamp=2026-11-27T08:00:00Z&to_timestamp=2026-11-27T12:00:00Z&sort=timestamp&order=ASC&limit=500

# Get all events for resource
GET /api/v1/audit/events?resource_type=account&resource_id=123&from_timestamp=2026-11-27T00:00:00Z&limit=200

# Get all events by request_id (correlate across services)
GET /api/v1/audit/events?request_id=req_abc123
```

#### Key Investigation Queries

**Compromised Account:**
```bash
# 1. Failed logins before success
GET /api/v1/audit/events?actor_username=victim&event_type=AUTH_LOGIN_FAILURE&from_timestamp=2026-11-26T00:00:00Z

# 2. Successful login from new IP/device
GET /api/v1/audit/events?actor_username=victim&event_type=AUTH_LOGIN_SUCCESS&from_timestamp=2026-11-26T00:00:00Z

# 3. Post-compromise activity
GET /api/v1/audit/events?actor_username=victim&from_timestamp=2026-11-27T10:00:00Z&limit=500
```

**Privilege Escalation:**
```bash
# 1. Admin actions on target user
GET /api/v1/audit/events?resource_username=victim&actor_type=admin&event_type=ADMIN_USER_CREATED,ADMIN_ADMIN_CREATED,ADMIN_USER_ENABLED

# 2. Who granted access
GET /api/v1/audit/events?event_type=ADMIN_ADMIN_CREATED&metadata.user_id=victim_id

# 3. Subsequent admin actions by escalated user
GET /api/v1/audit/events?actor_username=victim&actor_type=admin&from_timestamp=2026-11-27T10:00:00Z
```

**Data Exfiltration:**
```bash
# 1. Large exports
GET /api/v1/audit/events?event_type=OP_CREDENTIAL_EXPORTED&from_timestamp=2026-11-01T00:00:00Z&limit=100
# Filter: metadata.accounts_count > 100

# 2. Bulk credential access
GET /api/v1/audit/events?event_type=OP_CREDENTIAL_RETRIEVED&actor_username=suspect&from_timestamp=2026-11-27T00:00:00Z&limit=500
# Count unique resource_ids accessed

# 3. Unusual access patterns
GET /api/v1/audit/events?actor_username=suspect&from_timestamp=2026-11-20T00:00:00Z&limit=1000
# Analyze: time of day, resource diversity, frequency
```

**Insider Threat:**
```bash
# 1. Admin actions outside normal hours
GET /api/v1/audit/events?actor_type=admin&from_timestamp=2026-11-01T00:00:00Z&limit=1000
# Filter: timestamp.hour < 6 or > 22

# 2. Access to unrelated resources
GET /api/v1/audit/events?actor_username=insider&resource_type=account&from_timestamp=2026-11-01T00:00:00Z
# Check: resources not owned by user or their groups

# 3. Configuration changes
GET /api/v1/audit/events?actor_username=insider&event_type=ADMIN_CONFIG_CHANGED&from_timestamp=2026-11-01T00:00:00Z
```

**Audit Tampering:**
```bash
# 1. Integrity verification
GET /api/v1/audit/events/verify?from_timestamp=2026-11-01T00:00:00Z&to_timestamp=2026-11-30T23:59:59Z

# 2. Events with missing/invalid signatures
# Requires application-side check

# 3. Who accessed audit config
GET /api/v1/audit/access-logs?action=configure&from_timestamp=2026-11-01T00:00:00Z

# 4. Archive verification failures
GET /api/v1/audit/archives?status=failed
```

#### Correlation Techniques

**Request ID Correlation:**
```bash
# Trace a single request across services
GET /api/v1/audit/events?request_id=req_xyz789
```

**Session Correlation:**
```bash
# All events in a session
GET /api/v1/audit/events?session_id=sess_abc123
```

**IP Correlation:**
```bash
# All actors from suspicious IP
GET /api/v1/audit/events?ip_address=192.168.1.100&from_timestamp=2026-11-01T00:00:00Z
```

---

### 4. Containment

#### Immediate Actions

| Incident Type | Containment Action |
|---------------|-------------------|
| Brute force | IP auto-locked (TrackService), notify user |
| Compromised credentials | Force password reset, revoke tokens, enable MFA |
| Privilege escalation | Revoke admin rights, disable account |
| Data exfiltration | Disable export, revoke access, rotate credentials |
| Insider threat | Restrict access, enable enhanced monitoring |
| Audit tampering | Isolate system, preserve evidence, notify leadership |

#### Evidence Preservation

```bash
# 1. Export relevant events (with chain of custody)
POST /api/v1/audit/events/export
{
  "actor_username": "suspect",
  "from_timestamp": "2026-11-01T00:00:00Z",
  "format": "jsonl",
  "export_all": true
}

# 2. Export access logs (who investigated)
GET /api/v1/audit/access-logs?from_timestamp=2026-11-27T00:00:00Z

# 3. Verify integrity of exported data
python -m app.audit_verify --export-file export_20261127.jsonl

# 4. Store in secure evidence locker
# Hash: sha256sum export_20261127.jsonl > export_20261127.jsonl.sha256
```

---

### 5. Eradication

#### Root Cause Analysis

1. **How** did the incident occur?
   - Vulnerability exploited?
   - Misconfiguration?
   - Social engineering?
   - Insider action?

2. **What** allowed persistence?
   - Missing MFA?
   - Excessive privileges?
   - Weak monitoring?

3. **What** controls failed?
   - Preventive?
   - Detective?
   - Corrective?

#### Remediation Actions

| Root Cause | Remediation |
|------------|-------------|
| Weak password | Enforce policy, require rotation |
| No MFA | Mandate MFA for all users |
| Excessive privileges | Implement least privilege, review quarterly |
| Missing alerts | Add alert rules, tune thresholds |
| Configuration drift | Implement IaC, drift detection |
| Insider access | Enhanced monitoring, separation of duties |

#### Verification

```bash
# Verify remediation
# 1. Test attack vector blocked
# 2. Confirm alerts fire
# 3. Verify audit logging captures new events
# 4. Run integrity check
GET /api/v1/audit/events/verify?from_timestamp=2026-11-28T00:00:00Z
```

---

### 6. Recovery

#### Service Restoration

1. **Restore** affected accounts/services
2. **Monitor** for recurrence (enhanced alerting)
3. **Communicate** to stakeholders
4. **Document** lessons learned

#### Post-Incident Audit Log Review

```bash
# Full timeline for incident report
GET /api/v1/audit/events/export
{
  "from_timestamp": "2026-11-27T00:00:00Z",
  "to_timestamp": "2026-11-28T23:59:59Z",
  "format": "jsonl"
}
```

---

### 7. Post-Incident Activity

#### Incident Report Template

```markdown
# Incident Report: {Title}

## Summary
- **Incident ID:** INC-2026-XXX
- **Date:** 2026-11-27
- **Duration:** X hours
- **Severity:** Critical/High/Medium/Low
- **Status:** Resolved

## Timeline
| Time (UTC) | Event | Source | Notes |
|------------|-------|--------|-------|
| 10:00 | Brute force alert | Audit log | 15 failures from 192.168.1.100 |
| 10:05 | IP auto-locked | TrackService | |
| 10:15 | Investigation started | Analyst | |
| 11:30 | Root cause identified | | Weak password, no MFA |
| 12:00 | Containment complete | | Account secured |
| 14:00 | Recovery verified | | |

## Root Cause
{Description}

## Impact
- **Systems affected:**
- **Data exposed:**
- **Users affected:**

## Evidence
- Audit log export: `export_INC-2026-XXX.jsonl`
- Access log: `access_INC-2026-XXX.jsonl`
- Integrity verification: PASS

## Remediation
1. {Action 1} - Complete
2. {Action 2} - In progress
3. {Action 3} - Planned

## Lessons Learned
1. {Lesson 1}
2. {Lesson 2}

## Action Items
- [ ] {Action} - Owner - Due date
```

#### Metrics to Track

| Metric | Target |
|--------|--------|
| Mean Time to Detect (MTTD) | < 1 hour |
| Mean Time to Respond (MTTR) | < 4 hours |
| Mean Time to Resolve | < 24 hours |
| Audit log completeness | 100% |
| Integrity verification | 100% pass |
| Evidence preservation | 100% |

---

## Forensic Procedures

### Evidence Handling

1. **Collection:** Export via API (preserves chain of custody)
2. **Preservation:** Hash immediately, store in WORM
3. **Analysis:** Work on copies, never originals
4. **Documentation:** Every action logged in `audit_access_logs`
5. **Transfer:** Secure handoff with signed receipts

### Legal Considerations

- **Chain of custody** maintained via `audit_access_logs`
- **Integrity** proven via HMAC signatures
- **Timestamps** from synchronized clocks (NTP)
- **Access control** limits who can view/modify
- **Retention** meets legal requirements (7 years)

### Expert Witness Preparation

Audit logs support:
- **Attribution:** Who did what, when
- **Sequence:** Exact order of events
- **Correlation:** Cross-system via request_id
- **Integrity:** Cryptographic proof of non-tampering
- **Completeness:** All events captured per policy

---

## Training Scenarios

### Tabletop Exercise: Credential Theft

**Scenario:** Attacker phishes admin credentials, exports all passwords.

**Injects:**
1. 08:00 - Admin clicks phishing link
2. 08:15 - Attacker logs in as admin (new IP)
3. 08:20 - Attacker exports 500 credentials
4. 08:35 - Alert fires (export >100)
5. 08:40 - Analyst investigates

**Expected Actions:**
- Detect via `OP_CREDENTIAL_EXPORTED` alert
- Query admin's session activity
- Identify anomalous IP
- Contain: disable admin, revoke tokens, force MFA
- Eradicate: rotate all exported credentials
- Recover: notify affected users

### Tabletop Exercise: Audit Tampering

**Scenario:** Compromised admin attempts to delete audit logs.

**Injects:**
1. 14:00 - Attacker gains admin access
2. 14:10 - Attacker tries `DELETE /api/v1/audit-log`
3. 14:15 - Integrity check fails (next run)
4. 14:30 - Alert fires

**Expected Actions:**
- Detect via integrity verification failure
- Identify tampered events
- Restore from immutable archive
- Investigate admin compromise
- Legal hold on all audit data

---

## Integration with SIEM/SOAR

### SIEM Forwarding

```python
# Forward to Splunk/Elastic/Sentinel
def forward_to_siem(event: AuditEvent):
    payload = {
        "time": event.timestamp.isoformat(),
        "event_id": event.event_id,
        "event_type": event.event_type.value,
        "severity": event.severity.value,
        "actor": {
            "type": event.actor_type,
            "id": event.actor_id,
            "username": event.actor_username
        },
        "resource": {
            "type": event.resource_type,
            "id": event.resource_id,
            "name": event.resource_name
        },
        "operation": event.operation_action,
        "result": event.result,
        "network": {
            "ip": event.ip_address,
            "user_agent": event.user_agent
        },
        "session_id": event.session_id,
        "request_id": event.request_id
    }
    siem_client.send(payload)
```

### SOAR Playbooks

**Playbook: Brute Force Response**
1. Receive alert from SIEM
2. Enrich with threat intel (IP reputation)
3. If malicious: block at firewall
4. Notify user/admin
5. Create ticket
6. Close on verification

**Playbook: Privilege Escalation**
1. Receive alert
2. Freeze affected account
3. Query audit log for grantor
4. Notify grantor and security
5. Revoke unauthorized access
6. Review all admin actions by escalated user
7. Create incident