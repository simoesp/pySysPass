# Audit Alerting Guide

Alert thresholds, delivery mechanisms, and configuration per ADR-0011.

## Alert Definitions

| Alert | Trigger | Severity | Evaluation Window | Action |
|-------|---------|----------|-------------------|--------|
| Brute Force | >10 failed logins from same IP | High | 15 minutes | Lock account, alert admin |
| Admin Action | Admin creates/disables user | Medium | Immediate | Log, notify admin |
| Credential Export | Export >100 credentials | High | Immediate | Alert admin, log |
| Service Token Misuse | Service token accessing restricted resources | Medium | 1 hour | Alert admin |
| Mass Modification | >10 accounts modified by same actor | Medium | 1 hour | Alert admin |
| Privilege Escalation | User gaining admin access | Critical | Immediate | Alert admin, freeze |
| Configuration Change | Critical config modified | Medium | Immediate | Log, notify admin |
| Backup Failure | Backup failed | High | Immediate | Alert admin |
| Audit Log Tampering | Integrity check fails | Critical | Daily | Alert admin |
| Unusual Access Pattern | Anomalous access detected | Medium | 24 hours | Alert admin |

---

## Alert Configuration

### Threshold Configuration (Database)

Alert thresholds are stored in `Config` table and can be modified via API:

```sql
-- Brute force threshold
INSERT INTO Config (parameter, value) VALUES ('alert.brute_force.max_attempts', '10');
INSERT INTO Config (parameter, value) VALUES ('alert.brute_force.window_minutes', '15');

-- Credential export threshold
INSERT INTO Config (parameter, value) VALUES ('alert.credential_export.max_accounts', '100');

-- Mass modification threshold
INSERT INTO Config (parameter, value) VALUES ('alert.mass_modification.max_accounts', '10');
INSERT INTO Config (parameter, value) VALUES ('alert.mass_modification.window_hours', '1');

-- Service token anomaly
INSERT INTO Config (parameter, value) VALUES ('alert.service_token.restricted_resources', '["admin", "config", "backup"]');
```

### Alert Rules Engine

The alerting system evaluates rules on a schedule:

```python
# app/services/alert_service.py (to be implemented)
class AlertService:
    def evaluate_brute_force(self):
        # Query failed logins in window
        events = audit.query(
            event_type="AUTH_LOGIN_FAILURE",
            from_timestamp=now - timedelta(minutes=15)
        )
        # Group by IP, count
        # Alert if count > threshold

    def evaluate_credential_export(self):
        # Check for exports > threshold
        events = audit.query(
            event_type="OP_CREDENTIAL_EXPORTED",
            from_timestamp=now - timedelta(hours=1)
        )
        for event in events:
            if event.metadata.get('accounts_count', 0) > 100:
                self.alert("credential_export", event)
```

---

## Delivery Mechanisms

### 1. Email Notifications

```python
# Configuration
ALERT_EMAIL_RECIPIENTS = ["security@company.com", "admin@company.com"]
ALERT_EMAIL_FROM = "alerts@syspass.company.com"
SMTP_HOST = "smtp.company.com"
SMTP_PORT = 587
SMTP_USER = "alerts"
SMTP_PASSWORD = "****"  # From vault

# Template
SUBJECT: "[ALERT] {severity}: {alert_name} - {count} events"
BODY:
Alert: {alert_name}
Severity: {severity}
Triggered: {timestamp}
Details: {details}
Affected: {actor_username} ({actor_id})
Resource: {resource_name} ({resource_id})
```

### 2. Slack/Teams Webhook

```python
# Configuration
ALERT_SLACK_WEBHOOK = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
ALERT_TEAMS_WEBHOOK = "https://company.webhook.office.com/webhookb2/XXX"

# Payload
{
  "text": "🚨 *{severity} Alert: {alert_name}*",
  "blocks": [
    {"type": "header", "text": {"type": "plain_text", "text": "Security Alert"}},
    {"type": "section", "fields": [
      {"type": "mrkdwn", "text": "*Alert:* {alert_name}"},
      {"type": "mrkdwn", "text": "*Severity:* {severity}"},
      {"type": "mrkdwn", "text": "*Actor:* {actor_username}"},
      {"type": "mrkdwn", "text": "*Resource:* {resource_name}"}
    ]},
    {"type": "section", "text": {"type": "mrkdwn", "text": "{details}"}},
    {"type": "actions", "elements": [
      {"type": "button", "text": {"type": "plain_text", "text": "View in Audit Log"}, "url": "{audit_url}"}
    ]}
  ]
}
```

### 3. PagerDuty Integration

```python
# Configuration
PAGERDUTY_INTEGRATION_KEY = "xxx"  # From vault
PAGERDUTY_SEVERITY_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info"
}

# Event API payload
{
  "routing_key": PAGERDUTY_INTEGRATION_KEY,
  "event_action": "trigger",
  "dedup_key": f"{alert_name}-{actor_id}-{date}",
  "payload": {
    "summary": f"{alert_name}: {details}",
    "severity": PAGERDUTY_SEVERITY_MAP[severity],
    "source": "syspass-audit",
    "custom_details": {
      "alert_name": alert_name,
      "actor_username": actor_username,
      "resource_name": resource_name,
      "event_count": count,
      "audit_url": audit_url
    }
  }
}
```

### 4. Syslog Forwarding

```python
# Configuration
SYSLOG_HOST = "syslog.company.com"
SYSLOG_PORT = 514
SYSLOG_PROTOCOL = "udp"  # or tcp, tls
SYSLOG_FACILITY = "local0"

# RFC 5424 format
<165>1 2026-11-27T10:30:00Z syspass audit - - - 
  alert_name="brute_force" severity="high" 
  actor_ip="192.168.1.100" attempts="15" window="15min"
```

### 5. Audit Log Review (Built-in)

All alerts generate `SYSTEM_ERROR` or `ADMIN_CONFIG_CHANGED` events in the audit log itself for review:

```sql
-- Review alerts
SELECT * FROM audit_events 
WHERE event_type IN ('SYSTEM_ERROR', 'ADMIN_CONFIG_CHANGED')
  AND metadata->>'$.alert_name' IS NOT NULL
ORDER BY timestamp DESC;
```

---

## Alert Suppression & Deduplication

### Deduplication Keys
- Brute force: `brute_force-{ip_address}`
- Credential export: `credential_export-{actor_id}-{date}`
- Admin action: `admin_action-{actor_id}-{event_type}-{resource_id}`
- Mass modification: `mass_mod-{actor_id}-{hour}`

### Suppression Rules
```yaml
# alert_suppression.yaml
suppressions:
  - name: "maintenance_window"
    schedule: "0 2 * * 0"  # Sunday 2AM
    duration_hours: 4
    alerts: ["backup_failure", "service_stopped"]

  - name: "known_scanners"
    condition: "actor_ip IN ('10.0.0.0/8', '172.16.0.0/12')"
    alerts: ["brute_force", "unusual_access"]
```

---

## Alert Response Procedures

### Brute Force (High)
1. **Immediate:** IP auto-locked by TrackService
2. **Review:** Check audit log for pattern
3. **Action:** 
   - If legitimate user: unlock IP, notify user
   - If attacker: block IP at firewall, review affected accounts
4. **Document:** Record in incident log

### Privilege Escalation (Critical)
1. **Immediate:** Freeze affected user account
2. **Investigate:** 
   - Who granted access? (check `ADMIN_ADMIN_CREATED`)
   - Was it authorized?
   - Any suspicious activity since?
3. **Remediate:** Revoke unauthorized access
4. **Report:** Security incident report

### Credential Export (High)
1. **Immediate:** Notify data owner and admin
2. **Investigate:**
   - Who exported? (actor)
   - How many accounts?
   - Where was data sent?
3. **Assess:** Data sensitivity, exposure risk
4. **Remediate:** Rotate affected credentials if needed

### Audit Tampering (Critical)
1. **Immediate:** Alert all admins, isolate system
2. **Investigate:**
   - Which events failed verification?
   - When did tampering occur?
   - Root cause (compromise, bug, hardware)?
3. **Recover:** Restore from immutable archive
4. **Report:** Full forensic investigation

---

## Monitoring Dashboard Queries

### Real-time Alert Status
```sql
-- Active alerts (last hour)
SELECT 
  metadata->>'$.alert_name' as alert,
  COUNT(*) as count,
  MAX(timestamp) as last_triggered
FROM audit_events
WHERE event_type = 'SYSTEM_ERROR'
  AND metadata->>'$.alert_name' IS NOT NULL
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
GROUP BY alert;
```

### Alert Trends (7 days)
```sql
SELECT 
  DATE(timestamp) as day,
  metadata->>'$.alert_name' as alert,
  COUNT(*) as count
FROM audit_events
WHERE event_type = 'SYSTEM_ERROR'
  AND metadata->>'$.alert_name' IS NOT NULL
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY day, alert
ORDER BY day DESC, count DESC;
```

### Top Alerting IPs/Users
```sql
-- Top brute force sources
SELECT 
  ip_address,
  COUNT(*) as alerts
FROM audit_events
WHERE event_type = 'AUTH_LOGIN_FAILURE'
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY ip_address
ORDER BY alerts DESC
LIMIT 20;

-- Top admin actors
SELECT 
  actor_username,
  COUNT(*) as admin_actions
FROM audit_events
WHERE actor_type = 'admin'
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY actor_username
ORDER BY admin_actions DESC
LIMIT 20;
```

---

## Testing Alerts

### Manual Trigger (Admin)
```bash
# Trigger test alert
POST /api/v1/admin/alerts/test
{
  "alert_type": "brute_force",
  "test_data": {
    "ip_address": "192.168.1.999",
    "attempts": 15
  }
}
```

### Simulated Events
```python
# In test environment
audit.log_auth_event(
    event_type=AuditEventType.AUTH_LOGIN_FAILURE,
    user_id=999,
    username="test_attacker",
    ip_address="192.168.1.999",
    user_agent="TestAgent",
    session_id=None,
    result="denied",
    error_message="invalid_password",
    metadata={"attempt_count": 15}
)
# Repeat 11 times to trigger alert
```

---

## Alert Tuning

### False Positive Reduction
1. **Whitelist known IPs** (monitoring, CI/CD, internal tools)
2. **Adjust thresholds** based on baseline (analyze 30 days of data)
3. **Add context** (geo-location, device fingerprint, time of day)
4. **Correlate** multiple signals before alerting

### Baseline Establishment
```sql
-- Failed login baseline (per IP, per hour)
SELECT 
  ip_address,
  HOUR(timestamp) as hour,
  AVG(cnt) as avg_attempts,
  STDDEV(cnt) as stddev_attempts
FROM (
  SELECT ip_address, timestamp, COUNT(*) as cnt
  FROM audit_events
  WHERE event_type = 'AUTH_LOGIN_FAILURE'
    AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
  GROUP BY ip_address, DATE(timestamp), HOUR(timestamp)
) t
GROUP BY ip_address, hour;

-- Credential export baseline
SELECT 
  AVG(metadata->>'$.accounts_count') as avg_export_size,
  MAX(metadata->>'$.accounts_count') as max_export_size
FROM audit_events
WHERE event_type = 'OP_CREDENTIAL_EXPORTED'
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 90 DAY);
```

---

## Runbook Integration

Each alert type should have a corresponding runbook:

| Alert | Runbook |
|-------|---------|
| Brute Force | `docs/runbooks/brute-force-response.md` |
| Privilege Escalation | `docs/runbooks/privilege-escalation.md` |
| Credential Export | `docs/runbooks/data-exfiltration.md` |
| Audit Tampering | `docs/runbooks/audit-tampering.md` |
| Backup Failure | `docs/runbooks/backup-failure.md` |

Runbook template:
```markdown
# Runbook: {Alert Name}

## Overview
{Description of alert and impact}

## Detection
{How the alert is triggered}

## Triage Steps
1. {Step 1}
2. {Step 2}
3. {Step 3}

## Investigation Queries
{SQL/API queries to run}

## Remediation
{Containment and recovery steps}

## Communication
{Who to notify, templates}

## Post-Incident
{Retrospective, improvements}
```