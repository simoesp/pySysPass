# ADR-0014 — Emergency Authentication Mode for Disaster Recovery

## Status

**Status:** **Proposed** (Pending approval)

---

## Context

### Problem Statement

When LDAP (Active Directory) is unavailable, administrators face a circular dependency:

1. Active Directory credentials are stored inside pySysPass
2. pySysPass needs LDAP to authenticate administrators
3. If LDAP is down, administrators cannot authenticate to reset AD credentials
4. Normal fail-closed policy denies all LDAP authentication

### Current Behavior

Per `app/api/v1/auth.py:165-168`:

```python
ldap_user = authenticate_ldap_login(db, form_data.username, plain_password)
if ldap_user is not None:
    user = ldap_user
if ldap_user is None and (not user or not verify_password(plain_password, user.password)):
    # Fallback to local auth
    track.record_attempt(...)
```

This implements **LDAP-to-local fallback**, which violates the fail-closed security policy (T-EVP-05 threat).

### Requirements

We need a controlled Emergency Authentication Mode that:

1. **Does NOT enable local password fallback for LDAP-bound users** (preserves security)
2. **Provides dedicated break-glass administrator accounts** (independent of LDAP)
3. **Requires explicit activation** (not automatic)
4. **Has time limits** (automatic expiration)
5. **Requires MFA** (additional verification)
6. **Logs all actions** (audit trail)
7. **Restricts resource access** (limited scope)

---

## Decision

### 1. Emergency Authentication Mode Activation

**Activation Mechanism: Out-of-Band CLI Only**

```bash
# Via application host CLI (not through web UI)
# Requires physical/server access
sudo /srv/pySysPass/scripts/activate-emergency-auth.sh

# Creates a flag file and logs the activation
# Flags the emergency mode for the next N hours
```

**Activation Requirements:**
- Server host access (console/SSH)
- Out-of-band activation script (not web UI)
- Activation logged to secure audit file
- Activation timestamp recorded
- Automatic deactivation timer set

**Deactivation:**
- Automatic after configured timeout (default: 24 hours)
- Manual deactivation via CLI
- Deactivation logged

### 2. Break-Glass Administrator Accounts

**Decision: Separate Emergency Credentials Table (NOT existing User model)**

Rationale: Preserves ADR-0002 interoperability requirements. Python-native extension metadata cannot represent emergency identity classification without modifying the original PHP schema.

**Separate EmergencyCredentials Table:**

```sql
-- Emergency credentials table (NOT modifying User table)
CREATE TABLE emergency_credentials (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARBINARY(500) NOT NULL,
    password_salt VARBINARY(255) NOT NULL,
    mfa_secret VARBINARY(2000),
    mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    is_recovery_account BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL,
    last_used_at DATETIME,
    recovery_token VARBINARY(64),
    recovery_token_expires_at DATETIME,
    created_by INT,
    created_at DATETIME NOT NULL,
    INDEX idx_username (username),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Account Properties:**
- `username`: Unique, not in LDAP (e.g., `break-glass-1`, `break-glass-2`)
- `password_hash`: bcrypt hash (same as normal users)
- `password_salt`: bcrypt salt
- `mfa_secret`: TOTP secret (required for recovery accounts)
- `mfa_enabled`: Must be TRUE (mandatory MFA)
- `enabled`: FALSE until explicitly activated
- `is_recovery_account`: TRUE for designated LDAP recovery personnel
- `created_by`: Admin who created account
- **NOT linked to LDAP** (independent identity)
- **Independent of PHP schema** (Python extension)

**Account Management:**
- Created by authorized administrators only
- Stored locally (not in LDAP)
- Independent of LDAP availability
- Separate from regular User table
- **No `isEmergency` column in User table**

### 3. Emergency Authentication Mode Activation

**Activation Window: 2-Hour Default (Configurable)**

- Initial activation window: 2 hours (configurable)
- Extensions require audit and justification
- Automatic expiration enforced
- Manual deactivation possible but logged

**Activation Requirements:**
- Server host access (console/SSH)
- Out-of-band activation script (not web UI)
- Activation logged to secure audit file
- Activation timestamp recorded
- **Explicit operator authorization required**
- **Multi-factor verification for activation**

### 4. Emergency Authentication Flow

**Activation Flow:**

```
1. Authorized operator with server access runs:
   sudo /srv/pySysPass/scripts/activate-emergency-auth.sh

2. Script prompts for operator authorization:
   "Enter operator authorization code:"
   
3. Script prompts for break-glass admin password:
   "Enter break-glass administrator password (will not be echoed):"
   
4. Script verifies password against local hash:
   - Password must match emergency_credentials.password_hash
   - Account must be enabled
   - MFA must be configured

5. Script sets emergency mode flag:
   - Creates /var/run/syspass/emergency-auth-active
   - Logs to /var/log/syspass/emergency-auth.log
   - Sets timeout (default 2 hours)
   - Logs authorization event

6. Script prints recovery token (if applicable):
   "Emergency mode activated. Recovery token: <TOKEN>"
   
7. Token must be used within timeout window

8. Administrator can authenticate via web UI:
   - Special endpoint: /api/v1/auth/emergency
   - Requires MFA verification
   - Logs all actions
```

**Emergency Authentication Endpoint:**

```python
@router.post("/auth/emergency", response_model=Token, status_code=200)
def emergency_login(
    username: str = Form(...),
    password: str = Form(...),
    mfa_code: str = Form(...),
    recovery_token: str = Form(None),  # Optional for non-recovery accounts
    request: Request = Depends(),
    db: Session = Depends(get_db),
):
    # Check emergency mode is active
    if not emergency_auth.is_active():
        raise HTTPException(403, "Emergency authentication not enabled")
    
    # Verify recovery token ONLY for recovery accounts (if provided)
    # Recovery tokens do NOT bypass MFA
    if recovery_token:
        user = db.query(emergency_credentials).filter(
            emergency_credentials.username == username,
            emergency_credentials.is_recovery_account == True
        ).first()
        
        if not user or not verify_token(recovery_token, username):
            raise HTTPException(403, "Invalid recovery token")
    
    # Authenticate against local hash (NOT LDAP)
    user = db.query(emergency_credentials).filter(
        emergency_credentials.username == username,
        emergency_credentials.enabled == True
    ).first()
    
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    
    # Verify MFA (mandatory for all emergency accounts)
    if not verify_totp(user.mfa_secret, mfa_code):
        raise HTTPException(401, "Invalid MFA code")
    
    # Log emergency authentication
    elog.log_event(
        "auth.emergency.login",
        f"Emergency login for '{username}' from {_client_ip(request)}",
        user_id=user.id,
        login=username,
        ip=_client_ip(request),
        level="CRITICAL",
    )
    
    # Emergency sessions terminated on deactivation
    # Issue short-lived token
    return issue_session_token(user, master_pass=None, timeout_seconds=3600)
```

### 5. Security Properties

| Property | Status | Implementation |
|----------|--------|----------------|
| **No LDAP fallback** | ✅ | Emergency accounts separate from LDAP users |
| **Explicit activation** | ✅ | CLI-only activation required |
| **Time-limited** | ✅ | Automatic deactivation after 2-hour default |
| **MFA required** | ✅ | TOTP mandatory for all break-glass accounts |
| **Audit logging** | ✅ | All actions logged as CRITICAL severity |
| **Resource restriction** | ✅ | Limited to vault access only |
| **One-time token** | ✅ | Recovery token expires after use |
| **Recovery tokens do NOT bypass MFA** | ✅ | All accounts require MFA verification |
| **Emergency sessions terminated on deactivation** | ✅ | All sessions invalidated on mode deactivation |
| **Recovery credentials accessible only during emergency** | ✅ | No credential exposure outside emergency mode |

### 5A. Emergency Authentication Clarifications

**Three Distinct Identity Categories:**

1. **Independent Local Break-Glass Administrators**
   - Can authenticate without AD (Active Directory)
   - Can authenticate WITHOUT emergency mode activation
   - Stored in `emergency_credentials` table (separate from User table)
   - Independent MFA required
   - Purpose: Primary recovery when infrastructure is compromised
   - Example: `break-glass-1`, `break-glass-2`

2. **Designated LDAP Recovery Personnel**
   - Can authenticate offline ONLY when emergency mode is explicitly activated
   - Stored in `emergency_credentials` table with `is_recovery_account=True`
   - Independent MFA required
   - Purpose: LDAP recovery personnel who need to access system when AD is unavailable
   - Example: `recovery-personnel-1`, `recovery-personnel-2`

3. **Ordinary LDAP Users**
   - MUST continue to fail closed (fail-closed policy enforced)
   - Cannot authenticate when LDAP is unavailable
   - NO fallback to local password authentication
   - Purpose: Normal users who rely on AD for authentication

**Recovery Token Usage:**

- Recovery tokens are OPTIONAL for recovery personnel
- Recovery tokens do NOT bypass MFA (all accounts require MFA)
- Recovery tokens are used when recovery personnel have lost MFA device
- Recovery tokens have expiry times (configured per token)
- Recovery tokens are audited (logged as CRITICAL)

**Cryptographic Access to Recovery Credentials:**

- Break-glass administrators have direct vault access when emergency mode is active
- Recovery personnel have vault access when emergency mode is active
- Emergency mode activation does NOT automatically grant vault access
- Vault access requires:
  - Emergency mode active (flag file exists)
  - Successful authentication (password + MFA)
  - Optional: valid recovery token (if provided)

**Circular Dependency Prevention:**

- Emergency credentials are stored OUTSIDE pySysPass (independent storage)
- Emergency mode activation script requires:
  - Server console/SSH access
  - Operator authorization code
  - Break-glass credentials (stored independently)
- Normal administrators CANNOT activate emergency mode without break-glass credentials
- Break-glass credentials are stored in secure offline storage (safe, encrypted USB, etc.)

**Emergency Credentials Storage:**

- `emergency_credentials` table stores bcrypt-hashed passwords
- MFA secrets stored separately (TOTP)
- Recovery tokens stored separately (if applicable)
- All sensitive data encrypted at rest
- Table stored in database but credentials managed independently

**Summary:**

| Identity Type | AD Required? | Emergency Mode Required? | MFA Required? | Stored Where? |
|---------------|--------------|--------------------------|---------------|---------------|
| Break-glass admin | ❌ No | ❌ No (can authenticate anytime) | ✅ Yes | `emergency_credentials` table (independent storage) |
| LDAP recovery personnel | ❌ No (when AD down) | ✅ Yes (when AD down) | ✅ Yes | `emergency_credentials` table (independent storage) |
| Ordinary LDAP users | ✅ Yes | ❌ N/A (cannot authenticate anyway) | ✅ Yes | LDAP (AD) |

---

### 5. Limitations

**What Emergency Mode Does NOT Do:**

- ❌ **Does NOT enable local password fallback for LDAP users**
  - LDAP-bound users still require LDAP authentication
  - If LDAP is down, LDAP users cannot authenticate
  - Only break-glass admin accounts can authenticate
  
- ❌ **Does NOT bypass MFA**
  - All break-glass accounts require MFA
  - No bypass mechanism
  
- ❌ **Does NOT grant unrestricted access**
  - Limited to vault access only
  - Cannot modify system configuration
  
- ❌ **Does NOT persist indefinitely**
  - Automatic deactivation after timeout
  - Manual deactivation required for extension

- ❌ **Does NOT store emergency credentials in pySysPass**
  - Recovery credentials stored independently
  - Not in pySysPass or application host
  - Separate secure storage required

### 6. Independent Recovery Storage

**Required:**
- Recovery credentials must NOT exist exclusively inside pySysPass or production application host
- Global master password recovery material must be stored independently
- Emergency administrator credentials must be stored independently
- Recovery instructions must be documented separately
- Persistent cryptographic keys must be stored independently

**Recommended:**
- Store emergency credentials in separate secure location (e.g., safe, encrypted USB)
- Maintain recovery copy of credentials
- Document offline recovery procedures
- Consider dual-control recovery for sensitive deployments

### 6. Recovery Procedures

**After LDAP Restoration:**

```python
# Emergency mode deactivates automatically after timeout
# OR administrator manually deactivates via CLI

# Normal authentication resumes when LDAP is back up
# LDAP users authenticate against LDAP again
# Local password fallback remains disabled
```

**Stale Credentials:**

```python
# Broken-glass accounts must be re-provisioned if:
# - Password changed in AD (not applicable - separate accounts)
# - MFA secrets rotated
# - Account disabled

# Remediation:
# 1. Generate new break-glass account via CLI
# 2. Distribute new credentials via secure channel
# 3. Deactivate old account after verification
```

**Session Revocation:**

```python
# All emergency sessions revoked on deactivation
# Session store marks emergency sessions as invalid
# Old tokens automatically expire
```

### 7. Audit Requirements

**Mandatory Audit Events:**

| Event | Severity | Fields |
|-------|----------|--------|
| Emergency mode activation | CRITICAL | `activated_by`, `timestamp`, `timeout_hours` |
| Emergency mode deactivation | CRITICAL | `deactivated_by`, `timestamp`, `reason` |
| Emergency login | CRITICAL | `user_id`, `username`, `ip`, `mfa_verified`, `token_used` |
| Break-glass account creation | CRITICAL | `created_by`, `username`, `created_at` |
| Break-glass account usage | CRITICAL | `used_by_recovery`, `username`, `timestamp` |

**Audit Storage:**
- Separate audit table: `emergency_audit_events`
- Append-only semantics
- Retention: minimum 1 year (configurable)
- Independent access control

### 8. Implementation Tables

```sql
-- emergency_credentials table (above)

-- Emergency audit table
CREATE TABLE emergency_audit_events (
    id INT PRIMARY KEY AUTO_INCREMENT,
    event_type VARCHAR(50) NOT NULL,
    timestamp DATETIME NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'CRITICAL',
    actor_type VARCHAR(20) NOT NULL DEFAULT 'system',
    actor_id INT,
    username VARCHAR(50),
    resource_type VARCHAR(50),
    resource_id INT,
    operation VARCHAR(50),
    parameters JSON,
    result VARCHAR(20) DEFAULT 'success',
    error_message TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    INDEX idx_timestamp (timestamp),
    INDEX idx_event_type (event_type),
    INDEX idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 9. CLI Script

```bash
#!/bin/bash
# /srv/pySysPass/scripts/activate-emergency-auth.sh

# Emergency Authentication Mode Activation Script
# Usage: sudo /srv/pySysPass/scripts/activate-emergency-auth.sh
# Requires: Python 3.8+, bcrypt, access to server console

set -euo pipefail

LOG_FILE="/var/log/syspass/emergency-auth.log"
ACTIVE_FILE="/var/run/syspass/emergency-auth-active"
TIMEOUT_HOURS=24

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root" >&2
        exit 1
    fi
}

check_emergency_mode() {
    if [ -f "$ACTIVE_FILE" ]; then
        log "Emergency mode already active"
        exit 0
    fi
}

create_break_glass_account() {
    log "Creating break-glass administrator account..."
    
    # Read password securely
    read -sp "Enter break-glass administrator password: " BREAK_PASS
    echo
    
    # Read MFA secret
    read -sp "Enter TOTP secret (32 hex characters): " MFA_SECRET
    echo
    
    # Verify password length
    if [ ${#BREAK_PASS} -lt 8 ]; then
        echo "Error: Password must be at least 8 characters" >&2
        exit 1
    fi
    
    # Hash password
    SALT=$(python3 -c "from app.services.auth_service import get_password_salt; print(get_password_salt().hex())")
    HASHED=$(python3 -c "
from app.services.auth_service import get_password_hash
print(get_password_hash('$BREAK_PASS').hex())
")
    
    # Generate recovery token
    TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    EXPIRES=$(date -d "+$TIMEOUT_HOURS hours" '+%Y-%m-%d %H:%M:%S')
    
    # Store in database
    python3 -c "
from sqlalchemy.orm import Session
from app.db.base import engine
from app.models.account import EmergencyCredentials
from datetime import datetime

db = Session(engine)
account = EmergencyCredentials(
    username='break-glass-1',
    password_hash=bytes.fromhex('$HASHED'),
    password_salt=bytes.fromhex('$SALT'),
    mfa_secret=bytes.fromhex('$MFA_SECRET'),
    mfa_enabled=True,
    enabled=True,
    created_at=datetime.utcnow()
)
db.add(account)
db.commit()
db.refresh(account)
print(f'Account created: {account.username}')
print(f'Recovery token: {TOKEN}')
print(f'Token expires: {EXPIRES}')
"
    
    # Activate emergency mode
    touch "$ACTIVE_FILE"
    echo "$TOKEN" > "$ACTIVE_FILE.token"
    echo "$EXPIRES" > "$ACTIVE_FILE.expires"
    
    log "Emergency mode activated"
    log "Recovery token: $TOKEN"
    log "Token expires: $EXPIRES"
}

create_recovery_account() {
    log "Creating recovery administrator account..."
    
    # Similar to create_break_glass_account
    # But with recovery-specific flags
}

deactivate_emergency_mode() {
    log "Deactivating emergency mode..."
    rm -f "$ACTIVE_FILE"
    rm -f "$ACTIVE_FILE.token"
    rm -f "$ACTIVE_FILE.expires"
    log "Emergency mode deactivated"
}

# Main
check_root
check_emergency_mode
echo "Emergency Authentication Mode Activation Wizard"
echo "================================================"
echo ""
echo "This script creates break-glass administrator accounts for disaster recovery."
echo "These accounts are INDEPENDENT of LDAP and can authenticate when LDAP is down."
echo ""
echo "WARNING: These accounts provide full vault access. Protect them carefully."
echo ""
read -p "Continue? [y/N]: " CONFIRM
if [ "$CONFIRM" != "y" ]; then
    echo "Cancelled"
    exit 1
fi

case "${1:-activate}" in
    activate)
        create_break_glass_account
        create_recovery_account
        ;;
    deactivate)
        deactivate_emergency_mode
        ;;
    *)
        echo "Usage: $0 {activate|deactivate}"
        ;;
esac
```

### 10. Threat Model Updates

**New Threats:**

| Threat | Asset | Actor | Boundary | Prerequisites | Impact | Existing Controls | Effectiveness | Residual Risk | Mitigation |
|--------|-------|-------|----------|---------------|--------|-------------------|---------------|---------------|------------|
| T-EAM-01 | Break-glass account | Attacker | Server→DB | Server access | Vault compromise | MFA, audit logging | Medium | Low | MFA enforcement |
| T-EAM-02 | Emergency mode flag | Attacker | Server→System | Server access | Bypass auth | Time-limited, audit | High | Low | Automatic deactivation |
| T-EAM-03 | Recovery token | Attacker | Server→DB | Server access | Emergency login | Token expiry | High | Low | Token expiry enforcement |

**Threat Mitigation:**
- Break-glass accounts require MFA (mitigates T-EAM-01)
- Time-limited emergency mode (mitigates T-EAM-02)
- One-time recovery tokens (mitigates T-EAM-03)
- All actions audited (improves detection)

**Existing Threat Mitigation:**
- T-EVP-05: LDAP-to-local fallback (mitigated by separate accounts)
- T-IDI-02: Master password exposure (mitigated by separate storage)

### 11. Security Implications

**Benefits:**
- ✅ Recovery when LDAP is unavailable
- ✅ No fallback to weaker authentication
- ✅ Explicit activation (not automatic)
- ✅ Time-limited access
- ✅ Full audit trail

**Risks:**
- ❌ Server access required for activation
- ❌ Break-glass credentials must be protected
- ❌ Potential for misuse if not properly controlled
- ❌ Audit logs must be protected

**Mitigations:**
- Physical/server access controls
- Break-glass credential storage procedures
- Regular audit log reviews
- Break-glass account rotation

---

## Consequences

### Operational
- Disaster recovery procedures updated
- Break-glass account management procedures
- Emergency activation/deactivation workflows
- Audit review requirements

### Development
- emergency_credentials table created
- Emergency authentication endpoint
- CLI activation script
- Audit logging integration

### Security
- Improved disaster recovery capabilities
- No weaker authentication fallback
- Full audit trail for emergency actions
- Time-limited emergency access

---

## References

- `docs/adr/0004-identity-provider-binding-administrator-provisioning-and-break-glass-access.md`: Normal local admin accounts (break-glass) that work when LDAP fails
- `docs/adr/0012-threat-model-and-trust-boundaries.md`
- `app/api/v1/auth.py`: Login endpoint
- `app/services/ldap_service.py`: LDAP authentication
- `app/services/auth_service.py`: Password hashing

---

## Next Steps

After approval, implement:

1. Create EmergencyAdmin database table
2. Implement emergency authentication endpoint
3. Create CLI activation script
4. Update audit logging
5. Update threat model
6. Create disaster recovery documentation
7. Train administrators on procedures
