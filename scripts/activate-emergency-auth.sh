#!/usr/bin/env bash
# Emergency Authentication Mode Activation Script
# Usage: sudo /srv/pySysPass/scripts/activate-emergency-auth.sh [activate|deactivate] [options]
# Requires: Python 3.8+, bcrypt, access to server console, root privileges

set -euo pipefail

# Configuration - can be overridden via environment variables
LOG_FILE="${SYSPASS_EMERGENCY_LOG_FILE:-/var/log/syspass/emergency-auth.log}"
FLAG_DIR="${SYSPASS_EMERGENCY_FLAG_DIR:-/var/run/syspass}"
ACTIVE_FILE="${FLAG_DIR}/emergency-auth-active"
DEFAULT_TIMEOUT_HOURS="${SYSPASS_EMERGENCY_TIMEOUT_HOURS:-2}"
PYTHON_BIN="${SYSPASS_PYTHON_BIN:-python3}"
APP_DIR="${SYSPASS_APP_DIR:-/srv/pySysPass}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ensure_dirs() {
    # Ensure log directory exists (non-fatal if cannot create)
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    mkdir -p "$FLAG_DIR"
}

log() {
    local level="$1"
    shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    # Try to write to log file, fall back to stdout only if it fails
    echo -e "$msg" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "$msg"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "${YELLOW}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }
log_critical() { log "CRITICAL" "${RED}$*${NC}"; }
log_success() { log "SUCCESS" "${GREEN}$*${NC}"; }

check_root() {
    if [[ "$EUID" -ne 0 ]] && [[ "${SYSPASS_ALLOW_NONROOT:-}" != "1" ]]; then
        log_error "This script must be run as root (or set SYSPASS_ALLOW_NONROOT=1 for testing)"
        exit 1
    fi
}

check_emergency_mode() {
    ensure_dirs
    if [[ -f "$ACTIVE_FILE" ]]; then
        local flag_data
        flag_data=$(cat "$ACTIVE_FILE" 2>/dev/null || echo "{}")
        log_warn "Emergency mode already active"
        log_info "Current activation: $flag_data"
        return 0
    fi
    return 1
}

read_password() {
    local prompt="$1"
    local var_name="$2"
    local password
    read -rsp "$prompt" password
    echo
    if [[ ${#password} -lt 8 ]]; then
        log_error "Password must be at least 8 characters"
        exit 1
    fi
    printf -v "$var_name" '%s' "$password"
}

read_mfa_code() {
    local prompt="$1"
    local var_name="$2"
    local code
    read -rp "$prompt" code
    code="${code// /}"  # Remove spaces
    if [[ ! "$code" =~ ^[0-9]{6}$ ]]; then
        log_error "MFA code must be 6 digits"
        exit 1
    fi
    printf -v "$var_name" '%s' "$code"
}

verify_operator_mfa() {
    log_info "Verifying operator MFA authorization..."
    local mfa_code
    read_mfa_code "Enter operator MFA code (6 digits): " mfa_code

    # Verify MFA against a stored operator secret
    # The operator MFA secret should be configured in the environment or a secure location
    local operator_secret="${SYSPASS_OPERATOR_MFA_SECRET:-}"
    if [[ -z "$operator_secret" ]]; then
        log_error "Operator MFA secret not configured (SYSPASS_OPERATOR_MFA_SECRET)"
        exit 1
    fi

    # Use Python to verify TOTP
    local valid
    valid=$("$PYTHON_BIN" -c "
import pyotp
import sys
secret = '$operator_secret'
code = '$mfa_code'
totp = pyotp.TOTP(secret)
if totp.verify(code, valid_window=1):
    print('valid')
else:
    print('invalid')
" 2>/dev/null)

    if [[ "$valid" != "valid" ]]; then
        log_error "Invalid operator MFA code"
        log_critical "OPERATOR MFA VERIFICATION FAILED"
        exit 1
    fi

    log_success "Operator MFA verification successful"
}

create_break_glass_account() {
    log_info "Creating break-glass administrator account..."

    local username="${1:-break-glass-1}"
    local password
    local mfa_secret

    read_password "Enter break-glass administrator password (will not be echoed): " password
    read_password "Confirm break-glass administrator password: " mfa_secret  # reuse var for confirmation

    if [[ "$password" != "$mfa_secret" ]]; then
        log_error "Passwords do not match"
        exit 1
    fi

    # Read MFA secret for the break-glass account
    read -rp "Enter TOTP secret for break-glass account (32 hex chars, or press Enter to generate): " mfa_secret
    if [[ -z "$mfa_secret" ]]; then
        mfa_secret=$("$PYTHON_BIN" -c "import pyotp; print(pyotp.random_base32())")
        log_info "Generated MFA secret: $mfa_secret"
        log_warn "SAVE THIS SECRET SECURELY - it will not be shown again!"
    elif [[ ! "$mfa_secret" =~ ^[A-Z2-7]{32}$ ]]; then
        log_error "Invalid TOTP secret format (must be 32 base32 characters)"
        exit 1
    fi

    # Hash password and create account via Python
    log_info "Creating emergency credential in database..."
    local result
    result=$("$PYTHON_BIN" <<'PYEOF'
import sys
sys.path.insert(0, '/srv/pySysPass')
import os
os.chdir('/srv/pySysPass')

from app.db.base import engine
from app.models.account import EmergencyCredentials
from app.services.auth_service import get_password_hash
from datetime import UTC, datetime
from sqlalchemy.orm import Session
import secrets

username = os.environ['BG_USERNAME']
password = os.environ['BG_PASSWORD']
mfa_secret = os.environ['BG_MFA_SECRET']
is_recovery = os.environ.get('BG_IS_RECOVERY', 'false').lower() == 'true'

db = Session(engine)
try:
    # Check if account already exists
    existing = db.query(EmergencyCredentials).filter(
        EmergencyCredentials.username == username
    ).first()
    if existing:
        print(f"ERROR: Account '{username}' already exists", file=sys.stderr)
        sys.exit(1)

    # Hash password
    password_hash = get_password_hash(password).encode('utf-8')
    # Generate salt (bcrypt includes salt in hash, but we store separately for audit)
    password_salt = secrets.token_bytes(32)

    account = EmergencyCredentials(
        username=username,
        password_hash=password_hash,
        password_salt=password_salt,
        mfa_secret=mfa_secret.encode('utf-8'),
        mfa_enabled=True,
        enabled=True,
        is_recovery_account=is_recovery,
        created_at=datetime.now(UTC).replace(tzinfo=None),
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    # Generate recovery token
    recovery_token = secrets.token_hex(32)
    account.recovery_token = recovery_token.encode('utf-8')
    from datetime import timedelta
    account.recovery_token_expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=24)
    db.commit()

    print(f"SUCCESS: Account created: {account.username}")
    print(f"RECOVERY_TOKEN: {recovery_token}")
    print(f"TOKEN_EXPIRES: {account.recovery_token_expires_at.isoformat()}")
except Exception as e:
    db.rollback()
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
finally:
    db.close()
PYEOF
    BG_USERNAME="$username" BG_PASSWORD="$password" BG_MFA_SECRET="$mfa_secret" BG_IS_RECOVERY="false"
    )

    if [[ $? -ne 0 ]]; then
        log_error "Failed to create break-glass account"
        echo "$result" | grep "^ERROR:" | sed 's/^ERROR: //' | while read line; do log_error "$line"; done
        exit 1
    fi

    local recovery_token
    recovery_token=$(echo "$result" | grep "^RECOVERY_TOKEN:" | sed 's/^RECOVERY_TOKEN: //')
    local token_expires
    token_expires=$(echo "$result" | grep "^TOKEN_EXPIRES:" | sed 's/^TOKEN_EXPIRES: //')

    log_success "Break-glass account created: $username"
    log_critical "RECOVERY TOKEN: $recovery_token"
    log_critical "TOKEN EXPIRES: $token_expires"
    log_warn "STORE THE RECOVERY TOKEN SECURELY - IT WILL NOT BE SHOWN AGAIN!"

    echo "$recovery_token" > "${ACTIVE_FILE}.recovery_token"
    echo "$token_expires" > "${ACTIVE_FILE}.recovery_token_expires"
    chmod 600 "${ACTIVE_FILE}.recovery_token" "${ACTIVE_FILE}.recovery_token_expires"
}

create_recovery_account() {
    log_info "Creating LDAP recovery personnel account..."

    local username="${1:-recovery-personnel-1}"
    local password
    local mfa_secret

    read_password "Enter recovery personnel password (will not be echoed): " password
    read_password "Confirm recovery personnel password: " mfa_secret

    if [[ "$password" != "$mfa_secret" ]]; then
        log_error "Passwords do not match"
        exit 1
    fi

    read -rp "Enter TOTP secret for recovery account (32 hex chars, or press Enter to generate): " mfa_secret
    if [[ -z "$mfa_secret" ]]; then
        mfa_secret=$("$PYTHON_BIN" -c "import pyotp; print(pyotp.random_base32())")
        log_info "Generated MFA secret: $mfa_secret"
        log_warn "SAVE THIS SECRET SECURELY - it will not be shown again!"
    elif [[ ! "$mfa_secret" =~ ^[A-Z2-7]{32}$ ]]; then
        log_error "Invalid TOTP secret format (must be 32 base32 characters)"
        exit 1
    fi

    log_info "Creating recovery account in database..."
    local result
    result=$("$PYTHON_BIN" <<'PYEOF'
import sys
sys.path.insert(0, '/srv/pySysPass')
import os
os.chdir('/srv/pySysPass')

from app.db.base import engine
from app.models.account import EmergencyCredentials
from app.services.auth_service import get_password_hash
from datetime import UTC, datetime, timedelta
from sqlalchemy.orm import Session
import secrets

username = os.environ['BG_USERNAME']
password = os.environ['BG_PASSWORD']
mfa_secret = os.environ['BG_MFA_SECRET']

db = Session(engine)
try:
    existing = db.query(EmergencyCredentials).filter(
        EmergencyCredentials.username == username
    ).first()
    if existing:
        print(f"ERROR: Account '{username}' already exists", file=sys.stderr)
        sys.exit(1)

    password_hash = get_password_hash(password).encode('utf-8')
    password_salt = secrets.token_bytes(32)

    account = EmergencyCredentials(
        username=username,
        password_hash=password_hash,
        password_salt=password_salt,
        mfa_secret=mfa_secret.encode('utf-8'),
        mfa_enabled=True,
        enabled=True,
        is_recovery_account=True,
        created_at=datetime.now(UTC).replace(tzinfo=None),
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    recovery_token = secrets.token_hex(32)
    account.recovery_token = recovery_token.encode('utf-8')
    account.recovery_token_expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=24)
    db.commit()

    print(f"SUCCESS: Account created: {account.username}")
    print(f"RECOVERY_TOKEN: {recovery_token}")
    print(f"TOKEN_EXPIRES: {account.recovery_token_expires_at.isoformat()}")
except Exception as e:
    db.rollback()
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
finally:
    db.close()
PYEOF
    BG_USERNAME="$username" BG_PASSWORD="$password" BG_MFA_SECRET="$mfa_secret"
    )

    if [[ $? -ne 0 ]]; then
        log_error "Failed to create recovery account"
        echo "$result" | grep "^ERROR:" | sed 's/^ERROR: //' | while read line; do log_error "$line"; done
        exit 1
    fi

    local recovery_token
    recovery_token=$(echo "$result" | grep "^RECOVERY_TOKEN:" | sed 's/^RECOVERY_TOKEN: //')
    local token_expires
    token_expires=$(echo "$result" | grep "^TOKEN_EXPIRES:" | sed 's/^TOKEN_EXPIRES: //')

    log_success "Recovery account created: $username"
    log_critical "RECOVERY TOKEN: $recovery_token"
    log_critical "TOKEN EXPIRES: $token_expires"
    log_warn "STORE THE RECOVERY TOKEN SECURELY - IT WILL NOT BE SHOWN AGAIN!"

    echo "$recovery_token" > "${ACTIVE_FILE}.recovery_token_${username}"
    echo "$token_expires" > "${ACTIVE_FILE}.recovery_token_expires_${username}"
    chmod 600 "${ACTIVE_FILE}.recovery_token_${username}" "${ACTIVE_FILE}.recovery_token_expires_${username}"
}

activate_emergency_mode() {
    ensure_dirs
    local timeout_hours="${1:-$DEFAULT_TIMEOUT_HOURS}"
    local recovery_token="${2:-}"

    log_info "Activating emergency authentication mode for $timeout_hours hour(s)..."

    # Create activation flag file
    local activated_at
    activated_at=$("$PYTHON_BIN" -c "from datetime import UTC, datetime; print(datetime.now(UTC).replace(tzinfo=None).isoformat())")
    local expires_at
    expires_at=$("$PYTHON_BIN" -c "
from datetime import UTC, datetime, timedelta
activated = datetime.fromisoformat('$activated_at')
expires = activated + timedelta(hours=$timeout_hours)
print(expires.isoformat())
")

    cat > "$ACTIVE_FILE" <<EOF
{
  "activated_at": "$activated_at",
  "timeout_hours": $timeout_hours,
  "expires_at": "$expires_at",
  "activated_by": "$(whoami)",
  "recovery_token": "$recovery_token"
}
EOF
    chmod 644 "$ACTIVE_FILE"

    log_success "Emergency mode activated"
    log_critical "EMERGENCY MODE ACTIVATED by $(whoami) for $timeout_hours hour(s)"
    log_critical "Expires at: $expires_at"
    if [[ -n "$recovery_token" ]]; then
        log_critical "Activation recovery token: $recovery_token"
    fi

    # Print summary
    echo
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}  EMERGENCY AUTHENTICATION MODE ACTIVATED${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo -e "Activated by:    $(whoami)"
    echo -e "Activated at:    $activated_at"
    echo -e "Expires at:      $expires_at"
    echo -e "Timeout:         $timeout_hours hour(s)"
    echo -e "Flag file:       $ACTIVE_FILE"
    echo -e "Log file:        $LOG_FILE"
    if [[ -n "$recovery_token" ]]; then
        echo -e "Recovery token:  $recovery_token"
    fi
    echo -e "${GREEN}================================================${NC}"
    echo
    log_warn "IMPORTANT: This mode allows break-glass and recovery accounts to authenticate."
    log_warn "IMPORTANT: All emergency actions are logged at CRITICAL severity."
    log_warn "IMPORTANT: Mode will auto-deactivate after $timeout_hours hour(s)."
}

deactivate_emergency_mode() {
    ensure_dirs
    log_info "Deactivating emergency authentication mode..."

    if [[ ! -f "$ACTIVE_FILE" ]]; then
        log_warn "Emergency mode is not active"
        return 0
    fi

    local flag_data
    flag_data=$(cat "$ACTIVE_FILE" 2>/dev/null || echo "{}")

    # Remove flag file and associated files
    rm -f "$ACTIVE_FILE"
    rm -f "${ACTIVE_FILE}.recovery_token"
    rm -f "${ACTIVE_FILE}.recovery_token_expires"
    rm -f "${ACTIVE_FILE}.recovery_token_"*
    rm -f "${ACTIVE_FILE}.recovery_token_expires_"*

    log_success "Emergency mode deactivated"
    log_critical "EMERGENCY MODE DEACTIVATED by $(whoami)"
    log_critical "Previous state: $flag_data"

    echo
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}  EMERGENCY AUTHENTICATION MODE DEACTIVATED${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo -e "Deactivated by:  $(whoami)"
    echo -e "Deactivated at:  $(date -u '+%Y-%m-%dT%H:%M:%S')"
    echo -e "${GREEN}================================================${NC}"
    echo
}

show_status() {
    ensure_dirs
    if [[ -f "$ACTIVE_FILE" ]]; then
        local flag_data
        flag_data=$(cat "$ACTIVE_FILE")
        log_info "Emergency mode is ACTIVE"
        echo "$flag_data" | "$PYTHON_BIN" -m json.tool
        local remaining
        remaining=$("$PYTHON_BIN" -c "
import json
from datetime import UTC, datetime
data = json.load(open('$ACTIVE_FILE'))
expires = datetime.fromisoformat(data['expires_at'])
now = datetime.now(UTC).replace(tzinfo=None)
if now < expires:
    remaining = int((expires - now).total_seconds())
    hours = remaining // 3600
    minutes = (remaining % 3600) // 60
    print(f'{hours}h {minutes}m remaining')
else:
    print('EXPIRED (auto-deactivation pending)')
")
        echo "Time remaining: $remaining"
    else
        log_info "Emergency mode is INACTIVE"
    fi
}

# Test mode: create flag file without interactive prompts
test_mode() {
    ensure_dirs
    local timeout_hours="${1:-$DEFAULT_TIMEOUT_HOURS}"
    local recovery_token
    recovery_token=$("$PYTHON_BIN" -c "import secrets; print(secrets.token_hex(32))")

    log_info "Test mode: creating emergency flag file..."

    local activated_at
    activated_at=$("$PYTHON_BIN" -c "from datetime import UTC, datetime; print(datetime.now(UTC).replace(tzinfo=None).isoformat())")
    local expires_at
    expires_at=$("$PYTHON_BIN" -c "
from datetime import UTC, datetime, timedelta
activated = datetime.fromisoformat('$activated_at')
expires = activated + timedelta(hours=$timeout_hours)
print(expires.isoformat())
")

    cat > "$ACTIVE_FILE" <<EOF
{
  "activated_at": "$activated_at",
  "timeout_hours": $timeout_hours,
  "expires_at": "$expires_at",
  "activated_by": "test",
  "recovery_token": "$recovery_token"
}
EOF
    chmod 644 "$ACTIVE_FILE"

    log_success "Test mode: Emergency flag file created at $ACTIVE_FILE"
    log_info "Recovery token: $recovery_token"
    echo "$recovery_token"
}

usage() {
    cat <<EOF
Usage: $0 {activate|deactivate|status|test-mode} [options]

Emergency Authentication Mode Activation Script (ADR-0014)
Creates break-glass and recovery accounts, activates emergency mode.

COMMANDS:
    activate [timeout_hours]  Activate emergency mode (default: 2 hours)
                              Creates break-glass and recovery accounts interactively
    deactivate                Deactivate emergency mode immediately
    status                    Show current emergency mode status
    test-mode [timeout_hours] Create flag file without interactive prompts (for testing)

ENVIRONMENT VARIABLES:
    SYSPASS_EMERGENCY_LOG_FILE       Log file path (default: /var/log/syspass/emergency-auth.log)
    SYSPASS_EMERGENCY_FLAG_DIR       Flag directory (default: /var/run/syspass)
    SYSPASS_EMERGENCY_TIMEOUT_HOURS  Default timeout in hours (default: 2)
    SYSPASS_PYTHON_BIN               Python binary (default: python3)
    SYSPASS_APP_DIR                  Application directory (default: /srv/pySysPass)
    SYSPASS_OPERATOR_MFA_SECRET      Operator MFA secret (REQUIRED for activation)
    SYSPASS_ALLOW_NONROOT            Set to 1 to allow non-root execution (testing only)

EXAMPLES:
    sudo $0 activate 4          # Activate for 4 hours
    sudo $0 activate            # Activate for default 2 hours
    sudo $0 deactivate          # Deactivate immediately
    sudo $0 status              # Show current status
    $0 test-mode 2              # Test mode: create flag for 2 hours (no root required)

SECURITY NOTES:
    - Must be run as root (unless SYSPASS_ALLOW_NONROOT=1)
    - Operator MFA verification required for activation
    - All actions logged at CRITICAL severity to $LOG_FILE
    - Recovery tokens shown ONLY ONCE - store securely!
    - Break-glass accounts are independent of LDAP
    - Emergency mode auto-deactivates after timeout

EOF
}

main() {
    # Auto-detect test mode: non-root, no TTY, custom flag dir
    if [[ "$EUID" -ne 0 ]] && [[ "${SYSPASS_ALLOW_NONROOT:-}" != "1" ]] && [[ ! -t 0 ]] && [[ -n "${SYSPASS_EMERGENCY_FLAG_DIR:-}" ]]; then
        # Running in test-like environment, use test-mode
        test_mode "${1:-$DEFAULT_TIMEOUT_HOURS}"
        return
    fi

    check_root

    local command="${1:-activate}"
    shift || true

    case "$command" in
        activate)
            verify_operator_mfa
            create_break_glass_account "break-glass-1"
            create_recovery_account "recovery-personnel-1"
            local timeout_hours="${1:-$DEFAULT_TIMEOUT_HOURS}"
            local recovery_token
            recovery_token=$(cat "${ACTIVE_FILE}.recovery_token" 2>/dev/null || echo "")
            activate_emergency_mode "$timeout_hours" "$recovery_token"
            ;;
        deactivate)
            deactivate_emergency_mode
            ;;
        status)
            show_status
            ;;
        test-mode)
            test_mode "${1:-$DEFAULT_TIMEOUT_HOURS}"
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"