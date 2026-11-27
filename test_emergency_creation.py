#!/usr/bin/env python3
"""Test the emergency credentials creation logic."""
import sys
import os
sys.path.insert(0, '/srv/pySysPass')
os.chdir('/srv/pySysPass')

from app.db.base import engine
from app.models.account import EmergencyCredentials
from app.services.auth_service import get_password_hash
from datetime import UTC, datetime, timedelta
from sqlalchemy.orm import Session
import secrets

# Test creating a break-glass account
username = "test-break-glass-1"
password = "TestPassword123!"
mfa_secret = "JBSWY3DPEHPK3PXP"
is_recovery = False

db = Session(engine)
try:
    existing = db.query(EmergencyCredentials).filter(
        EmergencyCredentials.username == username
    ).first()
    if existing:
        print(f"Account '{username}' already exists, deleting...")
        db.delete(existing)
        db.commit()

    password_hash = get_password_hash(password).encode('utf-8')
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

    recovery_token = secrets.token_hex(32)
    account.recovery_token = recovery_token.encode('utf-8')
    account.recovery_token_expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=24)
    db.commit()

    print(f"SUCCESS: Account created: {account.username}")
    print(f"RECOVERY_TOKEN: {recovery_token}")
    print(f"TOKEN_EXPIRES: {account.recovery_token_expires_at.isoformat()}")
    print(f"is_active: {account.is_active}")
    print(f"is_recovery: {account.is_recovery}")
except Exception as e:
    db.rollback()
    print(f"ERROR: {e}")
    sys.exit(1)
finally:
    db.close()

# Test creating a recovery account
username2 = "test-recovery-1"
password2 = "TestPassword123!"
mfa_secret2 = "JBSWY3DPEHPK3PXP"

db = Session(engine)
try:
    existing = db.query(EmergencyCredentials).filter(
        EmergencyCredentials.username == username2
    ).first()
    if existing:
        print(f"Account '{username2}' already exists, deleting...")
        db.delete(existing)
        db.commit()

    password_hash = get_password_hash(password2).encode('utf-8')
    password_salt = secrets.token_bytes(32)

    account = EmergencyCredentials(
        username=username2,
        password_hash=password_hash,
        password_salt=password_salt,
        mfa_secret=mfa_secret2.encode('utf-8'),
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

    print(f"SUCCESS: Recovery account created: {account.username}")
    print(f"RECOVERY_TOKEN: {recovery_token}")
    print(f"TOKEN_EXPIRES: {account.recovery_token_expires_at.isoformat()}")
    print(f"is_active: {account.is_active}")
    print(f"is_recovery: {account.is_recovery}")
except Exception as e:
    db.rollback()
    print(f"ERROR: {e}")
    sys.exit(1)
finally:
    db.close()