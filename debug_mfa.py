#!/usr/bin/env python
"""Debug script for MFA vault unlock test."""
from app.db.base import get_db
from sqlalchemy.orm import Session

from app.services.auth_service import decrypt_user_master_pass, store_user_master_pass, get_password_hash
from app.models.account import User, Config
from app.core.security import get_encryption_service
from app.services.two_factor_service import TwoFactorConfig, TwoFactorService, TwoFactorStore

# Create a test session
from tests.conftest import TestingSessionLocal, Base, engine, PHYSICAL_TABLES

Base.metadata.create_all(bind=engine, tables=PHYSICAL_TABLES)
db = TestingSessionLocal()

# Bootstrap fixtures
from tests.conftest import _bootstrap_test_fixtures
_bootstrap_test_fixtures(db)
db.commit()

# Create test user
user = User(
    id=999,
    name='debug',
    username='debug',
    email='debug@example.com',
    password=get_password_hash('pass1234').encode('utf-8'),
    userGroupId=1,
    userProfileId=1,
    hashSalt=b'salt',
)
db.add(user)
store_user_master_pass(user, 'pass1234', 'vault-master')
db.add(Config(parameter='masterPwd', value=get_password_hash('vault-master')))
db.commit()

# Test decrypt
master_pass = decrypt_user_master_pass(user, 'pass1234')
print(f'Decrypted master_pass: {master_pass}')

# Enroll 2FA
TwoFactorConfig(db).set_mode('enforced')
store = TwoFactorStore(db, get_encryption_service(), master_pass='vault-master')
secret = TwoFactorService.generate_secret()
store.start_setup(user.id, secret)
store.enable(user.id, ['1111122222'])

# Check if enabled
print(f'2FA enabled: {store.is_enabled(user.id)}')
print(f'Secret: {store.get_secret(user.id)}')

# Now try with derived master_pass
store2 = TwoFactorStore(db, get_encryption_service(), master_pass=master_pass)
print(f'2FA enabled (derived): {store2.is_enabled(user.id)}')
print(f'Secret (derived): {store2.get_secret(user.id)}')

db.close()