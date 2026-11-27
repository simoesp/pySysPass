#!/usr/bin/env python3
"""Test script to verify service vault bootstrap works."""

import os
import sys
sys.path.insert(0, '/srv/pySysPass')

os.environ['SERVICE_VAULT_KEY'] = 'test-service-vault-key-32bytes-long!!'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from app.db.base import Base

# Create engine and session
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables
from app.models.account import User, Config, UserGroup, UserProfile
import json
PHYSICAL_TABLES = [table for table in Base.metadata.sorted_tables if not table.info.get("is_view")]
Base.metadata.create_all(bind=engine, tables=PHYSICAL_TABLES)

db = TestingSessionLocal()

try:
    # Create reference rows
    permissions = {key: True for key in ["account_view", "account_add", "account_edit", "account_delete", "account_export", "admin_all"]}
    profile = UserProfile(
        id=1,
        name="Default Profile",
        profile=json.dumps(permissions).encode("utf-8"),
    )
    db.add(profile)
    db.flush()
    group = UserGroup(id=1, name="Default Group", description="Test group")
    db.add(group)
    db.flush()
    db.commit()
    
    # Create test user
    from app.services.auth_service import get_password_hash, store_user_master_pass, hash_master_key
    hashed = get_password_hash("testpassword")
    if isinstance(hashed, str):
        hashed = hashed.encode("utf-8")
    
    user = User(
        id=2,
        name="Test User",
        username="testuser",
        email="test@example.com",
        password=hashed,
        isUserAdmin=False,
        userGroupId=1,
        userProfileId=1,
        hashSalt=os.urandom(32),
        loginCount=0,
        lastUpdateMPass=0,
    )
    db.add(user)
    db.flush()
    
    # Store master password for the user
    master_password = "test-master-password-123"
    store_user_master_pass(user, "testpassword", master_password)
    
    # Set master password hash in Config
    db.add(Config(parameter="masterPwd", value=hash_master_key(master_password)))
    db.commit()
    db.refresh(user)
    
    print(f"Created user: {user.username}")
    
    # Create bootstrap artifact
    from app.core.service_vault_key import seal_master_artifact, master_key_provider
    path = seal_master_artifact(master_password)
    print(f"Created bootstrap artifact: {path}")
    
    # Verify master key provider can resolve it
    master = master_key_provider.resolve(db)
    print(f"Resolved master password: {master is not None}")
    assert master == master_password, f"Expected {master_password}, got {master}"
    
    # Create service account
    from app.services.service_account_service import ServiceAccountService
    svc = ServiceAccountService(db)
    result = svc.create_service_account(
        service_name="ci-cd-pipeline",
        owner_id=2,
        purpose="GitHub Actions CI/CD integration",
        scopes=["read", "write"],
        resource_restrictions={"groups": ["developers"], "exclude_private": True},
    )
    
    print(f"Created service account: {result['service_id']}")
    print(f"Service token: {result['service_token']}")
    
    # Verify vault context exists
    from app.services.service_vault_context_service import _store
    store = _store()
    context = store.get_context(result['service_id'])
    print(f"Vault context exists: {context is not None}")
    assert context is not None
    assert context.service_id == result['service_id']
    assert context.encrypted_context is not None
    
    # Verify we can decrypt it
    from app.core.service_vault_crypto import decrypt_service_vault_context
    payload = decrypt_service_vault_context(context.encrypted_context, context.encrypted_with_key)
    print(f"Decrypted payload keys: {list(payload.keys())}")
    assert "master_password" in payload
    assert "service_key" in payload
    assert payload["master_password"] == master_password
    
    print("\n✅ All checks passed!")
    sys.exit(0)
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
finally:
    db.close()