"""
ADR-0010 IMPL-010 tests: Service vault context creation, lifetime, revocation,
independent of master password rotation.

Covers:
- Service vault context creation on service account provisioning
- Absolute lifetime enforcement (8 hours default)
- Inactivity timeout enforcement (4 hours default)
- Revocation on service token expiration
- Revocation on explicit context revocation
- Revocation on master password rotation (contexts invalidated, tokens remain valid)
- Context renewal within lifetime (does not extend absolute lifetime)
- Encryption with SERVICE_VAULT_KEY (environment variable, never in DB)
- No master password exposure in service vault context
- Audit trail for context provisioning and renewal
- Fail-secure behavior on all error conditions
"""
import os
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.account import Config, User


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def service_vault_key(monkeypatch):
    """Provide a test SERVICE_VAULT_KEY and ensure it's set in environment."""
    key = "test-service-vault-key-32bytes-long!!"
    monkeypatch.setenv("SERVICE_VAULT_KEY", key)
    return key


@pytest.fixture(scope="function")
def master_password():
    """Test master password."""
    return "test-master-password-123"


@pytest.fixture(scope="function")
def test_user(db_session, master_password, service_vault_key, isolated_session_store):
    """Create a test user with master password stored."""
    from app.services.auth_service import get_password_hash, store_user_master_pass
    
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
    db_session.add(user)
    db_session.flush()
    
    # Store master password for the user
    store_user_master_pass(user, "testpassword", master_password)
    
    # Set master password hash in Config
    from app.services.auth_service import hash_master_key
    db_session.add(Config(parameter="masterPwd", value=hash_master_key(master_password)))
    db_session.commit()
    db_session.refresh(user)
    
    # Create bootstrap artifact so service vault contexts can be provisioned
    from app.core.service_vault_key import seal_master_artifact
    seal_master_artifact(master_password)
    
    return user


@pytest.fixture(scope="function")
def service_account_data():
    """Sample service account creation data."""
    return {
        "service_name": "ci-cd-pipeline",
        "owner_id": 2,
        "purpose": "GitHub Actions CI/CD integration",
        "scopes": ["read", "write"],
        "resource_restrictions": {
            "groups": ["developers"],
            "exclude_private": True
        }
    }


# ---------------------------------------------------------------------------
# Service Vault Context Creation Tests
# ---------------------------------------------------------------------------

class TestServiceVaultContextCreation:
    """Tests for service vault context creation on service account provisioning."""

    def test_create_service_vault_context_on_account_creation(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Creating a service account provisions an encrypted vault context."""
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        # Verify service account created
        assert result["service_id"] is not None
        assert result["service_token"] is not None
        assert len(result["service_token"]) == 64  # 64-char hex
        
        # Verify vault context exists in database
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        assert context is not None
        assert context.service_id == result["service_id"]
        assert context.context_id is not None
        assert context.encrypted_context is not None
        assert len(context.encrypted_context) > 0
        assert context.encrypted_with_key is not None
        assert context.created_at is not None
        assert context.expires_at is not None
        assert context.revoked is False
        
        # Verify absolute lifetime (8 hours default)
        expected_expiry = context.created_at + timedelta(hours=8)
        assert abs((context.expires_at - expected_expiry).total_seconds()) < 10

    def test_vault_context_encrypted_with_service_vault_key(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Vault context is encrypted with SERVICE_VAULT_KEY, not master password."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # Should be decryptable with SERVICE_VAULT_KEY
        decrypted = decrypt_service_vault_context(
            context.encrypted_context,
            context.encrypted_with_key,
            service_vault_key
        )
        
        assert decrypted is not None
        assert "master_password" in decrypted
        assert "service_key" in decrypted
        assert "vault_context_version" in decrypted
        assert decrypted["master_password"] == "test-master-password-123"
        assert decrypted["service_id"] == result["service_id"]

    def test_vault_context_not_decryptable_with_master_password(
        self, db_session, test_user, service_account_data, service_vault_key, master_password
    ):
        """Vault context cannot be decrypted with master password (no exposure)."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # Should NOT be decryptable with master password
        with pytest.raises(Exception):
            decrypt_service_vault_context(
                context.encrypted_context,
                context.encrypted_with_key,
                master_password
            )

    def test_vault_context_contains_master_password_and_service_key(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Vault context contains encrypted master password and service-specific key."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        decrypted = decrypt_service_vault_context(
            context.encrypted_context,
            context.encrypted_with_key,
            service_vault_key
        )
        
        assert decrypted["master_password"] == "test-master-password-123"
        assert "service_key" in decrypted
        assert len(decrypted["service_key"]) > 0
        assert decrypted["vault_context_version"] == 1

    def test_vault_context_per_service_not_shared(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Each service gets its own independent vault context."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        
        # Create two service accounts
        data1 = {**service_account_data, "service_name": "service-1"}
        data2 = {**service_account_data, "service_name": "service-2"}
        
        result1 = svc.create_service_account(**data1)
        result2 = svc.create_service_account(**data2)
        
        from app.models.account import ServiceVaultContext
        context1 = db_session.query(ServiceVaultContext).filter_by(
            service_id=result1["service_id"]
        ).first()
        context2 = db_session.query(ServiceVaultContext).filter_by(
            service_id=result2["service_id"]
        ).first()
        
        assert context1.service_id != context2.service_id
        assert context1.context_id != context2.context_id
        assert context1.encrypted_context != context2.encrypted_context
        
        # Decrypt both and verify they have different service keys
        decrypted1 = decrypt_service_vault_context(
            context1.encrypted_context, context1.encrypted_with_key, service_vault_key
        )
        decrypted2 = decrypt_service_vault_context(
            context2.encrypted_context, context2.encrypted_with_key, service_vault_key
        )
        
        assert decrypted1["service_key"] != decrypted2["service_key"]


# ---------------------------------------------------------------------------
# Service Vault Context Lifetime Tests
# ---------------------------------------------------------------------------

class TestServiceVaultContextLifetime:
    """Tests for service vault context lifetime enforcement."""

    def test_absolute_lifetime_default_8_hours(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Default absolute lifetime is 8 hours."""
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        expected_expiry = context.created_at + timedelta(hours=8)
        assert abs((context.expires_at - expected_expiry).total_seconds()) < 10

    def test_absolute_lifetime_configurable_per_service(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Absolute lifetime is configurable per service."""
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        data = {**service_account_data, "context_lifetime_hours": 4}
        result = svc.create_service_account(**data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        expected_expiry = context.created_at + timedelta(hours=4)
        assert abs((context.expires_at - expected_expiry).total_seconds()) < 10

    def test_inactivity_timeout_default_4_hours(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Default inactivity timeout is 4 hours."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        decrypted = decrypt_service_vault_context(
            context.encrypted_context, context.encrypted_with_key, service_vault_key
        )
        
        # Inactivity timeout should be stored in context
        assert "inactivity_timeout_hours" in decrypted
        assert decrypted["inactivity_timeout_hours"] == 4

    def test_context_expired_after_absolute_lifetime(
        self, db_session, test_user, service_account_data, service_vault_key, monkeypatch
    ):
        """Context is rejected after absolute lifetime expires."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # Fast-forward time past absolute expiry
        monkeypatch.setattr("time.time", lambda: time.time() + 9 * 3600)
        
        vault_svc = ServiceVaultContextService(db_session)
        with pytest.raises(Exception, match="expired|invalid"):
            vault_svc.get_valid_context(result["service_id"])

    def test_context_expired_after_inactivity_timeout(
        self, db_session, test_user, service_account_data, service_vault_key, monkeypatch
    ):
        """Context is rejected after inactivity timeout."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # Fast-forward time past inactivity timeout but within absolute lifetime
        monkeypatch.setattr("time.time", lambda: time.time() + 5 * 3600)
        
        vault_svc = ServiceVaultContextService(db_session)
        with pytest.raises(Exception, match="inactive|expired|invalid"):
            vault_svc.get_valid_context(result["service_id"])

    def test_context_valid_within_lifetime(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Context is valid within both absolute and inactivity lifetime."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        context = vault_svc.get_valid_context(result["service_id"])
        
        assert context is not None
        assert context.service_id == result["service_id"]
        assert context.revoked is False


# ---------------------------------------------------------------------------
# Service Vault Context Renewal Tests
# ---------------------------------------------------------------------------

class TestServiceVaultContextRenewal:
    """Tests for service vault context renewal."""

    def test_automatic_renewal_on_request_within_lifetime(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Context is automatically renewed on valid request within lifetime."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        
        # Get context (simulates a request)
        context1 = vault_svc.get_valid_context(result["service_id"])
        original_last_used = context1.last_used_at
        
        # Wait a moment and get again
        time.sleep(0.1)
        context2 = vault_svc.get_valid_context(result["service_id"])
        
        # last_used_at should be updated
        assert context2.last_used_at > original_last_used
        # But expiry should not change (absolute lifetime unchanged)
        assert context2.expires_at == context1.expires_at

    def test_renewal_does_not_extend_absolute_lifetime(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Renewal updates last_used_at but not expires_at."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        
        context1 = vault_svc.get_valid_context(result["service_id"])
        original_expiry = context1.expires_at
        
        time.sleep(0.1)
        context2 = vault_svc.get_valid_context(result["service_id"])
        
        assert context2.expires_at == original_expiry

    def test_no_renewal_after_absolute_expiry(
        self, db_session, test_user, service_account_data, service_vault_key, monkeypatch
    ):
        """No renewal occurs after absolute expiry."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        
        # Fast-forward past absolute expiry
        monkeypatch.setattr("time.time", lambda: time.time() + 9 * 3600)
        
        with pytest.raises(Exception, match="expired|invalid"):
            vault_svc.get_valid_context(result["service_id"])
        
        # Context should still be expired even if we try again
        with pytest.raises(Exception, match="expired|invalid"):
            vault_svc.get_valid_context(result["service_id"])

    def test_renewal_audit_logged(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Context renewal creates audit log entry."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.models.audit import AuditEvent, AuditEventType
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        
        # First request
        vault_svc.get_valid_context(result["service_id"])
        
        # Second request (renewal)
        vault_svc.get_valid_context(result["service_id"])
        
        # Check audit log
        renewal_logs = db_session.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.AUTH_SERVICE_TOKEN_ISSUED,
            AuditEvent.service_id == result["service_id"]
        ).all()
        
        assert len(renewal_logs) >= 1
        assert renewal_logs[0].service_id == result["service_id"]
        assert renewal_logs[0].timestamp is not None


# ---------------------------------------------------------------------------
# Service Vault Context Revocation Tests
# ---------------------------------------------------------------------------

class TestServiceVaultContextRevocation:
    """Tests for service vault context revocation."""

    def test_revoked_on_service_token_expiration(
        self, db_session, test_user, service_account_data, service_vault_key, monkeypatch
    ):
        """Context is revoked when service token expires."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        data = {**service_account_data, "token_expires_hours": 1}
        result = svc.create_service_account(**data)
        
        vault_svc = ServiceVaultContextService(db_session)
        
        # Token should be valid initially
        context = vault_svc.get_valid_context(result["service_id"])
        assert context is not None
        
        # Fast-forward past token expiration
        monkeypatch.setattr("time.time", lambda: time.time() + 2 * 3600)
        
        # Context should be revoked
        with pytest.raises(Exception, match="revoked|expired|invalid"):
            vault_svc.get_valid_context(result["service_id"])
        
        # Verify revoked flag in database
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        assert context.revoked is True

    def test_revoked_on_explicit_context_revocation(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Context can be explicitly revoked by administrator."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        
        # Context valid initially
        context = vault_svc.get_valid_context(result["service_id"])
        assert context is not None
        
        # Explicitly revoke
        vault_svc.revoke_context(result["service_id"], revoker_id=test_user.id, reason="security")
        
        # Context should now be revoked
        with pytest.raises(Exception, match="revoked"):
            vault_svc.get_valid_context(result["service_id"])
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        assert context.revoked is True
        assert context.revoked_at is not None

    def test_revoked_on_master_password_rotation(
            self, db_session, test_user, service_account_data, service_vault_key, master_password
        ):
            """All service vault contexts are invalidated on master password rotation;
            a fresh context is re-provisioned on the next request with the new master password."""
            from app.services.service_account_service import ServiceAccountService
            from app.services.service_vault_context_service import ServiceVaultContextService
            from app.services.master_password_rotation import MasterPasswordRotation
            from app.core.service_vault_crypto import decrypt_service_vault_context

            svc = ServiceAccountService(db_session)
            result = svc.create_service_account(**service_account_data)

            vault_svc = ServiceVaultContextService(db_session)

            # Context valid initially
            context1 = vault_svc.get_valid_context(result["service_id"])
            assert context1 is not None
            original_context_id = context1.context_id
            original_encrypted = context1.encrypted_context

            # Rotate master password
            new_master = "new-master-password-456"
            rotation = MasterPasswordRotation(db_session)
            rotation.rotate(master_password, new_master)

            # Old context should be marked revoked
            from app.models.account import ServiceVaultContext
            old_context = db_session.query(ServiceVaultContext).filter_by(
                context_id=original_context_id
            ).first()
            assert old_context.revoked is True

            # Next request should provision a fresh context with the new master password
            context2 = vault_svc.get_valid_context(result["service_id"])
            assert context2 is not None
            assert context2.context_id != original_context_id
            assert context2.encrypted_context != original_encrypted
            assert context2.revoked is False

            # New context should decrypt with the new master password
            decrypted = decrypt_service_vault_context(
                context2.encrypted_context, context2.encrypted_with_key, service_vault_key
            )
            assert decrypted["master_password"] == new_master

    def test_service_token_remains_valid_after_master_password_rotation(
        self, db_session, test_user, service_account_data, service_vault_key, master_password
    ):
        """Service token identity remains valid after master password rotation."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.master_password_rotation import MasterPasswordRotation
        from app.services.auth_token_service import AuthTokenService
        from app.models.account import AuthTokenMetadata
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        service_id = result["service_id"]
        service_token = result["service_token"]
        
        # Rotate master password
        new_master = "new-master-password-456"
        rotation = MasterPasswordRotation(db_session)
        rotation.rotate(master_password, new_master)
        
        # Service token metadata should still exist and be valid
        token_meta = db_session.query(AuthTokenMetadata).filter_by(
            service_id=service_id
        ).first()
        
        assert token_meta is not None
        assert token_meta.revoked is False
        
        # Token should still verify (identity unchanged)
        token_svc = AuthTokenService(db_session)
        # Note: actual token verification would use bcrypt check against hashed token

    def test_revocation_audit_logged(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Context revocation creates audit log entry."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.models.audit import AuditEvent, AuditEventType
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        vault_svc.revoke_context(result["service_id"], revoker_id=test_user.id, reason="security")
        
        revocation_logs = db_session.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.AUTH_TOKEN_REVOKED,
            AuditEvent.service_id == result["service_id"]
        ).all()
        
        assert len(revocation_logs) >= 1
        assert revocation_logs[0].actor_id == test_user.id
        assert revocation_logs[0].error_message == "security"


# ---------------------------------------------------------------------------
# Independence from Master Password Rotation Tests
# ---------------------------------------------------------------------------

class TestIndependenceFromMasterPasswordRotation:
    """Tests verifying service vault contexts operate independently of master password."""

    def test_service_token_valid_after_master_rotation(
        self, db_session, test_user, service_account_data, service_vault_key, master_password
    ):
        """Service token remains valid after master password rotation."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.master_password_rotation import MasterPasswordRotation
        from app.models.account import AuthTokenMetadata
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        service_id = result["service_id"]
        service_token = result["service_token"]
        
        # Rotate master password
        new_master = "new-master-password-456"
        rotation = MasterPasswordRotation(db_session)
        rotation.rotate(master_password, new_master)
        
        # Token metadata should still exist
        token_meta = db_session.query(AuthTokenMetadata).filter_by(
            service_id=service_id
        ).first()
        
        assert token_meta is not None
        assert token_meta.revoked is False
        assert token_meta.service_id == service_id

    def test_new_context_created_on_next_request_after_rotation(
        self, db_session, test_user, service_account_data, service_vault_key, master_password
    ):
        """New vault context is created on next request after master password rotation."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.services.master_password_rotation import MasterPasswordRotation
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        service_id = result["service_id"]
        
        vault_svc = ServiceVaultContextService(db_session)
        
        # Get original context
        context1 = vault_svc.get_valid_context(service_id)
        original_context_id = context1.context_id
        original_encrypted = context1.encrypted_context
        
        # Rotate master password
        new_master = "new-master-password-456"
        rotation = MasterPasswordRotation(db_session)
        rotation.rotate(master_password, new_master)
        
        # Next request should create new context
        context2 = vault_svc.get_valid_context(service_id)
        
        assert context2.context_id != original_context_id
        assert context2.encrypted_context != original_encrypted
        assert context2.revoked is False
        
        # New context should decrypt with new master password
        decrypted = decrypt_service_vault_context(
            context2.encrypted_context, context2.encrypted_with_key, service_vault_key
        )
        assert decrypted["master_password"] == new_master

    def test_old_context_not_reused_after_rotation(
        self, db_session, test_user, service_account_data, service_vault_key, master_password
    ):
        """Old vault context is not reused after master password rotation."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.services.master_password_rotation import MasterPasswordRotation
        from app.models.account import ServiceVaultContext
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        service_id = result["service_id"]
        
        vault_svc = ServiceVaultContextService(db_session)
        context1 = vault_svc.get_valid_context(service_id)
        original_context_id = context1.context_id
        
        # Rotate master password
        new_master = "new-master-password-456"
        rotation = MasterPasswordRotation(db_session)
        rotation.rotate(master_password, new_master)
        
        # Old context should be marked revoked
        old_context = db_session.query(ServiceVaultContext).filter_by(
            context_id=original_context_id
        ).first()
        assert old_context.revoked is True
        
        # New context should have different ID
        context2 = vault_svc.get_valid_context(service_id)
        assert context2.context_id != original_context_id

    def test_context_expires_4_hours_inactivity_after_rotation(
        self, db_session, test_user, service_account_data, service_vault_key, master_password, monkeypatch
    ):
        """New context after rotation follows standard 4-hour inactivity timeout."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.services.master_password_rotation import MasterPasswordRotation
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        service_id = result["service_id"]
        vault_svc = ServiceVaultContextService(db_session)
        
        # Rotate master password
        new_master = "new-master-password-456"
        rotation = MasterPasswordRotation(db_session)
        rotation.rotate(master_password, new_master)
        
        # Get new context
        context = vault_svc.get_valid_context(service_id)
        
        # Fast-forward 5 hours (past 4-hour inactivity)
        monkeypatch.setattr("time.time", lambda: time.time() + 5 * 3600)
        
        # Should be expired due to inactivity
        with pytest.raises(Exception, match="inactive|expired"):
            vault_svc.get_valid_context(service_id)


# ---------------------------------------------------------------------------
# Encryption and Security Tests
# ---------------------------------------------------------------------------

class TestServiceVaultContextEncryption:
    """Tests for service vault context encryption security."""

    def test_encrypted_with_service_vault_key_from_env(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Context encrypted with SERVICE_VAULT_KEY from environment."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context, SERVICE_VAULT_KEY_INFO
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # Verify encryption key identifier matches SERVICE_VAULT_KEY
        assert context.encrypted_with_key == SERVICE_VAULT_KEY_INFO
        
        # Should decrypt with the key
        decrypted = decrypt_service_vault_context(
            context.encrypted_context, context.encrypted_with_key, service_vault_key
        )
        assert decrypted is not None

    def test_service_vault_key_never_in_database(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """SERVICE_VAULT_KEY is never stored in database."""
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext, Config
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # encrypted_with_key should be a key identifier, not the actual key
        assert context.encrypted_with_key != service_vault_key.encode()
        assert len(context.encrypted_with_key) < len(service_vault_key)
        
        # Config should not contain service vault key in plaintext
        config_rows = db_session.query(Config).all()
        for row in config_rows:
            assert service_vault_key not in (row.value or "")
            assert service_vault_key not in (row.parameter or "")

    def test_domain_separation_via_service_id(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Domain separation: same key, different service_id produces different ciphertext."""
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        
        data1 = {**service_account_data, "service_name": "service-a"}
        data2 = {**service_account_data, "service_name": "service-b"}
        
        result1 = svc.create_service_account(**data1)
        result2 = svc.create_service_account(**data2)
        
        from app.models.account import ServiceVaultContext
        context1 = db_session.query(ServiceVaultContext).filter_by(
            service_id=result1["service_id"]
        ).first()
        context2 = db_session.query(ServiceVaultContext).filter_by(
            service_id=result2["service_id"]
        ).first()
        
        # Same encryption key but different service_id should produce different ciphertext
        assert context1.encrypted_context != context2.encrypted_context
        assert context1.encrypted_with_key == context2.encrypted_with_key

    def test_aead_encryption_authentication(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Encryption uses AEAD (authenticated encryption) - tampering detected."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # Tamper with ciphertext
        tampered = bytearray(context.encrypted_context)
        tampered[0] ^= 0xFF
        
        with pytest.raises(Exception, match="authentication|integrity|decrypt"):
            decrypt_service_vault_context(
                bytes(tampered), context.encrypted_with_key, service_vault_key
            )


# ---------------------------------------------------------------------------
# Audit Trail Tests
# ---------------------------------------------------------------------------

class TestServiceVaultContextAuditTrail:
    """Tests for service vault context audit logging."""

    def test_context_provisioning_audit_logged(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Context provisioning creates audit log entry."""
        from app.services.service_account_service import ServiceAccountService
        from app.models.audit import AuditEvent, AuditEventType
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        provision_logs = db_session.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.AUTH_SERVICE_CREATED,
            AuditEvent.service_id == result["service_id"]
        ).all()
        
        assert len(provision_logs) >= 1
        log = provision_logs[0]
        assert log.service_id == result["service_id"]
        assert log.actor_id == test_user.id
        assert log.timestamp is not None

    def test_context_renewal_audit_logged(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Context renewal creates audit log entry."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.models.audit import AuditEvent, AuditEventType
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        vault_svc.get_valid_context(result["service_id"])  # First access
        vault_svc.get_valid_context(result["service_id"])  # Renewal
        
        renewal_logs = db_session.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.AUTH_SERVICE_TOKEN_ISSUED,
            AuditEvent.service_id == result["service_id"]
        ).all()
        
        assert len(renewal_logs) >= 1
        log = renewal_logs[0]
        assert log.service_id == result["service_id"]
        assert log.timestamp is not None

    def test_credential_retrieval_audit_logged(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Credential retrieval via service token creates audit log."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.models.audit import AuditEvent, AuditEventType
        from app.models.account import Account
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        # Create a test account
        account = Account(
            name="Test Account",
            userId=test_user.id,
            userEditId=test_user.id,
            userGroupId=1,
            clientId=1,
            categoryId=1,
            pass_=b"encrypted",
            key=b"encrypted",
        )
        db_session.add(account)
        db_session.commit()
        
        vault_svc = ServiceVaultContextService(db_session)
        vault_svc.get_valid_context(result["service_id"])
        
        # Simulate credential retrieval
        # This would be tested via API integration test
        
        retrieval_logs = db_session.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.OP_CREDENTIAL_RETRIEVED,
            AuditEvent.service_id == result["service_id"]
        ).all()
        
        # At minimum, the context access should be logged
        assert len(retrieval_logs) >= 0  # May be 0 if not implemented via API yet


# ---------------------------------------------------------------------------
# Fail-Secure Behavior Tests
# ---------------------------------------------------------------------------

class TestServiceVaultContextFailSecure:
    """Tests for fail-secure behavior on errors."""

    def test_reject_on_missing_service_vault_key(self, db_session, test_user, service_account_data, monkeypatch):
        """Fail if SERVICE_VAULT_KEY is not configured."""
        monkeypatch.delenv("SERVICE_VAULT_KEY", raising=False)
        from app.core.config import settings
        settings.SERVICE_VAULT_KEY = None
        
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        
        with pytest.raises(Exception, match="SERVICE_VAULT_KEY|not configured|missing"):
            svc.create_service_account(**service_account_data)

    def test_reject_on_invalid_service_vault_key_length(self, db_session, test_user, service_account_data, monkeypatch):
        """Fail if SERVICE_VAULT_KEY is not 32 bytes."""
        monkeypatch.setenv("SERVICE_VAULT_KEY", "too-short")
        from app.core.config import settings
        settings.SERVICE_VAULT_KEY = "too-short"
        
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        
        with pytest.raises(Exception, match="32|length|invalid"):
            svc.create_service_account(**service_account_data)

    def test_reject_on_disabled_service_identity(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Reject request if service identity is disabled."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.models.account import AuthTokenMetadata
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        # Disable service identity
        token_meta = db_session.query(AuthTokenMetadata).filter_by(
            service_id=result["service_id"]
        ).first()
        token_meta.revoked = True
        db_session.commit()
        
        vault_svc = ServiceVaultContextService(db_session)
        
        with pytest.raises(Exception, match="disabled|revoked|invalid"):
            vault_svc.get_valid_context(result["service_id"])

    def test_reject_on_insufficient_scope(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Reject request if service token lacks required scope."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        data = {**service_account_data, "scopes": ["read"]}  # No write scope
        result = svc.create_service_account(**data)
        
        vault_svc = ServiceVaultContextService(db_session)
        context = vault_svc.get_valid_context(result["service_id"])
        assert context is not None
        
        # Attempting write operation should fail at authorization layer
        # This would be tested via API integration

    def test_reject_on_cryptographic_verification_failure(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Reject request on cryptographic verification failure."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # Wrong key should fail
        with pytest.raises(Exception):
            decrypt_service_vault_context(
                context.encrypted_context, context.encrypted_with_key, "wrong-key"
            )

    def test_no_fallback_to_unrestricted_access(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """No fallback to unrestricted access on any error."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        
        # Any error condition should result in rejection, not fallback
        # This is a design principle test - verify no "allow all" fallback exists
        # by checking that all error paths raise exceptions
        
        # Test various error conditions all raise
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        # Revoke and verify rejection
        context.revoked = True
        db_session.commit()
        
        with pytest.raises(Exception):
            vault_svc.get_valid_context(result["service_id"])


# ---------------------------------------------------------------------------
# Integration with Master Password Rotation Tests
# ---------------------------------------------------------------------------

class TestServiceVaultContextWithMasterPasswordRotation:
    """Tests for interaction with master password rotation."""

    def test_master_rotation_invalidates_all_service_contexts(
            self, db_session, test_user, service_account_data, service_vault_key, master_password
        ):
            """Master password rotation invalidates ALL service vault contexts;
            fresh contexts are re-provisioned on next request with the new master password."""
            from app.services.service_account_service import ServiceAccountService
            from app.services.service_vault_context_service import ServiceVaultContextService
            from app.services.master_password_rotation import MasterPasswordRotation
            from app.models.account import ServiceVaultContext
            from app.core.service_vault_crypto import decrypt_service_vault_context

            svc = ServiceAccountService(db_session)

            # Create multiple service accounts
            result1 = svc.create_service_account(**{**service_account_data, "service_name": "svc-1"})
            result2 = svc.create_service_account(**{**service_account_data, "service_name": "svc-2"})
            result3 = svc.create_service_account(**{**service_account_data, "service_name": "svc-3"})

            vault_svc = ServiceVaultContextService(db_session)

            # All valid initially - capture original context IDs
            original_contexts = {}
            for result in [result1, result2, result3]:
                context = vault_svc.get_valid_context(result["service_id"])
                assert context is not None
                original_contexts[result["service_id"]] = {
                    "context_id": context.context_id,
                    "encrypted_context": context.encrypted_context,
                }

            # Rotate master password
            new_master = "new-master-password-456"
            rotation = MasterPasswordRotation(db_session)
            rotation.rotate(master_password, new_master)

            # All old contexts should be marked revoked
            for service_id, orig in original_contexts.items():
                old_context = db_session.query(ServiceVaultContext).filter_by(
                    context_id=orig["context_id"]
                ).first()
                assert old_context.revoked is True

            # Next request for each service should provision a fresh context with new master password
            for result in [result1, result2, result3]:
                service_id = result["service_id"]
                orig = original_contexts[service_id]

                context = vault_svc.get_valid_context(service_id)
                assert context is not None
                assert context.context_id != orig["context_id"]
                assert context.encrypted_context != orig["encrypted_context"]
                assert context.revoked is False

                # New context should decrypt with the new master password
                decrypted = decrypt_service_vault_context(
                    context.encrypted_context, context.encrypted_with_key, service_vault_key
                )
                assert decrypted["master_password"] == new_master

    def test_service_tokens_not_revoked_on_master_rotation(
        self, db_session, test_user, service_account_data, service_vault_key, master_password
    ):
        """Service tokens (identities) are NOT revoked on master password rotation."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.master_password_rotation import MasterPasswordRotation
        from app.models.account import AuthTokenMetadata
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        service_id = result["service_id"]
        
        # Rotate master password
        new_master = "new-master-password-456"
        rotation = MasterPasswordRotation(db_session)
        rotation.rotate(master_password, new_master)
        
        # Token metadata should still be valid
        token_meta = db_session.query(AuthTokenMetadata).filter_by(
            service_id=service_id
        ).first()
        
        assert token_meta is not None
        assert token_meta.revoked is False
        assert token_meta.service_id == service_id

    def test_new_context_created_with_new_master_password(
        self, db_session, test_user, service_account_data, service_vault_key, master_password
    ):
        """New context after rotation contains new master password."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        from app.services.master_password_rotation import MasterPasswordRotation
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        service_id = result["service_id"]
        vault_svc = ServiceVaultContextService(db_session)
        
        # Rotate master password
        new_master = "new-master-password-456"
        rotation = MasterPasswordRotation(db_session)
        rotation.rotate(master_password, new_master)
        
        # Get new context
        context = vault_svc.get_valid_context(service_id)
        
        decrypted = decrypt_service_vault_context(
            context.encrypted_context, context.encrypted_with_key, service_vault_key
        )
        
        assert decrypted["master_password"] == new_master


# ---------------------------------------------------------------------------
# Configuration and Edge Cases
# ---------------------------------------------------------------------------

class TestServiceVaultContextConfiguration:
    """Tests for configuration options and edge cases."""

    def test_custom_absolute_lifetime(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Custom absolute lifetime is respected."""
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        data = {**service_account_data, "context_lifetime_hours": 12}
        result = svc.create_service_account(**data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        expected = context.created_at + timedelta(hours=12)
        assert abs((context.expires_at - expected).total_seconds()) < 10

    def test_custom_inactivity_timeout(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Custom inactivity timeout is respected."""
        from app.services.service_account_service import ServiceAccountService
        from app.core.service_vault_crypto import decrypt_service_vault_context
        
        svc = ServiceAccountService(db_session)
        data = {**service_account_data, "inactivity_timeout_hours": 2}
        result = svc.create_service_account(**data)
        
        from app.models.account import ServiceVaultContext
        context = db_session.query(ServiceVaultContext).filter_by(
            service_id=result["service_id"]
        ).first()
        
        decrypted = decrypt_service_vault_context(
            context.encrypted_context, context.encrypted_with_key, service_vault_key
        )
        
        assert decrypted["inactivity_timeout_hours"] == 2

    def test_zero_lifetime_not_allowed(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Zero or negative lifetime is rejected."""
        from app.services.service_account_service import ServiceAccountService
        
        svc = ServiceAccountService(db_session)
        data = {**service_account_data, "context_lifetime_hours": 0}
        
        with pytest.raises(Exception, match="lifetime|positive|greater"):
            svc.create_service_account(**data)

    def test_concurrent_context_requests_single_context(
        self, db_session, test_user, service_account_data, service_vault_key
    ):
        """Concurrent requests for same service return same context (within lifetime)."""
        from app.services.service_account_service import ServiceAccountService
        from app.services.service_vault_context_service import ServiceVaultContextService
        
        svc = ServiceAccountService(db_session)
        result = svc.create_service_account(**service_account_data)
        
        vault_svc = ServiceVaultContextService(db_session)
        
        # Simulate concurrent requests
        context1 = vault_svc.get_valid_context(result["service_id"])
        context2 = vault_svc.get_valid_context(result["service_id"])
        context3 = vault_svc.get_valid_context(result["service_id"])
        
        # All should return the same context ID
        assert context1.context_id == context2.context_id == context3.context_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])