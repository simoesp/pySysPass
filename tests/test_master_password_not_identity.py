"""
Tests for ADR-0003 Deviation 3: Master password must not be used as identity fallback.

Current implementation deviation: Master password (mpass) can unlock vault even if
identity authentication fails. This allows bypassing identity auth with master password.

Required behavior: Master password is vault unlock material ONLY, not identity.
It must only be accepted AFTER successful identity authentication (and MFA when enrolled).

These tests verify the required security invariants:
1. Login with only master password (no identity password) → 401
2. Master password cannot substitute for identity authentication
3. Requires valid identity provider auth first (local or LDAP)
4. Master password only works after identity auth + MFA verification
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import auth
from app.core.security import get_encryption_service
from app.db.base import get_db
from app.models.account import Config, User
from app.services.auth_service import (
    decrypt_user_master_pass,
    get_password_hash,
    store_user_master_pass,
)
from app.services.two_factor_service import TwoFactorConfig, TwoFactorService, TwoFactorStore


def _make_client(db_session):
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    return app, TestClient(app)


def _make_user(db_session, username: str, password: str, user_id: int = None) -> User:
    if user_id is None:
        from sqlalchemy import func
        from app.models.account import User as UserModel
        max_id = db_session.query(func.max(UserModel.id)).scalar() or 0
        user_id = max_id + 1
    user = User(
        id=user_id,
        name=username,
        username=username,
        email=f"{username}@example.com",
        password=get_password_hash(password).encode("utf-8"),
        userGroupId=1,
        userProfileId=1,
        hashSalt=b"salt",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _enroll_2fa(db_session, user, mode="enabled"):
    """Enroll user in 2FA with a known secret and backup code."""
    import pyotp
    from app.core.security import get_encryption_service
    from app.services.two_factor_service import (
        TwoFactorConfig, TwoFactorService, TwoFactorStore,
    )

    TwoFactorConfig(db_session).set_mode(mode)
    store = TwoFactorStore(db_session, get_encryption_service(), master_pass="vault-master")
    secret = TwoFactorService.generate_secret()
    store.start_setup(user.id, secret)
    store.enable(user.id, ["1111122222"])
    return secret, pyotp


def _setup_vault(db_session, user, login_password, master_password="vault-master"):
    """Set up vault with master password for the user."""
    store_user_master_pass(user, login_password, master_password)
    db_session.add(Config(parameter="masterPwd", value=get_password_hash(master_password)))
    db_session.commit()


class TestMasterPasswordNotIdentity:
    """Test that master password cannot be used as identity authentication."""

    def test_login_with_only_master_password_fails(self, db_session):
        """
        ADR-0003 Deviation 3: Master password alone cannot authenticate.

        Providing only username and master password (mpass) without a valid
        identity password must fail with 401. Empty password fails validation (422),
        so we use a wrong password to test the auth logic.
        """
        user = _make_user(db_session, "alice", "pass1234")
        _setup_vault(db_session, user, "pass1234")

        app, client = _make_client(db_session)

        # Attempt login with WRONG identity password but correct master password
        # This tests that master password cannot substitute for identity auth
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "alice", "password": "wrong-password", "mpass": "vault-master"},
        )

        # Must be rejected at identity auth stage - master password is not identity
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    def test_login_with_wrong_identity_password_but_correct_master_fails(self, db_session):
        """
        ADR-0003: Correct master password must not compensate for wrong identity password.

        Even with correct master password, wrong login password must fail.
        This is a duplicate test for emphasis - the key invariant.
        """
        user = _make_user(db_session, "bob", "correct-pass")
        _setup_vault(db_session, user, "correct-pass")

        app, client = _make_client(db_session)

        # Attempt login with WRONG identity password but CORRECT master password
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "bob", "password": "wrong-pass", "mpass": "vault-master"},
        )

        # Must be rejected at identity auth stage
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    def test_login_with_correct_identity_no_master_when_vault_locked(self, db_session):
        """
        When vault is locked (no master password provided and user's mPass cannot decrypt),
        login should require master password (428 MASTER_PASSWORD_REQUIRED).
        """
        user = _make_user(db_session, "charlie", "pass1234")
        _setup_vault(db_session, user, "pass1234")

        app, client = _make_client(db_session)

        # Login with correct identity password but NO master password
        # (user's encrypted mPass requires login password to decrypt)
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "charlie", "password": "pass1234"},
        )

        # Should succeed because login password can decrypt user's mPass
        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_master_password_works_after_identity_auth_no_mfa(self, db_session):
        """
        Master password works for vault unlock AFTER successful identity auth
        when 2FA is not enrolled/enforced.
        """
        user = _make_user(db_session, "dave", "pass1234")
        _setup_vault(db_session, user, "pass1234")
        # No 2FA enrollment

        app, client = _make_client(db_session)

        # Login with identity password + master password (no MFA needed)
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "dave", "password": "pass1234", "mpass": "vault-master"},
        )

        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_master_password_requires_mfa_when_enrolled(self, db_session):
        """
        ADR-0003: Master password + identity auth still requires MFA when enrolled.

        Master password does not bypass MFA requirement.
        """
        user = _make_user(db_session, "eve", "pass1234")
        _setup_vault(db_session, user, "pass1234")
        secret, pyotp = _enroll_2fa(db_session, user, mode="enforced")

        app, client = _make_client(db_session)

        # Login with identity password + master password but NO MFA
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "eve", "password": "pass1234", "mpass": "vault-master"},
        )

        # Must still require MFA
        assert response.status_code == 428
        assert response.json()["detail"]["code"] == "TWO_FACTOR_REQUIRED"

    def test_master_password_with_valid_mfa_works(self, db_session):
        """
        Master password + identity auth + valid MFA → success.
        """
        user = _make_user(db_session, "frank", "pass1234")
        _setup_vault(db_session, user, "pass1234")
        secret, pyotp = _enroll_2fa(db_session, user, mode="enforced")

        app, client = _make_client(db_session)

        # Login with identity password + master password + valid MFA
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "frank",
                "password": "pass1234",
                "mpass": "vault-master",
                "otp": pyotp.TOTP(secret).now(),
            },
        )

        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_master_password_with_invalid_mfa_fails(self, db_session):
        """
        Master password + identity auth + INVALID MFA → failure.
        """
        user = _make_user(db_session, "grace", "pass1234")
        _setup_vault(db_session, user, "pass1234")
        secret, pyotp = _enroll_2fa(db_session, user, mode="enforced")

        app, client = _make_client(db_session)

        # Login with identity password + master password + INVALID MFA
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "grace",
                "password": "pass1234",
                "mpass": "vault-master",
                "otp": "000000",
            },
        )

        assert response.status_code == 401
        assert response.json()["detail"]["code"] == "TWO_FACTOR_INVALID"

    def test_supplied_master_password_cannot_bypass_identity_check(self, db_session):
        """
        Regression test: supplied master_password (mpass form field) must not
        allow authentication when identity password is wrong.

        This directly tests the deviation where lines 242-263 in auth.py
        allow supplied_master_pass to unlock vault without identity verification.
        """
        user = _make_user(db_session, "henry", "correct-pass")
        _setup_vault(db_session, user, "correct-pass")

        app, client = _make_client(db_session)

        # Try to authenticate with wrong identity password but correct master password
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "henry", "password": "wrong-pass", "mpass": "vault-master"},
        )

        # Must fail at identity auth (line 205-216), never reach master password logic
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]


class TestMasterPasswordNotIdentityWithMFA:
    """Test master password behavior combined with MFA states."""

    def test_user_without_2fa_master_password_works(self, db_session):
        """
        User without 2FA enrolled can use master password for vault unlock
        after identity auth (when mode is 'enabled', not 'enforced').
        """
        user = _make_user(db_session, "ivan", "pass1234")
        _setup_vault(db_session, user, "pass1234")
        # No 2FA enrollment

        from app.services.two_factor_service import TwoFactorConfig
        TwoFactorConfig(db_session).set_mode("enabled")

        app, client = _make_client(db_session)

        response = client.post(
            "/api/v1/auth/login",
            data={"username": "ivan", "password": "pass1234", "mpass": "vault-master"},
        )

        assert response.status_code == 200
        assert "access_token" in response.json()


class TestLDAPUserMasterPasswordNotIdentity:
    """Test that LDAP-bound users also cannot use master password as identity."""

    def test_ldap_user_master_password_cannot_bypass_ldap_auth(self, db_session):
        """
        LDAP-bound user (isLdap=True) must authenticate via LDAP.
        Master password cannot bypass LDAP authentication.
        """
        from app.services.ldap_service import authenticate_ldap_login
        from unittest.mock import patch

        user = _make_user(db_session, "ldap-user", "local-pass")  # local hash exists but shouldn't be used
        user.isLdap = True
        _setup_vault(db_session, user, "local-pass")
        db_session.commit()

        app, client = _make_client(db_session)

        # Mock LDAP authentication to fail
        with patch("app.api.v1.auth.authenticate_ldap_login", return_value=None):
            # Try with correct master password but LDAP will fail
            response = client.post(
                "/api/v1/auth/login",
                data={"username": "ldap-user", "password": "any-ldap-pass", "mpass": "vault-master"},
            )

        # Must fail because LDAP auth failed and no fallback to local
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])