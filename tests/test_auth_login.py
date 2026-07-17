from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db.base import get_db
from app.api.v1 import auth
from app.models.account import Config, User
from app.services.auth_service import (
    decrypt_user_master_pass,
    get_password_hash,
    store_user_master_pass,
)
from app.services.temporary_master_password_service import TemporaryMasterPasswordService


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


def _make_user(db_session, username: str, password: str) -> User:
    user = User(
        id=1,
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


def test_login_requests_old_password_for_changed_password(db_session):
    user = _make_user(db_session, "alice", "newpass")
    store_user_master_pass(user, "oldpass", "vault-master")
    user.isChangedPass = True
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()

    app, client = _make_client(db_session)
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "newpass"},
    )

    assert response.status_code == 428
    assert response.json()["detail"]["code"] == "OLD_PASSWORD_REQUIRED"

    app.dependency_overrides.clear()


def test_login_migrates_master_key_with_old_password(db_session):
    user = _make_user(db_session, "alice", "newpass")
    store_user_master_pass(user, "oldpass", "vault-master")
    user.isChangedPass = True
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()

    app, client = _make_client(db_session)

    wrong_old_password = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "newpass", "oldpass": "wrongpass"},
    )
    assert wrong_old_password.status_code == 401
    assert wrong_old_password.json()["detail"]["code"] == "OLD_PASSWORD_INVALID"

    migrated = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "newpass", "oldpass": "oldpass"},
    )
    assert migrated.status_code == 200
    assert "access_token" in migrated.json()

    db_session.refresh(user)
    assert user.isChangedPass is False
    assert decrypt_user_master_pass(user, "newpass") == "vault-master"
    assert decrypt_user_master_pass(user, "oldpass") is None

    app.dependency_overrides.clear()


def test_login_accepts_temporary_master_password(db_session):
    user = _make_user(db_session, "alice", "newpass")
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()

    temp_service = TemporaryMasterPasswordService(db_session)
    temp_password, _ = temp_service.create("vault-master", max_time=3600)

    app, client = _make_client(db_session)
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "newpass", "mpass": temp_password},
    )

    assert response.status_code == 200
    db_session.refresh(user)
    assert decrypt_user_master_pass(user, "newpass") == "vault-master"

    app.dependency_overrides.clear()


def _enroll_2fa(db_session, user, mode="enabled"):
    import pyotp
    from app.core.security import get_encryption_service
    from app.services.two_factor_service import (
        TwoFactorConfig, TwoFactorService, TwoFactorStore,
    )

    TwoFactorConfig(db_session).set_mode(mode)
    store = TwoFactorStore(db_session, get_encryption_service())
    secret = TwoFactorService.generate_secret()
    store.start_setup(user.id, secret)
    store.enable(user.id, ["1111122222"])
    return secret, pyotp


def test_login_requires_otp_for_enrolled_user(db_session):
    user = _make_user(db_session, "alice", "pass1234")
    store_user_master_pass(user, "pass1234", "vault-master")
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()
    secret, pyotp = _enroll_2fa(db_session, user)

    app, client = _make_client(db_session)

    # No code supplied → challenged
    response = client.post(
        "/api/v1/auth/login", data={"username": "alice", "password": "pass1234"},
    )
    assert response.status_code == 428
    assert response.json()["detail"]["code"] == "TWO_FACTOR_REQUIRED"

    # Wrong code → rejected
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "pass1234", "otp": "000000"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "TWO_FACTOR_INVALID"

    # Valid TOTP → token issued
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "pass1234", "otp": pyotp.TOTP(secret).now()},
    )
    assert response.status_code == 200
    assert response.json()["access_token"]


def test_login_accepts_backup_code_and_consumes_it(db_session):
    from app.core.security import get_encryption_service
    from app.services.two_factor_service import TwoFactorStore

    user = _make_user(db_session, "alice", "pass1234")
    store_user_master_pass(user, "pass1234", "vault-master")
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()
    _enroll_2fa(db_session, user)

    app, client = _make_client(db_session)
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "pass1234", "otp": "1111122222"},
    )
    assert response.status_code == 200

    store = TwoFactorStore(db_session, get_encryption_service())
    assert store.get_backup_codes(user.id) == []

    # Consumed code cannot be reused
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "pass1234", "otp": "1111122222"},
    )
    assert response.status_code == 401


def test_login_skips_otp_when_mode_disabled(db_session):
    user = _make_user(db_session, "alice", "pass1234")
    store_user_master_pass(user, "pass1234", "vault-master")
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()
    _enroll_2fa(db_session, user, mode="disabled")

    app, client = _make_client(db_session)
    response = client.post(
        "/api/v1/auth/login", data={"username": "alice", "password": "pass1234"},
    )
    assert response.status_code == 200
