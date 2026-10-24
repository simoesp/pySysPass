"""R7 / #51: session revocation and the configured inactivity timeout."""
import hashlib
import time
from datetime import timedelta

import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import auth, two_factor, users
from app.db.base import get_db
from app.models.account import Config, User, UserPassRecover
from app.services.auth_service import (
    create_access_token,
    decode_token,
    get_password_hash,
    issue_session_token,
    store_user_master_pass,
)
from app.services.password_reset_service import PasswordResetService
from app.services.session_service import (
    DEFAULT_SESSION_TIMEOUT,
    MAX_SESSION_SECONDS,
    MIN_SESSION_TIMEOUT,
    SessionStore,
    session_fingerprint,
)
from app.services.user_service import UserService


def _client(db_session):
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")
    app.include_router(users.router, prefix="/api/v1")
    app.include_router(two_factor.router, prefix="/api/v1")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _me(client, token):
    return client.get("/api/v1/auth/me", headers=_bearer(token)).status_code


def _login(client, db_session, user, password="testpassword"):
    store_user_master_pass(user, password, "vault-master")
    if not db_session.query(Config).filter_by(parameter="masterPwd").first():
        db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()
    response = client.post("/api/v1/auth/login", data={"username": user.username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_login_token_uses_configured_session_timeout(db_session, test_user):
    client = _client(db_session)
    payload = decode_token(_login(client, db_session, test_user))
    assert payload["exp"] - payload["iat"] == pytest.approx(DEFAULT_SESSION_TIMEOUT, abs=1)
    assert payload["sfp"] == session_fingerprint(test_user)

    db_session.add(Config(parameter="session_timeout", value="900"))
    db_session.commit()
    payload = decode_token(_login(client, db_session, test_user))
    assert payload["exp"] - payload["iat"] == pytest.approx(900, abs=1)

    db_session.query(Config).filter_by(parameter="session_timeout").update({"value": "5"})
    db_session.commit()
    payload = decode_token(_login(client, db_session, test_user))
    assert payload["exp"] - payload["iat"] == pytest.approx(MIN_SESSION_TIMEOUT, abs=1)


def test_expired_and_legacy_tokens_are_rejected(db_session, test_user):
    client = _client(db_session)
    expired = create_access_token(
        {"user_id": test_user.id, "username": test_user.username, "jti": "x",
         "sfp": session_fingerprint(test_user), "iat": time.time() - 600},
        expires_delta=timedelta(seconds=-1),
    )
    assert _me(client, expired) == 401
    # Pre-revocation 24-hour tokens carry no fingerprint or session id.
    legacy = create_access_token({"user_id": test_user.id, "username": test_user.username})
    assert _me(client, legacy) == 401


def test_logout_revokes_only_the_presented_session(db_session, test_user):
    client = _client(db_session)
    first = _login(client, db_session, test_user)
    second = _login(client, db_session, test_user)

    assert client.post("/api/v1/auth/logout", headers=_bearer(first)).status_code == 204
    assert _me(client, first) == 401
    assert _me(client, second) == 200


def test_refresh_rotates_token_and_preserves_vault(db_session, test_user):
    client = _client(db_session)
    old = _login(client, db_session, test_user)
    response = client.post("/api/v1/auth/refresh", headers=_bearer(old))
    assert response.status_code == 200
    new = response.json()["access_token"]

    assert _me(client, old) == 401
    assert _me(client, new) == 200
    old_payload, new_payload = decode_token(old), decode_token(new)
    assert new_payload["master_pass"] == "vault-master"
    assert new_payload["auth_time"] == old_payload["auth_time"]
    assert new_payload["jti"] != old_payload["jti"]


def test_refresh_cannot_extend_past_maximum_session(db_session, test_user, monkeypatch):
    client = _client(db_session)
    started = time.time() - MAX_SESSION_SECONDS + 30
    token = issue_session_token(test_user, timeout_seconds=300, auth_time=started)
    payload = decode_token(token)
    assert payload["exp"] <= started + MAX_SESSION_SECONDS + 1

    response = client.post("/api/v1/auth/refresh", headers=_bearer(token))
    assert response.status_code == 200
    assert decode_token(response.json()["access_token"])["exp"] <= started + MAX_SESSION_SECONDS + 1

    real_time = time.time
    monkeypatch.setattr(auth.time, "time", lambda: real_time() + 60)
    token = issue_session_token(test_user, timeout_seconds=300, auth_time=started - 31)
    assert client.post("/api/v1/auth/refresh", headers=_bearer(token)).status_code == 401


def test_password_reset_revokes_existing_sessions(db_session, test_user):
    client = _client(db_session)
    token = _login(client, db_session, test_user)
    service = PasswordResetService(db_session)
    db_session.add(UserPassRecover(
        userId=test_user.id, hash=service._hash_token("reset-token"), date=int(time.time()), used=False,
    ))
    db_session.commit()

    assert service.confirm_reset("reset-token", "brand-new-password") is True
    assert _me(client, token) == 401
    assert _me(client, _login(client, db_session, test_user, "brand-new-password")) == 200


def test_admin_password_change_revokes_target_sessions(db_session, test_user):
    client = _client(db_session)
    token = _login(client, db_session, test_user)
    UserService(db_session).update_user_password(test_user.id, "set-by-admin")
    assert _me(client, token) == 401


def test_php_side_password_change_revokes_sessions(db_session, test_user):
    client = _client(db_session)
    token = _login(client, db_session, test_user)
    # sysPass PHP writes password_hash() output ($2y$) straight into User.pass.
    test_user.password = get_password_hash("changed-in-php").encode()
    db_session.commit()
    assert _me(client, token) == 401


def test_self_password_change_keeps_acting_session_only(db_session, test_user):
    client = _client(db_session)
    acting = _login(client, db_session, test_user)
    other = _login(client, db_session, test_user)
    response = client.post(
        f"/api/v1/users/{test_user.id}/password",
        json={"current_password": "testpassword", "new_password": "next-password-123"},
        headers=_bearer(acting),
    )
    assert response.status_code == 200, response.text
    replacement = response.json()["access_token"]

    assert _me(client, acting) == 401
    assert _me(client, other) == 401
    assert _me(client, replacement) == 200
    assert decode_token(replacement)["master_pass"] == "vault-master"


def test_two_factor_enrollment_changes_revoke_other_sessions(db_session, test_user):
    client = _client(db_session)
    acting = _login(client, db_session, test_user)
    other = _login(client, db_session, test_user)

    from app.services.two_factor_service import TwoFactorConfig

    TwoFactorConfig(db_session).set_mode("enabled")
    db_session.commit()
    setup = client.post("/api/v1/2fa/setup", json={"password": "testpassword"}, headers=_bearer(acting))
    assert setup.status_code == 200, setup.text
    code = pyotp.TOTP(setup.json()["secret"]).now()
    enabled = client.post("/api/v1/2fa/enable", json={"code": code}, headers=_bearer(acting))
    assert enabled.status_code == 200, enabled.text
    acting = enabled.json()["access_token"]

    assert _me(client, other) == 401
    assert _me(client, acting) == 200

    survivor = issue_session_token(db_session.get(User, test_user.id))
    disabled = client.post("/api/v1/2fa/disable", json={"password": "testpassword"}, headers=_bearer(acting))
    assert disabled.status_code == 200, disabled.text
    assert _me(client, survivor) == 401
    assert _me(client, disabled.json()["access_token"]) == 200


def test_api_tokens_cannot_use_session_endpoints(db_session, test_user):
    from app.models.account import AuthToken

    value = hashlib.sha256(b"api").hexdigest()
    db_session.add(AuthToken(userId=test_user.id, token=value.encode(), actionId=1, createdBy=test_user.id,
                             startDate=int(time.time()), vault=b"", hash=b""))
    db_session.commit()
    # Logout/refresh are not in any API token scope, so the token is refused.
    response = _client(db_session).post("/api/v1/auth/logout", headers=_bearer(value))
    assert response.status_code in (400, 403)


def test_session_store_is_shared_and_prunes(tmp_path):
    path = tmp_path / "sessions.json"
    worker_a, worker_b = SessionStore(path), SessionStore(path)
    payload = {"jti": "abc", "user_id": 7, "iat": time.time()}
    assert worker_b.is_revoked(payload) is False

    worker_a.revoke_token("abc", time.time() + 60)
    assert worker_b.is_revoked(payload) is True

    worker_a.revoke_token("expired", time.time() - 1)
    worker_a.revoke_token("short", time.time() + 0.2)
    time.sleep(0.3)
    worker_a.revoke_token("later", time.time() + 60)
    assert "expired" not in path.read_text()
    assert "short" not in path.read_text()
    assert oct(path.stat().st_mode & 0o777) == "0o600"

    worker_a.revoke_user(8)
    assert worker_b.is_revoked({"jti": "z", "user_id": 8, "iat": time.time() - 5}) is True
    assert worker_b.is_revoked({"jti": "z", "user_id": 8, "iat": time.time() + 1}) is False


def test_corrupt_session_store_does_not_lock_everyone_out(tmp_path):
    path = tmp_path / "sessions.json"
    path.write_text("{not json")
    store = SessionStore(path)
    assert store.is_revoked({"jti": "abc", "user_id": 1, "iat": time.time()}) is False
    store.revoke_token("abc", time.time() + 60)
    assert store.is_revoked({"jti": "abc", "user_id": 1, "iat": time.time()}) is True


def test_vault_claim_is_authenticated_and_bound_to_the_user(monkeypatch):
    import base64

    from app.services import auth_service

    claim = auth_service._encrypt_short("vault-master", user_id=2)
    assert claim.startswith("g2:") and "vault-master" not in claim
    assert auth_service._decrypt_short(claim, user_id=2) == "vault-master"
    assert auth_service._decrypt_short(claim, user_id=3) is None  # moved into another user's token
    raw = bytearray(base64.urlsafe_b64decode(claim[3:]))
    raw[-1] ^= 1
    assert auth_service._decrypt_short("g2:" + base64.urlsafe_b64encode(bytes(raw)).decode(), user_id=2) is None
    assert auth_service._decrypt_short("bm90LWdjbQ==", user_id=2) is None  # pre-GCM claims are ignored
    monkeypatch.setattr(auth_service.settings, "ENCRYPTION_KEY", "another-encryption-key-32-bytes!")
    assert auth_service._decrypt_short(claim, user_id=2) is None
