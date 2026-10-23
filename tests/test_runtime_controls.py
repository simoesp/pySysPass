"""R9 / #52: security settings shown in the UI are enforced server-side."""
import base64
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.main as main_module
from app.api.v1 import accounts, auth, config_settings, files, password_reset, public_links, tags
from app.db.base import get_db
from app.models.account import AuthToken, Config, User
from app.schemas.user_profile import ProfilePermissions
from app.services.account_service import AccountService
from app.services.auth_service import get_password_hash, issue_session_token, store_user_master_pass
from app.services.runtime_policy import RuntimePolicy, invalidate_policy_cache
from tests.account_refs import account_create


@pytest.fixture(autouse=True)
def isolated_runtime_config(tmp_path, monkeypatch):
    # Settings resolve from runtime JSON first; keep tests off the checkout's file.
    monkeypatch.setattr(
        "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH",
        str(tmp_path / "runtime-config.json"),
    )


def _client(db_session, **kwargs):
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")
    app.include_router(password_reset.router, prefix="/api/v1/auth")
    for module in (accounts, config_settings, files, public_links, tags):
        app.include_router(module.router, prefix="/api/v1")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app, **kwargs)


def _set(db_session, **values):
    for key, value in values.items():
        row = db_session.query(Config).filter_by(parameter=key).first()
        if row:
            row.value = value
        else:
            db_session.add(Config(parameter=key, value=value))
    db_session.commit()
    # The settings API clears this cache on save; direct DB writes (or PHP)
    # converge within runtime_policy.CACHE_SECONDS.
    invalidate_policy_cache()


def _grant_all(db_session, user):
    user.userProfile.profile = json.dumps({k: True for k in ProfilePermissions.model_fields}).encode()
    db_session.commit()


def _bearer(user):
    return {"Authorization": f"Bearer {issue_session_token(user)}"}


def _admin(db_session):
    admin = User(
        id=3, name="Admin", username="admin", email="admin@example.com",
        password=get_password_hash("adminpass").encode(), userGroupId=1, userProfileId=1,
        hashSalt=b"s" * 32, isAdminApp=True,
    )
    db_session.add(admin)
    db_session.commit()
    return admin


# ── Maintenance mode ─────────────────────────────────────────────────────

def test_maintenance_blocks_non_admin_api_access(db_session, test_user):
    _grant_all(db_session, test_user)
    admin = _admin(db_session)
    client = _client(db_session)
    assert client.get("/api/v1/accounts", headers=_bearer(test_user)).status_code == 200

    _set(db_session, maintenance="true")
    response = client.get("/api/v1/accounts", headers=_bearer(test_user))
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "MAINTENANCE"
    assert client.post(
        "/api/v1/accounts", headers=_bearer(test_user),
        json={"title": "x", "password": "y", "client_id": 900, "category_id": 900, "is_public": True},
    ).status_code == 503
    # Application administrators keep access so they can end maintenance.
    assert client.get("/api/v1/accounts", headers=_bearer(admin)).status_code == 200


def test_maintenance_blocks_non_admin_login_without_revealing_accounts(db_session, test_user):
    _admin(db_session)
    store_user_master_pass(test_user, "testpassword", "vault-master")
    admin = db_session.get(User, 3)
    store_user_master_pass(admin, "adminpass", "vault-master")
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()
    _set(db_session, maintenance="true")
    client = _client(db_session)

    login = lambda u, p: client.post("/api/v1/auth/login", data={"username": u, "password": p})  # noqa: E731
    assert login("testuser", "wrong").status_code == 401
    assert login("nobody", "wrong").status_code == 401
    assert login("testuser", "testpassword").status_code == 503
    assert login("admin", "adminpass").status_code == 200


def test_maintenance_blocks_unauthenticated_entry_points_and_api_tokens(db_session, test_user):
    _set(db_session, maintenance="true")
    client = _client(db_session)
    assert client.get("/api/v1/public-links/abc/access").status_code == 503
    assert client.post("/api/v1/auth/password-reset/request", json={"email": "a@example.com"}).status_code == 503
    assert client.post("/api/v1/auth/password-reset/confirm",
                       json={"token": "t", "new_password": "x" * 12}).status_code == 503

    db_session.add(AuthToken(userId=test_user.id, token=b"a" * 64, actionId=3, createdBy=test_user.id,
                             startDate=int(time.time()), vault=b"", hash=b""))
    db_session.commit()
    response = client.get("/api/v1/accounts", headers={"Authorization": "Bearer " + "a" * 64})
    assert response.status_code == 503


# ── Force HTTPS ──────────────────────────────────────────────────────────

def test_force_https_redirects_plain_http(monkeypatch):
    monkeypatch.setattr(main_module, "get_policy", lambda: RuntimePolicy(https_required=True))
    client = TestClient(main_module.app, follow_redirects=False)

    response = client.get("/api/v1/accounts?page=2")
    assert response.status_code == 308
    assert response.headers["location"] == "https://testserver/api/v1/accounts?page=2"
    # A caller cannot opt out by claiming HTTPS from an untrusted address.
    spoofed = client.get("/api/v1/accounts", headers={"X-Forwarded-Proto": "https"})
    assert spoofed.status_code == 308
    assert client.get("/health").status_code == 200

    secure = TestClient(main_module.app, base_url="https://testserver", follow_redirects=False)
    assert secure.get("/").status_code == 200


def test_force_https_cannot_be_enabled_over_http(db_session, test_user):
    _grant_all(db_session, test_user)
    body = {"https_enabled": True, "session_timeout": 300}
    plain = _client(db_session)
    response = plain.put("/api/v1/settings/general", json=body, headers=_bearer(test_user))
    assert response.status_code == 400

    secure = _client(db_session, base_url="https://testserver")
    response = secure.put("/api/v1/settings/general", json=body, headers=_bearer(test_user))
    assert response.status_code == 200
    assert response.json()["https_enabled"] is True


# ── File attachments ─────────────────────────────────────────────────────

def _account(db_session, encryption_service, user):
    return AccountService(db_session, encryption_service).create_account(
        account_create(title="Files", password="secret", is_public=True), user.id
    )


def _upload(client, user, account_id, content: bytes, name="note.txt", **extra):
    body = {"name": name, "type": "text/plain", "content": base64.b64encode(content).decode(), **extra}
    return client.post(f"/api/v1/accounts/{account_id}/files", json=body, headers=_bearer(user))


def test_upload_uses_decoded_size_and_php_extension(db_session, encryption_service, test_user):
    _grant_all(db_session, test_user)
    account = _account(db_session, encryption_service, test_user)
    client = _client(db_session)

    response = _upload(client, test_user, account.id, b"hello", name="Report.final.pdf", size=1, extension="exe")
    assert response.status_code == 201, response.text
    assert response.json()["size"] == 5
    assert response.json()["extension"] == "PDF"


def test_upload_enforces_configured_size(db_session, encryption_service, test_user):
    _grant_all(db_session, test_user)
    account = _account(db_session, encryption_service, test_user)
    _set(db_session, files_allowed_size="1")
    client = _client(db_session)

    assert _upload(client, test_user, account.id, b"x" * 1000).status_code == 201
    assert _upload(client, test_user, account.id, b"x" * 1001).status_code == 413
    # Oversized base64 is refused before decoding.
    huge = {"name": "a.txt", "type": "text/plain", "content": "A" * 8000}
    response = client.post(f"/api/v1/accounts/{account.id}/files", json=huge, headers=_bearer(test_user))
    assert response.status_code == 413


def test_upload_enforces_allowed_extensions_and_valid_base64(db_session, encryption_service, test_user):
    _grant_all(db_session, test_user)
    account = _account(db_session, encryption_service, test_user)
    _set(db_session, files_allowed_exts="pdf, .PNG")
    client = _client(db_session)

    assert _upload(client, test_user, account.id, b"x", name="a.pdf").status_code == 201
    assert _upload(client, test_user, account.id, b"x", name="b.png").status_code == 201
    assert _upload(client, test_user, account.id, b"x", name="c.exe").status_code == 415
    assert _upload(client, test_user, account.id, b"x", name="noextension").status_code == 415
    bad = {"name": "a.pdf", "type": "application/pdf", "content": "not base64!"}
    response = client.post(f"/api/v1/accounts/{account.id}/files", json=bad, headers=_bearer(test_user))
    assert response.status_code == 400


def test_disabled_files_block_upload_and_listing(db_session, encryption_service, test_user):
    _grant_all(db_session, test_user)
    account = _account(db_session, encryption_service, test_user)
    _set(db_session, files_enabled="false")
    client = _client(db_session)

    assert _upload(client, test_user, account.id, b"x").status_code == 403
    response = client.get(f"/api/v1/accounts/{account.id}/files", headers=_bearer(test_user))
    assert response.status_code == 403


def test_file_size_setting_has_php_ceiling(db_session, test_user):
    _grant_all(db_session, test_user)
    client = _client(db_session)
    response = client.get("/api/v1/settings/accounts", headers=_bearer(test_user))
    body = {**response.json(), "files_allowed_size": 16385}
    assert client.put("/api/v1/settings/accounts", json=body, headers=_bearer(test_user)).status_code == 422
    body["files_allowed_size"] = 16384
    assert client.put("/api/v1/settings/accounts", json=body, headers=_bearer(test_user)).status_code == 200


def test_oversized_request_bodies_are_refused_before_parsing():
    client = TestClient(main_module.app)
    response = client.post(
        "/api/v1/auth/login", content=b"x", headers={"Content-Length": str(25 * 1024 * 1024)},
    )
    assert response.status_code == 413


def test_tag_lookup_requires_authentication(db_session):
    assert _client(db_session).get("/api/v1/tags/1").status_code in (401, 403)


def test_force_https_runs_after_trusted_proxy_normalization(monkeypatch):
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    # user_middleware[0] is outermost: proxy normalization must wrap HTTPS checks.
    order = [getattr(m, "kwargs", {}).get("dispatch", m.cls) for m in main_module.app.user_middleware]
    assert order.index(ProxyHeadersMiddleware) < order.index(main_module.force_https_middleware)

    replica = FastAPI()
    replica.get("/probe")(lambda: {"ok": True})
    replica.middleware("http")(main_module.force_https_middleware)
    replica.add_middleware(ProxyHeadersMiddleware, trusted_hosts=["127.0.0.1"])
    monkeypatch.setattr(main_module, "get_policy", lambda: RuntimePolicy(https_required=True))
    trusted = TestClient(replica, client=("127.0.0.1", 1234), follow_redirects=False)
    assert trusted.get("/probe", headers={"X-Forwarded-Proto": "https"}).status_code == 200
    assert trusted.get("/probe").status_code == 308
