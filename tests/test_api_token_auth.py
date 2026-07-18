"""API tokens authenticate REST calls, scoped by their PHP actionId."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db.base import get_db
from app.api.v1 import accounts, categories
from app.models.account import User
from app.schemas.account import AccountCreate
from app.services.account_service import AccountService
from app.services.auth_token_service import AuthTokenService
import app.core.security as core_security


def _make_client(db_session, encryption_service, monkeypatch):
    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1")
    app.include_router(categories.router, prefix="/api/v1")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(core_security, "get_encryption_service", lambda: encryption_service)
    monkeypatch.setattr(accounts, "get_encryption_service", lambda: encryption_service)
    return TestClient(app)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_account_search_token_lists_accounts(db_session, encryption_service, test_user, monkeypatch):
    AccountService(db_session, encryption_service).create_account(
        AccountCreate(title="Token Visible", password="pass"), test_user.id,
    )
    token = AuthTokenService(db_session).create_token(test_user.id, 3, test_user.id).token

    client = _make_client(db_session, encryption_service, monkeypatch)
    response = client.get("/api/v1/accounts", headers=_auth(token))
    assert response.status_code == 200
    assert [a["title"] for a in response.json()] == ["Token Visible"]

    count = client.get("/api/v1/accounts/count", headers=_auth(token))
    assert count.status_code == 200 and count.json()["count"] == 1


def test_token_scope_rejects_other_routes(db_session, encryption_service, test_user, monkeypatch):
    token = AuthTokenService(db_session).create_token(test_user.id, 3, test_user.id).token
    client = _make_client(db_session, encryption_service, monkeypatch)

    # Search token cannot create accounts nor read categories
    assert client.post(
        "/api/v1/accounts", json={"title": "X", "password": "p"}, headers=_auth(token),
    ).status_code == 403
    assert client.get("/api/v1/categories", headers=_auth(token)).status_code == 403


def test_category_token_scope(db_session, encryption_service, test_user, monkeypatch):
    token = AuthTokenService(db_session).create_token(test_user.id, 102, test_user.id).token
    client = _make_client(db_session, encryption_service, monkeypatch)

    assert client.get("/api/v1/categories", headers=_auth(token)).status_code == 200
    assert client.get("/api/v1/accounts", headers=_auth(token)).status_code == 403


def test_invalid_token_rejected(db_session, encryption_service, monkeypatch):
    client = _make_client(db_session, encryption_service, monkeypatch)
    assert client.get("/api/v1/accounts", headers=_auth("f" * 64)).status_code == 401


def test_disabled_user_token_rejected(db_session, encryption_service, test_user, monkeypatch):
    token = AuthTokenService(db_session).create_token(test_user.id, 3, test_user.id).token
    test_user.isDisabled = True
    db_session.commit()

    client = _make_client(db_session, encryption_service, monkeypatch)
    assert client.get("/api/v1/accounts", headers=_auth(token)).status_code == 401


def test_list_tokens_omits_secret_but_create_reveals_it(db_session):
    svc = AuthTokenService(db_session)
    created = svc.create_token(1, 3, 1)
    assert created.token and len(created.token) == 64      # revealed on create

    regenerated = svc.regenerate_token(created.id)
    assert regenerated.token and regenerated.token != created.token  # revealed on regen

    listed = svc.list_tokens()
    assert listed and all(t.token is None for t in listed)  # never in listings


def test_token_scopes_map_to_registered_routes():
    """Every API_TOKEN_SCOPES template must match a real route, so a route
    rename can't silently make a token scope unreachable."""
    from app.main import app
    from app.api.deps import API_TOKEN_SCOPES
    from tests.conftest import api_route_paths

    registered = set(api_route_paths(app))
    for action_id, pairs in API_TOKEN_SCOPES.items():
        for method, path in pairs:
            assert path in registered, f"action {action_id}: {method} {path} not registered"
