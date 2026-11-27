from fastapi import FastAPI
from fastapi import Request
from fastapi.testclient import TestClient
import pytest
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.api.v1 import auth
from app.api.v1.auth import _client_ip
from app.core.config import Settings
from app.core.config import validate_production_settings
from app.db.base import get_db
from app.main import _get_ip
from app.main import app as main_app
from app.main import settings
from app.services.security_log_service import TrackService


@pytest.mark.parametrize(
    "peer, expected",
    [("198.51.100.25", "198.51.100.25"), ("10.0.0.10", "203.0.113.7")],
)
def test_forwarded_addresses_only_apply_to_trusted_peer(peer, expected):
    app = FastAPI()
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=["10.0.0.10"])

    @app.get("/address")
    def address(request: Request):
        return {"login": _client_ip(request), "audit": _get_ip(request)}

    client = TestClient(app, client=(peer, 1234))
    response = client.get(
        "/address",
        headers={"X-Real-IP": "192.0.2.99", "X-Forwarded-For": "192.0.2.99, 203.0.113.7"},
    )
    assert response.json() == {"login": expected, "audit": expected}


@pytest.fixture
def production_environment(monkeypatch):
    for key in ("DATABASE_URL", "SECRET_KEY", "ENCRYPTION_KEY", "DEBUG", "TRUSTED_PROXY_HOSTS"):
        monkeypatch.delenv(key, raising=False)


def test_production_rejects_generated_secrets(production_environment):
    config = Settings(_env_file=None, DEBUG=False, DATABASE_URL="sqlite://")
    with pytest.raises(RuntimeError, match="SECRET_KEY must be explicitly"):
        validate_production_settings(config)


@pytest.mark.parametrize("secret", ["", "short", "change-this-in-production-very-secure-key"])
def test_production_rejects_empty_short_and_example_keys(production_environment, secret):
    config = Settings(
        _env_file=None, DEBUG=False, DATABASE_URL="sqlite://",
        SECRET_KEY=secret, ENCRYPTION_KEY="a" * 64,
    )
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        validate_production_settings(config)


def test_production_accepts_effective_dotenv_secrets(production_environment, tmp_path):
    env = tmp_path / ".env"
    env.write_text("DEBUG=false\nDATABASE_URL=sqlite://\nSECRET_KEY=" + "a" * 64
                   + "\nENCRYPTION_KEY=" + "b" * 64 + "\n")
    validate_production_settings(Settings(_env_file=env))


def test_production_rejects_missing_database_and_wildcard_proxy(production_environment):
    config = Settings(
        _env_file=None, DEBUG=False, SECRET_KEY="a" * 64, ENCRYPTION_KEY="b" * 64,
        TRUSTED_PROXY_HOSTS=["*"],
    )
    with pytest.raises(RuntimeError, match="DATABASE_URL.*TRUSTED_PROXY_HOSTS"):
        validate_production_settings(config)


def test_explicit_debug_mode_allows_ephemeral_development_keys(production_environment):
    validate_production_settings(Settings(_env_file=None, DEBUG=True))


def test_application_startup_rejects_unsafe_production_config(monkeypatch):
    monkeypatch.setattr(settings, "DEBUG", False)
    monkeypatch.setattr(settings, "SECRET_KEY", "short")
    with pytest.raises(RuntimeError, match="Invalid production configuration"):
        with TestClient(main_app):
            pytest.fail("Unsafe configuration started the application")


def test_rotating_spoofed_headers_cannot_evade_login_lockout(db_session, test_user):
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=["10.0.0.10"])
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app, client=("198.51.100.25", 1234))
    statuses = []
    for attempt in range(6):
        response = client.post(
            "/api/v1/auth/login",
            data={"username": test_user.username, "password": "wrong-password"},
            headers={"X-Real-IP": f"192.0.2.{attempt + 1}", "X-Forwarded-For": f"192.0.2.{attempt + 1}"},
        )
        statuses.append(response.status_code)
    assert statuses == [401] * 5 + [429]
    assert TrackService(db_session).is_locked("198.51.100.25")
