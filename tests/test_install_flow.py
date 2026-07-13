from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import auth
from app.db.base import get_db
from app.models.account import Config, User
from app.services.auth_service import decrypt_user_master_pass, verify_master_password_hash


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


def test_install_generates_master_password_for_initial_admin(db_session):
    app, client = _make_client(db_session)

    response = client.post(
        "/api/v1/auth/install",
        json={
            "username": "admin",
            "password": "admin-password",
            "email": "admin@example.test",
            "generate_master_password": True,
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["master_password_generated"] is True
    assert payload["master_password"]
    assert payload["message"] == "Save the generated master password in a secure place before continuing."

    user = db_session.query(User).filter(User.username == "admin").first()
    assert user is not None
    assert user.isUserAdmin is True
    assert decrypt_user_master_pass(user, "admin-password") == payload["master_password"]

    master_row = db_session.query(Config).filter(Config.parameter == "masterPwd").first()
    assert master_row is not None
    assert verify_master_password_hash(payload["master_password"], master_row.value)

    app.dependency_overrides.clear()


def test_install_accepts_specified_master_password_and_hides_it_in_response(db_session):
    app, client = _make_client(db_session)

    response = client.post(
        "/api/v1/auth/install",
        json={
            "username": "admin",
            "password": "admin-password",
            "master_password": "vault-master-password",
            "generate_master_password": False,
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["master_password_generated"] is False
    assert payload["master_password"] is None
    assert payload["message"] == "Installation completed successfully. Redirecting to login."

    user = db_session.query(User).filter(User.username == "admin").first()
    assert decrypt_user_master_pass(user, "admin-password") == "vault-master-password"

    app.dependency_overrides.clear()


def test_install_cannot_run_after_system_is_initialized(db_session):
    app, client = _make_client(db_session)

    first = client.post(
        "/api/v1/auth/install",
        json={
            "username": "admin",
            "password": "admin-password",
            "generate_master_password": True,
        },
    )
    assert first.status_code == 201

    second = client.post(
        "/api/v1/auth/install",
        json={
            "username": "admin2",
            "password": "another-password",
            "generate_master_password": True,
        },
    )
    assert second.status_code == 409

    status_response = client.get("/api/v1/auth/install/status")
    assert status_response.status_code == 200
    assert status_response.json()["installed"] is True

    app.dependency_overrides.clear()
