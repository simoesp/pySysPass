"""R16 / #65: failures are observable and blocking work is off the event loop."""
import inspect
import logging
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.main as main_module
from app.api.v1 import auth, security
from app.core.operations import failure_snapshot, reset_failures
from app.db.base import get_db
from app.models.account import User, UserPassRecover
from app.services.auth_service import get_password_hash, issue_session_token
from app.services.password_reset_service import PasswordResetService


@pytest.fixture(autouse=True)
def clean_counters():
    reset_failures()
    yield
    reset_failures()


def test_audit_write_failure_is_logged_and_counted(monkeypatch, caplog):
    replica = FastAPI()
    replica.post("/api/v1/categories")(lambda: {"ok": True})
    replica.middleware("http")(main_module.audit_log_middleware)

    def broken(*args):
        raise RuntimeError("event log table unavailable")

    monkeypatch.setattr(main_module, "_write_audit_event", broken)
    with caplog.at_level(logging.ERROR, logger="app.main"):
        response = TestClient(replica).post("/api/v1/categories")
    assert response.status_code == 200  # the request itself still succeeds
    assert "Audit event write failed" in caplog.text
    assert failure_snapshot()["audit_log_write"]["count"] == 1


def test_reset_email_failure_is_logged_and_counted(db_session, test_user, monkeypatch, caplog):
    class BrokenMail:
        def send_password_reset(self, **kwargs):
            raise ConnectionError("SMTP down")

    service = PasswordResetService(db_session)
    monkeypatch.setattr(service, "_email_service", lambda: BrokenMail())
    with caplog.at_level(logging.ERROR, logger="app.services.password_reset_service"):
        assert service.request_reset(test_user.email) is True  # same answer: no enumeration
    assert "Password reset e-mail could not be sent" in caplog.text
    assert failure_snapshot()["password_reset_email"]["count"] == 1
    assert db_session.query(UserPassRecover).count() == 1


def test_empty_scheduler_is_not_started(monkeypatch):
    from app.services.task_service import task_service

    monkeypatch.setattr(task_service, "tasks", {})
    monkeypatch.setattr(main_module, "validate_production_settings", lambda config: None)
    monkeypatch.setattr(main_module, "bootstrap_database_on_startup", lambda: None)
    started = []
    monkeypatch.setattr(task_service, "start_scheduler", lambda: started.append(True))
    with TestClient(main_module.app):
        pass
    assert started == []


def test_operations_endpoint_is_admin_only(db_session, test_user):
    app = FastAPI()
    app.include_router(security.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    user_headers = {"Authorization": f"Bearer {issue_session_token(test_user)}"}
    assert client.get("/api/v1/security/operations", headers=user_headers).status_code == 403

    admin = User(id=3, name="A", username="admin", email="a@example.com", userGroupId=1, userProfileId=1,
                 password=get_password_hash("x").encode(), hashSalt=b"s" * 32, isAdminApp=True)
    db_session.add(admin)
    db_session.commit()
    body = client.get("/api/v1/security/operations",
                      headers={"Authorization": f"Bearer {issue_session_token(admin)}"}).json()
    assert body["scheduler"] == {"running": False, "registered_tasks": [], "automated_backups": False,
                                 "automated_expiry_notices": False}
    assert body["failures"] == {}


def test_login_runs_in_the_threadpool():
    # Sync FastAPI routes execute in the threadpool, keeping bcrypt and Defuse
    # key derivation off the event loop.
    assert not inspect.iscoroutinefunction(auth.login)


def test_slow_login_does_not_block_other_requests(db_session, test_user, monkeypatch):
    import threading

    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")
    app.get("/ping")(lambda: {"ok": True})
    app.dependency_overrides[get_db] = lambda: db_session
    monkeypatch.setattr(auth, "verify_password", lambda *a: time.sleep(1.5) or False)
    client = TestClient(app)

    thread = threading.Thread(target=lambda: client.post(
        "/api/v1/auth/login", data={"username": "testuser", "password": "x"}))
    thread.start()
    time.sleep(0.2)
    started = time.monotonic()
    assert client.get("/ping").status_code == 200
    assert time.monotonic() - started < 1.0
    thread.join()
