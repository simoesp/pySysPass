"""R16 / #65: failures are observable and blocking work is off the event loop."""
import inspect
import logging
import time
from contextlib import contextmanager

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


def test_no_async_route_runs_blocking_work_on_the_event_loop():
    """async routes must await something; others are plain def (threadpool)."""
    import ast
    from pathlib import Path

    offenders = []
    for path in sorted(Path("app/api/v1").glob("*.py")):
        for node in ast.parse(path.read_text()).body:
            is_route = any(
                isinstance(d, ast.Call) and getattr(d.func, "attr", "") in {"get", "post", "put", "delete", "patch"}
                for d in getattr(node, "decorator_list", [])
            )
            if isinstance(node, ast.AsyncFunctionDef) and is_route and not any(
                isinstance(n, (ast.Await, ast.AsyncFor, ast.AsyncWith)) for n in ast.walk(node)
            ):
                offenders.append(f"{path.name}:{node.name}")
    assert offenders == []



@contextmanager
def _serve(app):
    """Run ``app`` on a real uvicorn server: one event loop for all requests.

    TestClient gives each call from a new thread its own loop, which hides
    event-loop blocking.
    """
    import socket
    import threading

    import uvicorn

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "server did not start"
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _ping_while(base_url, slow_request):
    """Seconds a /ping takes while ``slow_request`` (1.5 s) is in flight."""
    import threading
    import urllib.request

    worker = threading.Thread(target=slow_request)
    worker.start()
    time.sleep(0.3)
    started = time.monotonic()
    with urllib.request.urlopen(f"{base_url}/ping", timeout=10) as response:
        assert response.status == 200
    elapsed = time.monotonic() - started
    worker.join()
    return elapsed


def test_slow_sign_in_does_not_block_other_requests(db_session, test_user, monkeypatch):
    import urllib.error
    import urllib.parse
    import urllib.request

    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")
    app.get("/ping")(lambda: {"ok": True})
    app.dependency_overrides[get_db] = lambda: db_session
    monkeypatch.setattr(auth, "verify_password", lambda *a: time.sleep(1.5) or False)

    with _serve(app) as base_url:
        def slow():
            body = urllib.parse.urlencode({"username": "testuser", "password": "x"}).encode()
            try:
                urllib.request.urlopen(f"{base_url}/api/v1/auth/login", data=body, timeout=10)
            except urllib.error.HTTPError:
                pass
        assert _ping_while(base_url, slow) < 1.0


def test_slow_database_route_does_not_block_other_requests(db_session, test_user, monkeypatch):
    import urllib.request

    from app.api.v1 import categories
    from app.services.category_service import CategoryService

    app = FastAPI()
    app.include_router(categories.router, prefix="/api/v1")
    app.get("/ping")(lambda: {"ok": True})
    app.dependency_overrides[get_db] = lambda: db_session
    monkeypatch.setattr(CategoryService, "get_categories", lambda self: time.sleep(1.5) or [])
    token = issue_session_token(test_user)

    with _serve(app) as base_url:
        def slow():
            request = urllib.request.Request(f"{base_url}/api/v1/categories",
                                             headers={"Authorization": f"Bearer {token}"})
            urllib.request.urlopen(request, timeout=10)
        assert _ping_while(base_url, slow) < 1.0
