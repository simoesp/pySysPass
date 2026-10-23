"""R13 / #62: liveness and readiness are separate, bounded probes."""
import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

import app.main as main_module
from app.core.config import Settings
from app.db.base import Base
from app.db.bootstrap import VIEW_TABLES
from app.services import readiness_service
from app.services.readiness_service import run_readiness_checks

SECRET = "s" * 40


def _config(tmp_path, **overrides):
    values = {
        "DEBUG": False,
        "DATABASE_URL": "sqlite://",
        "SECRET_KEY": SECRET,
        "ENCRYPTION_KEY": "e" * 40,
        "TRUSTED_PROXY_HOSTS": ["127.0.0.1"],
        "SYSPASS_RUNTIME_CONFIG_JSON_PATH": str(tmp_path / "data" / "runtime-config.json"),
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture(autouse=True)
def isolated_executor(monkeypatch):
    # Join readiness threads after each test; later tests fork processes.
    executor = ThreadPoolExecutor(max_workers=4)
    monkeypatch.setattr(readiness_service, "_executor", executor)
    yield
    executor.shutdown(wait=True)


@pytest.fixture()
def storage(tmp_path, monkeypatch):
    (tmp_path / "data").mkdir()
    (tmp_path / "backups").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(readiness_service, "BASE_DIR", tmp_path)
    monkeypatch.setattr(
        "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH",
        str(tmp_path / "data" / "runtime-config.json"),
    )
    return tmp_path


def _engine(with_schema: bool):
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    if with_schema:
        Base.metadata.create_all(
            engine, tables=[t for t in Base.metadata.sorted_tables if not t.info.get("is_view")]
        )
        with engine.begin() as conn:
            for view in VIEW_TABLES:
                conn.execute(text(f"CREATE VIEW {view} AS SELECT 1 AS id"))
    return engine


def _run(engine, config):
    return asyncio.run(run_readiness_checks(engine, config=config, timeout=1.0))


def test_ready_when_all_prerequisites_hold(storage):
    result = _run(_engine(with_schema=True), _config(storage))
    assert result["ready"] is True
    assert all(check["ok"] for check in result["checks"].values())


def test_not_ready_without_database(storage):
    result = _run(None, _config(storage))
    assert result["ready"] is False
    assert result["checks"]["database"] == {"ok": False, "reason": "database not configured"}
    assert result["checks"]["schema"] == {"ok": False, "reason": "database unavailable"}


def test_not_ready_when_schema_missing(storage):
    result = _run(_engine(with_schema=False), _config(storage))
    assert result["checks"]["database"]["ok"] is True
    assert result["checks"]["schema"] == {"ok": False, "reason": "sysPass schema tables or views missing"}
    assert result["ready"] is False


def test_not_ready_with_unsafe_production_configuration(storage):
    config = _config(storage, SECRET_KEY="change-this-" + "x" * 40)
    result = _run(_engine(with_schema=True), config)
    assert result["checks"]["configuration"] == {"ok": False, "reason": "invalid production configuration"}
    assert result["ready"] is False


def test_not_ready_with_malformed_runtime_configuration(storage):
    (storage / "data" / "runtime-config.json").write_text("[1, 2]")
    result = _run(_engine(with_schema=True), _config(storage))
    assert result["checks"]["configuration"] == {"ok": False, "reason": "runtime configuration unreadable"}


def test_not_ready_when_storage_missing_or_read_only(storage):
    (storage / "backups").rmdir()
    result = _run(_engine(with_schema=True), _config(storage))
    assert result["checks"]["storage"] == {"ok": False, "reason": "backup directory missing"}

    (storage / "backups").mkdir()
    (storage / "data").chmod(0o500)
    try:
        result = _run(_engine(with_schema=True), _config(storage))
    finally:
        (storage / "data").chmod(0o700)
    assert result["checks"]["storage"]["ok"] is False
    assert result["checks"]["storage"]["reason"].endswith("not writable")


def test_hung_check_times_out(storage, monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(readiness_service, "check_database", lambda engine: release.wait(5))
    started = time.monotonic()
    try:
        result = asyncio.run(run_readiness_checks(_engine(True), config=_config(storage), timeout=0.2))
        elapsed = time.monotonic() - started
    finally:
        release.set()
    assert elapsed < 2
    assert result["checks"]["database"] == {"ok": False, "reason": "timed out"}
    assert result["ready"] is False


def test_endpoints_separate_liveness_from_readiness(storage, monkeypatch):
    monkeypatch.setattr(main_module.db_base, "engine", None)
    client = TestClient(main_module.app)

    for path in ("/health", "/health/live"):
        assert client.get(path).json() == {"status": "healthy"}

    response = client.get("/health/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert set(body["checks"]) == {"configuration", "database", "schema", "storage"}
    # Unauthenticated probe output must not disclose paths or secrets.
    serialized = json.dumps(body)
    assert str(storage) not in serialized
    assert SECRET not in serialized


def test_ready_endpoint_returns_200(storage, monkeypatch):
    async def ready(engine):
        return {"ready": True, "checks": {"database": {"ok": True}}}

    monkeypatch.setattr(main_module, "run_readiness_checks", ready)
    response = TestClient(main_module.app).get("/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
