"""ADR-0014 extension-table guards for IMPL-041.

Companion to the 18 unmodified defect tests in ``test_emergency_auth.py``.
Covers migration 003 presence, readiness reporting of the extension table,
and fail-closed (401-class, never 500) authentication on a PHP-only database
where the Python extension table has not been applied.
"""
from __future__ import annotations

import ast
import asyncio
import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.v1 import auth as auth_router
from app.db.base import Base, get_db
from app.models.account import EmergencyCredentials
from app.services import emergency_auth
from app.services.readiness_service import run_readiness_checks

MIGRATION = (
    Path(__file__).resolve().parents[1] / "alembic" / "versions" / "003_emergency_credentials.py"
)


def _engine():
    """In-memory SQLite, shared across connections like the project fixtures."""
    return create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )


def test_migration_003_present_and_chained() -> None:
    """The Alembic migration for the ADR-0014 extension table is present (DoD)."""
    assert MIGRATION.is_file(), "ADR-0014 requires an Alembic migration for emergency_credentials"
    source = MIGRATION.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assigned = {
        target.id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant)
    }
    assert assigned["revision"] == "003"
    assert assigned["down_revision"] == "002"
    assert "emergency_credentials" in source


def test_migration_003_upgrade_creates_extension_table(monkeypatch) -> None:
    """Running the migration's upgrade() creates the expected extension table."""
    spec = importlib.util.spec_from_file_location("m003_emergency", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    created = []
    monkeypatch.setattr(module.op, "create_table", lambda name, *a, **kw: created.append(name))
    monkeypatch.setattr(module.op, "create_index", lambda *a, **kw: None)
    module.upgrade()
    assert created == ["emergency_credentials"]

    columns = {
        node.args[0].value
        for node in ast.walk(ast.parse(source=MIGRATION.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Column"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }
    for required in ("username", "password_hash", "mfa_secret", "is_recovery_account"):
        assert required in columns


def test_readiness_reports_emergency_table_state(monkeypatch) -> None:
    """Readiness reports extension state without changing the four core checks."""
    monkeypatch.setattr(
        "app.services.readiness_service.check_configuration", lambda config: {"ok": True}
    )
    monkeypatch.setattr("app.services.readiness_service.check_database", lambda engine: {"ok": True})
    monkeypatch.setattr("app.services.readiness_service.check_storage", lambda config: {"ok": True})
    monkeypatch.setattr("app.services.readiness_service.check_schema", lambda engine: {"ok": True})

    engine = _engine()
    absent = asyncio.run(run_readiness_checks(engine))
    assert absent["ready"] is True
    assert set(absent["checks"]) == {"configuration", "database", "schema", "storage"}
    assert absent["extensions"]["emergency_credentials"]["present"] is False

    Base.metadata.create_all(engine, tables=[EmergencyCredentials.__table__])
    present = asyncio.run(run_readiness_checks(engine))
    assert present["extensions"]["emergency_credentials"]["present"] is True


def test_emergency_login_without_extension_table_is_auth_class(tmp_path, monkeypatch) -> None:
    """A PHP-only database (no emergency table) yields 401, never an ORM 500."""
    engine = _engine()
    core_tables = [table for name, table in Base.metadata.tables.items() if name != "emergency_credentials"]
    Base.metadata.create_all(engine, tables=core_tables)
    db = sessionmaker(bind=engine)()

    activated = (datetime.now(UTC) - timedelta(minutes=1)).replace(tzinfo=None).isoformat()
    flag = tmp_path / "emergency-auth-active"
    flag.write_text(f'{{"activated_at": "{activated}", "timeout_hours": 2}}', encoding="utf-8")
    monkeypatch.setattr(emergency_auth, "EMERGENCY_FLAG_FILE", flag)

    app = FastAPI()
    app.include_router(auth_router.router, prefix="/api/v1/auth")
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app)

    response = client.post(
        "/api/v1/auth/emergency",
        data={"username": "break-glass", "password": "***", "mfa_code": "123456"},
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Invalid credentials"
