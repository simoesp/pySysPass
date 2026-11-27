"""Upgrade-path contract for the coordinated schema-mutation lock (IMPL-035).

Verifies that Alembic revision 001 is a baseline stamp that never re-executes
the PHP-owned ``schemas/dbstructure.sql`` as a second mutation authority, that
PHP-created databases are unaffected by upgrade/downgrade, and that restamping
an already-stamped database is idempotent.  All schema metadata mutations run
under the coordinated schema-mutation lock acquired by ``alembic/env.py``.

Requires ``PYSYSPASS_MYSQL_TEST_URL`` (a disposable MySQL server); skipped
locally unless it is set (CI ``backend-tests-mysql``).
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from alembic.command import downgrade as alembic_downgrade, upgrade as alembic_upgrade
from alembic.config import Config

from app.core.config import settings
from app.db.bootstrap import bootstrap_database

_MYSQL_URL = os.environ.get("PYSYSPASS_MYSQL_TEST_URL")
_PROJ = Path(__file__).resolve().parents[1]
MIGRATION_PATH = _PROJ / "alembic" / "versions" / "001_initial_syspass_schema.py"

PHP_BASE_TABLES = ("User", "Account", "UserGroup")
CANONICAL_VIEWS = ("account_data_v", "account_search_v")


def _new_database(server_url):
    """Create a fresh disposable database on the MySQL server; return its URL."""
    import secrets

    database = f"pysyspass_upgrade_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    with admin.begin() as conn:
        conn.execute(text(f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4"))
    admin.dispose()
    return server_url.set(database=database), database, admin


@pytest.fixture
def mysql_engine():
    """Provide a fresh disposable MySQL database engine (bootstrapped ready)."""
    if not _MYSQL_URL:
        pytest.skip("PYSYSPASS_MYSQL_TEST_URL not set")
    server_url = make_url(_MYSQL_URL)
    url, database, admin = _new_database(server_url)
    engine = create_engine(url)
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))
        admin.dispose()


def _alembic_cfg(db_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setattr(settings, "DATABASE_URL", db_url)
    return Config(str(_PROJ / "alembic.ini"))


@pytest.mark.skipif(not _MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_bootstrap_then_upgrade_stamps_baseline_preserves_php_tables(mysql_engine, monkeypatch):
    """Bootstrap from dbstructure.sql, then ``alembic upgrade head``: one lock,
    PHP base tables preserved, baseline stamped at head, canonical views present.
    """
    assert bootstrap_database(mysql_engine) is True
    cfg = _alembic_cfg(mysql_engine.url.render_as_string(hide_password=False), monkeypatch)
    alembic_upgrade(cfg, "head")

    with mysql_engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == "002", f"Expected alembic_version '002', got '{version}'"
        tables = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
                )
            ).fetchall()
        }
        for t in PHP_BASE_TABLES:
            assert t in tables, f"PHP base table {t} must survive upgrade"
        views = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = DATABASE() AND table_type = 'VIEW'"
                )
            ).fetchall()
        }
        for v in CANONICAL_VIEWS:
            assert v in views, f"canonical PHP view {v} must exist after 002"


@pytest.mark.skipif(not _MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_restamp_is_idempotent(mysql_engine, monkeypatch):
    """Running ``alembic upgrade head`` on an already-stamped database is a no-op."""
    assert bootstrap_database(mysql_engine) is True
    db_url = mysql_engine.url.render_as_string(hide_password=False)
    cfg = _alembic_cfg(db_url, monkeypatch)
    alembic_upgrade(cfg, "head")
    alembic_upgrade(cfg, "head")  # restamp: must not raise or duplicate the stamp

    with mysql_engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "002"


@pytest.mark.skipif(not _MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_downgrade_clears_stamp_keeps_php_tables(mysql_engine, monkeypatch):
    """Downgrading past the baseline removes the alembic_version row but never
    drops the PHP-owned base tables (PHP-created databases unaffected)."""
    assert bootstrap_database(mysql_engine) is True
    db_url = mysql_engine.url.render_as_string(hide_password=False)
    cfg = _alembic_cfg(db_url, monkeypatch)
    alembic_upgrade(cfg, "head")
    alembic_downgrade(cfg, "base")

    with mysql_engine.connect() as conn:
        row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
        assert row == [], "alembic_version must be cleared after downgrade to base"
        tables = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
                )
            ).fetchall()
        }
        for t in PHP_BASE_TABLES:
            assert t in tables, f"PHP base table {t} must survive downgrade"


@pytest.mark.skipif(not _MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_001_never_manually_writes_alembic_version():
    """Static guard: revision 001 must not INSERT/UPDATE/DELETE alembic_version
    itself — Alembic writes the stamp after the revision runs, and a manual
    write collides with it (IntegrityError 1062, Alembic 1.20.1)."""
    tree = ast.parse(MIGRATION_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "execute" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                    if arg.func.id == "text" and arg.args:
                        literal = arg.args[0]
                        if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
                            lowered = literal.value.lower()
                            assert "alembic_version" not in lowered, (
                                "001 must not execute DML against alembic_version "
                                f"directly: {literal.value!r}"
                            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
