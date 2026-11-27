"""Readiness against a real MySQL server (R13 / #62); see test_mysql_account_references."""
import asyncio
import os
import secrets

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.db.bootstrap import bootstrap_database
from app.services.readiness_service import run_readiness_checks
from tests.test_readiness import _config, storage  # noqa: F401 -- shared fixture

MYSQL_URL = os.environ.get("PYSYSPASS_MYSQL_TEST_URL")

pytestmark = pytest.mark.skipif(
    not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set (disposable MySQL server required)"
)


def test_readiness_tracks_canonical_schema_on_mysql(storage):  # noqa: F811
    server_url = make_url(MYSQL_URL)
    database = f"pysyspass_ready_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    with admin.begin() as conn:
        conn.execute(text(f"CREATE DATABASE `{database}`"))
    engine = create_engine(server_url.set(database=database))
    config = _config(storage)
    try:
        empty = asyncio.run(run_readiness_checks(engine, config=config))
        assert empty["checks"]["database"]["ok"] is True
        assert empty["checks"]["schema"]["ok"] is False
        assert empty["ready"] is False

        bootstrap_database(engine)
        assert asyncio.run(run_readiness_checks(engine, config=config))["ready"] is True

        with engine.begin() as conn:
            conn.execute(text("DROP VIEW account_search_v"))
        assert asyncio.run(run_readiness_checks(engine, config=config))["ready"] is False
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))
        admin.dispose()


def test_unreachable_mysql_is_not_ready(storage):  # noqa: F811
    # Port 9 (discard) on loopback refuses connections immediately.
    engine = create_engine(make_url(MYSQL_URL).set(port=9, database="none"))
    result = asyncio.run(run_readiness_checks(engine, config=_config(storage)))
    assert result["checks"]["database"] == {"ok": False, "reason": "database unreachable"}
    assert result["ready"] is False


def test_concurrent_workers_bootstrap_a_virgin_database_once(monkeypatch):
    # WEB_CONCURRENCY workers all run the startup hook; on a virgin database the
    # losers used to fail with "Table ... already exists" and stop uvicorn.
    from concurrent.futures import ThreadPoolExecutor

    from app.db import bootstrap

    monkeypatch.setattr(bootstrap.settings, "AUTO_INIT_DB_ON_STARTUP", True)
    server_url = make_url(MYSQL_URL)
    database = f"pysyspass_race_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    with admin.begin() as conn:
        conn.execute(text(f"CREATE DATABASE `{database}`"))
    engines = [create_engine(server_url.set(database=database)) for _ in range(4)]
    try:
        with ThreadPoolExecutor(len(engines)) as pool:
            results = list(pool.map(lambda e: bootstrap.bootstrap_database_on_startup(e), engines))
        assert results.count(True) == 1  # exactly one worker applied the schema
        assert bootstrap.database_requires_bootstrap(engines[0]) is False
    finally:
        for engine in engines:
            engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))
        admin.dispose()
