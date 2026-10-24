"""Readiness checks for orchestration probes (R13 / #62).

Liveness (``/health``) only says the process answers. Readiness says the
prerequisites for serving database-backed requests hold: configuration and
secrets, database connectivity, the canonical sysPass schema, and writable
runtime storage. Each check is bounded by a timeout so a hung dependency makes
the probe fail instead of hang.

Probe responses are unauthenticated, so they carry fixed check names and
generic reasons only, never exception text, paths, or connection details.
"""
import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.core.config import BASE_DIR, Settings, settings, validate_production_settings
from app.core.runtime_json_config import load_runtime_json_config

logger = logging.getLogger(__name__)

CHECK_TIMEOUT_SECONDS = 3.0
# Dedicated workers so a hung check cannot exhaust the default thread pool
# that request handlers rely on.
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="readiness")


class CheckFailedError(Exception):
    """A readiness prerequisite is not met; the message is safe to publish."""


def check_configuration(config: Settings = settings) -> None:
    try:
        validate_production_settings(config)
    except RuntimeError:
        raise CheckFailedError("invalid production configuration")
    if not config.DATABASE_URL:
        raise CheckFailedError("database not configured")
    for name in ("SECRET_KEY", "ENCRYPTION_KEY"):
        if not getattr(config, name, "").strip():
            raise CheckFailedError(f"{name} is empty")
    try:
        load_runtime_json_config()
    except (OSError, ValueError):
        raise CheckFailedError("runtime configuration unreadable")


def check_database(engine: Optional[Engine]) -> None:
    if engine is None:
        raise CheckFailedError("database not configured")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        raise CheckFailedError("database unreachable")


def check_schema(engine: Optional[Engine]) -> None:
    from app.db.bootstrap import database_requires_bootstrap

    if engine is None:
        raise CheckFailedError("database not configured")
    try:
        incomplete = database_requires_bootstrap(engine)
    except Exception:
        raise CheckFailedError("schema inspection failed")
    if incomplete:
        raise CheckFailedError("sysPass schema tables or views missing")


def _require_writable_dir(path: Path, label: str) -> None:
    if not path.is_dir():
        raise CheckFailedError(f"{label} directory missing")
    if not os.access(path, os.W_OK | os.X_OK):
        raise CheckFailedError(f"{label} directory not writable")


def check_storage(config: Settings = settings) -> None:
    # RSA transport keys and runtime JSON live under data/; archives under
    # backups/ (relative to the working directory, as BackupService uses).
    _require_writable_dir(BASE_DIR / "data", "data")
    _require_writable_dir(Path(config.SYSPASS_RUNTIME_CONFIG_JSON_PATH).parent, "runtime config")
    _require_writable_dir(Path("./backups"), "backup")


async def _run_check(func: Callable[[], None], timeout: float) -> dict:
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(loop.run_in_executor(_executor, func), timeout)
    except CheckFailedError as exc:
        return {"ok": False, "reason": str(exc)}
    except asyncio.TimeoutError:
        return {"ok": False, "reason": "timed out"}
    except Exception:
        logger.exception("Readiness check crashed")
        return {"ok": False, "reason": "check error"}
    return {"ok": True}


async def run_readiness_checks(
    engine: Optional[Engine],
    config: Settings = settings,
    timeout: float = CHECK_TIMEOUT_SECONDS,
) -> dict:
    checks = {
        "configuration": lambda: check_configuration(config),
        "database": lambda: check_database(engine),
        "storage": lambda: check_storage(config),
    }
    results = dict(zip(checks, await asyncio.gather(*(_run_check(f, timeout) for f in checks.values()))))
    # Schema inspection is meaningless (and slow) without a working connection.
    if results["database"]["ok"]:
        results["schema"] = await _run_check(lambda: check_schema(engine), timeout)
    else:
        results["schema"] = {"ok": False, "reason": "database unavailable"}
    for name, result in results.items():
        if not result["ok"]:
            logger.warning("Readiness check %s failed: %s", name, result["reason"])
    return {"ready": all(result["ok"] for result in results.values()), "checks": results}
