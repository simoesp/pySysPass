"""Coordinated schema-mutation lock: ONE authority for bootstrap and Alembic.

A single lock identity (``pysyspass_schema_mutation``) is scoped to the target
database. Schema initialization (bootstrap) and schema migration (Alembic)
acquire it before *any* schema mutation, so they can never run concurrently
against the same database.

Lock ownership is tied to the acquiring connection: on MySQL/MariaDB the
connection-scoped ``GET_LOCK`` is taken on the same connection that runs the
DDL, and MySQL releases it automatically if that connection dies.  Lock
acquisition failure aborts safely *before* DDL; release is reliable (context
managed, result logged).  The acquisition timeout (default 600 s, configurable)
bounds only the wait to acquire — it is distinct from migration duration.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Generator

from sqlalchemy import Engine, text
from sqlalchemy.engine import Connection

from app.core.config import settings

logger = logging.getLogger(__name__)

SCHEMA_MUTATION_LOCK_NAME = "pysyspass_schema_mutation"
"""Single lock identity shared by bootstrap and Alembic (ADR-0016 Decision 6)."""

SCHEMA_MUTATION_LOCK_SECONDS = 600
"""Default lock acquisition timeout in seconds (Decision 6: 600 s, configurable).

Overridden at runtime by the ``SCHEMA_MUTATION_LOCK_SECONDS`` setting
(env var ``PYSYSPASS_SCHEMA_MUTATION_LOCK_SECONDS``).
"""

_DEFAULT_LOCK_SECONDS = SCHEMA_MUTATION_LOCK_SECONDS


def _lock_wait_seconds(timeout: float | None) -> float:
    """Resolve the acquisition timeout: argument > settings > default."""
    if timeout is not None:
        return float(timeout)
    return float(getattr(settings, "SCHEMA_MUTATION_LOCK_SECONDS", _DEFAULT_LOCK_SECONDS))


@contextlib.contextmanager
def schema_mutation_lock(engine_obj: Engine, timeout: float | None = None) -> Generator[Connection, None, None]:
    """Acquire the coordinated schema-mutation lock for *engine_obj*'s database.

    Yields the connection that holds the lock; DDL must run on that same
    connection so ownership stays tied to the acquiring connection.

    MySQL/MariaDB: ``GET_LOCK(name, wait)`` on a dedicated connection;
    ``RELEASE_LOCK`` is called reliably in ``finally`` (a dead owning
    connection auto-releases the lock server-side).
    Other dialects (SQLite, tests): ``fcntl`` file lock keyed by database URL.
    """
    wait = _lock_wait_seconds(timeout)

    if engine_obj.dialect.name == "mysql":
        with engine_obj.connect() as connection:
            acquired = connection.execute(
                text(f"SELECT GET_LOCK(:name, :wait)"),
                {"name": SCHEMA_MUTATION_LOCK_NAME, "wait": wait},
            ).scalar()
            if acquired != 1:
                raise RuntimeError(
                    f"Timed out after {wait:.0f}s waiting for schema-mutation lock "
                    f"'{SCHEMA_MUTATION_LOCK_NAME}'; aborting before any DDL"
                )
            try:
                yield connection
            finally:
                try:
                    released = connection.execute(
                        text(f"SELECT RELEASE_LOCK(:name)"),
                        {"name": SCHEMA_MUTATION_LOCK_NAME},
                    ).scalar()
                    logger.debug(
                        "Schema-mutation lock '%s' released: %s",
                        SCHEMA_MUTATION_LOCK_NAME,
                        released,
                    )
                except Exception:
                    # The owning connection died: MySQL already released the
                    # connection-scoped lock on disconnect.  Log and continue;
                    # recovery follows the interrupted-migration procedure.
                    logger.exception(
                        "Schema-mutation lock '%s': RELEASE_LOCK failed "
                        "(connection may be lost; lock auto-released by server)",
                        SCHEMA_MUTATION_LOCK_NAME,
                    )
        return

    import fcntl

    key = hashlib.sha256(str(engine_obj.url).encode()).hexdigest()[:16]
    lock_path = Path(tempfile.gettempdir()) / f"pysyspass-schema-mutation-{key}.lock"
    with engine_obj.connect() as connection:
        with open(lock_path, "w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield connection
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
