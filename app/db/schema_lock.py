"""Coordinated schema-mutation lock: ONE authority for bootstrap and Alembic.

A single lock identity (``pysyspass_schema_mutation``) is scoped to the target
database. Schema initialization (bootstrap) and schema migration (Alembic)
acquire it before *any* schema mutation, so they can never run concurrently
against the same database.

Lock ownership is tied to the acquiring connection: on MySQL/MariaDB the
connection-scoped ``GET_LOCK`` is taken on the same connection that runs the
DDL, and MySQL releases it automatically if that connection dies.  MySQL
user-level lock names live in a *server-wide* namespace (not per database),
so the target database name is embedded in the lock name
(``pysyspass_schema_mutation:<database>``, never longer than 64 characters) —
distinct databases on one server therefore do not serialize against each
other.  Lock acquisition failure aborts safely *before* DDL; release is
reliable (context managed, result logged).  The acquisition timeout
(default 600 s, configurable) bounds only the wait to acquire — it is
distinct from migration duration.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import math
import tempfile
import time
from pathlib import Path
from typing import Generator

from sqlalchemy import Engine, text
from sqlalchemy.engine import Connection

from app.core.config import settings

logger = logging.getLogger(__name__)

SCHEMA_MUTATION_LOCK_NAME = "pysyspass_schema_mutation"
"""Single lock identity shared by bootstrap and Alembic (ADR-0016 Decision 6)."""

MYSQL_LOCK_NAME_MAX = 64
"""MySQL rejects user-level lock names longer than 64 characters (error 4163)."""

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


def _mysql_lock_wait(wait: float) -> int:
    """Cast the acquisition wait to the integer ``GET_LOCK`` actually honors.

    MySQL truncates fractional *bind-parameter* timeouts to 0 (a 0.5 s wait
    becomes a non-blocking probe), while a literal 0.5 is rounded half-up to
    1 s.  Cast in Python exactly the way the server rounds literals (nearest
    integer, half up, never negative) so ``SCHEMA_MUTATION_LOCK_SECONDS`` and
    fractional timeouts behave identically through bind parameters.
    """
    return max(0, math.floor(wait + 0.5))


def mysql_lock_name(engine_obj: Engine) -> str:
    """Return the MySQL ``GET_LOCK`` name scoped to *engine_obj*'s database.

    ``GET_LOCK`` names are server-wide, not database-scoped, so the target
    database name is embedded in the name.  The result never exceeds 64
    characters; over-long names are folded into a hash suffix.
    """
    database = engine_obj.url.database or ""
    name = f"{SCHEMA_MUTATION_LOCK_NAME}:{database}"
    if len(name) <= MYSQL_LOCK_NAME_MAX:
        return name
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    return f"{SCHEMA_MUTATION_LOCK_NAME[: MYSQL_LOCK_NAME_MAX - 17]}:{digest}"


@contextlib.contextmanager
def schema_mutation_lock(engine_obj: Engine, timeout: float | None = None) -> Generator[Connection, None, None]:
    """Acquire the coordinated schema-mutation lock for *engine_obj*'s database.

    Yields the connection that holds the lock; DDL must run on that same
    connection so ownership stays tied to the acquiring connection.

    MySQL/MariaDB: ``GET_LOCK(name, wait)`` on a dedicated connection, with
    the database embedded in *name* (server-wide namespace, per-database
    identity); ``RELEASE_LOCK`` is called reliably in ``finally`` (a dead
    owning connection auto-releases the lock server-side).  The wait is cast
    to an integer because MySQL truncates fractional bind-param timeouts.
    Other dialects (SQLite, tests): ``fcntl`` file lock keyed by database URL,
    acquired with a deadline-based non-blocking retry loop that honors the
    timeout.
    """
    wait = _lock_wait_seconds(timeout)

    if engine_obj.dialect.name == "mysql":
        lock_name = mysql_lock_name(engine_obj)
        wait_seconds = _mysql_lock_wait(wait)
        with engine_obj.connect() as connection:
            acquired = connection.execute(
                text("SELECT GET_LOCK(:name, :wait)"),
                {"name": lock_name, "wait": wait_seconds},
            ).scalar()
            if acquired != 1:
                raise RuntimeError(
                    f"Timed out after {wait:.0f}s waiting for schema-mutation lock "
                    f"'{lock_name}'; aborting before any DDL"
                )
            try:
                yield connection
            finally:
                try:
                    released = connection.execute(
                        text("SELECT RELEASE_LOCK(:name)"),
                        {"name": lock_name},
                    ).scalar()
                    logger.debug(
                        "Schema-mutation lock '%s' released: %s",
                        lock_name,
                        released,
                    )
                except Exception:
                    # The owning connection died: MySQL already released the
                    # connection-scoped lock on disconnect.  Log and continue;
                    # recovery follows the interrupted-migration procedure.
                    logger.exception(
                        "Schema-mutation lock '%s': RELEASE_LOCK failed "
                        "(connection may be lost; lock auto-released by server)",
                        lock_name,
                    )
        return

    import fcntl

    key = hashlib.sha256(str(engine_obj.url).encode()).hexdigest()[:16]
    lock_path = Path(tempfile.gettempdir()) / f"pysyspass-schema-mutation-{key}.lock"
    with engine_obj.connect() as connection:
        with open(lock_path, "w") as handle:
            deadline = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError(
                            f"Timed out after {wait:.0f}s waiting for schema-mutation lock "
                            f"'{SCHEMA_MUTATION_LOCK_NAME}'; aborting before any DDL"
                        ) from None
                    time.sleep(min(0.05, remaining))
            try:
                yield connection
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
