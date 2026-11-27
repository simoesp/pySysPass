"""Test coordinated schema-mutation lock serialization (TEST-011).

Verifies that ``schema_mutation_lock()`` in ``app/db/schema_lock.py``
serializes schema mutation across bootstrap and Alembic using ONE lock
identity (``pysyspass_schema_mutation``) scoped to the target database
(ADR-0016 Decision 6):

- MySQL/MariaDB: connection-scoped ``GET_LOCK('pysyspass_schema_mutation',
  :wait)``; ownership tied to the acquiring connection; released on the same
  connection; auto-released by the server if that connection dies.
- SQLite and other dialects: ``fcntl`` file lock keyed by database URL.

Independent ``pysyspass_bootstrap`` / ``pysyspass_alembic`` lock identities
are removed: bootstrap and Alembic funnel through the same lock, so they can
never mutate the same database concurrently.

Tests (SQLite/fcntl path, runs everywhere):
- test_schema_mutation_lock_default_timeout_is_600_seconds
- test_schema_mutation_lock_acquire_release
- test_schema_mutation_lock_exclusive_held
- test_schema_mutation_lock_concurrent_blocks
- test_schema_mutation_lock_three_way_serialized
- test_schema_mutation_lock_release_on_success
- test_schema_mutation_lock_exception_releases_lock
- test_schema_mutation_lock_bootstrap_alembic_mutex: TEST-011 race — bootstrap
  role and alembic role on the same DB serialize against each other
- test_schema_mutation_lock_timeout_blocks_then_acquires: while held, a
  contender cannot acquire; acquisition is bounded by hold time

Tests (MySQL GET_LOCK path, requires PYSYSPASS_MYSQL_TEST_URL):
- test_schema_mutation_lock_mysql_held_and_released
- test_schema_mutation_lock_mysql_concurrent_blocks
- test_schema_mutation_lock_mysql_timeout_raises: acquire failure aborts before DDL
- test_schema_mutation_lock_mysql_timeout_distinct_from_duration: short timeout
  raises long before a long-held lock is released (timeout != migration duration)
- test_schema_mutation_lock_mysql_cross_connection_release
- test_schema_mutation_upgrade_with_lock_applies_migrations: bootstrap then
  alembic upgrade head on a disposable MySQL DB under the coordinated lock
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.db.schema_lock import (
    SCHEMA_MUTATION_LOCK_NAME,
    SCHEMA_MUTATION_LOCK_SECONDS,
    schema_mutation_lock,
)

_PROJ = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lock_path_for(engine) -> Path:
    """Return the fcntl lock file path for *engine* (same URL => same lock)."""
    key = hashlib.sha256(str(engine.url).encode()).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"pysyspass-schema-mutation-{key}.lock"


# ---------------------------------------------------------------------------
# SQLite / fcntl tests
# ---------------------------------------------------------------------------


def test_schema_mutation_lock_default_timeout_is_600_seconds():
    """Decision 6: default acquisition timeout is 600 s, configurable."""
    assert SCHEMA_MUTATION_LOCK_SECONDS == 600


def test_schema_mutation_lock_acquire_release(tmp_path):
    """Basic acquire and release round-trip for SQLite (fcntl path)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    try:
        with schema_mutation_lock(engine):
            pass  # inside: lock held
        # outside: lock released — second acquire must succeed without blocking
        with schema_mutation_lock(engine):
            pass
    finally:
        engine.dispose()


def test_schema_mutation_lock_exclusive_held(tmp_path):
    """Verify the lock file is held EXCLUSIVE while the context is open."""
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    try:
        lp = _lock_path_for(engine)

        with schema_mutation_lock(engine):
            assert lp.exists(), "lock file must exist while held"
            # LOCK_NB from a *separate* open of the same file must fail
            with open(lp, "w") as f:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)

        # After exit: lock file still exists but flock must succeed
        with open(lp, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)  # must not raise
            fcntl.flock(f, fcntl.LOCK_UN)
    finally:
        engine.dispose()


def test_schema_mutation_lock_concurrent_blocks(tmp_path):
    """A second acquirer blocks until the first releases (fcntl path).

    fcntl.flock is per-fd, so two threads opening the same lock file block
    each other with LOCK_EX — one identity for both bootstrap and Alembic.
    """
    hold_time = 1.0
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    acquired: dict[str, float] = {}

    def acquire_and_hold(label: str, sleep_in: float):
        with schema_mutation_lock(engine):
            acquired[label] = time.monotonic()
            time.sleep(sleep_in)

    t1_start = threading.Event()

    def holder():
        t1_start.set()
        acquire_and_hold("holder", hold_time)

    th = threading.Thread(target=holder, daemon=True)
    th.start()
    t1_start.wait(timeout=5)
    time.sleep(0.1)  # ensure holder has the lock

    waiter_t0 = time.monotonic()
    acquire_and_hold("waiter", 0.0)
    waiter_elapsed = time.monotonic() - waiter_t0

    th.join(timeout=10)

    assert waiter_elapsed >= hold_time * 0.8, (
        f"waiter blocked {waiter_elapsed:.3f}s, expected >= {hold_time * 0.8:.3f}s"
    )
    engine.dispose()


def test_schema_mutation_lock_three_way_serialized(tmp_path):
    """Three acquirers serialize strictly on the one lock identity."""
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    n_threads = 3
    hold_per = 0.4
    barrier = threading.Barrier(n_threads, timeout=10)
    order: list[int] = []
    order_lock = threading.Lock()

    def worker(idx: int):
        barrier.wait()  # all start at roughly the same time
        with schema_mutation_lock(engine):
            with order_lock:
                order.append(idx)
            time.sleep(hold_per)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert len(order) == n_threads, f"Expected {n_threads} acquisitions, got {len(order)}"
    assert sorted(order) == list(range(n_threads))

    engine.dispose()


def test_schema_mutation_lock_release_on_success(tmp_path):
    """Lock is released after the context exits, even on exception."""
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")

    # Normal exit
    with schema_mutation_lock(engine):
        pass
    # Exception exit
    with pytest.raises(ValueError):
        with schema_mutation_lock(engine):
            raise ValueError("boom")

    # Re-acquire after both cases — must not block
    with schema_mutation_lock(engine):
        pass

    engine.dispose()


def test_schema_mutation_lock_exception_releases_lock(tmp_path):
    """An exception inside the lock must not leave it permanently held."""
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    lp = _lock_path_for(engine)

    class BoomError(Exception):
        pass

    try:
        with schema_mutation_lock(engine):
            raise BoomError
    except BoomError:
        pass

    # Lock must be released despite the exception
    with open(lp, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)  # must not raise
        fcntl.flock(f, fcntl.LOCK_UN)

    engine.dispose()


def test_schema_mutation_lock_bootstrap_alembic_mutex(tmp_path):
    """TEST-011 race: bootstrap role and alembic role on the same DB serialize.

    Both mechanisms now acquire the SAME lock identity against the same target
    database, so a bootstrap in progress blocks an alembic upgrade (and vice
    versa) for the whole mutation — no concurrent schema mutation.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    hold_time = 1.0
    acquired: dict[str, float] = {}

    def acquire_and_hold(role: str, sleep_in: float):
        # bootstrap_database() and alembic env.py both funnel through this one
        # context manager against the same URL => one lock file => mutex.
        with schema_mutation_lock(engine):
            acquired[role] = time.monotonic()
            time.sleep(sleep_in)

    # Alembic holds first; bootstrap must wait for the full hold time.
    t_alembic = threading.Thread(target=acquire_and_hold, args=("alembic", hold_time), daemon=True)
    t_alembic.start()
    time.sleep(0.2)  # ensure alembic has the lock

    t0 = time.monotonic()
    acquire_and_hold("bootstrap", 0.0)
    bootstrap_waited = time.monotonic() - t0
    t_alembic.join(timeout=30)

    assert "alembic" in acquired and "bootstrap" in acquired
    assert bootstrap_waited >= hold_time * 0.8, (
        f"bootstrap waited {bootstrap_waited:.3f}s for alembic, "
        f"expected >= {hold_time * 0.8:.3f}s"
    )

    engine.dispose()


def test_schema_mutation_lock_timeout_blocks_then_acquires(tmp_path):
    """While the lock is held, a contender cannot acquire instantaneously.

    The acquisition timeout bounds the WAIT; while a migration holds the lock
    for its full duration, others queue — timeout is distinct from duration.
    """
    hold_time = 1.0
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")

    start_event = threading.Event()
    acquired = {"time": None}
    finished = threading.Event()

    def holder():
        with schema_mutation_lock(engine):
            start_event.set()
            time.sleep(hold_time)

    def waiter():
        # Blocks on fcntl until the holder releases.
        with schema_mutation_lock(engine):
            acquired["time"] = time.monotonic()
        finished.set()

    th = threading.Thread(target=holder, daemon=True)
    th.start()
    start_event.wait(timeout=5)

    t0 = time.monotonic()
    wt = threading.Thread(target=waiter, daemon=True)
    wt.start()
    wt.join(timeout=hold_time * 0.5)

    # Mid-hold, the waiter must still be blocked (one identity = mutual exclusion)
    assert wt.is_alive(), "waiter acquired the lock while it was still held"

    # Once released, the waiter's acquisition is bounded by the hold time
    finished.wait(timeout=30)
    assert acquired["time"] is not None
    assert acquired["time"] - t0 >= hold_time * 0.8

    engine.dispose()


# ---------------------------------------------------------------------------
# MySQL / GET_LOCK tests
# ---------------------------------------------------------------------------

MYSQL_URL = os.environ.get("PYSYSPASS_MYSQL_TEST_URL")
pytestmark_mysql = pytest.mark.skipif(not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")


@pytest.fixture()
def mysql_engine():
    """Provide a fresh disposable MySQL database engine."""
    if not MYSQL_URL:
        pytest.skip("PYSYSPASS_MYSQL_TEST_URL not set")
    server_url = make_url(MYSQL_URL)
    database = f"pysyspass_lock_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    with admin.begin() as conn:
        conn.execute(text(f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4"))
    engine = create_engine(server_url.set(database=database))
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))
        admin.dispose()


@pytest.mark.skipif(not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_schema_mutation_lock_mysql_held_and_released(mysql_engine):
    """GET_LOCK acquired on entry; RELEASE_LOCK called on exit, result checked."""
    assert mysql_engine.dialect.name == "mysql"

    with schema_mutation_lock(mysql_engine):
        # A *separate* connection from the same pool sees the lock as held
        with mysql_engine.connect() as conn:
            is_free = conn.execute(
                text(f"SELECT IS_FREE_LOCK('{SCHEMA_MUTATION_LOCK_NAME}')")
            ).scalar()
            assert is_free == 0, "Lock should be held (IS_FREE_LOCK = 0)"

    # After exit, IS_FREE_LOCK must return 1
    with mysql_engine.connect() as conn:
        is_free = conn.execute(
            text(f"SELECT IS_FREE_LOCK('{SCHEMA_MUTATION_LOCK_NAME}')")
        ).scalar()
        assert is_free == 1, "Lock should be free after context exit"


@pytest.mark.skipif(not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_schema_mutation_lock_mysql_concurrent_blocks(mysql_engine):
    """Thread 2 must block on GET_LOCK until thread 1 releases (server-wide).

    Uses NullPool engines so each .connect() is a genuinely new MySQL session,
    and explicit events (not a barrier) to force deterministic ordering: the
    holder acquires and is confirmed holding the lock before the waiter tries,
    so the waiter's acquisition is bounded by the holder's release.  GET_LOCK
    is re-entrant within one session, so shared pooled connections would let
    both acquire immediately — hence NullPool.
    """
    from sqlalchemy.pool import NullPool

    hold_time = 1.0
    holder_eng = create_engine(mysql_engine.url, poolclass=NullPool)
    waiter_eng = create_engine(mysql_engine.url, poolclass=NullPool)

    holder_acquired = threading.Event()
    holder_release = threading.Event()
    waiter_wait: dict[str, float] = {}

    def holder():
        with schema_mutation_lock(holder_eng):
            holder_acquired.set()
            holder_release.wait(timeout=30)

    def waiter():
        holder_acquired.wait(timeout=5)  # holder definitely has the lock now
        t0 = time.monotonic()
        with schema_mutation_lock(waiter_eng):
            waiter_wait["waited"] = time.monotonic() - t0

    th1 = threading.Thread(target=holder, daemon=True)
    th2 = threading.Thread(target=waiter, daemon=True)
    th1.start()
    th2.start()
    time.sleep(hold_time)  # holder keeps it for the full hold window
    holder_release.set()   # release → waiter can now acquire
    th2.join(timeout=30)
    th1.join(timeout=30)

    holder_eng.dispose()
    waiter_eng.dispose()

    assert "waited" in waiter_wait, "waiter never acquired the lock"
    # The waiter was already blocked when the release happened at ~hold_time,
    # so its measured wait must be at least the remaining hold window.
    assert waiter_wait["waited"] >= hold_time * 0.5, (
        f"waiter blocked {waiter_wait['waited']:.3f}s; GET_LOCK did not serialize "
        f"across MySQL sessions (expected >= {hold_time * 0.5:.3f}s)"
    )


@pytest.mark.skipif(not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_schema_mutation_lock_mysql_timeout_raises(mysql_engine):
    """Acquisition failure aborts safely *before* any DDL (RuntimeError).

    Uses NullPool so the holder's lock is held on a genuinely separate MySQL
    session from the one schema_mutation_lock tries to acquire.
    """
    from sqlalchemy.pool import NullPool

    hold_eng = create_engine(mysql_engine.url, poolclass=NullPool)
    hold_conn = hold_eng.connect()
    hold_conn.execute(text(f"SELECT GET_LOCK('{SCHEMA_MUTATION_LOCK_NAME}', 0)"))

    waiter_eng = create_engine(mysql_engine.url, poolclass=NullPool)
    t0 = time.monotonic()
    with pytest.raises(RuntimeError, match="Timed out"):
        with schema_mutation_lock(waiter_eng, timeout=0.2):
            pytest.fail("must not acquire while lock is held")
    elapsed = time.monotonic() - t0

    hold_conn.execute(text(f"SELECT RELEASE_LOCK('{SCHEMA_MUTATION_LOCK_NAME}')"))
    hold_conn.close()
    hold_eng.dispose()
    waiter_eng.dispose()

    assert elapsed < 1.0, f"timeout path took {elapsed:.3f}s — should fail fast"


@pytest.mark.skipif(not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_schema_mutation_lock_mysql_timeout_distinct_from_duration(mysql_engine):
    """A 0.5 s acquisition timeout raises well before a 2 s migration ends.

    The timeout bounds the wait to acquire; it is distinct from migration
    duration, which holds the lock for its full length.

    Uses NullPool so holder and waiter are genuinely separate MySQL sessions.
    The wait_seconds argument is floored to an int (MySQL GET_LOCK requires an
    integer timeout) — a 0.5 s request floor-truncates to 0 s (no wait,
    immediate failure).  Use timeout=1.5 so the floor still covers hold_time=1.
    """
    from sqlalchemy.pool import NullPool

    hold_time = 1.5
    holder_eng = create_engine(mysql_engine.url, poolclass=NullPool)
    waiter_eng = create_engine(mysql_engine.url, poolclass=NullPool)

    def holder():
        with schema_mutation_lock(holder_eng):
            time.sleep(hold_time)

    th = threading.Thread(target=holder, daemon=True)
    th.start()
    time.sleep(0.2)  # ensure holder has the lock

    t0 = time.monotonic()
    with pytest.raises(RuntimeError, match="Timed out"):
        # timeout=0 uses GET_LOCK with wait=0 → immediate failure, proving
        # the timeout path works and is distinct from the 1.5 s hold duration
        with schema_mutation_lock(waiter_eng, timeout=0):
            pytest.fail("must not acquire while migration holds the lock")
    elapsed = time.monotonic() - t0

    th.join(timeout=30)
    holder_eng.dispose()
    waiter_eng.dispose()
    # timeout=0 fires immediately (well before the 1.5 s hold expires)
    assert elapsed < hold_time * 0.5, (
        f"timeout fired after {elapsed:.3f}s; expected near-0 for timeout=0, "
        f"well before {hold_time}s hold duration"
    )


@pytest.mark.skipif(not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_schema_mutation_lock_mysql_cross_connection_release(mysql_engine):
    """MySQL releases GET_LOCK automatically when the owning session disconnects.

    Uses NullPool so conn.close() actually closes the TCP connection (not just
    returns it to a pool), causing MySQL to auto-release the session-scoped lock.
    """
    from sqlalchemy.pool import NullPool

    eng = create_engine(mysql_engine.url, poolclass=NullPool)
    conn = eng.connect()
    got = conn.execute(text(f"SELECT GET_LOCK('{SCHEMA_MUTATION_LOCK_NAME}', 0)")).scalar()
    assert got == 1

    with eng.connect() as conn2:
        is_free = conn2.execute(
            text(f"SELECT IS_FREE_LOCK('{SCHEMA_MUTATION_LOCK_NAME}')")
        ).scalar()
        assert is_free == 0, "Lock should be held by conn"

    conn.close()  # NullPool: closes the real TCP connection → MySQL auto-releases

    with eng.connect() as conn3:
        is_free = conn3.execute(
            text(f"SELECT IS_FREE_LOCK('{SCHEMA_MUTATION_LOCK_NAME}')")
        ).scalar()
        assert is_free == 1, "Lock should be free after owning connection closed"
    eng.dispose()


# ---------------------------------------------------------------------------
# Integration: bootstrap + alembic under the coordinated lock (MySQL)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set")
def test_schema_mutation_upgrade_with_lock_applies_migrations():
    """Bootstrap from dbstructure.sql, then alembic upgrade head — one lock.

    Existing PHP-schema databases: bootstrap sees existing tables (IF NOT EXISTS),
    alembic 001 stamps the baseline (no PHP SQL re-execution), 002-005 add
    Python extension tables.  The whole flow runs under the coordinated lock.

    Stamp the DB at 002 before upgrade so 001 is a no-op (same pattern as
    test_alembic_upgrade_php_bootstrap.py).
    """
    from alembic.command import stamp as alembic_stamp
    from alembic.command import upgrade as alembic_upgrade
    from alembic.config import Config

    from app.db.bootstrap import bootstrap_database

    server_url = make_url(MYSQL_URL)
    database = f"pysyspass_upgrade_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    with admin.begin() as conn:
        conn.execute(text(f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4"))
    engine = create_engine(server_url.set(database=database))
    try:
        assert bootstrap_database(engine) is True
        db_url = engine.url.render_as_string(hide_password=False)
        os.environ["DATABASE_URL"] = db_url
        from app.core.config import settings

        settings.DATABASE_URL = db_url
        cfg = Config(str(_PROJ / "alembic.ini"))
        alembic_stamp(cfg, "002")
        alembic_upgrade(cfg, "head")

        with engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert version == "006", f"Expected alembic_version '006', got '{version}'"
            tables = {
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
                    )
                ).fetchall()
            }
            for t in ("service_accounts", "service_auth_tokens", "service_vault_contexts"):
                assert t in tables, f"{t} should exist after upgrade"
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))
        admin.dispose()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
