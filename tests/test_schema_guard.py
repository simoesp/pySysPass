"""Test that SchemaMutationError is raised on CREATE/ALTER/DROP in GuardedSession."""
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import pytest

from app.db.base import SCHEMA_STATEMENT_RE, SchemaMutationError, engine, SessionLocal, Base
from sqlalchemy import text


def test_schema_guard_blocks_create():
    """CREATE TABLE in GuardedSession should raise SchemaMutationError."""
    db = SessionLocal()

    try:
        # Attempt CREATE TABLE - should be blocked by schema guard
        with pytest.raises(SchemaMutationError, match="SQLAlchemy schema-guard mode is enabled"):
            db.execute(text("CREATE TABLE test (id INTEGER PRIMARY KEY)"))
        db.rollback()
    finally:
        db.close()


def test_schema_guard_blocks_alter():
    """ALTER TABLE in GuardedSession should raise SchemaMutationError."""
    db = SessionLocal()

    try:
        # Attempt ALTER TABLE - should be blocked by schema guard
        # (table doesn't need to exist beforehand; guard blocks the statement regardless)
        with pytest.raises(SchemaMutationError, match="SQLAlchemy schema-guard mode is enabled"):
            db.execute(text("ALTER TABLE test ADD COLUMN name VARCHAR(100)"))
        db.rollback()
    finally:
        db.close()


def test_schema_guard_blocks_drop():
    """DROP TABLE in GuardedSession should raise SchemaMutationError."""
    db = SessionLocal()

    try:
        # Attempt DROP TABLE - should be blocked by schema guard
        with pytest.raises(SchemaMutationError, match="SQLAlchemy schema-guard mode is enabled"):
            db.execute(text("DROP TABLE IF EXISTS test"))
        db.rollback()
    finally:
        db.close()


def test_schema_guard_blocks_truncate():
    """TRUNCATE TABLE in GuardedSession should raise SchemaMutationError."""
    db = SessionLocal()

    try:
        # Attempt TRUNCATE - should be blocked by schema guard
        with pytest.raises(SchemaMutationError, match="SQLAlchemy schema-guard mode is enabled"):
            db.execute(text("TRUNCATE TABLE test"))
        db.rollback()
    finally:
        db.close()


def test_schema_guard_disabled_when_config_false():
    """When SQLALCHEMY_SCHEMA_GUARD is false, DDL should not be blocked."""
    from app.core.config import settings

    # Temporarily disable the guard
    original_value = settings.SQLALCHEMY_SCHEMA_GUARD
    settings.SQLALCHEMY_SCHEMA_GUARD = False

    try:
        db = SessionLocal()
        try:
            # Should NOT raise when guard is disabled
            db.execute(text("CREATE TABLE guard_disabled_test (id INTEGER PRIMARY KEY)"))
            db.rollback()
        finally:
            db.close()
    finally:
        settings.SQLALCHEMY_SCHEMA_GUARD = original_value


def test_sqla_statement_re_pattern():
    """Verify the SCHEMA_STATEMENT_RE regex matches expected statements."""
    # These should match
    assert SCHEMA_STATEMENT_RE.match("CREATE TABLE foo (id INT)") is not None
    assert SCHEMA_STATEMENT_RE.match("ALTER TABLE foo ADD COLUMN bar INT") is not None
    assert SCHEMA_STATEMENT_RE.match("DROP TABLE foo") is not None
    assert SCHEMA_STATEMENT_RE.match("TRUNCATE TABLE foo") is not None
    assert SCHEMA_STATEMENT_RE.match("RENAME TABLE foo TO bar") is not None
    assert SCHEMA_STATEMENT_RE.match("GRANT SELECT ON foo TO bar") is not None
    assert SCHEMA_STATEMENT_RE.match("REVOKE SELECT ON foo FROM bar") is not None

    # These should NOT match (safe statements)
    assert SCHEMA_STATEMENT_RE.match("SELECT * FROM foo") is None
    assert SCHEMA_STATEMENT_RE.match("INSERT INTO foo (id) VALUES (1)") is None
    assert SCHEMA_STATEMENT_RE.match("UPDATE foo SET bar = 1") is None
    assert SCHEMA_STATEMENT_RE.match("DELETE FROM foo") is None