from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable
import re

from sqlalchemy import inspect
from sqlalchemy.engine import Engine

from app.core.config import settings
from app.db.base import engine

logger = logging.getLogger(__name__)

CREATE_TABLE_RE = re.compile(r"CREATE TABLE(?: IF NOT EXISTS)? `?([^`\s(]+)`?", re.IGNORECASE)
CREATE_TABLE_PREFIX_RE = re.compile(r"^CREATE TABLE\s+", re.IGNORECASE)
INSERT_PREFIX_RE = re.compile(r"^INSERT INTO\s+", re.IGNORECASE)
FOREIGN_KEY_REF_RE = re.compile(r"REFERENCES `?([^`\s(]+)`?", re.IGNORECASE)
VIEW_TABLES = {"account_data_v", "account_search_v"}


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "dbstructure.sql"


def _split_sql_script(script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_single_quote = False
    in_double_quote = False
    in_backtick = False

    for line in script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue

        i = 0
        while i < len(line):
            char = line[i]
            prev = line[i - 1] if i > 0 else ""

            if char == "'" and not in_double_quote and not in_backtick and prev != "\\":
                in_single_quote = not in_single_quote
            elif char == '"' and not in_single_quote and not in_backtick and prev != "\\":
                in_double_quote = not in_double_quote
            elif char == "`" and not in_single_quote and not in_double_quote:
                in_backtick = not in_backtick

            if char == ";" and not in_single_quote and not in_double_quote and not in_backtick:
                statement = "".join(current).strip()
                if statement:
                    statements.append(statement)
                current = []
            else:
                current.append(char)

            i += 1

        current.append("\n")

    tail = "".join(current).strip()
    if tail:
        statements.append(tail)

    return statements


def _normalize_bootstrap_statement(statement: str) -> str | None:
    normalized = statement.strip()
    lower = normalized.lower()

    if (
        not normalized
        or lower.startswith("drop table")
        or lower.startswith("lock tables")
        or lower.startswith("unlock tables")
        or lower.startswith("/*!")
        or lower.startswith("alter table")
        or lower.startswith("create algorithm")
    ):
        return None

    table_match = CREATE_TABLE_RE.match(normalized)
    if table_match:
        table_name = table_match.group(1)
        if table_name in VIEW_TABLES:
            return None
        return CREATE_TABLE_PREFIX_RE.sub("CREATE TABLE IF NOT EXISTS ", normalized, count=1)

    if lower.startswith("insert into"):
        return INSERT_PREFIX_RE.sub("INSERT IGNORE INTO ", normalized, count=1)

    return None


def _order_bootstrap_statements(statements: Iterable[str]) -> list[str]:
    create_statements: dict[str, str] = {}
    create_order: list[str] = []
    other_statements: list[str] = []

    for statement in statements:
        table_match = CREATE_TABLE_RE.match(statement)
        if not table_match:
            other_statements.append(statement)
            continue

        table_name = table_match.group(1)
        create_statements[table_name] = statement
        create_order.append(table_name)

    dependencies: dict[str, set[str]] = {}
    for table_name, statement in create_statements.items():
        refs = {
            ref
            for ref in FOREIGN_KEY_REF_RE.findall(statement)
            if ref in create_statements and ref != table_name
        }
        dependencies[table_name] = refs

    ordered_tables: list[str] = []
    remaining = set(create_order)
    while remaining:
        ready = [
            table_name
            for table_name in create_order
            if table_name in remaining and dependencies[table_name].issubset(ordered_tables)
        ]
        if not ready:
            ready = [table_name for table_name in create_order if table_name in remaining]

        for table_name in ready:
            ordered_tables.append(table_name)
            remaining.remove(table_name)

    return [create_statements[table_name] for table_name in ordered_tables] + other_statements


def _load_schema_statements(schema_path: Path | None = None) -> list[str]:
    path = schema_path or _schema_path()
    script = path.read_text(encoding="utf-8")
    statements = _split_sql_script(script)
    normalized = [stmt for raw in statements if (stmt := _normalize_bootstrap_statement(raw))]
    return _order_bootstrap_statements(normalized)


def _schema_table_names(schema_path: Path | None = None) -> tuple[str, ...]:
    path = schema_path or _schema_path()
    schema = path.read_text(encoding="utf-8")
    return tuple(name for name in CREATE_TABLE_RE.findall(schema) if name not in VIEW_TABLES)


def _ordered_schema_table_names(schema_path: Path | None = None) -> tuple[str, ...]:
    """Return physical tables in the same FK-safe order used for creation."""
    names: list[str] = []
    for statement in _load_schema_statements(schema_path):
        match = CREATE_TABLE_RE.match(statement)
        if match:
            names.append(match.group(1))
    return tuple(names)


def database_requires_bootstrap(
    engine_obj: Engine = engine,
    required_tables: Iterable[str] | None = None,
) -> bool:
    tables = tuple(required_tables) if required_tables is not None else _schema_table_names()
    inspector = inspect(engine_obj)
    return not all(inspector.has_table(table_name) for table_name in tables)


def execute_schema_statements(
    statements: Iterable[str],
    engine_obj: Engine = engine,
) -> None:
    connection = engine_obj.raw_connection()
    cursor = connection.cursor()
    try:
        for statement in statements:
            cursor.execute(statement)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def bootstrap_database(engine_obj: Engine = engine) -> bool:
    if not database_requires_bootstrap(engine_obj):
        return False

    logger.warning("Incomplete or virgin sysPass database detected; applying bootstrap schema.")
    execute_schema_statements(_load_schema_statements(), engine_obj=engine_obj)
    logger.warning("sysPass bootstrap schema applied successfully.")
    return True


def bootstrap_database_on_startup(engine_obj: Engine = engine) -> bool:
    if not settings.AUTO_INIT_DB_ON_STARTUP:
        return False
    return bootstrap_database(engine_obj=engine_obj)
