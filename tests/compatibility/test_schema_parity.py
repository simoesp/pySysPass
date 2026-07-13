from pathlib import Path
import re

import pytest
from app.db.base import Base
import app.models  # noqa: F401 -- register every model with Base.metadata
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects import mysql

from tests.compatibility.schema_parity import (
    SchemaForeignKey,
    SchemaIndex,
    normalized_sql,
    parse_mysql_constraints,
    parse_mysql_tables,
)


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "dbstructure.sql"
UPSTREAM_SCHEMA_DIR = ROOT.parent / "phpSysPass" / "schemas"
ORM_VIEWS = {"account_data_v", "account_search_v"}

# These fields predate the parity guard and do not exist in sysPass PHP. Keep
# the exception narrow so no additional persisted semantics can be introduced.
# Replacing them with compatibility-preserving derived/API data is tracked in
# docs/project/php-compatibility-checklist.md.
KNOWN_PYTHON_ONLY_COLUMNS = {
    "AccountHistory": {"action", "oldValue", "newValue"},
}
KNOWN_NULLABILITY_DRIFT = {
    "Account.clientId",
    "Account.categoryId",
    "AccountHistory.clientId",
    "AccountHistory.categoryId",
    "User.id",
    "User.name",
    "User.userProfileId",
    "User.hashSalt",
    "UserGroup.id",
    "UserProfile.id",
}
BASELINE_DIR = Path(__file__).with_name("baselines")


def _orm_tables():
    return {
        name: table
        for name, table in Base.metadata.tables.items()
        if name not in ORM_VIEWS
    }


def _orm_type_signature(column) -> tuple[str, str | None, bool]:
    compiled = column.type.compile(dialect=mysql.dialect()).lower()
    match = re.match(r"([a-z]+)(?:\((\d+)\))?", compiled)
    if not match:
        return compiled, None, False
    type_name, length = match.groups()
    if type_name in {"bool", "boolean"}:
        return "tinyint", "1", False
    if type_name == "integer":
        type_name = "int"
    return type_name, length, "unsigned" in compiled


def _orm_default(column) -> str | None:
    default = column.server_default
    if default is None:
        return None
    value = str(default.arg).strip("'\"").lower()
    return None if value == "null" else value


def _orm_indexes(table) -> set[SchemaIndex]:
    primary_columns = tuple(column.name for column in table.primary_key.columns)
    indexes = {SchemaIndex("PRIMARY", primary_columns, primary=True)} if primary_columns else set()
    indexes.update(
        SchemaIndex(index.name, tuple(column.name for column in index.columns), unique=bool(index.unique))
        for index in table.indexes
    )
    indexes.update(
        SchemaIndex(constraint.name, tuple(column.name for column in constraint.columns), unique=True)
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    )
    return indexes


def _orm_foreign_keys(table) -> set[SchemaForeignKey]:
    foreign_keys: set[SchemaForeignKey] = set()
    for constraint in table.foreign_key_constraints:
        elements = list(constraint.elements)
        foreign_keys.add(
            SchemaForeignKey(
                name=constraint.name,
                columns=tuple(element.parent.name for element in elements),
                referred_table=elements[0].column.table.name,
                referred_columns=tuple(element.column.name for element in elements),
                on_delete=constraint.ondelete.lower() if constraint.ondelete else None,
                on_update=constraint.onupdate.lower() if constraint.onupdate else None,
            )
        )
    return foreign_keys


def _assert_reviewable_baseline(name: str, lines: list[str]) -> None:
    baseline_path = BASELINE_DIR / f"{name}.txt"
    expected = [
        line
        for line in baseline_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert lines == expected, (
        f"{name} drift changed; review and update {baseline_path.relative_to(ROOT)}:\n"
        + "\n".join(lines)
    )


def test_vendored_php_schema_matches_upstream_checkout_when_available():
    """Catch stale vendored snapshots for developers with phpSysPass beside us."""
    if not UPSTREAM_SCHEMA_DIR.is_dir():
        pytest.skip("../phpSysPass is unavailable; vendored schema freshness was not checked")

    local_files = {path.name for path in (ROOT / "schemas").glob("*.sql")}
    upstream_files = {path.name for path in UPSTREAM_SCHEMA_DIR.glob("*.sql")}
    shared_files = sorted(local_files & upstream_files)

    assert shared_files
    for filename in shared_files:
        assert normalized_sql(ROOT / "schemas" / filename) == normalized_sql(
            UPSTREAM_SCHEMA_DIR / filename
        ), f"schemas/{filename} has drifted from ../phpSysPass/schemas/{filename}"


def test_sqlalchemy_table_and_column_surface_matches_php_schema():
    php_tables = parse_mysql_tables(SCHEMA_PATH)
    orm_tables = _orm_tables()

    assert set(orm_tables) == set(php_tables)

    unexpected_drift: dict[str, dict[str, set[str]]] = {}
    for table_name, php_columns in php_tables.items():
        orm_columns = set(orm_tables[table_name].columns.keys())
        missing = set(php_columns) - orm_columns
        extra = orm_columns - set(php_columns)
        allowed_extra = KNOWN_PYTHON_ONLY_COLUMNS.get(table_name, set())
        if missing or extra != allowed_extra:
            unexpected_drift[table_name] = {
                "missing_from_python": missing,
                "extra_in_python": extra,
                "allowed_extra": allowed_extra,
            }

    assert not unexpected_drift


def test_sqlalchemy_nullability_matches_php_schema():
    php_tables = parse_mysql_tables(SCHEMA_PATH)
    mismatches: list[str] = []
    for table_name, php_columns in php_tables.items():
        orm_table = _orm_tables()[table_name]
        for column_name, php_column in php_columns.items():
            orm_column = orm_table.columns[column_name]
            if orm_column.nullable != php_column.nullable:
                qualified_name = f"{table_name}.{column_name}"
                if qualified_name in KNOWN_NULLABILITY_DRIFT:
                    continue
                mismatches.append(
                    f"{qualified_name}: "
                    f"PHP nullable={php_column.nullable}, "
                    f"SQLAlchemy nullable={orm_column.nullable}"
                )

    assert not mismatches, "\n".join(mismatches)


def test_sqlalchemy_types_lengths_and_unsigned_flags_match_php_schema():
    php_tables = parse_mysql_tables(SCHEMA_PATH)
    mismatches: list[str] = []
    for table_name, php_columns in php_tables.items():
        orm_table = _orm_tables()[table_name]
        for column_name, php_column in php_columns.items():
            qualified_name = f"{table_name}.{column_name}"
            orm_signature = _orm_type_signature(orm_table.columns[column_name])
            php_signature = (
                php_column.sql_type,
                php_column.length,
                php_column.unsigned,
            )
            if orm_signature != php_signature:
                mismatches.append(
                    f"{qualified_name}: PHP={php_signature}, SQLAlchemy={orm_signature}"
                )

    _assert_reviewable_baseline("types", mismatches)


def test_sqlalchemy_scalar_defaults_match_php_schema():
    php_tables = parse_mysql_tables(SCHEMA_PATH)
    mismatches: list[str] = []
    for table_name, php_columns in php_tables.items():
        orm_table = _orm_tables()[table_name]
        for column_name, php_column in php_columns.items():
            qualified_name = f"{table_name}.{column_name}"
            orm_default = _orm_default(orm_table.columns[column_name])
            if orm_default != php_column.default:
                mismatches.append(
                    f"{qualified_name}: PHP={php_column.default!r}, SQLAlchemy={orm_default!r}"
                )

    assert not mismatches, "\n".join(mismatches)


def test_sqlalchemy_autoincrement_matches_php_schema():
    php_tables = parse_mysql_tables(SCHEMA_PATH)
    mismatches: list[str] = []
    for table_name, php_columns in php_tables.items():
        orm_table = _orm_tables()[table_name]
        for column_name, php_column in php_columns.items():
            orm_column = orm_table.columns[column_name]
            orm_autoincrement = orm_table.autoincrement_column is orm_column
            if orm_autoincrement != php_column.autoincrement:
                mismatches.append(
                    f"{table_name}.{column_name}: PHP={php_column.autoincrement}, "
                    f"SQLAlchemy={orm_autoincrement}"
                )

    assert not mismatches, "\n".join(mismatches)


def test_sqlalchemy_indexes_match_php_schema_baseline():
    php_indexes, _ = parse_mysql_constraints(SCHEMA_PATH)
    mismatches: list[str] = []
    for table_name, expected in php_indexes.items():
        actual = _orm_indexes(_orm_tables()[table_name])
        if actual != expected:
            mismatches.append(
                f"{table_name}: missing={sorted(expected - actual)!r}, "
                f"extra={sorted(actual - expected)!r}"
            )

    _assert_reviewable_baseline("indexes", mismatches)


def test_sqlalchemy_foreign_keys_match_php_schema_baseline():
    _, php_foreign_keys = parse_mysql_constraints(SCHEMA_PATH)
    mismatches: list[str] = []
    for table_name, expected in php_foreign_keys.items():
        actual = _orm_foreign_keys(_orm_tables()[table_name])
        if actual != expected:
            mismatches.append(
                f"{table_name}: missing={sorted(expected - actual)!r}, "
                f"extra={sorted(actual - expected)!r}"
            )

    _assert_reviewable_baseline("foreign_keys", mismatches)
