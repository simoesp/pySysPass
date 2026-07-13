import re
from pathlib import Path

from sqlalchemy.dialects import mysql
from sqlalchemy.schema import CreateTable

from app.db.base import Base, PHP_MYSQL_TABLE_OPTIONS
import app.models  # noqa: F401 -- populate and configure Base.metadata


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "dbstructure.sql"


def _physical_tables():
    return [table for table in Base.metadata.tables.values() if not table.info.get("is_view")]


def test_every_physical_table_has_php_mysql_storage_options():
    for table in _physical_tables():
        options = table.dialect_options["mysql"]
        assert {
            key: options.get(key) for key in PHP_MYSQL_TABLE_OPTIONS
        } == PHP_MYSQL_TABLE_OPTIONS, table.name


def test_mapped_views_do_not_receive_physical_table_options():
    views = [table for table in Base.metadata.tables.values() if table.info.get("is_view")]

    assert {table.name for table in views} == {"account_data_v", "account_search_v"}
    for table in views:
        options = table.dialect_options["mysql"]
        assert all(options.get(key) is None for key in PHP_MYSQL_TABLE_OPTIONS)


def test_mysql_create_table_ddl_emits_php_storage_options():
    for table in _physical_tables():
        ddl = str(CreateTable(table).compile(dialect=mysql.dialect()))
        assert "ENGINE=InnoDB" in ddl, table.name
        assert "CHARSET=utf8" in ddl, table.name
        assert "COLLATE utf8_unicode_ci" in ddl, table.name


def test_canonical_php_schema_uses_the_same_storage_options():
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    create_statements = re.findall(
        r"CREATE TABLE `?([A-Za-z][A-Za-z0-9_]*)`?\s*\(.*?\)\s*"
        r"ENGINE\s*=\s*InnoDB\s*DEFAULT CHARSET\s*=\s*utf8\s*"
        r"COLLATE\s+utf8_unicode_ci\s*;",
        schema,
        flags=re.IGNORECASE | re.DOTALL,
    )

    assert set(create_statements) == {table.name for table in _physical_tables()}
