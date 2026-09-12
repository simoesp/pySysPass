from pathlib import Path

import pytest

from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.bootstrap import (
    _load_schema_statements,
    _missing_view_statements,
    _view_name,
    _normalize_bootstrap_statement,
    _order_bootstrap_statements,
    _split_sql_script,
    _schema_table_names,
    database_requires_bootstrap,
    execute_schema_statements,
)


def _sqlite_engine():
    return create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def test_split_sql_script_skips_comments_and_keeps_strings():
    script = """
    -- comment
    CREATE TABLE demo (value TEXT);

    INSERT INTO demo (value) VALUES ('hello;world');
    """

    statements = _split_sql_script(script)

    assert statements == [
        "CREATE TABLE demo (value TEXT)",
        "INSERT INTO demo (value) VALUES ('hello;world')",
    ]


def test_normalize_bootstrap_statement_rewrites_schema_statements():
    assert _normalize_bootstrap_statement("DROP TABLE IF EXISTS `User`") is None
    assert (
        _normalize_bootstrap_statement("CREATE TABLE `User` (`id` int NOT NULL)")
        == "CREATE TABLE IF NOT EXISTS `User` (`id` int NOT NULL)"
    )
    assert (
        _normalize_bootstrap_statement("INSERT INTO CustomFieldType (id) VALUES (1)")
        == "INSERT IGNORE INTO CustomFieldType (id) VALUES (1)"
    )


def test_order_bootstrap_statements_sorts_foreign_key_dependencies():
    statements = [
        "CREATE TABLE IF NOT EXISTS `CustomFieldData` (`definitionId` int, CONSTRAINT `fk_1` "
        "FOREIGN KEY (`definitionId`) REFERENCES `CustomFieldDefinition` (`id`))",
        "CREATE TABLE IF NOT EXISTS `CustomFieldDefinition` (`typeId` int, CONSTRAINT `fk_2` "
        "FOREIGN KEY (`typeId`) REFERENCES `CustomFieldType` (`id`))",
        "CREATE TABLE IF NOT EXISTS `CustomFieldType` (`id` int NOT NULL)",
        "INSERT IGNORE INTO CustomFieldType (id) VALUES (1)",
    ]

    ordered = _order_bootstrap_statements(statements)

    assert ordered == [
        "CREATE TABLE IF NOT EXISTS `CustomFieldType` (`id` int NOT NULL)",
        "CREATE TABLE IF NOT EXISTS `CustomFieldDefinition` (`typeId` int, CONSTRAINT `fk_2` "
        "FOREIGN KEY (`typeId`) REFERENCES `CustomFieldType` (`id`))",
        "CREATE TABLE IF NOT EXISTS `CustomFieldData` (`definitionId` int, CONSTRAINT `fk_1` "
        "FOREIGN KEY (`definitionId`) REFERENCES `CustomFieldDefinition` (`id`))",
        "INSERT IGNORE INTO CustomFieldType (id) VALUES (1)",
    ]


def test_database_requires_bootstrap_checks_required_tables():
    engine = _sqlite_engine()

    assert database_requires_bootstrap(engine, required_tables=("User",)) is True

    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE "User" (id INTEGER PRIMARY KEY)'))

    assert database_requires_bootstrap(engine, required_tables=("User",)) is False


def test_schema_table_names_match_bootstrap_schema():
    table_names = _schema_table_names()

    assert len(table_names) == 27
    assert "User" in table_names
    assert "AccountFile" in table_names
    assert "Config" in table_names
    assert "PluginData" in table_names


def test_database_requires_bootstrap_for_partial_schema_when_expected_tables_missing():
    engine = _sqlite_engine()

    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE "User" (id INTEGER PRIMARY KEY)'))
        connection.execute(text('CREATE TABLE "UserGroup" (id INTEGER PRIMARY KEY)'))
        connection.execute(text('CREATE TABLE "UserProfile" (id INTEGER PRIMARY KEY)'))
        connection.execute(text('CREATE TABLE "Category" (id INTEGER PRIMARY KEY)'))
        connection.execute(text('CREATE TABLE "Client" (id INTEGER PRIMARY KEY)'))
        connection.execute(text('CREATE TABLE "Account" (id INTEGER PRIMARY KEY)'))
        connection.execute(text('CREATE TABLE "AccountHistory" (id INTEGER PRIMARY KEY)'))
        connection.execute(text('CREATE TABLE "Tag" (id INTEGER PRIMARY KEY)'))

    assert database_requires_bootstrap(engine, required_tables=_schema_table_names()) is True


def test_execute_schema_statements_runs_each_statement():
    engine = _sqlite_engine()

    execute_schema_statements(
        [
            "CREATE TABLE demo (id INTEGER PRIMARY KEY, value TEXT)",
            "INSERT INTO demo (id, value) VALUES (1, 'ok')",
        ],
        engine_obj=engine,
    )

    with engine.connect() as connection:
        value = connection.execute(text("SELECT value FROM demo WHERE id = 1")).scalar_one()

    assert value == "ok"


def test_bootstrap_schema_uses_matching_integer_sizes_for_user_foreign_keys():
    schema = Path("schemas/dbstructure.sql").read_text(encoding="utf-8")

    assert "`id`              smallint(5) unsigned NOT NULL AUTO_INCREMENT" in schema
    assert "`userId`             smallint(5) unsigned  NOT NULL" in schema
    assert "`userEditId`         smallint(5) unsigned  NOT NULL" in schema
    assert "`userGroupId`        smallint(5) unsigned  NOT NULL" in schema
    assert "`tagId`     int(10) unsigned      NOT NULL" in schema


def test_sqlalchemy_registry_includes_legacy_account_views():
    assert "account_data_v" in Base.metadata.tables
    assert "account_search_v" in Base.metadata.tables


def test_bootstrap_includes_canonical_php_views_after_tables():
    statements = _load_schema_statements()
    views = {name: statement for statement in statements if (name := _view_name(statement))}
    assert set(views) == {'account_data_v', 'account_search_v'}
    assert '`PublicLink`.`totalCountViews`' in views['account_search_v']
    assert 'SQL SECURITY DEFINER' in views['account_data_v']
    first_view = min(statements.index(statement) for statement in views.values())
    assert all(not statement.startswith('CREATE TABLE') for statement in statements[first_view:])


def test_view_repair_preserves_existing_php_views():
    engine = _sqlite_engine()
    with engine.begin() as connection:
        connection.execute(text('CREATE VIEW account_data_v AS SELECT 1 AS id'))
        connection.execute(text('CREATE VIEW account_search_v AS SELECT 2 AS id'))
    assert _missing_view_statements(engine) == []
    with engine.connect() as connection:
        assert connection.execute(text('SELECT id FROM account_search_v')).scalar_one() == 2


def test_view_repair_refuses_to_replace_a_table():
    engine = _sqlite_engine()
    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE account_data_v (id INTEGER)'))
    with pytest.raises(RuntimeError, match='refusing to replace'):
        _missing_view_statements(engine)
