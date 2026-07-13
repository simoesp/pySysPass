import ast
from pathlib import Path

from app.db.base import Base
from app.db.bootstrap import (
    CREATE_TABLE_RE,
    FOREIGN_KEY_REF_RE,
    _load_schema_statements,
    _ordered_schema_table_names,
)
import app.models  # noqa: F401 -- populate Base.metadata


ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = ROOT / "alembic" / "versions" / "001_initial_syspass_schema.py"


def test_initial_migration_uses_the_canonical_php_schema_loader():
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    called_functions = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    called_operations = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert "_load_schema_statements" in called_functions
    assert "create_table" not in called_operations


def test_initial_migration_canonical_schema_covers_every_orm_table():
    migration_tables = set(_ordered_schema_table_names())
    orm_tables = {
        name for name, table in Base.metadata.tables.items() if not table.info.get("is_view")
    }

    assert migration_tables == orm_tables


def test_initial_migration_downgrade_order_is_foreign_key_safe():
    statements = _load_schema_statements()
    dependencies: dict[str, set[str]] = {}
    for statement in statements:
        match = CREATE_TABLE_RE.match(statement)
        if not match:
            continue
        table_name = match.group(1)
        dependencies[table_name] = set(FOREIGN_KEY_REF_RE.findall(statement)) - {table_name}

    remaining = set(dependencies)
    for table_name in reversed(_ordered_schema_table_names()):
        referrers = {
            candidate
            for candidate in remaining - {table_name}
            if table_name in dependencies[candidate]
        }
        assert not referrers, f"cannot drop {table_name}; still referenced by {referrers}"
        remaining.remove(table_name)
