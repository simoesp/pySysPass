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


def test_initial_migration_is_a_baseline_stamp_not_a_second_authority():
    """Revision 001 stamps the bootstrapped PHP schema as a baseline; it must
    not re-execute schemas/dbstructure.sql as a second mutation authority
    (ADR-0016 Decision 6, IMPL-035 coordinated schema-mutation lock).
    """
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

    # The guard inspects the bootstrapped base tables via the bootstrap helper.
    assert "_schema_table_names" in called_functions
    # 001 must NOT re-execute the PHP schema SQL — bootstrap owns that.
    assert "_load_schema_statements" not in called_functions
    # 001 emits no DDL of its own: it is a baseline stamp only.
    assert "create_table" not in called_operations
    assert "drop_table" not in called_operations
    # Schema-metadata mutations go through the connection Alembic provides,
    # which runs under the coordinated schema-mutation lock in env.py.
    assert "get_bind" in called_operations
    assert "inspect" in called_functions


def test_initial_migration_canonical_schema_covers_every_orm_table():
    migration_tables = set(_ordered_schema_table_names())
    orm_tables = {
        name
        for name, table in Base.metadata.tables.items()
        if not table.info.get("is_view") and not table.info.get("is_php_extension")
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
