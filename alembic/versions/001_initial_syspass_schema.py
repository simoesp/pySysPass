"""Create the canonical sysPass PHP schema.

Revision ID: 001
Revises:
Create Date: 2026-06-20

The PHP-owned SQL snapshot is deliberately the single source of truth. Keeping
a second hand-written set of ``op.create_table`` calls here previously allowed
Alembic-created databases to diverge from both PHP and SQLAlchemy metadata.
"""

from alembic import op

from app.db.bootstrap import _load_schema_statements, _ordered_schema_table_names


revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    for statement in _load_schema_statements():
        op.execute(statement)


def downgrade() -> None:
    for table_name in reversed(_ordered_schema_table_names()):
        op.drop_table(table_name)
