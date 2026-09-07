"""Restore missing canonical PHP account views on previously initialized databases."""

from alembic import context
from alembic import op

from app.db.bootstrap import _missing_view_statements


revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("Revision 002 requires an online connection to preserve existing PHP views")
    for statement in _missing_view_statements(op.get_bind()):
        op.execute(statement)


def downgrade() -> None:
    # These are PHP-owned views, possibly present before this migration. Keep
    # them on downgrade to 001; downgrade of 001 removes the complete schema.
    pass
