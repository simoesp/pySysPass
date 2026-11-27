"""Baseline the PHP-owned sysPass schema at Alembic revision 001.

The PHP-owned SQL snapshot (``schemas/dbstructure.sql``) remains the single
source of truth for the base schema.  Revision 001 no longer executes it as a
second mutation authority: bootstrap owns base-schema creation (idempotent
``CREATE TABLE IF NOT EXISTS`` from dbstructure.sql), and 001 merely records
that the base schema is present by stamping this revision.

Both actions run under the coordinated schema-mutation lock
(``pysyspass_schema_mutation``) acquired by ``alembic/env.py`` — a restamp of
an already-stamped database is itself a schema-metadata mutation.

Databases already stamped at 001: upgrade is an idempotent no-op.
"""

from alembic import op
from sqlalchemy import inspect, text

from app.db.bootstrap import _schema_table_names

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def _base_tables_present(connection) -> bool:
    inspector = inspect(connection)
    existing = set(inspector.get_table_names())
    return all(name in existing for name in _schema_table_names())


def upgrade() -> None:
    connection = op.get_bind()
    if not _base_tables_present(connection):
        raise RuntimeError(
            "sysPass base schema is not bootstrapped: run "
            "bootstrap_database_on_startup() (or apply schemas/dbstructure.sql) "
            "before 'alembic upgrade head'. Revision 001 is a baseline stamp "
            "only and does not create the PHP-owned schema."
        )

    current = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    if current is None:
        connection.execute(text("INSERT INTO alembic_version (version_num) VALUES ('001')"))
    elif current != "001":
        # Restamp path: record the base schema as baselined without touching
        # any PHP-owned table.  Safe on databases stamped at a later revision
        # too — Alembic would not run 001 in that case; this is defensive.
        connection.execute(text("UPDATE alembic_version SET version_num = '001'"))


def downgrade() -> None:
    # 001 is a baseline record only: drop the stamp, never the PHP-owned
    # base tables (PHP-created databases must remain unaffected).
    connection = op.get_bind()
    connection.execute(text("DELETE FROM alembic_version WHERE version_num = '001'"))
