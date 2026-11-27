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
from sqlalchemy import inspect

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
    # Baseline stamp only: Alembic's migration context writes the
    # alembic_version row itself after this revision runs.  Never INSERT or
    # UPDATE alembic_version manually here — the writer's own insert would
    # collide with ours (IntegrityError 1062, duplicate entry '001').


def downgrade() -> None:
    # 001 is a baseline record only: Alembic removes the alembic_version row
    # itself when downgrading past this revision — never DELETE from
    # alembic_version manually, and never drop the PHP-owned base tables
    # (PHP-created databases must remain unaffected).
    op.get_bind()
