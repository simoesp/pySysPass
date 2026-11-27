from __future__ import annotations

import logging

from sqlalchemy import engine_from_config, pool
from alembic import context
from app.db.base import Base
from app.core.config import settings
from app.db.schema_lock import schema_mutation_lock

logger = logging.getLogger(__name__)

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    from logging.config import fileConfig

    fileConfig(config.config_file_name)

# Set target metadata for autogenerate support
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Offline mode emits SQL without a live connection, so the connection-scoped
    schema-mutation lock cannot be acquired here; offline runs are non-mutating
    (generated SQL only).  Apply generated SQL through the online path so it
    runs under the coordinated lock.
    """
    url = settings.DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode under the coordinated schema-mutation lock.

    The lock is acquired on the same connection that runs the DDL, so lock
    ownership stays tied to the acquiring connection for the whole migration.
    Bootstrap and Alembic share one lock identity
    (``pysyspass_schema_mutation``), so they never mutate the same database
    concurrently (ADR-0016 Decision 6).
    """
    connectable = engine_from_config(
        {"sqlalchemy.url": settings.DATABASE_URL},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with schema_mutation_lock(connectable) as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # For SQLite compatibility
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
