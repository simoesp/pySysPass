"""session table

Revision ID: 006
Revises: 005
Create Date: 2026-11-27 14:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "session",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("authenticated_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vault_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("revoked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id"),
    )
    op.create_index("ix_session_user_id", "session", ["user_id"], unique=False)
    op.create_index("ix_session_revoked", "session", ["revoked"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_session_revoked", table_name="session")
    op.drop_index("ix_session_user_id", table_name="session")
    op.drop_table("session")
