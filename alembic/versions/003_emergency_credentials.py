"""Create emergency_credentials table for ADR-0014 Emergency Authentication Mode.

Revision ID: 003
Revises: 002
Create Date: 2026-11-27

This table stores break-glass administrator and LDAP recovery accounts
for disaster recovery when LDAP is unavailable.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "emergency_credentials",
        sa.Column(
            "id",
            mysql.INTEGER(display_width=11, unsigned=True),
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column(
            "password_hash",
            mysql.VARBINARY(500),
            nullable=False,
        ),
        sa.Column(
            "password_salt",
            mysql.VARBINARY(255),
            nullable=False,
        ),
        sa.Column(
            "mfa_secret",
            mysql.VARBINARY(2000),
            nullable=True,
        ),
        sa.Column(
            "mfa_enabled",
            sa.Boolean(),
            default=True,
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            default=False,
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "is_recovery_account",
            sa.Boolean(),
            default=False,
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            default=sa.func.current_timestamp(),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column(
            "recovery_token",
            mysql.VARBINARY(64),
            nullable=True,
        ),
        sa.Column("recovery_token_expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_by",
            mysql.SMALLINT(display_width=5, unsigned=True),
            sa.ForeignKey("User.id", name="fk_emergency_credentials_created_by"),
            nullable=True,
        ),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
        mysql_collate="utf8_unicode_ci",
    )
    op.create_index(
        "uk_emergency_credentials_01",
        "emergency_credentials",
        ["username"],
        unique=True,
    )
    op.create_index(
        "idx_emergency_credentials_01",
        "emergency_credentials",
        ["username"],
    )
    op.create_index(
        "idx_emergency_credentials_02",
        "emergency_credentials",
        ["enabled"],
    )
    op.create_index(
        "fk_emergency_credentials_created_by",
        "emergency_credentials",
        ["created_by"],
    )


def downgrade() -> None:
    op.drop_table("emergency_credentials")
