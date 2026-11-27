"""Add service_accounts, service_auth_tokens, service_vault_contexts tables (ADR-0010 / IMPL-010).

These are Python-only extension tables (is_php_extension=True) that extend the
sysPass schema without touching PHP-managed tables.

Revision ID: 005_service_accounts
Revises: 004_audit_logging
Create Date: 2026-11-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # service_accounts table
    op.create_table(
        'service_accounts',
        sa.Column('id', mysql.INTEGER(unsigned=True), autoincrement=True, nullable=False),
        sa.Column('service_id', sa.String(64), nullable=False),
        sa.Column('service_name', sa.String(190), nullable=False),
        sa.Column('owner_id', mysql.SMALLINT(unsigned=True), nullable=False),
        sa.Column('purpose', sa.Text(), nullable=True),
        sa.Column('scopes', sa.Text(), nullable=True),
        sa.Column('resource_restrictions', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), server_default=sa.text('1'), nullable=False),
        sa.Column('context_lifetime_hours', sa.Float(), nullable=True),
        sa.Column('inactivity_timeout_hours', sa.Float(), nullable=True),
        sa.Column('token_expires_hours', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('service_name', name='uk_service_accounts_name'),
        sa.UniqueConstraint('service_id', name='uk_service_accounts_service_id'),
        sa.ForeignKeyConstraint(['owner_id'], ['User.id'], name='fk_service_accounts_owner'),
        sa.Index('idx_service_accounts_owner', 'owner_id'),
        sa.Index('idx_service_accounts_enabled', 'enabled'),
        mysql_engine='InnoDB',
        mysql_charset='utf8mb4',
        mysql_collate='utf8mb4_unicode_ci',
    )

    # service_auth_tokens table
    op.create_table(
        'service_auth_tokens',
        sa.Column('id', mysql.INTEGER(unsigned=True), autoincrement=True, nullable=False),
        sa.Column('service_id', sa.String(64), nullable=False),
        sa.Column('token_hash', sa.String(255), nullable=False),
        sa.Column('owner_id', mysql.SMALLINT(unsigned=True), nullable=True),
        sa.Column('scopes', sa.Text(), nullable=True),
        sa.Column('resource_restrictions', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('revoked', sa.Boolean(), server_default=sa.text('0'), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoke_reason', sa.String(190), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('service_id', name='uk_service_auth_tokens_service'),
        sa.ForeignKeyConstraint(['owner_id'], ['User.id'], name='fk_service_auth_tokens_owner'),
        sa.Index('idx_service_auth_tokens_expires', 'expires_at'),
        sa.Index('idx_service_auth_tokens_revoked', 'revoked'),
        mysql_engine='InnoDB',
        mysql_charset='utf8mb4',
        mysql_collate='utf8mb4_unicode_ci',
    )

    # service_vault_contexts table
    op.create_table(
        'service_vault_contexts',
        sa.Column('id', mysql.INTEGER(unsigned=True), autoincrement=True, nullable=False),
        sa.Column('context_id', sa.String(64), nullable=False),
        sa.Column('service_id', sa.String(64), nullable=False),
        sa.Column('encrypted_context', sa.LargeBinary(length=4096), nullable=False),
        sa.Column('encrypted_with_key', sa.VARBINARY(64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('revoked', sa.Boolean(), server_default=sa.text('0'), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoke_reason', sa.String(190), nullable=True),
        sa.Column('sealed_epoch', mysql.INTEGER(), server_default=sa.text('0'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('service_id', name='uk_service_vault_contexts_service'),
        sa.UniqueConstraint('context_id', name='uk_service_vault_contexts_context_id'),
        sa.Index('idx_service_vault_contexts_expires', 'expires_at'),
        sa.Index('idx_service_vault_contexts_revoked', 'revoked'),
        mysql_engine='InnoDB',
        mysql_charset='utf8mb4',
        mysql_collate='utf8mb4_unicode_ci',
    )

    # Add is_php_extension info as table comments (for documentation)
    op.execute("ALTER TABLE service_accounts COMMENT='Python extension table (is_php_extension=true)'")
    op.execute("ALTER TABLE service_auth_tokens COMMENT='Python extension table (is_php_extension=true)'")
    op.execute("ALTER TABLE service_vault_contexts COMMENT='Python extension table (is_php_extension=true)'")


def downgrade() -> None:
    op.drop_table('service_vault_contexts')
    op.drop_table('service_auth_tokens')
    op.drop_table('service_accounts')
