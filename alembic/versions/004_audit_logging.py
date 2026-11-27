"""Create audit logging tables per ADR-0011.

Revision ID: 004
Revises: 003
Create Date: 2026-11-27

This migration creates the core audit logging infrastructure:
- audit_events: Primary audit event storage with integrity protection
- audit_archives: Archive tracking for retention and compliance
- audit_retention_policies: Configurable retention policies
- audit_access_logs: Meta-auditing of audit log access
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Audit Events table - primary audit log storage
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.Enum("info", "warn", "error", name="audit_severity"), nullable=False),
        sa.Column("actor_type", sa.Enum("user", "service", "admin", "unknown", name="audit_actor_type"), nullable=False),
        sa.Column("actor_id", mysql.INTEGER(unsigned=True), nullable=True),
        sa.Column("actor_username", sa.String(255), nullable=True),
        sa.Column("token_type", sa.Enum("jwt", "service", "api", "unknown", name="audit_token_type"), nullable=True),
        sa.Column("resource_type", sa.Enum("account", "user", "group", "config", "token", name="audit_resource_type"), nullable=True),
        sa.Column("resource_id", mysql.INTEGER(unsigned=True), nullable=True),
        sa.Column("resource_name", sa.String(255), nullable=True),
        sa.Column("operation_action", sa.Enum("read", "write", "delete", "export", "admin", name="audit_operation_action"), nullable=True),
        sa.Column("operation_scope", sa.Text(), nullable=True),  # JSON array
        sa.Column("operation_params", sa.Text(), nullable=True),  # JSON object
        sa.Column("result", sa.Enum("success", "denied", "error", name="audit_result"), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("session_id", sa.String(128), nullable=True),
        sa.Column("service_id", sa.String(64), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("metadata", sa.Text(), nullable=True),  # JSON object
        sa.Column("signature", sa.String(128), nullable=True),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
        mysql_collate="utf8mb4_unicode_ci",
    )

    op.create_index("idx_audit_events_timestamp", "audit_events", ["timestamp"])
    op.create_index("idx_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("idx_audit_events_actor", "audit_events", ["actor_type", "actor_id"])
    op.create_index("idx_audit_events_resource", "audit_events", ["resource_type", "resource_id"])
    op.create_index("idx_audit_events_result", "audit_events", ["result"])
    op.create_index("idx_audit_events_severity", "audit_events", ["severity"])
    op.create_index("idx_audit_events_session", "audit_events", ["session_id"])
    op.create_index("idx_audit_events_request", "audit_events", ["request_id"])
    op.create_index("idx_audit_events_ip", "audit_events", ["ip_address"])

    # Audit Archives table - archive tracking for retention/compliance
    op.create_table(
        "audit_archives",
        sa.Column("id", mysql.INTEGER(), primary_key=True, autoincrement=True),
        sa.Column("archive_id", sa.String(64), unique=True, nullable=False),
        sa.Column("period_start", sa.DateTime(), nullable=False),
        sa.Column("period_end", sa.DateTime(), nullable=False),
        sa.Column("event_count", mysql.INTEGER(unsigned=True), default=0),
        sa.Column("file_path", sa.String(512), nullable=True),
        sa.Column("file_size", mysql.INTEGER(unsigned=True), nullable=True),
        sa.Column("checksum", sa.String(128), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("storage_type", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
        mysql_collate="utf8mb4_unicode_ci",
    )

    op.create_index("idx_audit_archives_period", "audit_archives", ["period_start", "period_end"])
    op.create_index("idx_audit_archives_status", "audit_archives", ["status"])

    # Audit Retention Policies table - configurable retention
    op.create_table(
        "audit_retention_policies",
        sa.Column("id", mysql.SMALLINT(), primary_key=True, autoincrement=True),
        sa.Column("data_type", sa.String(50), nullable=False),
        sa.Column("retention_days", mysql.INTEGER(unsigned=True), nullable=False),
        sa.Column("storage_location", sa.String(512), nullable=True),
        sa.Column("enabled", mysql.TINYINT(), default=1, server_default="1", nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
        mysql_collate="utf8mb4_unicode_ci",
    )

    op.create_index("uk_audit_retention_data_type", "audit_retention_policies", ["data_type"], unique=True)

    # Audit Access Logs table - meta-auditing
    op.create_table(
        "audit_access_logs",
        sa.Column("id", mysql.INTEGER(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("user_id", mysql.SMALLINT(unsigned=True), sa.ForeignKey("User.id"), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("accessed_event_id", sa.String(64), nullable=True),
        sa.Column("query_params", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
        mysql_collate="utf8mb4_unicode_ci",
    )

    op.create_index("idx_audit_access_logs_timestamp", "audit_access_logs", ["timestamp"])
    op.create_index("idx_audit_access_logs_user", "audit_access_logs", ["user_id"])
    op.create_index("idx_audit_access_logs_event", "audit_access_logs", ["accessed_event_id"])

    # Insert default retention policies per ADR-0011
    op.execute("""
        INSERT INTO audit_retention_policies (data_type, retention_days, storage_location, enabled, created_at)
        VALUES
            ('application_logs', 90, '/app/logs/audit.jsonl', 1, NOW()),
            ('database_events', 365, 'audit_events table', 1, NOW()),
            ('immutable_archive', 2555, 'WORM storage', 1, NOW()),
            ('compliance_reports', 2555, '/var/log/syspass/compliance/', 1, NOW())
    """)


def downgrade() -> None:
    op.drop_table("audit_access_logs")
    op.drop_table("audit_retention_policies")
    op.drop_table("audit_archives")
    op.drop_table("audit_events")