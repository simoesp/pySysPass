"""Audit logging models per ADR-0011.

This module defines the audit_events table for comprehensive security event
logging with mandatory coverage, redaction, append-only storage, configurable
retention, and Security Auditor role support.
"""
from datetime import UTC, datetime
from enum import Enum as PyEnum
from typing import Callable

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import relationship

from app.db.base import Base, FlexibleBinary, mysql_integer, mysql_mediumint, mysql_smallint, mysql_tinyint


def _utc_now_naive() -> datetime:
    """Return current UTC time as naive datetime for MySQL storage."""
    return datetime.now(UTC).replace(tzinfo=None)


class AuditEventType(str, PyEnum):
    """Audit event type enumeration per ADR-0011."""

    # Authentication events
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_MFA_ENROLL = "AUTH_MFA_ENROLL"
    AUTH_MFA_VERIFY = "AUTH_MFA_VERIFY"
    AUTH_TOKEN_ISSUED = "AUTH_TOKEN_ISSUED"
    AUTH_TOKEN_REVOKED = "AUTH_TOKEN_REVOKED"
    AUTH_SERVICE_CREATED = "AUTH_SERVICE_CREATED"
    AUTH_SERVICE_TOKEN_ISSUED = "AUTH_SERVICE_TOKEN_ISSUED"

    # Authorization events
    AUTHZ_CHECK = "AUTHZ_CHECK"
    AUTHZ_DENIED = "AUTHZ_DENIED"
    AUTHZ_SCOPE_CHECK = "AUTHZ_SCOPE_CHECK"
    AUTHZ_RESOURCE_RESTRICTION = "AUTHZ_RESOURCE_RESTRICTION"

    # Operation events
    OP_ACCOUNT_CREATED = "OP_ACCOUNT_CREATED"
    OP_ACCOUNT_UPDATED = "OP_ACCOUNT_UPDATED"
    OP_ACCOUNT_DELETED = "OP_ACCOUNT_DELETED"
    OP_ACCOUNT_SHARED = "OP_ACCOUNT_SHARED"
    OP_CREDENTIAL_RETRIEVED = "OP_CREDENTIAL_RETRIEVED"
    OP_CREDENTIAL_MODIFIED = "OP_CREDENTIAL_MODIFIED"
    OP_CREDENTIAL_EXPORTED = "OP_CREDENTIAL_EXPORTED"
    OP_GROUP_CREATED = "OP_GROUP_CREATED"
    OP_GROUP_MEMBER_ADDED = "OP_GROUP_MEMBER_ADDED"
    OP_GROUP_MEMBER_REMOVED = "OP_GROUP_MEMBER_REMOVED"
    OP_PROFILE_MODIFIED = "OP_PROFILE_MODIFIED"

    # Administrative events
    ADMIN_USER_CREATED = "ADMIN_USER_CREATED"
    ADMIN_USER_DISABLED = "ADMIN_USER_DISABLED"
    ADMIN_USER_ENABLED = "ADMIN_USER_ENABLED"
    ADMIN_ADMIN_CREATED = "ADMIN_ADMIN_CREATED"
    ADMIN_TOKEN_CREATED = "ADMIN_TOKEN_CREATED"
    ADMIN_CONFIG_CHANGED = "ADMIN_CONFIG_CHANGED"
    ADMIN_BACKUP_CREATED = "ADMIN_BACKUP_CREATED"
    ADMIN_MASTER_PASSWORD_ROTATED = "ADMIN_MASTER_PASSWORD_ROTATED"

    # System events
    SYSTEM_ERROR = "SYSTEM_ERROR"
    SYSTEM_CONFIG_CHANGED = "SYSTEM_CONFIG_CHANGED"
    SYSTEM_SERVICE_STARTED = "SYSTEM_SERVICE_STARTED"
    SYSTEM_SERVICE_STOPPED = "SYSTEM_SERVICE_STOPPED"
    SYSTEM_MAINTENANCE_MODE = "SYSTEM_MAINTENANCE_MODE"
    SYSTEM_BACKUP_COMPLETED = "SYSTEM_BACKUP_COMPLETED"
    SYSTEM_BACKUP_FAILED = "SYSTEM_BACKUP_FAILED"


class AuditSeverity(str, PyEnum):
    """Audit event severity levels."""

    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class AuditActorType(str, PyEnum):
    """Actor type enumeration."""

    USER = "user"
    SERVICE = "service"
    ADMIN = "admin"
    UNKNOWN = "unknown"


class AuditTokenType(str, PyEnum):
    """Token type enumeration."""

    JWT = "jwt"
    SERVICE = "service"
    API = "api"
    UNKNOWN = "unknown"


class AuditResourceType(str, PyEnum):
    """Resource type enumeration."""

    ACCOUNT = "account"
    USER = "user"
    GROUP = "group"
    CONFIG = "config"
    TOKEN = "token"


class AuditOperationAction(str, PyEnum):
    """Operation action enumeration."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXPORT = "export"
    ADMIN = "admin"


class AuditResult(str, PyEnum):
    """Audit event result enumeration."""

    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


class AuditEvent(Base):
    """Audit event model per ADR-0011.

    Comprehensive security event logging with tamper-resistant design,
    mandatory coverage, redaction support, and configurable retention.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("idx_audit_events_timestamp", "timestamp"),
        Index("idx_audit_events_event_type", "event_type"),
        Index("idx_audit_events_actor", "actor_type", "actor_id"),
        Index("idx_audit_events_resource", "resource_type", "resource_id"),
        Index("idx_audit_events_result", "result"),
        Index("idx_audit_events_severity", "severity"),
        Index("idx_audit_events_session", "session_id"),
        Index("idx_audit_events_request", "request_id"),
        Index("idx_audit_events_ip", "ip_address"),
        {"info": {"is_php_extension": True}},
    )

    event_id = Column(String(64), primary_key=True, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=_utc_now_naive)
    event_type = Column(Enum(AuditEventType, native_enum=False, length=64), nullable=False)
    severity = Column(Enum(AuditSeverity, native_enum=False, length=10), nullable=False)

    # Actor identification
    actor_type = Column(Enum(AuditActorType, native_enum=False, length=20), nullable=False)
    actor_id = Column(mysql_integer(unsigned=True), nullable=True)
    actor_username = Column(String(255), nullable=True)
    token_type = Column(Enum(AuditTokenType, native_enum=False, length=20), nullable=True)

    # Resource identification
    resource_type = Column(Enum(AuditResourceType, native_enum=False, length=20), nullable=True)
    resource_id = Column(mysql_integer(unsigned=True), nullable=True)
    resource_name = Column(String(255), nullable=True)

    # Operation details
    operation_action = Column(Enum(AuditOperationAction, native_enum=False, length=20), nullable=True)
    operation_scope = Column(Text, nullable=True)  # JSON array
    operation_params = Column(Text, nullable=True)  # JSON object

    # Result
    result = Column(Enum(AuditResult, native_enum=False, length=20), nullable=False)
    error_message = Column(Text, nullable=True)

    # Context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    session_id = Column(String(128), nullable=True)
    service_id = Column(String(64), nullable=True)
    request_id = Column(String(64), nullable=False, index=True)

    # Metadata (flexible JSON)
    event_metadata = Column(Text, nullable=True)  # JSON object

    # Integrity: HMAC signature for tamper detection
    signature = Column(String(128), nullable=True)

    # Relationships
    actor_user = relationship("User", foreign_keys=[actor_id], primaryjoin="AuditEvent.actor_id==User.id")

    def __repr__(self) -> str:
        return f"<AuditEvent(event_id={self.event_id}, event_type={self.event_type}, actor={self.actor_username})>"


class AuditArchive(Base):
    """Audit archive tracking for retention and compliance."""

    __tablename__ = "audit_archives"
    __table_args__ = (
        Index("idx_audit_archives_period", "period_start", "period_end"),
        Index("idx_audit_archives_status", "status"),
        {"info": {"is_php_extension": True}},
    )

    id = Column(mysql_integer(), primary_key=True, autoincrement=True)
    archive_id = Column(String(64), unique=True, nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    event_count = Column(mysql_integer(unsigned=True), default=0)
    file_path = Column(String(512), nullable=True)
    file_size = Column(mysql_integer(unsigned=True), nullable=True)
    checksum = Column(String(128), nullable=True)
    status = Column(String(20), nullable=False, default="pending")  # pending, completed, verified, failed
    storage_type = Column(String(20), nullable=False)  # local, s3, worm
    created_at = Column(DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None))
    verified_at = Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"<AuditArchive(archive_id={self.archive_id}, status={self.status})>"


class AuditRetentionPolicy(Base):
    """Configurable retention policy for audit data."""

    __tablename__ = "audit_retention_policies"
    __table_args__ = (
        UniqueConstraint("data_type", name="uk_audit_retention_data_type"),
        {"info": {"is_php_extension": True}},
    )

    id = Column(mysql_smallint(), primary_key=True, autoincrement=True)
    data_type = Column(String(50), nullable=False)  # application_logs, database_events, immutable_archive, compliance_reports
    retention_days = Column(mysql_integer(unsigned=True), nullable=False)
    storage_location = Column(String(512), nullable=True)
    enabled = Column(mysql_tinyint(), default=1, server_default="1", nullable=False)
    created_at = Column(DateTime, default=_utc_now_naive)
    updated_at = Column(DateTime, onupdate=_utc_now_naive)

    def __repr__(self) -> str:
        return f"<AuditRetentionPolicy(data_type={self.data_type}, retention_days={self.retention_days})>"


class AuditAccessLog(Base):
    """Access log for audit log access (who accessed audit logs)."""

    __tablename__ = "audit_access_logs"
    __table_args__ = (
        Index("idx_audit_access_logs_timestamp", "timestamp"),
        Index("idx_audit_access_logs_user", "user_id"),
        Index("idx_audit_access_logs_event", "accessed_event_id"),
        {"info": {"is_php_extension": True}},
    )

    id = Column(mysql_integer(), primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=_utc_now_naive)
    user_id = Column(mysql_smallint(unsigned=True), ForeignKey("User.id"), nullable=False)
    action = Column(String(50), nullable=False)  # view, export, query, configure
    accessed_event_id = Column(String(64), nullable=True)
    query_params = Column(Text, nullable=True)  # JSON of query parameters
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)

    user = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<AuditAccessLog(user_id={self.user_id}, action={self.action})>"