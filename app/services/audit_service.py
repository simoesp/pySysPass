"""Audit logging service per ADR-0011.

Provides comprehensive audit event logging, querying, archival, and retention
management with mandatory security event coverage, redaction, append-only
storage, configurable retention, and Security Auditor role support.
"""
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

from sqlalchemy import and_, desc, func, or_
from sqlalchemy.orm import Session

from app.models.audit import (
    AuditAccessLog,
    AuditArchive,
    AuditEvent,
    AuditEventType,
    AuditRetentionPolicy,
    AuditSeverity,
)
from app.models.account import User
from app.core.config import settings

logger = logging.getLogger(__name__)

# HMAC key for audit event integrity (in production, load from secure config)
_AUDIT_HMAC_KEY = settings.AUDIT_HMAC_KEY.encode() if getattr(settings, "AUDIT_HMAC_KEY", None) else b""
if not _AUDIT_HMAC_KEY:
    # Generate a persistent key for development; production MUST set AUDIT_HMAC_KEY
    _AUDIT_HMAC_KEY = secrets.token_bytes(32)
    logger.warning("AUDIT_HMAC_KEY not set; using ephemeral key (NOT for production)")


def _utc_now_naive() -> datetime:
    """Return current UTC time as naive datetime for MySQL storage."""
    return datetime.now(UTC).replace(tzinfo=None)


def _generate_event_id() -> str:
    """Generate a unique event ID."""
    return f"evt_{secrets.token_urlsafe(32)}"


def _generate_request_id() -> str:
    """Generate a unique request ID for traceability."""
    return f"req_{secrets.token_urlsafe(16)}"


def _generate_archive_id() -> str:
    """Generate a unique archive ID."""
    return f"arc_{secrets.token_urlsafe(16)}"


def _compute_signature(event_data: dict) -> str:
    """Compute HMAC signature for audit event integrity."""
    # Create a deterministic string representation
    canonical = json.dumps(event_data, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(_AUDIT_HMAC_KEY, canonical.encode(), hashlib.sha256).hexdigest()
    return signature


def _verify_signature(event_data: dict, signature: str) -> bool:
    """Verify HMAC signature for audit event integrity."""
    expected = _compute_signature(event_data)
    return hmac.compare_digest(expected, signature)


def _redact_sensitive_data(data: dict, event_type: AuditEventType) -> dict:
    """Redact sensitive fields from audit event data per ADR-0011.

    Audit logs must not contain credentials, secrets, or sensitive PII.
    Only nested fields (operation_params, metadata) are redacted;
    top-level fields are stored as separate columns and not redacted here.
    """
    redacted = data.copy()

    # Fields that should never appear in audit logs
    sensitive_fields = {
        "password",
        "pass",
        "secret",
        "token",
        "key",
        "hash",
        "salt",
        "mfa_secret",
        "mfa_code",
        "totp",
        "private_key",
        "api_key",
        "access_token",
        "refresh_token",
        "authorization",
        "credential",
        "master_password",
        "encryption_key",
        "decryption_key",
    }

    def _redact_recursive(obj: Any, path: str = "") -> Any:
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                lower_k = k.lower()
                # Check if key contains sensitive field names
                if any(sensitive in lower_k for sensitive in sensitive_fields):
                    result[k] = "[REDACTED]"
                else:
                    result[k] = _redact_recursive(v, f"{path}.{k}")
            return result
        elif isinstance(obj, list):
            return [_redact_recursive(item, f"{path}[]") for item in obj]
        else:
            return obj

    # Only redact nested fields that are stored as JSON
    if "operation_params" in redacted:
        redacted["operation_params"] = _redact_recursive(redacted["operation_params"])
    if "metadata" in redacted:
        redacted["metadata"] = _redact_recursive(redacted["metadata"])

    return redacted


class AuditService:
    """Core audit logging service per ADR-0011."""

    def __init__(self, db: Session):
        self.db = db

    def log_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        actor_type: str,
        result: str,
        request_id: Optional[str] = None,
        actor_id: Optional[int] = None,
        actor_username: Optional[str] = None,
        token_type: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        resource_name: Optional[str] = None,
        operation_action: Optional[str] = None,
        operation_scope: Optional[list] = None,
        operation_params: Optional[dict] = None,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        service_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AuditEvent:
        """Log an audit event with integrity protection and redaction.

        This is the primary method for writing audit events. It handles:
        - Event ID generation
        - Timestamp assignment
        - Sensitive data redaction
        - HMAC signature for tamper detection
        - Database persistence
        """
        request_id = request_id or _generate_request_id()
        event_id = _generate_event_id()
        timestamp = _utc_now_naive()

        # Prepare event data for redaction and signing
        event_data = {
            "event_id": event_id,
            "timestamp": timestamp.isoformat(),
            "event_type": event_type.value if isinstance(event_type, AuditEventType) else event_type,
            "severity": severity.value if isinstance(severity, AuditSeverity) else severity,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "actor_username": actor_username,
            "token_type": token_type,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "operation_action": operation_action,
            "operation_scope": operation_scope,
            "operation_params": operation_params,
            "result": result,
            "error_message": error_message,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "session_id": session_id,
            "service_id": service_id,
            "request_id": request_id,
            "metadata": metadata,
        }

        # Redact sensitive data
        redacted_data = _redact_sensitive_data(event_data, event_type)

        # Compute integrity signature
        signature = _compute_signature(redacted_data)

        # Create audit event record
        event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_username=actor_username,
            token_type=token_type,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            operation_action=operation_action,
            operation_scope=json.dumps(operation_scope) if operation_scope else None,
            operation_params=json.dumps(redacted_data.get("operation_params")) if operation_params else None,
            result=result,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            service_id=service_id,
            request_id=request_id,
            event_metadata=json.dumps(redacted_data.get("metadata")) if metadata else None,
            signature=signature,
        )

        self.db.add(event)
        self.db.commit()

        logger.info(
            "Audit event logged: %s (type=%s, actor=%s, result=%s)",
            event_id,
            event_type,
            actor_username or actor_id,
            result,
        )

        return event

    def log_auth_event(
        self,
        event_type: AuditEventType,
        user_id: int,
        username: str,
        ip_address: str,
        user_agent: Optional[str],
        session_id: Optional[str],
        result: str,
        error_message: Optional[str] = None,
        metadata: Optional[dict] = None,
        **kwargs,
    ) -> AuditEvent:
        """Log an authentication event with standardized fields."""
        return self.log_event(
            event_type=event_type,
            severity=AuditSeverity.INFO if result == "success" else AuditSeverity.WARN,
            actor_type="user",
            actor_id=user_id,
            actor_username=username,
            token_type="jwt",
            resource_type="user",
            resource_id=user_id,
            resource_name=username,
            operation_action="read",
            result=result,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            metadata=metadata,
            **kwargs,
        )

    def log_authz_event(
        self,
        event_type: AuditEventType,
        actor_id: int,
        actor_username: str,
        actor_type: str,
        resource_type: str,
        resource_id: int,
        resource_name: str,
        operation: str,
        granted: bool,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        **kwargs,
    ) -> AuditEvent:
        """Log an authorization event with standardized fields."""
        return self.log_event(
            event_type=event_type,
            severity=AuditSeverity.INFO if granted else AuditSeverity.WARN,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_username=actor_username,
            token_type="jwt",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            operation_action=operation,
            result="success" if granted else "denied",
            error_message=reason if not granted else None,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            **kwargs,
        )

    def log_operation_event(
        self,
        event_type: AuditEventType,
        actor_id: int,
        actor_username: str,
        actor_type: str,
        resource_type: str,
        resource_id: int,
        resource_name: str,
        operation_action: str,
        result: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[dict] = None,
        error_message: Optional[str] = None,
        **kwargs,
    ) -> AuditEvent:
        """Log an operation event with standardized fields."""
        severity = AuditSeverity.INFO
        if result == "error":
            severity = AuditSeverity.ERROR
        elif result == "denied":
            severity = AuditSeverity.WARN
        elif event_type in (AuditEventType.OP_CREDENTIAL_EXPORTED, AuditEventType.OP_ACCOUNT_DELETED):
            severity = AuditSeverity.WARN

        return self.log_event(
            event_type=event_type,
            severity=severity,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_username=actor_username,
            token_type="jwt",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            operation_action=operation_action,
            result=result,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
            **kwargs,
        )

    def log_admin_event(
        self,
        event_type: AuditEventType,
        admin_id: int,
        admin_username: str,
        target_user_id: Optional[int],
        target_username: Optional[str],
        action: str,
        result: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[dict] = None,
        error_message: Optional[str] = None,
        **kwargs,
    ) -> AuditEvent:
        """Log an administrative event with standardized fields."""
        return self.log_event(
            event_type=event_type,
            severity=AuditSeverity.WARN,
            actor_type="admin",
            actor_id=admin_id,
            actor_username=admin_username,
            token_type="jwt",
            resource_type="user" if target_user_id else "config",
            resource_id=target_user_id,
            resource_name=target_username,
            operation_action=action,
            result=result,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
            **kwargs,
        )

    def log_system_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        message: str,
        error_message: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[dict] = None,
        **kwargs,
    ) -> AuditEvent:
        """Log a system event with standardized fields."""
        return self.log_event(
            event_type=event_type,
            severity=severity,
            actor_type="unknown",
            actor_id=None,
            actor_username="system",
            token_type="unknown",
            resource_type="config",
            resource_id=None,
            resource_name="system",
            operation_action="admin",
            result="success" if severity == AuditSeverity.INFO else "error",
            error_message=error_message or message,
            ip_address=None,
            user_agent=None,
            session_id=None,
            request_id=request_id,
            metadata=metadata,
            **kwargs,
        )

    def query(
        self,
        event_type: Optional[str] = None,
        actor_type: Optional[str] = None,
        actor_id: Optional[int] = None,
        actor_username: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        operation_action: Optional[str] = None,
        ip_address: Optional[str] = None,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None,
        severity: Optional[str] = None,
        result: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        sort: str = "timestamp",
        order: str = "DESC",
    ) -> list[AuditEvent]:
        """Query audit events with flexible filtering."""
        query = self.db.query(AuditEvent)

        if event_type:
            query = query.filter(AuditEvent.event_type == event_type)
        if actor_type:
            query = query.filter(AuditEvent.actor_type == actor_type)
        if actor_id:
            query = query.filter(AuditEvent.actor_id == actor_id)
        if actor_username:
            query = query.filter(AuditEvent.actor_username == actor_username)
        if resource_type:
            query = query.filter(AuditEvent.resource_type == resource_type)
        if resource_id:
            query = query.filter(AuditEvent.resource_id == resource_id)
        if operation_action:
            query = query.filter(AuditEvent.operation_action == operation_action)
        if ip_address:
            query = query.filter(AuditEvent.ip_address == ip_address)
        if from_timestamp:
            query = query.filter(AuditEvent.timestamp >= from_timestamp)
        if to_timestamp:
            query = query.filter(AuditEvent.timestamp <= to_timestamp)
        if severity:
            query = query.filter(AuditEvent.severity == severity)
        if result:
            query = query.filter(AuditEvent.result == result)
        if session_id:
            query = query.filter(AuditEvent.session_id == session_id)
        if request_id:
            query = query.filter(AuditEvent.request_id == request_id)

        # Sorting
        sort_column = getattr(AuditEvent, sort, AuditEvent.timestamp)
        if order.upper() == "DESC":
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(sort_column)

        return query.offset(offset).limit(limit).all()

    def count(
        self,
        event_type: Optional[str] = None,
        actor_type: Optional[str] = None,
        actor_id: Optional[int] = None,
        actor_username: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        operation_action: Optional[str] = None,
        ip_address: Optional[str] = None,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None,
        severity: Optional[str] = None,
        result: Optional[str] = None,
    ) -> int:
        """Count audit events matching filters."""
        query = self.db.query(func.count(AuditEvent.event_id))

        if event_type:
            query = query.filter(AuditEvent.event_type == event_type)
        if actor_type:
            query = query.filter(AuditEvent.actor_type == actor_type)
        if actor_id:
            query = query.filter(AuditEvent.actor_id == actor_id)
        if actor_username:
            query = query.filter(AuditEvent.actor_username == actor_username)
        if resource_type:
            query = query.filter(AuditEvent.resource_type == resource_type)
        if resource_id:
            query = query.filter(AuditEvent.resource_id == resource_id)
        if operation_action:
            query = query.filter(AuditEvent.operation_action == operation_action)
        if ip_address:
            query = query.filter(AuditEvent.ip_address == ip_address)
        if from_timestamp:
            query = query.filter(AuditEvent.timestamp >= from_timestamp)
        if to_timestamp:
            query = query.filter(AuditEvent.timestamp <= to_timestamp)
        if severity:
            query = query.filter(AuditEvent.severity == severity)
        if result:
            query = query.filter(AuditEvent.result == result)

        return query.scalar() or 0

    def get_event(self, event_id: str) -> Optional[AuditEvent]:
        """Get a single audit event by ID."""
        return self.db.query(AuditEvent).filter(AuditEvent.event_id == event_id).first()

    def verify_event_integrity(self, event_id: str) -> bool:
        """Verify the HMAC signature of an audit event."""
        event = self.get_event(event_id)
        if not event:
            return False

        event_data = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "event_type": event.event_type.value if event.event_type else None,
            "severity": event.severity.value if event.severity else None,
            "actor_type": event.actor_type,
            "actor_id": event.actor_id,
            "actor_username": event.actor_username,
            "token_type": event.token_type,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "resource_name": event.resource_name,
            "operation_action": event.operation_action,
            "operation_scope": json.loads(event.operation_scope) if event.operation_scope else None,
            "operation_params": json.loads(event.operation_params) if event.operation_params else None,
            "result": event.result,
            "error_message": event.error_message,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
            "session_id": event.session_id,
            "service_id": event.service_id,
            "request_id": event.request_id,
            "metadata": json.loads(event.event_metadata) if event.event_metadata else None,
        }

        return _verify_signature(event_data, event.signature or "")

    def verify_all_events(self, from_timestamp: Optional[datetime] = None, to_timestamp: Optional[datetime] = None) -> tuple[int, int]:
        """Verify integrity of all events in a time range.

        Returns: (verified_count, failed_count)
        """
        query = self.db.query(AuditEvent)
        if from_timestamp:
            query = query.filter(AuditEvent.timestamp >= from_timestamp)
        if to_timestamp:
            query = query.filter(AuditEvent.timestamp <= to_timestamp)

        verified = 0
        failed = 0

        for event in query.yield_per(100):
            event_data = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "event_type": event.event_type.value if event.event_type else None,
                "severity": event.severity.value if event.severity else None,
                "actor_type": event.actor_type,
                "actor_id": event.actor_id,
                "actor_username": event.actor_username,
                "token_type": event.token_type,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "resource_name": event.resource_name,
                "operation_action": event.operation_action,
                "operation_scope": json.loads(event.operation_scope) if event.operation_scope else None,
                "operation_params": json.loads(event.operation_params) if event.operation_params else None,
                "result": event.result,
                "error_message": event.error_message,
                "ip_address": event.ip_address,
                "user_agent": event.user_agent,
                "session_id": event.session_id,
                "service_id": event.service_id,
                "request_id": event.request_id,
                "metadata": json.loads(event.event_metadata) if event.event_metadata else None,
            }

            if _verify_signature(event_data, event.signature or ""):
                verified += 1
            else:
                failed += 1
                logger.error("Audit event integrity check failed: %s", event.event_id)

        return verified, failed

    # --- Archive management ---

    def create_archive(
        self,
        period_start: datetime,
        period_end: datetime,
        storage_type: str = "local",
        file_path: Optional[str] = None,
    ) -> AuditArchive:
        """Create an audit archive record."""
        archive_id = _generate_archive_id()

        # Count events in period
        event_count = (
            self.db.query(func.count(AuditEvent.event_id))
            .filter(
                and_(
                    AuditEvent.timestamp >= period_start,
                    AuditEvent.timestamp <= period_end,
                )
            )
            .scalar()
            or 0
        )

        archive = AuditArchive(
            archive_id=archive_id,
            period_start=period_start,
            period_end=period_end,
            event_count=event_count,
            file_path=file_path,
            storage_type=storage_type,
            status="pending",
        )

        self.db.add(archive)
        self.db.commit()

        return archive

    def get_archive(self, archive_id: str) -> Optional[AuditArchive]:
        """Get an archive by ID."""
        return self.db.query(AuditArchive).filter(AuditArchive.archive_id == archive_id).first()

    def list_archives(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditArchive]:
        """List audit archives."""
        query = self.db.query(AuditArchive).order_by(desc(AuditArchive.created_at))

        if status:
            query = query.filter(AuditArchive.status == status)

        return query.offset(offset).limit(limit).all()

    # --- Retention policy management ---

    def get_retention_policy(self, data_type: str) -> Optional[AuditRetentionPolicy]:
        """Get retention policy for a data type."""
        return (
            self.db.query(AuditRetentionPolicy)
            .filter(AuditRetentionPolicy.data_type == data_type)
            .first()
        )

    def set_retention_policy(
        self,
        data_type: str,
        retention_days: int,
        storage_location: Optional[str] = None,
        enabled: bool = True,
    ) -> AuditRetentionPolicy:
        """Set or update a retention policy."""
        policy = self.get_retention_policy(data_type)
        if policy:
            policy.retention_days = retention_days
            policy.storage_location = storage_location
            policy.enabled = enabled
            policy.updated_at = _utc_now_naive()
        else:
            policy = AuditRetentionPolicy(
                data_type=data_type,
                retention_days=retention_days,
                storage_location=storage_location,
                enabled=enabled,
            )
            self.db.add(policy)

        self.db.commit()
        return policy

    def list_retention_policies(self) -> list[AuditRetentionPolicy]:
        """List all retention policies."""
        return self.db.query(AuditRetentionPolicy).all()

    # --- Access logging ---

    def log_access(
        self,
        user_id: int,
        action: str,
        accessed_event_id: Optional[str] = None,
        query_params: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditAccessLog:
        """Log access to audit logs (meta-auditing)."""
        access_log = AuditAccessLog(
            user_id=user_id,
            action=action,
            accessed_event_id=accessed_event_id,
            query_params=json.dumps(query_params) if query_params else None,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.db.add(access_log)
        self.db.commit()

        return access_log

    def get_access_logs(
        self,
        user_id: Optional[int] = None,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditAccessLog]:
        """Get audit log access logs."""
        query = self.db.query(AuditAccessLog).order_by(desc(AuditAccessLog.timestamp))

        if user_id:
            query = query.filter(AuditAccessLog.user_id == user_id)
        if from_timestamp:
            query = query.filter(AuditAccessLog.timestamp >= from_timestamp)
        if to_timestamp:
            query = query.filter(AuditAccessLog.timestamp <= to_timestamp)

        return query.offset(offset).limit(limit).all()

    # --- Export ---

    def export_events(
        self,
        event_type: Optional[str] = None,
        actor_type: Optional[str] = None,
        actor_id: Optional[int] = None,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None,
        format: str = "jsonl",
    ) -> str:
        """Export audit events in specified format."""
        events = self.query(
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
            limit=10000,  # Max export limit
        )

        if format == "jsonl":
            lines = []
            for event in events:
                event_dict = {
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "event_type": event.event_type.value if event.event_type else None,
                    "severity": event.severity.value if event.severity else None,
                    "actor_type": event.actor_type,
                    "actor_id": event.actor_id,
                    "actor_username": event.actor_username,
                    "token_type": event.token_type,
                    "resource_type": event.resource_type,
                    "resource_id": event.resource_id,
                    "resource_name": event.resource_name,
                    "operation_action": event.operation_action,
                    "operation_scope": json.loads(event.operation_scope) if event.operation_scope else None,
                    "operation_params": json.loads(event.operation_params) if event.operation_params else None,
                    "result": event.result,
                    "error_message": event.error_message,
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "session_id": event.session_id,
                    "service_id": event.service_id,
                    "request_id": event.request_id,
                    "metadata": json.loads(event.event_metadata) if event.event_metadata else None,
                }
                lines.append(json.dumps(event_dict))
            return "\n".join(lines)

        elif format == "csv":
            import csv
            import io

            output = io.StringIO()
            writer = csv.writer(output)

            # Header
            writer.writerow([
                "event_id", "timestamp", "event_type", "severity",
                "actor_type", "actor_id", "actor_username", "token_type",
                "resource_type", "resource_id", "resource_name",
                "operation_action", "operation_scope", "operation_params",
                "result", "error_message", "ip_address", "user_agent",
                "session_id", "service_id", "request_id", "metadata"
            ])

            for event in events:
                writer.writerow([
                    event.event_id,
                    event.timestamp.isoformat() if event.timestamp else "",
                    event.event_type.value if event.event_type else "",
                    event.severity.value if event.severity else "",
                    event.actor_type,
                    event.actor_id or "",
                    event.actor_username or "",
                    event.token_type or "",
                    event.resource_type or "",
                    event.resource_id or "",
                    event.resource_name or "",
                    event.operation_action or "",
                    event.operation_scope or "",
                    event.operation_params or "",
                    event.result,
                    event.error_message or "",
                    event.ip_address or "",
                    event.user_agent or "",
                    event.session_id or "",
                    event.service_id or "",
                    event.request_id,
                    event.event_metadata or "",
                ])

            return output.getvalue()

        else:
            raise ValueError(f"Unsupported export format: {format}")