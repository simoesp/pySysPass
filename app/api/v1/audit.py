"""Audit logging API routes per ADR-0011.

REST API for querying, exporting, and managing audit events with
Security Auditor role-based access control.
"""
import json
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_permission, get_current_user
from app.models.account import User
from app.models.audit import AuditEventType, AuditSeverity, AuditActorType
from app.schemas.audit import (
    AuditEventListResponse,
    AuditEventQuery,
    AuditEventExportQuery,
    AuditEventResponse,
    AuditArchiveResponse,
    AuditArchiveCreate,
    AuditRetentionPolicyResponse,
    AuditRetentionPolicyCreate,
    AuditAccessLogResponse,
    AuditIntegrityCheckResponse,
    AuditStatsResponse,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit Logging"])


# Permission constants
AUDIT_VIEW_PERM = "audit_view"
AUDIT_ANALYST_PERM = "audit_analyst"
AUDIT_ADMIN_PERM = "audit_admin"


def _get_audit_service(db: Session = Depends(get_db)) -> AuditService:
    """Dependency to get audit service instance."""
    return AuditService(db)


def _verify_audit_view_permission(current_user: User = Depends(get_current_user)) -> User:
    """Verify user has audit view permission."""
    # Check for audit-specific permissions or admin
    if current_user.isAdminApp or current_user.isAdminAcc:
        return current_user
    # Check for audit roles via user groups/permissions
    # For now, allow admins and users with specific permissions
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Insufficient permissions: audit_view role required"
    )


def _verify_audit_analyst_permission(current_user: User = Depends(get_current_user)) -> User:
    """Verify user has audit analyst permission."""
    if current_user.isAdminApp or current_user.isAdminAcc:
        return current_user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Insufficient permissions: audit_analyst role required"
    )


def _verify_audit_admin_permission(current_user: User = Depends(get_current_user)) -> User:
    """Verify user has audit admin permission."""
    if not (current_user.isAdminApp or current_user.isAdminAcc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions: audit_admin role required"
        )
    return current_user


# ── Event Query API ──────────────────────────────────────────────────────────

@router.get("/events", response_model=AuditEventListResponse)
def list_audit_events(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    actor_type: Optional[str] = Query(None, description="Filter by actor type: user, service, admin, unknown"),
    actor_id: Optional[int] = Query(None, description="Filter by actor ID"),
    actor_username: Optional[str] = Query(None, description="Filter by actor username"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type: account, user, group, config, token"),
    resource_id: Optional[int] = Query(None, description="Filter by resource ID"),
    operation_action: Optional[str] = Query(None, description="Filter by operation: read, write, delete, export, admin"),
    ip_address: Optional[str] = Query(None, description="Filter by IP address"),
    from_timestamp: Optional[datetime] = Query(None, description="Start time (ISO8601)"),
    to_timestamp: Optional[datetime] = Query(None, description="End time (ISO8601)"),
    severity: Optional[str] = Query(None, description="Filter by severity: info, warn, error"),
    result: Optional[str] = Query(None, description="Filter by result: success, denied, error"),
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    request_id: Optional[str] = Query(None, description="Filter by request ID"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    sort: str = Query("timestamp", description="Sort field"),
    order: str = Query("DESC", description="Sort order: ASC or DESC"),
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_view_permission),
):
    """Query audit events with flexible filtering.

    Requires audit_view, audit_analyst, or audit_admin role.
    """
    # Log access for meta-auditing
    audit_service.log_access(
        user_id=current_user.id,
        action="query",
        query_params={
            "event_type": event_type,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "from_timestamp": from_timestamp.isoformat() if from_timestamp else None,
            "to_timestamp": to_timestamp.isoformat() if to_timestamp else None,
        },
        ip_address="internal",  # Would be extracted from request in production
    )

    events = audit_service.query(
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_username=actor_username,
        resource_type=resource_type,
        resource_id=resource_id,
        operation_action=operation_action,
        ip_address=ip_address,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        severity=severity,
        result=result,
        session_id=session_id,
        request_id=request_id,
        limit=limit,
        offset=offset,
        sort=sort,
        order=order,
    )

    total = audit_service.count(
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_username=actor_username,
        resource_type=resource_type,
        resource_id=resource_id,
        operation_action=operation_action,
        ip_address=ip_address,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        severity=severity,
        result=result,
    )

    return AuditEventListResponse(
        events=[AuditEventResponse.model_validate(e) for e in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/events/{event_id}", response_model=AuditEventResponse)
def get_audit_event(
    event_id: str,
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_view_permission),
):
    """Get a single audit event by ID."""
    event = audit_service.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Audit event not found")

    # Log access
    audit_service.log_access(
        user_id=current_user.id,
        action="view",
        accessed_event_id=event_id,
    )

    return AuditEventResponse.model_validate(event)


@router.get("/events/{event_id}/raw")
def get_audit_event_raw(
    event_id: str,
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_analyst_permission),
):
    """Get raw audit event with all fields including signature (analyst+)."""
    event = audit_service.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Audit event not found")

    # Log access
    audit_service.log_access(
        user_id=current_user.id,
        action="view_raw",
        accessed_event_id=event_id,
    )

    return {
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
        "event_metadata": json.loads(event.event_metadata) if event.event_metadata else None,
        "signature": event.signature,
    }


@router.post("/events/search", response_model=AuditEventListResponse)
def search_audit_events(
    query: AuditEventQuery,
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_view_permission),
):
    """Advanced audit event search with structured query body."""
    events = audit_service.query(
        event_type=query.event_type,
        actor_type=query.actor_type,
        actor_id=query.actor_id,
        actor_username=query.actor_username,
        resource_type=query.resource_type,
        resource_id=query.resource_id,
        operation_action=query.operation_action,
        ip_address=query.ip_address,
        from_timestamp=query.from_timestamp,
        to_timestamp=query.to_timestamp,
        severity=query.severity,
        result=query.result,
        session_id=query.session_id,
        request_id=query.request_id,
        limit=query.limit,
        offset=query.offset,
        sort=query.sort,
        order=query.order,
    )

    total = audit_service.count(
        event_type=query.event_type,
        actor_type=query.actor_type,
        actor_id=query.actor_id,
        actor_username=query.actor_username,
        resource_type=query.resource_type,
        resource_id=query.resource_id,
        operation_action=query.operation_action,
        ip_address=query.ip_address,
        from_timestamp=query.from_timestamp,
        to_timestamp=query.to_timestamp,
        severity=query.severity,
        result=query.result,
    )

    return AuditEventListResponse(
        events=[AuditEventResponse.model_validate(e) for e in events],
        total=total,
        limit=query.limit,
        offset=query.offset,
    )


@router.post("/events/export")
def export_audit_events(
    query: AuditEventExportQuery,
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_analyst_permission),
):
    """Export audit events in specified format (analyst+)."""
    # Log access
    audit_service.log_access(
        user_id=current_user.id,
        action="export",
        query_params=query.model_dump(),
    )

    export_data = audit_service.export_events(
        event_type=query.event_type,
        actor_type=query.actor_type,
        actor_id=query.actor_id,
        from_timestamp=query.from_timestamp,
        to_timestamp=query.to_timestamp,
        format=query.format,
    )

    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"audit_export_{timestamp}.{query.format}"

    media_type = {
        "jsonl": "application/x-jsonlines",
        "json": "application/json",
        "csv": "text/csv",
    }.get(query.format, "application/octet-stream")

    return Response(
        content=export_data,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/events/stats", response_model=AuditStatsResponse)
def get_audit_stats(
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_view_permission),
):
    """Get audit event statistics."""
    from sqlalchemy import func
    from app.models.audit import AuditEvent

    db = audit_service.db

    # Total events
    total = db.query(func.count(AuditEvent.event_id)).scalar() or 0

    # Events by type
    events_by_type = dict(
        db.query(AuditEvent.event_type, func.count())
        .group_by(AuditEvent.event_type)
        .all()
    )

    # Events by severity
    events_by_severity = dict(
        db.query(AuditEvent.severity, func.count())
        .group_by(AuditEvent.severity)
        .all()
    )

    # Events by result
    events_by_result = dict(
        db.query(AuditEvent.result, func.count())
        .group_by(AuditEvent.result)
        .all()
    )

    # Events last 24h
    from datetime import timedelta
    day_ago = datetime.now() - timedelta(days=1)
    events_last_24h = db.query(func.count(AuditEvent.event_id)).filter(AuditEvent.timestamp >= day_ago).scalar() or 0

    # Events last 7d
    week_ago = datetime.now() - timedelta(days=7)
    events_last_7d = db.query(func.count(AuditEvent.event_id)).filter(AuditEvent.timestamp >= week_ago).scalar() or 0

    # Oldest/newest
    oldest = db.query(func.min(AuditEvent.timestamp)).scalar()
    newest = db.query(func.max(AuditEvent.timestamp)).scalar()

    return AuditStatsResponse(
        total_events=total,
        events_by_type={str(k): v for k, v in events_by_type.items()},
        events_by_severity={str(k): v for k, v in events_by_severity.items()},
        events_by_result={str(k): v for k, v in events_by_result.items()},
        events_last_24h=events_last_24h,
        events_last_7d=events_last_7d,
        oldest_event=oldest,
        newest_event=newest,
    )


# ── Integrity Verification ──────────────────────────────────────────────────

@router.get("/events/verify", response_model=AuditIntegrityCheckResponse)
def verify_audit_integrity(
    from_timestamp: Optional[datetime] = Query(None, description="Start time for verification"),
    to_timestamp: Optional[datetime] = Query(None, description="End time for verification"),
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_admin_permission),
):
    """Verify integrity of audit events via HMAC signatures (admin only)."""
    verified, failed = audit_service.verify_all_events(from_timestamp, to_timestamp)

    return AuditIntegrityCheckResponse(
        verified_count=verified,
        failed_count=failed,
        total_checked=verified + failed,
        check_timestamp=datetime.now(),
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
    )


# ── Archive Management ──────────────────────────────────────────────────────

@router.post("/archives", response_model=AuditArchiveResponse, status_code=status.HTTP_201_CREATED)
def create_audit_archive(
    archive: AuditArchiveCreate,
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_admin_permission),
):
    """Create a new audit archive (admin only)."""
    created = audit_service.create_archive(
        period_start=archive.period_start,
        period_end=archive.period_end,
        storage_type=archive.storage_type,
        file_path=archive.file_path,
    )

    # Log access
    audit_service.log_access(
        user_id=current_user.id,
        action="create_archive",
        query_params=archive.model_dump(),
    )

    return AuditArchiveResponse.model_validate(created)


@router.get("/archives", response_model=list[AuditArchiveResponse])
def list_audit_archives(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_view_permission),
):
    """List audit archives."""
    archives = audit_service.list_archives(status=status, limit=limit, offset=offset)
    return [AuditArchiveResponse.model_validate(a) for a in archives]


@router.get("/archives/{archive_id}", response_model=AuditArchiveResponse)
def get_audit_archive(
    archive_id: str,
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_view_permission),
):
    """Get an audit archive by ID."""
    archive = audit_service.get_archive(archive_id)
    if not archive:
        raise HTTPException(status_code=404, detail="Archive not found")
    return AuditArchiveResponse.model_validate(archive)


# ── Retention Policy Management ─────────────────────────────────────────────

@router.get("/retention-policies", response_model=list[AuditRetentionPolicyResponse])
def list_retention_policies(
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_view_permission),
):
    """List all retention policies."""
    policies = audit_service.list_retention_policies()
    return [AuditRetentionPolicyResponse.model_validate(p) for p in policies]


@router.post("/retention-policies", response_model=AuditRetentionPolicyResponse, status_code=status.HTTP_201_CREATED)
def create_retention_policy(
    policy: AuditRetentionPolicyCreate,
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_admin_permission),
):
    """Create or update a retention policy (admin only)."""
    created = audit_service.set_retention_policy(
        data_type=policy.data_type,
        retention_days=policy.retention_days,
        storage_location=policy.storage_location,
        enabled=policy.enabled,
    )

    # Log access
    audit_service.log_access(
        user_id=current_user.id,
        action="configure_retention",
        query_params=policy.model_dump(),
    )

    return AuditRetentionPolicyResponse.model_validate(created)


@router.put("/retention-policies/{data_type}", response_model=AuditRetentionPolicyResponse)
def update_retention_policy(
    data_type: str,
    policy: AuditRetentionPolicyCreate,
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_admin_permission),
):
    """Update a retention policy (admin only)."""
    if policy.data_type != data_type:
        raise HTTPException(status_code=400, detail="Data type mismatch")

    updated = audit_service.set_retention_policy(
        data_type=data_type,
        retention_days=policy.retention_days,
        storage_location=policy.storage_location,
        enabled=policy.enabled,
    )

    # Log access
    audit_service.log_access(
        user_id=current_user.id,
        action="update_retention",
        query_params=policy.model_dump(),
    )

    return AuditRetentionPolicyResponse.model_validate(updated)


# ── Access Logs (Meta-Auditing) ─────────────────────────────────────────────

@router.get("/access-logs", response_model=list[AuditAccessLogResponse])
def list_audit_access_logs(
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    from_timestamp: Optional[datetime] = Query(None, description="Start time"),
    to_timestamp: Optional[datetime] = Query(None, description="End time"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    audit_service: AuditService = Depends(_get_audit_service),
    current_user: User = Depends(_verify_audit_admin_permission),
):
    """List audit log access logs (admin only - who accessed audit logs)."""
    logs = audit_service.get_access_logs(
        user_id=user_id,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        limit=limit,
        offset=offset,
    )
    return [AuditAccessLogResponse.model_validate(log) for log in logs]


# ── Event Type Reference ────────────────────────────────────────────────────

@router.get("/event-types")
def list_event_types():
    """List all available audit event types with descriptions."""
    return {
        "authentication": [
            {"type": "AUTH_LOGIN_SUCCESS", "description": "Successful user login"},
            {"type": "AUTH_LOGIN_FAILURE", "description": "Failed login attempt"},
            {"type": "AUTH_MFA_ENROLL", "description": "MFA enrollment"},
            {"type": "AUTH_MFA_VERIFY", "description": "MFA verification"},
            {"type": "AUTH_TOKEN_ISSUED", "description": "API token issued"},
            {"type": "AUTH_TOKEN_REVOKED", "description": "API token revoked"},
            {"type": "AUTH_SERVICE_CREATED", "description": "Service account created"},
            {"type": "AUTH_SERVICE_TOKEN_ISSUED", "description": "Service token issued"},
        ],
        "authorization": [
            {"type": "AUTHZ_CHECK", "description": "Permission evaluation"},
            {"type": "AUTHZ_DENIED", "description": "Permission denied"},
            {"type": "AUTHZ_SCOPE_CHECK", "description": "Scope validation"},
            {"type": "AUTHZ_RESOURCE_RESTRICTION", "description": "Resource restriction check"},
        ],
        "operations": [
            {"type": "OP_ACCOUNT_CREATED", "description": "Account created"},
            {"type": "OP_ACCOUNT_UPDATED", "description": "Account updated"},
            {"type": "OP_ACCOUNT_DELETED", "description": "Account deleted"},
            {"type": "OP_ACCOUNT_SHARED", "description": "Account shared"},
            {"type": "OP_CREDENTIAL_RETRIEVED", "description": "Credential accessed"},
            {"type": "OP_CREDENTIAL_MODIFIED", "description": "Credential changed"},
            {"type": "OP_CREDENTIAL_EXPORTED", "description": "Credentials exported"},
            {"type": "OP_GROUP_CREATED", "description": "Group created"},
            {"type": "OP_GROUP_MEMBER_ADDED", "description": "Group member added"},
            {"type": "OP_GROUP_MEMBER_REMOVED", "description": "Group member removed"},
            {"type": "OP_PROFILE_MODIFIED", "description": "Profile updated"},
        ],
        "administrative": [
            {"type": "ADMIN_USER_CREATED", "description": "User created by admin"},
            {"type": "ADMIN_USER_DISABLED", "description": "User disabled by admin"},
            {"type": "ADMIN_USER_ENABLED", "description": "User enabled by admin"},
            {"type": "ADMIN_ADMIN_CREATED", "description": "Admin user created"},
            {"type": "ADMIN_TOKEN_CREATED", "description": "Admin token created"},
            {"type": "ADMIN_CONFIG_CHANGED", "description": "Configuration changed"},
            {"type": "ADMIN_BACKUP_CREATED", "description": "Backup created"},
            {"type": "ADMIN_MASTER_PASSWORD_ROTATED", "description": "Master password rotated"},
        ],
        "system": [
            {"type": "SYSTEM_ERROR", "description": "Application error"},
            {"type": "SYSTEM_CONFIG_CHANGED", "description": "System configuration changed"},
            {"type": "SYSTEM_SERVICE_STARTED", "description": "Service started"},
            {"type": "SYSTEM_SERVICE_STOPPED", "description": "Service stopped"},
            {"type": "SYSTEM_MAINTENANCE_MODE", "description": "Maintenance mode toggled"},
            {"type": "SYSTEM_BACKUP_COMPLETED", "description": "Backup completed successfully"},
            {"type": "SYSTEM_BACKUP_FAILED", "description": "Backup failed"},
        ],
    }