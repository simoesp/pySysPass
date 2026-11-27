"""Audit logging schemas per ADR-0011.

Pydantic models for audit event requests, responses, and query parameters.
"""
import json
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from app.models.audit import (
    AuditEventType,
    AuditSeverity,
    AuditActorType,
    AuditTokenType,
    AuditResourceType,
    AuditOperationAction,
    AuditResult,
)


class AuditEventBase(BaseModel):
    """Base audit event fields."""

    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="Event timestamp (ISO8601)")
    event_type: str = Field(..., description="Event type from AuditEventType enum")
    severity: str = Field(..., description="Event severity: info, warn, error")

    # Actor identification
    actor_type: str = Field(..., description="Actor type: user, service, admin, unknown")
    actor_id: Optional[int] = Field(None, description="Actor user/service ID")
    actor_username: Optional[str] = Field(None, description="Actor username")
    token_type: Optional[str] = Field(None, description="Token type: jwt, service, api, unknown")

    # Resource identification
    resource_type: Optional[str] = Field(None, description="Resource type: account, user, group, config, token")
    resource_id: Optional[int] = Field(None, description="Resource ID")
    resource_name: Optional[str] = Field(None, description="Resource name")

    # Operation details
    operation_action: Optional[str] = Field(None, description="Operation: read, write, delete, export, admin")
    operation_scope: Optional[list[str]] = Field(None, description="Scope array")
    operation_params: Optional[dict[str, Any]] = Field(None, description="Operation parameters")

    # Result
    result: str = Field(..., description="Result: success, denied, error")
    error_message: Optional[str] = Field(None, description="Error message if failed")

    # Context
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="Client user agent")
    session_id: Optional[str] = Field(None, description="Session ID")
    service_id: Optional[str] = Field(None, description="Service account ID")
    request_id: str = Field(..., description="Request ID for traceability")
    event_metadata: Optional[dict[str, Any]] = Field(None, description="Additional metadata")

    # Integrity
    signature: Optional[str] = Field(None, description="HMAC signature for tamper detection")


class AuditEventResponse(AuditEventBase):
    """Audit event response model."""

    model_config = {"from_attributes": True}


class AuditEventCreate(BaseModel):
    """Request model for creating an audit event (internal use)."""

    event_type: AuditEventType = Field(..., description="Event type")
    severity: AuditSeverity = Field(..., description="Event severity")
    actor_type: AuditActorType = Field(..., description="Actor type")
    actor_id: Optional[int] = None
    actor_username: Optional[str] = None
    token_type: Optional[AuditTokenType] = None
    resource_type: Optional[AuditResourceType] = None
    resource_id: Optional[int] = None
    resource_name: Optional[str] = None
    operation_action: Optional[AuditOperationAction] = None
    operation_scope: Optional[list[str]] = None
    operation_params: Optional[dict[str, Any]] = None
    result: AuditResult = Field(..., description="Event result")
    error_message: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    service_id: Optional[str] = None
    request_id: Optional[str] = None
    event_metadata: Optional[dict[str, Any]] = None


class AuditEventQuery(BaseModel):
    """Query parameters for audit event search."""

    event_type: Optional[str] = Field(None, description="Filter by event type")
    actor_type: Optional[str] = Field(None, description="Filter by actor type")
    actor_id: Optional[int] = Field(None, description="Filter by actor ID")
    actor_username: Optional[str] = Field(None, description="Filter by actor username")
    resource_type: Optional[str] = Field(None, description="Filter by resource type")
    resource_id: Optional[int] = Field(None, description="Filter by resource ID")
    operation_action: Optional[str] = Field(None, description="Filter by operation action")
    ip_address: Optional[str] = Field(None, description="Filter by IP address")
    from_timestamp: Optional[datetime] = Field(None, description="Start time (ISO8601)")
    to_timestamp: Optional[datetime] = Field(None, description="End time (ISO8601)")
    severity: Optional[str] = Field(None, description="Filter by severity")
    result: Optional[str] = Field(None, description="Filter by result")
    session_id: Optional[str] = Field(None, description="Filter by session ID")
    request_id: Optional[str] = Field(None, description="Filter by request ID")
    limit: int = Field(100, ge=1, le=1000, description="Max results")
    offset: int = Field(0, ge=0, description="Pagination offset")
    sort: str = Field("timestamp", description="Sort field")
    order: str = Field("DESC", description="Sort order: ASC or DESC")

    @field_validator("order")
    @classmethod
    def validate_order(cls, v: str) -> str:
        if v.upper() not in ("ASC", "DESC"):
            raise ValueError("Order must be ASC or DESC")
        return v.upper()

    @field_validator("sort")
    @classmethod
    def validate_sort(cls, v: str) -> str:
        allowed = [
            "timestamp", "event_type", "actor_id", "actor_username",
            "resource_type", "resource_id", "operation_action",
            "result", "severity", "ip_address", "session_id", "request_id"
        ]
        if v not in allowed:
            raise ValueError(f"Sort must be one of: {', '.join(allowed)}")
        return v


class AuditEventExportQuery(AuditEventQuery):
    """Query parameters for audit event export."""

    format: str = Field("jsonl", description="Export format: jsonl, csv, json")
    export_all: bool = Field(False, description="Export all fields including event_metadata")

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        if v not in ("jsonl", "csv", "json"):
            raise ValueError("Format must be jsonl, csv, or json")
        return v


class AuditEventListResponse(BaseModel):
    """Paginated audit event list response."""

    events: list[AuditEventResponse]
    total: int
    limit: int
    offset: int


class AuditArchiveResponse(BaseModel):
    """Audit archive response model."""

    id: int
    archive_id: str
    period_start: datetime
    period_end: datetime
    event_count: int
    file_path: Optional[str]
    file_size: Optional[int]
    checksum: Optional[str]
    status: str
    storage_type: str
    created_at: datetime
    verified_at: Optional[datetime]

    model_config = {"from_attributes": True}


class AuditArchiveCreate(BaseModel):
    """Request model for creating an audit archive."""

    period_start: datetime = Field(..., description="Archive period start")
    period_end: datetime = Field(..., description="Archive period end")
    storage_type: str = Field("local", description="Storage type: local, s3, worm")
    file_path: Optional[str] = None


class AuditRetentionPolicyResponse(BaseModel):
    """Retention policy response model."""

    id: int
    data_type: str
    retention_days: int
    storage_location: Optional[str]
    enabled: bool
    created_at: datetime
    updated_at: Optional[datetime]

    model_config = {"from_attributes": True}


class AuditRetentionPolicyCreate(BaseModel):
    """Request model for creating/updating a retention policy."""

    data_type: str = Field(..., description="Data type: application_logs, database_events, immutable_archive, compliance_reports")
    retention_days: int = Field(..., ge=1, description="Retention period in days")
    storage_location: Optional[str] = None
    enabled: bool = True


class AuditAccessLogResponse(BaseModel):
    """Audit access log response model (meta-auditing)."""

    id: int
    timestamp: datetime
    user_id: int
    action: str
    accessed_event_id: Optional[str]
    query_params: Optional[dict[str, Any]]
    ip_address: Optional[str]
    user_agent: Optional[str]

    model_config = {"from_attributes": True}

    @field_validator("query_params", mode="before")
    @classmethod
    def parse_query_params(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        return v


class AuditIntegrityCheckResponse(BaseModel):
    """Integrity verification response."""

    verified_count: int
    failed_count: int
    total_checked: int
    check_timestamp: datetime
    from_timestamp: Optional[datetime] = None
    to_timestamp: Optional[datetime] = None


class AuditStatsResponse(BaseModel):
    """Audit statistics response."""

    total_events: int
    events_by_type: dict[str, int]
    events_by_severity: dict[str, int]
    events_by_result: dict[str, int]
    events_last_24h: int
    events_last_7d: int
    oldest_event: Optional[datetime]
    newest_event: Optional[datetime]