"""Session model for database-backed session storage.

This module defines the SQLAlchemy Session model and provides a service
for database-backed session management. It is designed to work with both
MySQL and PostgreSQL, and can fall back to file-based storage for single-
instance development.
"""
from __future__ import annotations

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    Boolean,
    func,
)
from sqlalchemy.orm import declarative_base

from app.db.base import Base

# The Session model inherits from app.db.base.Base which is the project's
# declarative_base(). It is registered as a Python extension table per ADR-0002.

__all__ = ["Session", "SessionService"]


class Session(Base):
    """Database-backed session store.

    This table stores authoritative session state that is shared across
    all workers/replicas. It replaces the file-based ``data/sessions.json``
    store for production deployments.

    Columns (per ADR-0009 §5):
        id: Primary key
        session_id: Unique identifier for the session (indexed)
        user_id: Foreign key reference to the user
        authenticated_until: Timestamp until which the session is authenticated
        vault_until: Timestamp until which the vault context is valid
        revoked: Whether the session has been revoked
        revoked_until: Timestamp until which the revocation is effective
        ip_address: Client IP address (indexed for revocation lookups)
        user_agent: Client user agent string
        created_at: Timestamp when the session was created
    """
    __tablename__ = "session"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(128), unique=True, nullable=False, index=True)
    user_id = Column(Integer, nullable=False)
    authenticated_until = Column(DateTime(timezone=True), nullable=True)
    vault_until = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, default=False, nullable=False)
    revoked_until = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(45), nullable=True, index=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationship to User (optional, for convenience)
    # user = Relationship("User", foreign_keys=[user_id])
