"""Service account / service vault context extension tables (ADR-0010, IMPL-010).

Python-only extension tables (ADR-0002 isolation: never PHP tables, excluded
from the PHP schema-parity gates via ``is_php_extension``), but they follow the
same ORM conventions so callers and tests can query them through the session:

    db_session.query(ServiceVaultContext).filter_by(service_id=...)
    db_session.query(AuthTokenMetadata).filter_by(service_id=...)

``AuthTokenMetadata`` holds the service token *metadata* (bcrypt hash, scopes,
expiry); the 64-hex token secret itself is disclosed once at creation and
never stored. ``ServiceVaultContext`` holds the sealed context blob — opaque
AES-256-GCM material encrypted under the environment ``SERVICE_VAULT_KEY``
(never stored here) — plus lifetime and revocation bookkeeping. A master
password rotation revokes contexts (they were sealed against the old master)
while the service token identity remains valid (ADR-0010 §5 independent
revocation).
"""
from datetime import UTC, datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import relationship

from app.db.base import Base, FlexibleBinary, mysql_integer


def _utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _ensure_account_aliases() -> None:
    """The QA harness imports these ORM classes from app.models.account."""
    import app.models.account as account_module

    for name, obj in (
        ("ServiceAccount", ServiceAccount),
        ("AuthTokenMetadata", AuthTokenMetadata),
        ("ServiceVaultContext", ServiceVaultContext),
    ):
        if not hasattr(account_module, name):
            setattr(account_module, name, obj)


class ServiceAccount(Base):
    """Service account identity per ADR-0010 §1 (distinct from User)."""

    __tablename__ = "service_accounts"
    __table_args__ = (
        UniqueConstraint("service_name", name="uk_service_accounts_name"),
        Index("idx_service_accounts_owner", "owner_id"),
        Index("idx_service_accounts_enabled", "enabled"),
        {"info": {"is_php_extension": True}},
    )

    id = Column(mysql_integer(unsigned=True), primary_key=True, autoincrement=True)
    service_id = Column(String(64), unique=True, nullable=False, index=True)
    service_name = Column(String(190), nullable=False)
    owner_id = Column(mysql_integer(unsigned=True),
                      ForeignKey("User.id", name="fk_service_accounts_owner"), nullable=False)
    purpose = Column(Text, nullable=True)
    scopes = Column(Text, nullable=True)  # JSON array
    resource_restrictions = Column(Text, nullable=True)  # JSON object
    enabled = Column(Boolean, default=True, server_default=text("1"), nullable=False)
    context_lifetime_hours = Column(Float, nullable=True)  # NULL -> ADR default
    inactivity_timeout_hours = Column(Float, nullable=True)
    token_expires_hours = Column(Float, nullable=True)
    created_at = Column(DateTime, default=_utc_now_naive, nullable=False)
    updated_at = Column(DateTime, default=_utc_now_naive, onupdate=_utc_now_naive, nullable=False)
    last_used_at = Column(DateTime, nullable=True)

    owner = relationship("User", foreign_keys=[owner_id])

    @property
    def scopes_list(self) -> list:
        import json

        return json.loads(self.scopes) if self.scopes else []

    @property
    def restrictions(self) -> dict:
        import json

        return json.loads(self.resource_restrictions) if self.resource_restrictions else {}


class AuthTokenMetadata(Base):
    """Service token metadata per ADR-0010 §2 (secret disclosed once only)."""

    __tablename__ = "service_auth_tokens"
    __table_args__ = (
        UniqueConstraint("service_id", name="uk_service_auth_tokens_service"),
        Index("idx_service_auth_tokens_expires", "expires_at"),
        Index("idx_service_auth_tokens_revoked", "revoked"),
        {"info": {"is_php_extension": True}},
    )

    id = Column(mysql_integer(unsigned=True), primary_key=True, autoincrement=True)
    service_id = Column(String(64), nullable=False)
    token_hash = Column(String(255), nullable=False)  # bcrypt of the 64-hex secret
    owner_id = Column(mysql_integer(unsigned=True),
                      ForeignKey("User.id", name="fk_service_auth_tokens_owner"), nullable=True)
    scopes = Column(Text, nullable=True)  # JSON array
    resource_restrictions = Column(Text, nullable=True)  # JSON object
    created_at = Column(DateTime, default=_utc_now_naive, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False, server_default=text("0"), nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoke_reason = Column(String(190), nullable=True)

    owner = relationship("User", foreign_keys=[owner_id])


class ServiceVaultContext(Base):
    """Sealed service vault context per ADR-0010 §3/§5.

    ``encrypted_context`` is opaque at-rest: it can only be opened with the
    environment ``SERVICE_VAULT_KEY``, which is never stored here.
    """

    __tablename__ = "service_vault_contexts"
    __table_args__ = (
        UniqueConstraint("service_id", name="uk_service_vault_contexts_service"),
        Index("idx_service_vault_contexts_expires", "expires_at"),
        Index("idx_service_vault_contexts_revoked", "revoked"),
        {"info": {"is_php_extension": True}},
    )

    id = Column(mysql_integer(unsigned=True), primary_key=True, autoincrement=True)
    context_id = Column(String(64), unique=True, nullable=False)
    service_id = Column(String(64), nullable=False)
    encrypted_context = Column(
        FlexibleBinary(4096, mysql_type=mysql.BLOB(length=4096)), nullable=False
    )
    encrypted_with_key = Column(
        FlexibleBinary(64, mysql_type=mysql.VARBINARY(64)), nullable=False
    )
    created_at = Column(DateTime, default=_utc_now_naive, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False, server_default=text("0"), nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoke_reason = Column(String(190), nullable=True)
    sealed_epoch = Column(mysql_integer(), nullable=False, server_default=text("0"))

    @property
    def inactivity_timeout_hours(self) -> float:
        from app.services.service_vault_context_service import DEFAULT_INACTIVITY_TIMEOUT_HOURS

        payload = _context_payload(self)
        if payload is None:
            return DEFAULT_INACTIVITY_TIMEOUT_HOURS
        return float(payload.get("inactivity_timeout_hours", DEFAULT_INACTIVITY_TIMEOUT_HOURS))


def _context_payload(context: ServiceVaultContext) -> Optional[dict]:
    """Best-effort decrypt of a context row's payload (None when unopenable)."""
    from app.core.service_vault_crypto import decrypt_service_vault_context, resolve_service_vault_key

    try:
        master = resolve_service_vault_key()
        return decrypt_service_vault_context(
            bytes(context.encrypted_context),
            bytes(context.encrypted_with_key),
            key=master.decode("latin-1"),
        )
    except Exception:
        return None


__all__ = ["ServiceAccount", "AuthTokenMetadata", "ServiceVaultContext"]

_ensure_account_aliases()
