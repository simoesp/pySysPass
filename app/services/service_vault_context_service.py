"""Service accounts, service tokens and service vault contexts (ADR-0010).

DB-backed via the extension tables in ``app.models.service_account`` (see that
module for the storage model). This module owns:

* ``ServiceVaultContextService`` — the context lifecycle surface: provision,
  ``get_valid_context`` (fail-secure validation + renewal that never extends
  the absolute lifetime), ``revoke_context``, and the master-password
  rotation hook that revokes all contexts while leaving token identities
  valid (ADR-0010 §5 independent revocation).
* Shared helpers used by ``app.services.service_account_service``.

Master-password resolution for sealing new contexts lives in
``app.core.service_vault_key`` (unlock artifact + login fingerprints).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.core.service_vault_crypto import (
    SERVICE_VAULT_KEY_INFO,
    SERVICE_VAULT_CONTEXT_VERSION,
    ServiceVaultDecryptError,
    ServiceVaultKeyError,
    _normalize_key_material,
    decrypt_service_vault_context,
    encrypt_service_vault_context,
    resolve_service_vault_key,
)
from app.core.service_vault_keyring import (
    ServiceVaultKeyMissing,
    delete_service_dek,
)
from app.models.service_account import (
    AuthTokenMetadata,
    ServiceAccount,
    ServiceVaultContext,
)

DEFAULT_CONTEXT_LIFETIME_HOURS = 8  # ADR-0010 §5 absolute lifetime
DEFAULT_INACTIVITY_TIMEOUT_HOURS = 4  # ADR-0010 §5 inactivity timeout
DEFAULT_TOKEN_EXPIRES_DAYS = 90  # ADR-0010 §2 configurable expiration

VALID_SCOPES = frozenset({"read", "write", "export", "admin"})

# Master-password rotation epoch (Config key): bumped by the rotation hook so
# sealed contexts — opaque at-rest — are recognized as stale on next use.
_EPOCH_KEY = "service_vault_epoch"


def _utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def new_service_id() -> str:
    return secrets.token_hex(16)


class ServiceVaultError(RuntimeError):
    """Base class for fail-secure service vault rejections."""


class ServiceVaultContextExpired(ServiceVaultError):
    """Absolute lifetime or inactivity timeout elapsed."""


class ServiceVaultContextRevoked(ServiceVaultError):
    """Context explicitly revoked or invalidated by a master rotation."""


class ServiceIdentityDisabled(ServiceVaultError):
    """The service account/identity is disabled or its token revoked."""


class ServiceAccountError(RuntimeError):
    """Invalid service account provisioning request."""


# The QA harness imports these ORM classes from app.models.account.
def _ensure_account_aliases() -> None:
    import app.models.account as account_module

    for name, obj in (
        ("ServiceAccount", ServiceAccount),
        ("AuthTokenMetadata", AuthTokenMetadata),
        ("ServiceVaultContext", ServiceVaultContext),
    ):
        if not hasattr(account_module, name):
            setattr(account_module, name, obj)


_ensure_account_aliases()


def _epoch(db: Session) -> int:
    from app.models.account import Config

    row = db.query(Config).filter(Config.parameter == _EPOCH_KEY).first()
    try:
        return int(row.value) if row and row.value else 0
    except (TypeError, ValueError):
        return 0


def _bump_epoch(db: Session) -> int:
    from app.models.account import Config

    value = _epoch(db) + 1
    row = db.query(Config).filter(Config.parameter == _EPOCH_KEY).first()
    if row is None:
        db.add(Config(parameter=_EPOCH_KEY, value=str(value)))
    else:
        row.value = str(value)
    db.commit()
    return value


class ServiceVaultContextService:
    """Create, validate, renew and revoke service vault contexts (ADR-0010 §5)."""

    def __init__(self, db: Session):
        self.db = db

    # ---- provisioning ------------------------------------------------------

    def provision_context(self, service_id: str, *, master_password: str,
                          service_key: Optional[str] = None,
                          lifetime_hours: float = DEFAULT_CONTEXT_LIFETIME_HOURS,
                          inactivity_timeout_hours: float = DEFAULT_INACTIVITY_TIMEOUT_HOURS,
                          key: Optional[str] = None,
                          commit: bool = True) -> ServiceVaultContext:
        """Seal a fresh encrypted context for ``service_id`` and persist it."""
        payload = {
            "service_id": service_id,
            "master_password": master_password,
            "service_key": service_key or secrets.token_hex(32),
            "vault_context_version": SERVICE_VAULT_CONTEXT_VERSION,
            "inactivity_timeout_hours": float(inactivity_timeout_hours),
            "sealed_epoch": _epoch(self.db),
        }
        blob = encrypt_service_vault_context(payload, service_id, key=key)
        now = _utc_now_naive()
        context = ServiceVaultContext(
            context_id=secrets.token_hex(16),
            service_id=service_id,
            encrypted_context=blob,
            encrypted_with_key=SERVICE_VAULT_KEY_INFO,
            created_at=now,
            expires_at=now + timedelta(hours=float(lifetime_hours)),
            last_used_at=now,
            revoked=False,
            sealed_epoch=payload["sealed_epoch"],
        )
        self.db.add(context)
        if commit:
            self.db.commit()
        else:
            self.db.flush()
        self.db.refresh(context)
        return context

    def rotate_master_password(self, old_master: str = "", new_master: str = "",
                               owner_id: Optional[int] = None) -> int:
        """Master-password rotation hook (called by MasterPasswordRotation).

        Sealed contexts are opaque at-rest, so every active context is revoked
        (``revoke_reason='master_password_rotated'``) and the rotation epoch is
        bumped; the next validated request re-provisions a context sealed
        against the new master. Service token identities are untouched —
        context revocation is independent of token revocation (ADR-0010 §5).

        Also rotates all service DEKs to ensure forward security: old contexts
        encrypted with previous DEKs become undecryptable.
        """
        _bump_epoch(self.db)
        # Collect service IDs before revoking
        service_ids = [
            ctx.service_id
            for ctx in self.db.query(ServiceVaultContext).filter_by(revoked=False).all()
        ]
        count = 0
        for context in self.db.query(ServiceVaultContext).filter_by(revoked=False).all():
            context.revoked = True
            context.revoked_at = _utc_now_naive()
            context.revoke_reason = "master_password_rotated"
            count += 1
            self._audit("AUTH_TOKEN_REVOKED", context.service_id,
                        reason="master_password_rotated", actor_id=owner_id)
        self.db.commit()
        from app.core.service_vault_key import master_key_provider

        master_key_provider.invalidate_all()
        # Rotate DEKs for all affected services to ensure forward security
        from app.core.service_vault_keyring import rotate_service_dek
        for service_id in service_ids:
            try:
                rotate_service_dek(service_id)
            except Exception:
                pass  # Best effort; DEK rotation failure shouldn't block master rotation
        return count

    # ---- validation / renewal ------------------------------------------------

    def get_valid_context(self, service_id: str, *, renew: bool = True) -> ServiceVaultContext:
        """Return a live context row for ``service_id`` or raise (fail-secure).

        Enforces, in order: identity exists and is enabled, token not revoked
        and not expired (expiry revokes the context with it), context not
        explicitly revoked, sealed under the current rotation epoch, absolute
        lifetime, inactivity timeout. A valid request renews the context —
        ``last_used_at`` only; the absolute lifetime is never extended. After
        a master-password rotation the stale context is revoked and a fresh one
        is provisioned and returned.
        """
        account = self.db.query(ServiceAccount).filter_by(service_id=service_id).first()
        if account is None:
            raise ServiceVaultError(f"unknown service '{service_id}'")
        token = self.db.query(AuthTokenMetadata).filter_by(service_id=service_id).first()
        if token is None or token.revoked or not account.enabled:
            raise ServiceIdentityDisabled(
                f"service identity '{account.service_name}' is disabled or revoked"
            )
        now = _utc_now_naive()
        if token.expires_at is not None and now >= token.expires_at:
            # Token expiration revokes the vault context with it (ADR-0010 §5).
            self._revoke_row(context_row=self._context_row(service_id),
                             reason="token_expired", audit_type="AUTH_TOKEN_REVOKED")
            raise ServiceVaultContextRevoked(
                f"service token for '{account.service_name}' has expired; context revoked"
            )

        context = self._context_row(service_id)
        if context is None:
            context = self._provision_current(service_id, account)
            self._audit("AUTH_SERVICE_TOKEN_ISSUED", service_id, reason="provisioned")
            return context

        if context.revoked:
            if context.revoke_reason == "master_password_rotated":
                context = self._provision_current(service_id, account)
                self._audit("AUTH_SERVICE_TOKEN_ISSUED", service_id,
                            reason="reprovisioned_after_master_rotation")
                return context
            raise ServiceVaultContextRevoked(
                f"service vault context for '{account.service_name}' is revoked"
            )

        try:
            payload = decrypt_service_vault_context(
                bytes(context.encrypted_context), bytes(context.encrypted_with_key)
            )
        except (ServiceVaultDecryptError, ServiceVaultKeyError):
            raise
        except Exception as exc:  # malformed blob -> fail closed
            raise ServiceVaultError(f"vault context unreadable: {exc}") from exc

        if int(context.sealed_epoch or 0) != _epoch(self.db):
            self._revoke_row(context_row=context, reason="master_password_rotated",
                             audit_type="AUTH_TOKEN_REVOKED")
            context = self._provision_current(service_id, account)
            self._audit("AUTH_SERVICE_TOKEN_ISSUED", service_id,
                        reason="reprovisioned_after_master_rotation")
            return context

        if context.expires_at is not None and now >= context.expires_at:
            raise ServiceVaultContextExpired(
                f"service vault context for '{account.service_name}' has expired "
                "(absolute lifetime)"
            )
        timeout_hours = float(payload.get("inactivity_timeout_hours",
                                          DEFAULT_INACTIVITY_TIMEOUT_HOURS))
        anchor = context.last_used_at or context.created_at
        if anchor is not None and now >= anchor + timedelta(hours=timeout_hours):
            raise ServiceVaultContextExpired(
                f"service vault context for '{account.service_name}' is inactive "
                f"(>{timeout_hours:g}h without use)"
            )

        if renew:
            context.last_used_at = now
            account.last_used_at = now
            token.last_used_at = now
            self.db.commit()
            self._audit("AUTH_SERVICE_TOKEN_ISSUED", service_id, reason="renewed")
        return context

    def _context_row(self, service_id: str) -> Optional[ServiceVaultContext]:
        return (self.db.query(ServiceVaultContext)
                .filter(ServiceVaultContext.service_id == service_id)
                .order_by(ServiceVaultContext.id.desc())
                .first())

    def _provision_current(self, service_id: str,
                           account: Optional[ServiceAccount] = None) -> ServiceVaultContext:
        if account is None:
            account = self.db.query(ServiceAccount).filter_by(service_id=service_id).first()
        if account is None:
            raise ServiceVaultError(f"unknown service '{service_id}'")
        from app.core.service_vault_key import master_key_provider
        from app.models.account import User

        owner = self.db.get(User, account.owner_id) if account.owner_id else None
        master = master_key_provider.resolve(self.db, user=owner)
        if master is None:
            raise ServiceVaultError(
                "cannot resolve the current master password to provision a "
                "service vault context (sign in or bootstrap the unlock artifact first)"
            )
        # Delete any existing contexts for this service before creating a new one
        self.db.query(ServiceVaultContext).filter_by(service_id=service_id).delete()
        self.db.flush()
        lifetime = float(account.context_lifetime_hours or DEFAULT_CONTEXT_LIFETIME_HOURS)
        inactivity = float(account.inactivity_timeout_hours or DEFAULT_INACTIVITY_TIMEOUT_HOURS)
        context = self.provision_context(
            service_id,
            master_password=master,
            lifetime_hours=lifetime,
            inactivity_timeout_hours=inactivity,
        )
        return context

    def _prune_stale(self, service_id: str, keep_context_id: str) -> None:
        """Keep exactly one un-revoked context row per service."""
        for row in self.db.query(ServiceVaultContext).filter_by(service_id=service_id).all():
            if row.context_id != keep_context_id:
                self.db.delete(row)
        self.db.commit()

    def revoke_context(self, service_id: str, *, revoker_id: Optional[int] = None,
                       reason: Optional[str] = None) -> bool:
        """Explicit (administrator-initiated) revocation of a service context.

        Independent of token revocation: the service identity keeps its token
        until revoked separately (ADR-0010 §5 independent revocation).
        """
        context = self._context_row(service_id)
        if context is None:
            return False
        was_active = not context.revoked
        context.revoked = True
        context.revoked_at = _utc_now_naive()
        context.revoke_reason = reason or "manual_revocation"
        self.db.commit()
        if was_active:
            self._audit("AUTH_TOKEN_REVOKED", service_id,
                        reason=context.revoke_reason, actor_id=revoker_id)
        return True

    def delete_service(self, service_id: str) -> bool:
        """Delete all vault context data for a service (including DEK from keyring).

        Called when a service account is permanently deleted. This removes
        the service's DEK from the keyring and revokes all context rows.
        """
        # Revoke all context rows
        for row in self.db.query(ServiceVaultContext).filter_by(service_id=service_id).all():
            if not row.revoked:
                row.revoked = True
                row.revoked_at = _utc_now_naive()
                row.revoke_reason = row.revoke_reason or "service_deleted"
        self.db.commit()

        # Delete the service DEK from the keyring
        try:
            delete_service_dek(service_id)
        except ServiceVaultKeyMissing:
            pass  # DEK already gone or keyring not initialized

        return True

    def _revoke_row(self, *, context_row: Optional[ServiceVaultContext], reason: str,
                    audit_type: str) -> None:
        if context_row is not None and not context_row.revoked:
            context_row.revoked = True
            context_row.revoked_at = _utc_now_naive()
            context_row.revoke_reason = reason
            self.db.commit()
            self._audit(audit_type, context_row.service_id, reason=reason)

    # ---- audit --------------------------------------------------------------

    def _audit(self, event_name: str, service_id: str, *, reason: Optional[str] = None,
               actor_id: Optional[int] = None) -> None:
        from app.models.audit import AuditEventType, AuditResult, AuditSeverity
        from app.services.audit_service import AuditService

        event_type = {
            "AUTH_SERVICE_TOKEN_ISSUED": AuditEventType.AUTH_SERVICE_TOKEN_ISSUED,
            "AUTH_TOKEN_REVOKED": AuditEventType.AUTH_TOKEN_REVOKED,
        }[event_name]
        actor_username = None
        if actor_id is not None:
            from app.models.account import User

            actor = self.db.get(User, actor_id)
            actor_username = actor.username if actor else None
        try:
            AuditService(self.db).log_event(
                event_type=event_type,
                severity=AuditSeverity.INFO,
                actor_type="service" if actor_id is None else "user",
                actor_id=actor_id,
                actor_username=actor_username,
                result=AuditResult.SUCCESS.value,
                resource_type="token",
                operation_action="write",
                service_id=service_id,
                error_message=reason,
                metadata={"reason": reason} if reason else None,
            )
        except Exception:  # pragma: no cover - audit must not break access
            from app.core.operations import record_failure

            record_failure("audit_service_vault")


__all__ = [
    "AuthTokenMetadata",
    "ServiceVaultContext",
    "ServiceAccount",
    "ServiceVaultContextService",
    "ServiceVaultError",
    "ServiceVaultContextExpired",
    "ServiceVaultContextRevoked",
    "ServiceIdentityDisabled",
    "ServiceAccountError",
    "DEFAULT_CONTEXT_LIFETIME_HOURS",
    "DEFAULT_INACTIVITY_TIMEOUT_HOURS",
    "DEFAULT_TOKEN_EXPIRES_DAYS",
    "VALID_SCOPES",
    "SERVICE_VAULT_KEY_INFO",
    "SERVICE_VAULT_CONTEXT_VERSION",
    "new_service_id",
]
