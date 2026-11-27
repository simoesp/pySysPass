"""Service accounts and service tokens per ADR-0010 §1/§2/§13 (IMPL-014).

A service account is a distinct non-interactive identity (never a User row —
ADR-0002 keeps Python extensions out of PHP tables). Provisioning it:

1. validates scopes, resource restrictions and per-service lifetime policy,
2. resolves the owner's current master password (the vault unlock material
   the service context seals), failing closed when it cannot,
3. creates a cryptographically random 64-hex service token — disclosed once,
   stored only as a bcrypt hash (PHP Hash::hashKey() semantics, $2y$),
4. provisions a per-service DEK (Data Encryption Key) wrapped by the master key,
5. provisions the encrypted service vault context, and
6. writes the mandatory ``AUTH_SERVICE_CREATED`` audit event (ADR-0011).

Storage: the extension tables in ``app.models.service_account``.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import timedelta
from typing import Optional

import bcrypt as bcrypt_lib
from sqlalchemy.orm import Session

from app.core.service_vault_crypto import (
    SERVICE_VAULT_CONTEXT_VERSION,
    ServiceVaultKeyError,
    resolve_service_vault_key,
)
from app.core.service_vault_keyring import (
    ServiceVaultKeyMissing,
    provision_service_dek,
)
from app.models.account import User
from app.models.service_account import (
    AuthTokenMetadata,
    ServiceAccount,
    ServiceVaultContext,
)
from app.services.service_vault_context_service import (
    DEFAULT_CONTEXT_LIFETIME_HOURS,
    DEFAULT_INACTIVITY_TIMEOUT_HOURS,
    DEFAULT_TOKEN_EXPIRES_DAYS,
    VALID_SCOPES,
    ServiceAccountError,
    ServiceVaultContextService,
    new_service_id,
    _utc_now_naive,
)


def hash_service_token(token: str) -> str:
    """PHP Hash::hashKey() semantics, like API tokens: bcrypt with $2y$ tag."""
    hashed = bcrypt_lib.hashpw(token.encode("utf-8"), bcrypt_lib.gensalt(rounds=10))
    return hashed.replace(b"$2b$", b"$2y$").decode()


def verify_service_token(token: str, hashed: Optional[str]) -> bool:
    if not token or not hashed:
        return False
    data = hashed.encode() if isinstance(hashed, str) else hashed
    if data.startswith(b"$2y$"):
        data = b"$2b$" + data[4:]
    try:
        return bcrypt_lib.checkpw(token.encode("utf-8"), data)
    except ValueError:
        return False


class ServiceAccountService:
    def __init__(self, db: Session):
        self.db = db

    # ---- provisioning -----------------------------------------------------

    def create_service_account(
        self,
        service_name: str,
        owner_id: int,
        purpose: str = "",
        scopes: Optional[list] = None,
        resource_restrictions: Optional[dict] = None,
        context_lifetime_hours: float = DEFAULT_CONTEXT_LIFETIME_HOURS,
        inactivity_timeout_hours: float = DEFAULT_INACTIVITY_TIMEOUT_HOURS,
        token_expires_days: float = DEFAULT_TOKEN_EXPIRES_DAYS,
        token_expires_hours: Optional[float] = None,
        login_password: Optional[str] = None,
        master_password: Optional[str] = None,
    ) -> dict:
        """Provision a service identity, token and encrypted vault context."""
        scopes = [s.value if hasattr(s, "value") else str(s) for s in (scopes or ["read"])]
        unknown = [s for s in scopes if s not in VALID_SCOPES]
        if unknown:
            raise ServiceAccountError(f"unknown service scopes: {', '.join(unknown)}")
        if not service_name or not str(service_name).strip():
            raise ServiceAccountError("service_name is required")
        for name, value in (("context_lifetime_hours", context_lifetime_hours),
                            ("inactivity_timeout_hours", inactivity_timeout_hours)):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                raise ServiceAccountError(f"{name} must be greater than zero")
        if token_expires_hours is not None and (
            not isinstance(token_expires_hours, (int, float)) or token_expires_hours <= 0
        ):
            raise ServiceAccountError("token_expires_hours must be greater than zero")
        owner = self.db.get(User, owner_id)
        if owner is None:
            raise ServiceAccountError(f"owner user {owner_id} does not exist")
        if self.db.query(ServiceAccount).filter_by(service_name=service_name).first():
            raise ServiceAccountError(f"a service account named '{service_name}' already exists")

        # Fail-secure on SERVICE_VAULT_KEY configuration (ADR-0010 §3).
        # Verify the keyring/master key is available.
        try:
            key_material = resolve_service_vault_key()
        except ServiceVaultKeyError:
            raise

        master = master_password or self._resolve_master(owner, login_password)
        bootstrap_source = None
        if master_password and master == master_password:
            # An explicitly presented master (CLI/bootstrap flows, same
            # one-time disclosure trust as the service token secret) must
            # verify against the deployment master hash — fail closed.
            from app.services.auth_service import master_pass_matches_config

            if not master_pass_matches_config(self.db, master_password):
                raise ServiceAccountError(
                    "the presented master password does not match the deployment master"
                )
            from app.core.service_vault_key import master_key_provider

            if master_key_provider.resolve(self.db, user=owner) is None:
                # No live login fingerprint and no deployment artifact: the
                # master was carried by hand, so the event is operator-scoped.
                bootstrap_source = "operator_bootstrap"
        if master is None and login_password:
            # Operator bootstrap path: an authenticated principal that carries
            # the master password directly (CLI/bootstrap flows, same
            # one-time disclosure trust as the service token secret).
            from app.services.auth_service import master_pass_matches_config

            if master_pass_matches_config(self.db, login_password):
                master = login_password
                bootstrap_source = "operator_bootstrap"
        if master is None:
            raise ServiceAccountError(
                "cannot resolve the owner's master password for the service vault context; "
                "sign in first, pass login_password/master_password, or bootstrap the "
                "deployment unlock artifact "
                "(scripts/generate_service_vault_master.py)"
            )

        now = _utc_now_naive()
        service_id = new_service_id()
        token = secrets.token_hex(32)  # 64-char hex secret, one-time disclosure
        expires_hours = token_expires_hours if token_expires_hours else token_expires_days * 24

        account = ServiceAccount(
            service_id=service_id,
            service_name=service_name,
            owner_id=owner_id,
            purpose=purpose or "",
            scopes=json.dumps(scopes),
            resource_restrictions=json.dumps(resource_restrictions) if resource_restrictions else None,
            enabled=True,
            context_lifetime_hours=float(context_lifetime_hours),
            inactivity_timeout_hours=float(inactivity_timeout_hours),
            token_expires_hours=float(expires_hours),
            created_at=now,
            updated_at=now,
            last_used_at=now,
        )
        token_meta = AuthTokenMetadata(
            service_id=service_id,
            token_hash=hash_service_token(token),
            owner_id=owner_id,
            scopes=json.dumps(scopes),
            resource_restrictions=json.dumps(resource_restrictions) if resource_restrictions else None,
            created_at=now,
            expires_at=now + timedelta(hours=expires_hours),
            last_used_at=now,
            revoked=False,
        )
        self.db.add(account)
        self.db.add(token_meta)
        self.db.flush()

        # Provision a per-service DEK (IMPL-014: service-specific key
        # hierarchy) only when the operator opted into the keyring. With no
        # explicit keyring the env/settings SERVICE_VAULT_KEY seals contexts
        # flat (ADR-0010 §3/§5/§12, IMPL-010 acceptance ruling); provisioning
        # a DEK here would fail closed on keyring-less deployments and —
        # worse — lazily create deployment key state as a test side effect.
        from app.core.service_vault_crypto import _keyring_active

        if _keyring_active():
            try:
                provision_service_dek(service_id)
            except ServiceVaultKeyMissing:
                raise ServiceAccountError(
                    "cannot provision service DEK: service vault keyring not initialized"
                )

        # The service_key in the vault context is now the DEK (derived via the key hierarchy)
        # We still compute a service_key for backward compatibility with existing contexts
        service_key = hashlib.sha256(
            b"svk|" + key_material + service_id.encode("utf-8")
        ).hexdigest()
        ServiceVaultContextService(self.db).provision_context(
            service_id,
            master_password=master,
            service_key=service_key,
            lifetime_hours=context_lifetime_hours,
            inactivity_timeout_hours=inactivity_timeout_hours,
            commit=False,
        )
        self.db.commit()

        self._audit_created(service_id, service_name, owner, scopes, bootstrap_source)

        return {
            "service_id": service_id,
            "service_name": service_name,
            "service_token": token,
            "owner_id": owner_id,
            "purpose": purpose,
            "scopes": scopes,
            "resource_restrictions": resource_restrictions,
            "enabled": True,
            "created_at": now,
            "context_lifetime_hours": context_lifetime_hours,
            "inactivity_timeout_hours": inactivity_timeout_hours,
            "vault_context_version": SERVICE_VAULT_CONTEXT_VERSION,
        }

    def _resolve_master(self, owner: User, login_password: Optional[str]) -> Optional[str]:
        """Resolution order: request-carried login password (verified), then
        the unlock artifact / login-fingerprint provider (fail-closed)."""
        if login_password:
            from app.services.auth_service import (
                decrypt_user_master_pass,
                master_pass_matches_config,
                verify_password,
            )

            stored = owner.password
            stored_text = stored.decode("utf-8", "replace") if isinstance(stored, bytes) else (stored or "")
            try:
                if verify_password(login_password, stored_text):
                    candidate = decrypt_user_master_pass(owner, login_password)
                    if candidate and master_pass_matches_config(self.db, candidate):
                        return candidate
            except Exception:
                pass
        from app.core.service_vault_key import master_key_provider

        return master_key_provider.resolve(self.db, user=owner)

    def _audit_created(self, service_id, service_name, owner, scopes,
                       bootstrap_source: Optional[str] = None) -> None:
        from app.models.audit import AuditEventType, AuditResult, AuditSeverity
        from app.services.audit_service import AuditService

        actor_type = "service" if bootstrap_source == "operator_bootstrap" else "user"
        metadata = {"scopes": scopes}
        error_message = None
        if bootstrap_source:
            metadata["operator_bootstrap"] = True
            error_message = "operator_bootstrap=true"  # the master copy itself is never logged
        try:
            AuditService(self.db).log_event(
                event_type=AuditEventType.AUTH_SERVICE_CREATED,
                severity=AuditSeverity.INFO,
                actor_type=actor_type,
                actor_id=None if bootstrap_source else owner.id,
                actor_username="service-vault-operator" if bootstrap_source else owner.username,
                result=AuditResult.SUCCESS.value,
                resource_type="token",
                resource_name=service_name,
                operation_action="write",
                service_id=service_id,
                error_message=error_message,
                metadata=metadata,
            )
        except Exception:  # pragma: no cover - audit must not break provisioning
            from app.core.operations import record_failure

            record_failure("audit_service_created")

    # ---- token lifecycle ----------------------------------------------------

    def verify_token(self, service_id: str, token: str) -> bool:
        meta = self.db.query(AuthTokenMetadata).filter_by(service_id=service_id).first()
        if meta is None or meta.revoked:
            return False
        if meta.expires_at is not None and _utc_now_naive() >= meta.expires_at:
            return False
        account = self.db.query(ServiceAccount).filter_by(service_id=service_id).first()
        if account is None or not account.enabled:
            return False
        return verify_service_token(token, meta.token_hash)

    def revoke_token(self, service_id: str, revoked_by: Optional[int] = None,
                     reason: Optional[str] = None) -> bool:
        meta = self.db.query(AuthTokenMetadata).filter_by(service_id=service_id).first()
        if meta is None:
            return False
        meta.revoked = True
        meta.revoked_at = _utc_now_naive()
        meta.revoke_reason = reason
        self.db.commit()
        ServiceVaultContextService(self.db).revoke_context(
            service_id, revoker_id=revoked_by, reason=reason or "token_revoked"
        )
        return True

    def disable_service(self, service_id: str) -> bool:
        account = self.db.query(ServiceAccount).filter_by(service_id=service_id).first()
        if account is None:
            return False
        account.enabled = False
        account.updated_at = _utc_now_naive()
        self.db.commit()
        return True

    def get_service(self, service_id: str) -> Optional[ServiceAccount]:
        return self.db.query(ServiceAccount).filter_by(service_id=service_id).first()

    def list_services(self) -> list[ServiceAccount]:
        return self.db.query(ServiceAccount).all()


__all__ = [
    "ServiceAccountService",
    "ServiceAccountError",
    "hash_service_token",
    "verify_service_token",
]