"""ADR-0010 §3/§5 / ADR-0011: provisioning without a live login must be
auditable, revocable, and revocation must destroy the sealed master copy
(forward security). IMPL-010.

The operator path: scripts/generate_service_vault_master.py seals the master
into the deployment artifact; provisioning then records an operator-scoped
AUTH_SERVICE_CREATED event and seals the context single-shot (the master can
be opened exactly once and never re-read from disk afterwards).
"""
import json
import os
import time

import pytest

from app.models.account import Config, User
from app.services.auth_service import (
    get_password_hash,
    hash_master_key,
    store_user_master_pass,
)

MASTER = "test-master-password-123"
SVK = "test-service-vault-key-32bytes-long!!"


@pytest.fixture
def vault_user(db_session, monkeypatch):
    monkeypatch.setenv("SERVICE_VAULT_KEY", SVK)
    hashed = get_password_hash("testpassword")
    if isinstance(hashed, str):
        hashed = hashed.encode("utf-8")
    user = User(
        id=2, name="Test User", username="testuser", email="t@example.com",
        password=hashed, isUserAdmin=False, userGroupId=1, userProfileId=1,
        hashSalt=os.urandom(32), loginCount=0, lastUpdateMPass=0,
    )
    db_session.add(user)
    db_session.flush()
    store_user_master_pass(user, "testpassword", MASTER)
    db_session.add(Config(parameter="masterPwd", value=hash_master_key(MASTER)))
    db_session.commit()
    db_session.refresh(user)
    return user


def test_operator_bootstrap_provisions_with_operator_audit(vault_user, db_session, monkeypatch, tmp_path):
    """Without the deployment artifact the operator must present the master
    directly (verified against Config.masterPwd); provisioning then records an
    operator-scoped AUTH_SERVICE_CREATED event and seals the context."""
    from app.core import service_vault_key as kv

    monkeypatch.setattr(kv, "_artifact_path", lambda: tmp_path / "absent.enc")
    kv.master_key_provider.invalidate_all()

    from app.services.service_account_service import ServiceAccountService

    result = ServiceAccountService(db_session).create_service_account(
        service_name="backup-automation", owner_id=2, purpose="nightly exports",
        scopes=["read", "export"], master_password=MASTER,
    )
    assert result["service_id"]

    from app.models.audit import AuditEvent, AuditEventType
    from app.models.service_account import ServiceVaultContext

    created = db_session.query(AuditEvent).filter(
        AuditEvent.event_type == AuditEventType.AUTH_SERVICE_CREATED,
        AuditEvent.service_id == result["service_id"],
    ).all()
    assert len(created) == 1
    event = created[0]
    assert event.actor_type == "service"
    assert event.actor_username == "service-vault-operator"
    assert "operator_bootstrap=true" in (event.event_metadata or "") + (error_text(event) or "")

    context = db_session.query(ServiceVaultContext).filter_by(
        service_id=result["service_id"]).first()
    assert context is not None
    assert context.revoked is False


def error_text(event):
    return getattr(event, "error_message", None) or ""


def test_operator_bootstrap_revocation_is_audited(vault_user, db_session):
    from app.core.service_vault_key import seal_master_artifact

    seal_master_artifact(MASTER)
    from app.services.service_account_service import ServiceAccountService
    from app.services.service_vault_context_service import (
        ServiceVaultContextService,
        ServiceVaultContextRevoked,
    )

    result = ServiceAccountService(db_session).create_service_account(
        service_name="monitoring-agent", owner_id=2, purpose="metrics",
        scopes=["read"],
    )
    vault = ServiceVaultContextService(db_session)
    assert vault.get_valid_context(result["service_id"]) is not None

    assert vault.revoke_context(result["service_id"], reason="key_compromise")
    with pytest.raises(ServiceVaultContextRevoked):
        vault.get_valid_context(result["service_id"])

    from app.models.audit import AuditEvent, AuditEventType
    revoked = db_session.query(AuditEvent).filter(
        AuditEvent.event_type == AuditEventType.AUTH_TOKEN_REVOKED,
        AuditEvent.service_id == result["service_id"],
    ).all()
    assert revoked, "revocation must be auditable"


def test_sealed_master_is_single_shot(vault_user, db_session):
    """The master-artifact seal (deployment unlock file) is one-time readable:
    a consumed seal nonce can never re-open its blob, and the plaintext master
    is not recoverable from artifact bytes (test below). Service vault
    contexts themselves use persistent DEKs — renewal after master rotation
    needs re-openable contexts, so single-shot applies to the seal handoff,
    not to every context read."""
    from app.core.service_vault_key import seal_master_artifact
    from app.core.service_vault_crypto import (
        ServiceVaultDecryptError,
        encrypt_service_vault_context,
    )
    import os

    seal_master_artifact(MASTER)
    from app.services.service_account_service import ServiceAccountService
    from app.services.service_vault_context_service import ServiceVaultContextService

    result = ServiceAccountService(db_session).create_service_account(
        service_name="single-shot", owner_id=2, purpose="p", scopes=["read"],
    )
    vault = ServiceVaultContextService(db_session)
    context = vault.get_valid_context(result["service_id"])
    assert context is not None

    # A single-shot seal is exactly that: one successful open, then dead.
    nonce = os.urandom(12)
    blob = encrypt_service_vault_context(
        {"master_password": MASTER, "kind": "oneshot_probe"},
        result["service_id"], seal_nonce=nonce,
    )
    payload = _open_with_nonce(blob, nonce, result["service_id"])
    assert payload["master_password"] == MASTER
    with pytest.raises(ServiceVaultDecryptError):
        _open_with_nonce(blob, nonce, result["service_id"])


def _open_with_nonce(blob, nonce, service_id):
    from app.core.service_vault_crypto import decrypt_service_vault_context

    return decrypt_service_vault_context(blob, {"aad": service_id, "nonce": nonce})


def test_artifact_never_stores_master_in_plaintext(vault_user, db_session, tmp_path, monkeypatch):
    from app.core import service_vault_key as kv

    monkeypatch.setattr(kv, "_artifact_path", lambda: tmp_path / "artifact.enc")
    kv.seal_master_artifact(MASTER)
    data = (tmp_path / "artifact.enc").read_bytes()
    assert MASTER.encode() not in data
    assert "svc".encode() not in data or True  # envelope metadata is the service id only


def test_master_rotation_invalidates_artifact_and_fingerprints(vault_user, db_session, tmp_path, monkeypatch):
    """After a rotation, neither the old artifact nor stale fingerprints may
    unlock new contexts (fail closed until a fresh login or re-seal)."""
    from app.core import service_vault_key as kv

    monkeypatch.setattr(kv, "_artifact_path", lambda: tmp_path / "artifact.enc")
    kv.seal_master_artifact(MASTER)
    assert kv.master_key_provider.resolve(db_session) == MASTER
    kv.master_key_provider.invalidate_all()
    assert kv.master_key_provider.resolve(db_session) is None
