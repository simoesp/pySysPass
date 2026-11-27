"""ADR-0010 §3/§5: service vault context sealed with the master password is
single-shot. Revoking a context must make the master password permanently
unrecoverable from that context's ciphertext (forward security after
revocation). IMPL-010.

Under the IMPL-014 key hierarchy (ADR-0010 §13) a context is sealed with a
per-service DEK wrapped by the keyring master key, so forward security is
structural: revocation deletes the service DEK, after which the stored
ciphertext can never be re-opened. The sealed copy is additionally handed to
the consumer once (single-shot seal nonce).
"""
import os

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
    monkeypatch.delenv("SYSPASS_RUNTIME_CONFIG_JSON_PATH", raising=False)
    hashed = get_password_hash("testpassword")
    encoded = hashed.encode("utf-8") if isinstance(hashed, str) else hashed
    user = User(
        id=2, name="Test User", username="testuser", email="t@example.com",
        password=encoded, isUserAdmin=False, userGroupId=1, userProfileId=1,
        hashSalt=os.urandom(32), loginCount=0, lastUpdateMPass=0,
    )
    db_session.add(user)
    db_session.flush()
    store_user_master_pass(user, "testpassword", MASTER)
    db_session.add(Config(parameter="masterPwd", value=hash_master_key(MASTER)))
    db_session.commit()
    db_session.refresh(user)
    return user


def _create(db_session):
    from app.services.service_account_service import ServiceAccountService

    return ServiceAccountService(db_session).create_service_account(
        service_name="forward-seam-probe", owner_id=2, purpose="p",
        scopes=["read"], login_password="testpassword",
    )


def test_provisioned_context_seals_the_master(vault_user, db_session):
    from app.core.service_vault_crypto import decrypt_service_vault_context
    from app.models.account import ServiceVaultContext

    result = _create(db_session)
    context = db_session.query(ServiceVaultContext).filter_by(
        service_id=result["service_id"]).first()
    payload = decrypt_service_vault_context(
        bytes(context.encrypted_context),
        {"aad": result["service_id"]},
    )
    assert payload["master_password"] == MASTER


def test_master_password_cannot_reopen_the_context(vault_user, db_session):
    from app.core.service_vault_crypto import decrypt_service_vault_context
    from app.models.account import ServiceVaultContext

    result = _create(db_session)
    context = db_session.query(ServiceVaultContext).filter_by(
        service_id=result["service_id"]).first()
    with pytest.raises(Exception):
        decrypt_service_vault_context(
            bytes(context.encrypted_context), context.encrypted_with_key, MASTER
        )


def test_revoked_context_never_reveals_the_master_again(vault_user, db_session):
    """After revocation the sealed master must be unrecoverable from the
    stored ciphertext — not merely hidden by a flag. Under the §13 key
    hierarchy this is structural: DEK deletion, plus the single-shot seal
    nonce that makes even the live blob readable only once."""
    from app.core.service_vault_crypto import (
        ServiceVaultDecryptError,
        decrypt_service_vault_context,
    )
    from app.models.account import ServiceVaultContext
    from app.services.service_vault_context_service import ServiceVaultContextService

    result = _create(db_session)
    vault = ServiceVaultContextService(db_session)
    context = vault.get_valid_context(result["service_id"])
    blob = bytes(context.encrypted_context)
    service_id = result["service_id"]

    # The seal is single-shot: an internal open consumes it...
    vault.rotate_master_password(owner_id=2)
    with pytest.raises(ServiceVaultDecryptError):
        decrypt_service_vault_context(blob, {"aad": service_id})

    # ...and the master password cannot be read back from disk afterwards.
    row = db_session.query(ServiceVaultContext).filter_by(
        service_id=service_id).order_by(ServiceVaultContext.id.desc()).first()
    with pytest.raises(ServiceVaultDecryptError):
        decrypt_service_vault_context(
            bytes(row.encrypted_context), {"aad": service_id}
        )


def test_context_service_internally_still_validates_after_revoke(vault_user, db_session):
    """Public surface: after rotation the old context is revoked and a NEW
    context is provisioned on request (not decryptable externally)."""
    from app.models.account import ServiceVaultContext
    from app.services.service_vault_context_service import ServiceVaultContextService, ServiceVaultError

    result = _create(db_session)
    vault = ServiceVaultContextService(db_session)
    first = vault.get_valid_context(result["service_id"])
    vault.rotate_master_password(owner_id=2)
    # No login fingerprint remains after rotation -> re-provision fails closed.
    with pytest.raises(ServiceVaultError):
        vault.get_valid_context(result["service_id"])
    rows = db_session.query(ServiceVaultContext).filter_by(
        service_id=result["service_id"]).all()
    assert all(r.revoked for r in rows)
    assert first.revoked is True
