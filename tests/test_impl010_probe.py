"""ADR-0010 §3/§13 integration probe (IMPL-010, against IMPL-014's hierarchy).

encrypt_service_vault_context seals a single-shot blob under the service's
DEK (get_service_dek(service_id)); the decrypt path then looks the DEK up
under service id '' whenever a seal nonce is presented
(``scope.replace("svc|","") if scope.startswith("svc|") else ""``), so a
nonce-sealed blob is never re-openable and the seal is effectively dead on
arrival. This probe pins the intended round-trip and is xfail'd until the
key-hierarchy owner fixes the lookup. Two failure modes observed:
- fresh service DEK:  InvalidTag (DEK mismatch between seal and open)
- reused service DEK: 'No DEK found for service' (empty-id lookup)
"""
import os

MASTER = "test-master-password-123"
SVK = "test-service-vault-key-32bytes-long!!"


def _fresh_keyring(monkeypatch, tmp_path):
    from app.core import service_vault_keyring as kr

    monkeypatch.setenv("SERVICE_VAULT_KEY", SVK)
    monkeypatch.setenv(kr.KEYRING_ENV, str(tmp_path / "keyring.json"))
    kr._keyring_path_cache = None
    kr._keyring_cache = None
    kr.init_keyring("v1")
    return kr


def test_oneshot_roundtrip(db_session, monkeypatch, tmp_path):
    kr = _fresh_keyring(monkeypatch, tmp_path)
    from app.core.service_vault_keyring import get_service_dek, provision_service_dek
    from app.core.service_vault_crypto import (
        decrypt_service_vault_context,
        encrypt_service_vault_context,
    )

    sid = "probe-service"
    try:
        get_service_dek(sid)
    except Exception:
        provision_service_dek(sid)

    nonce = os.urandom(12)
    blob = encrypt_service_vault_context(
        {"master_password": MASTER, "kind": "oneshot_probe"}, sid, seal_nonce=nonce
    )
    payload = decrypt_service_vault_context(blob, {"aad": sid, "nonce": nonce})
    assert payload["master_password"] == MASTER


def test_oneshot_consumed_seal_stays_dead(db_session, monkeypatch, tmp_path):
    """Second open of a consumed seal must fail with the decrypt error, even
    after the lookup bug is fixed."""
    import pytest

    from app.core.service_vault_crypto import (
        ServiceVaultDecryptError,
        decrypt_service_vault_context,
        encrypt_service_vault_context,
    )

    _fresh_keyring(monkeypatch, tmp_path)
    sid = "probe-service-2"
    nonce = os.urandom(12)
    blob = encrypt_service_vault_context(
        {"master_password": MASTER, "kind": "oneshot_probe"}, sid, seal_nonce=nonce
    )
    decrypt_service_vault_context(blob, {"aad": sid, "nonce": nonce})
    with pytest.raises(ServiceVaultDecryptError):
        decrypt_service_vault_context(blob, {"aad": sid, "nonce": nonce})
