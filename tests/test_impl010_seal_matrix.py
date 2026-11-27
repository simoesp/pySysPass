"""Diagnostic sessionfixture added to /srv/pySysPass/tests/test_impl010_seal_matrix.py:
flat-seal + DEK-seal x open-literal + open-None matrix, under ambient keyring."""
import hashlib
import os

os.environ.setdefault("SERVICE_VAULT_KEY", "test-service-vault-key-32bytes-long!!")


def _payload(sid):
    from app.core.service_vault_crypto import resolve_service_vault_key

    km = resolve_service_vault_key()
    sk = hashlib.sha256(b"svk|" + km + sid.encode()).hexdigest()
    return {"service_id": sid, "master_password": "test-master-password-123",
            "service_key": sk, "vault_context_version": "v1",
            "inactivity_timeout_hours": 4.0, "sealed_epoch": 0}


def test_seal_matrix(tmp_path):
    import app.core.service_vault_key as KV
    import app.core.service_vault_keyring as KR
    import app.core.service_vault_crypto as C

    KV.seal_master_artifact("test-master-password-123")
    print("PATH", KR._keyring_path())
    print("ACTIVE", C._keyring_active())
    results = []
    # 1: flat seal (key=literal)
    sid = "m-flat"
    blob = C.encrypt_service_vault_context(_payload(sid), sid,
                                           key="test-service-vault-key-32bytes-long!!")
    for label, k in (("literal", "test-service-vault-key-32bytes-long!!"), ("none", None)):
        try:
            C.decrypt_service_vault_context(blob, "service_vault_key_v1", k)
            results.append(f"M1 flat open-{label}: OK")
        except Exception as e:
            results.append(f"M1 flat open-{label}: {type(e).__name__}")
    # 2: DEK seal (key=None, keyring active)
    sid2 = "m-dek"
    KR.provision_service_dek(sid2)
    blob2 = C.encrypt_service_vault_context(_payload(sid2), sid2, key=None)
    for label, k in (("literal", "test-service-vault-key-32bytes-long!!"), ("none", None)):
        try:
            C.decrypt_service_vault_context(blob2, "service_vault_key_v1", k)
            results.append(f"M2 dek open-{label}: OK")
        except Exception as e:
            results.append(f"M2 dek open-{label}: {type(e).__name__}")
    print("\n".join(results))
    assert True
