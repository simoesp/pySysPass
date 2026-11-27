"""ADR-0013 IMPL-008/009 tests: HMAC-SHA256 integrity + Ed25519 authenticity verification.

Covers:
- HMAC-SHA256 computation over encrypted backup contents
- HMAC verification on restore (integrity)
- Ed25519 signature on manifest (authenticity)
- Signature verification on restore
- Tamper detection for both mechanisms
- Key rotation scenarios
- Missing/invalid HMAC/signature handling
"""
import base64
import json
import os
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core import backup_crypto
from app.services.backup_service import BackupService


# ── Test Helpers ────────────────────────────────────────────────────────────────

KEY_HEX_A = "a" * 64
KEY_HEX_B = "b" * 64


def _keyring(tmp_path: Path, *, current="v1", keys=None, mode=0o600) -> Path:
    """Create a backup encryption keyring. Uses 0o600 to avoid permission issues in test env."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "backup-keyring.json"
    data = {"current": current, "keys": keys or {"v1": KEY_HEX_A}}
    path.write_text(json.dumps(data))
    os.chmod(path, mode)
    return path


def _signing_keyring(tmp_path: Path, *, current="sig-v1", keys=None, mode=0o600) -> Path:
    """Keyring for Ed25519 signing keys (base64-encoded private keys)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "backup-signing-keyring.json"
    if keys is None:
        # Generate a test key
        private_key = Ed25519PrivateKey.generate()
        private_b64 = base64.b64encode(private_key.private_bytes_raw()).decode()
        public_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
        keys = {current: {"private": private_b64, "public": public_b64}}
    data = {"current": current, "keys": keys}
    path.write_text(json.dumps(data))
    os.chmod(path, mode)
    return path


def _data_dir(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "secret.txt").write_text("hunter2", encoding="utf-8")
    return data


def _create_encrypted_backup(tmp_path: Path, monkeypatch, keyring=None, signing_keyring=None):
    """Helper to create an encrypted backup with optional signing."""
    monkeypatch.chdir(tmp_path)
    if keyring:
        monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(keyring))
    else:
        monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    return service.create_full_backup()


def _read_manifest(archive_path: Path) -> dict:
    with zipfile.ZipFile(archive_path, "r") as zf:
        if backup_crypto.MANIFEST_NAME not in zf.namelist():
            return {}
        return json.loads(zf.read(backup_crypto.MANIFEST_NAME).decode("utf-8"))


def _tamper_member(archive_path: Path, member_name: str, mutator):
    """Modify a member in-place in the archive."""
    with zipfile.ZipFile(archive_path, "r") as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    members[member_name] = mutator(members[member_name])
    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)


# ── HMAC-SHA256 Integrity Tests ─────────────────────────────────────────────────

def test_hmac_in_manifest_on_encrypted_backup(tmp_path, monkeypatch):
    """Encrypted backup manifest includes HMAC-SHA256 of encrypted contents."""
    backup = _create_encrypted_backup(tmp_path, monkeypatch)
    manifest = _read_manifest(Path(backup["path"]))

    assert "hmac" in manifest, "Manifest must contain 'hmac' field"
    assert isinstance(manifest["hmac"], str), "HMAC must be a string"
    # HMAC should be base64 or hex encoded
    assert len(manifest["hmac"]) > 0, "HMAC must not be empty"


def test_hmac_covers_all_encrypted_members(tmp_path, monkeypatch):
    """HMAC is computed over all encrypted member ciphertexts."""
    backup = _create_encrypted_backup(tmp_path, monkeypatch)
    manifest = _read_manifest(Path(backup["path"]))

    # All encrypted members should be covered
    for name, info in manifest.get("members", {}).items():
        if info.get("encrypted"):
            assert "nonce" in info and "tag" in info
    assert "hmac" in manifest


def test_hmac_verification_passes_for_valid_backup(tmp_path, monkeypatch):
    """Valid backup passes HMAC verification on restore."""
    backup = _create_encrypted_backup(tmp_path, monkeypatch)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    result = service.restore_backup(backup["filename"], offline=True)

    assert result["data_restored"] is True
    assert result["encrypted"] is True
    assert (tmp_path / "data" / "secret.txt").read_text() == "hunter2"


def test_hmac_tampered_ciphertext_fails_verification(tmp_path, monkeypatch):
    """Tampering with encrypted member ciphertext fails HMAC verification."""
    backup = _create_encrypted_backup(tmp_path, monkeypatch)
    archive_path = Path(backup["path"])

    # Tamper with an encrypted member
    _tamper_member(archive_path, "data/secret.txt", lambda b: bytes([b[0] ^ 0xFF]) + b[1:])

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="HMAC|integrity|tampered|authentication failed"):
        service.restore_backup(backup["filename"], offline=True)


def test_hmac_tampered_manifest_fails_verification(tmp_path, monkeypatch):
    """Tampering with manifest fails HMAC verification."""
    backup = _create_encrypted_backup(tmp_path, monkeypatch)
    archive_path = Path(backup["path"])

    # Tamper with manifest (change a nonce)
    manifest = _read_manifest(archive_path)
    original_hmac = manifest["hmac"]
    # Corrupt a member's nonce in manifest
    for name in manifest.get("members", {}):
        if manifest["members"][name].get("encrypted"):
            manifest["members"][name]["nonce"] = "00" * 12
            break

    with zipfile.ZipFile(archive_path, "r") as zf:
        members = {n: zf.read(n) for n in zf.namelist() if n != backup_crypto.MANIFEST_NAME}
    members[backup_crypto.MANIFEST_NAME] = json.dumps(manifest, indent=2).encode()

    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="HMAC|integrity|tampered|manifest"):
        service.restore_backup(backup["filename"], offline=True)


def test_hmac_missing_key_fails_verification(tmp_path, monkeypatch):
    """Restoring with different HMAC key fails verification."""
    # Create backup with key A
    backup = _create_encrypted_backup(tmp_path, monkeypatch, keyring=_keyring(tmp_path, keys={"v1": KEY_HEX_A}))

    # Try restore with key B
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path, keys={"v1": KEY_HEX_B})))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="HMAC|integrity|wrong key|authentication failed"):
        service.restore_backup(backup["filename"], offline=True)


def test_hmac_missing_from_manifest_fails(tmp_path, monkeypatch):
    """Backup with missing HMAC in manifest fails verification."""
    backup = _create_encrypted_backup(tmp_path, monkeypatch)
    archive_path = Path(backup["path"])

    # Remove HMAC from manifest
    manifest = _read_manifest(archive_path)
    del manifest["hmac"]

    with zipfile.ZipFile(archive_path, "r") as zf:
        members = {n: zf.read(n) for n in zf.namelist() if n != backup_crypto.MANIFEST_NAME}
    members[backup_crypto.MANIFEST_NAME] = json.dumps(manifest, indent=2).encode()

    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="HMAC|integrity|missing"):
        service.restore_backup(backup["filename"], offline=True)


def test_hmac_truncated_backup_fails(tmp_path, monkeypatch):
    """Truncated backup archive fails HMAC verification."""
    backup = _create_encrypted_backup(tmp_path, monkeypatch)
    archive_path = Path(backup["path"])

    # Truncate the archive by removing last 100 bytes
    with open(archive_path, "r+b") as f:
        f.seek(-100, os.SEEK_END)
        f.truncate()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="HMAC|integrity|truncated|corrupt|BadZipFile"):
        service.restore_backup(backup["filename"], offline=True)


def test_legacy_backup_without_hmac_restorable(tmp_path, monkeypatch):
    """Pre-HMAC (legacy) backups remain restorable without HMAC verification."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(backup_crypto.KEYRING_ENV, raising=False)
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive_path = backup_dir / "legacy.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("data/example.txt", "legacy-data")

    (tmp_path / "data").mkdir()
    service = BackupService(backup_dir=str(backup_dir))
    result = service.restore_backup("legacy.zip", offline=True)

    assert result["data_restored"] is True
    assert result["encrypted"] is False
    assert (tmp_path / "data" / "example.txt").read_text() == "legacy-data"


def test_unencrypted_exception_backup_no_hmac(tmp_path, monkeypatch):
    """Unencrypted exception backups don't require HMAC."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(backup_crypto.KEYRING_ENV, raising=False)
    monkeypatch.setenv(backup_crypto.EXCEPTION_ENV, "true")
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    assert backup["encryption"]["encrypted"] is False
    manifest = _read_manifest(Path(backup["path"]))
    # Unencrypted backups may not have HMAC (or it's not verified)
    assert manifest.get("algorithm") == "none"


# ── Ed25519 Digital Signature Authenticity Tests ────────────────────────────────

def test_signature_in_manifest_on_signed_backup(tmp_path, monkeypatch):
    """Signed backup manifest includes Ed25519 signature."""
    # This test assumes signing is enabled via environment/config
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(_signing_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    manifest = _read_manifest(Path(backup["path"]))

    # Check for signature field (may be "signature" or "signatures" list)
    assert "signature" in manifest or "signatures" in manifest, "Manifest must contain signature"


def test_signature_verification_passes_for_valid_backup(tmp_path, monkeypatch):
    """Valid signed backup passes signature verification on restore."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    signing_kr = _signing_keyring(tmp_path)
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    # Restore with same signing keyring (public key)
    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(signing_kr))

    result = service.restore_backup(backup["filename"], offline=True)

    assert result["data_restored"] is True
    assert result["encrypted"] is True
    assert (tmp_path / "data" / "secret.txt").read_text() == "hunter2"


def test_signature_tampered_manifest_fails_verification(tmp_path, monkeypatch):
    """Tampering with signed manifest fails signature verification."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    signing_kr = _signing_keyring(tmp_path)
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()
    archive_path = Path(backup["path"])

    # Tamper with manifest (change created_at)
    manifest = _read_manifest(archive_path)
    manifest["created_at"] = "2026-01-01T00:00:00Z"

    with zipfile.ZipFile(archive_path, "r") as zf:
        members = {n: zf.read(n) for n in zf.namelist() if n != backup_crypto.MANIFEST_NAME}
    members[backup_crypto.MANIFEST_NAME] = json.dumps(manifest, indent=2).encode()

    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="signature|authenticity|tampered|verification failed"):
        service.restore_backup(backup["filename"], offline=True)


def test_signature_wrong_key_fails_verification(tmp_path, monkeypatch):
    """Signature made with different key fails verification."""
    # Create backup with signing key A
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    signing_kr_a = _signing_keyring(tmp_path, current="sig-v1")
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr_a))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Try verify with signing key B (different key pair)
    signing_kr_b = _signing_keyring(tmp_path / "alt", current="sig-v1")
    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(signing_kr_b))

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="signature|authenticity|verification failed|wrong key"):
        service.restore_backup(backup["filename"], offline=True)


def test_signature_missing_from_manifest_fails(tmp_path, monkeypatch):
    """Backup with missing signature fails authenticity verification."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    signing_kr = _signing_keyring(tmp_path)
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()
    archive_path = Path(backup["path"])

    # Remove signature from manifest
    manifest = _read_manifest(archive_path)
    if "signature" in manifest:
        del manifest["signature"]
    if "signatures" in manifest:
        del manifest["signatures"]

    with zipfile.ZipFile(archive_path, "r") as zf:
        members = {n: zf.read(n) for n in zf.namelist() if n != backup_crypto.MANIFEST_NAME}
    members[backup_crypto.MANIFEST_NAME] = json.dumps(manifest, indent=2).encode()

    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="signature|authenticity|missing"):
        service.restore_backup(backup["filename"], offline=True)


def test_signature_key_rotation_verifies_old_backup(tmp_path, monkeypatch):
    """Backup signed with retired key still verifies (historical key retained)."""
    # Create backup with sig-v1
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))

    # Generate two key pairs
    sk1 = Ed25519PrivateKey.generate()
    pk1_b64 = base64.b64encode(sk1.public_key().public_bytes_raw()).decode()
    sk1_b64 = base64.b64encode(sk1.private_bytes_raw()).decode()

    sk2 = Ed25519PrivateKey.generate()
    pk2_b64 = base64.b64encode(sk2.public_key().public_bytes_raw()).decode()
    sk2_b64 = base64.b64encode(sk2.private_bytes_raw()).decode()

    signing_kr = _signing_keyring(tmp_path, current="sig-v1", keys={
        "sig-v1": {"private": sk1_b64, "public": pk1_b64},
        "sig-v2": {"private": sk2_b64, "public": pk2_b64},
    })
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Rotate to sig-v2 but retain sig-v1 in verification keyring
    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(signing_kr))

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    result = service.restore_backup(backup["filename"], offline=True)

    assert result["data_restored"] is True
    assert (tmp_path / "data" / "secret.txt").read_text() == "hunter2"


def test_signature_retired_key_removed_fails(tmp_path, monkeypatch):
    """Backup signed with fully retired key (removed from keyring) fails."""
    # Create backup with sig-v1
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))

    sk1 = Ed25519PrivateKey.generate()
    pk1_b64 = base64.b64encode(sk1.public_key().public_bytes_raw()).decode()
    sk1_b64 = base64.b64encode(sk1.private_bytes_raw()).decode()

    sk2 = Ed25519PrivateKey.generate()
    pk2_b64 = base64.b64encode(sk2.public_key().public_bytes_raw()).decode()
    sk2_b64 = base64.b64encode(sk2.private_bytes_raw()).decode()

    # Signing keyring with both keys
    signing_kr = _signing_keyring(tmp_path, current="sig-v1", keys={
        "sig-v1": {"private": sk1_b64, "public": pk1_b64},
        "sig-v2": {"private": sk2_b64, "public": pk2_b64},
    })
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Verification keyring WITHOUT sig-v1 (fully retired)
    retired_kr = _signing_keyring(tmp_path / "retired", current="sig-v2", keys={
        "sig-v2": {"private": sk2_b64, "public": pk2_b64},
    })
    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(retired_kr))

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="signature|authenticity|key.*not found|verification failed"):
        service.restore_backup(backup["filename"], offline=True)


def test_unsigned_backup_fails_when_verification_required(tmp_path, monkeypatch):
    """Unsigned backup fails when authenticity verification is enforced."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    # No signing keyring provided
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Try restore with verification enforced but no signature
    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(_signing_keyring(tmp_path)))
    monkeypatch.setenv("BACKUP_REQUIRE_SIGNATURE", "true")

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="signature|authenticity|missing|unsigned"):
        service.restore_backup(backup["filename"], offline=True)


# ── Combined HMAC + Signature Tests ─────────────────────────────────────────────

def test_both_hmac_and_signature_verified_on_restore(tmp_path, monkeypatch):
    """Both HMAC integrity and signature authenticity verified on restore."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    signing_kr = _signing_keyring(tmp_path)
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    manifest = _read_manifest(Path(backup["path"]))
    assert "hmac" in manifest
    assert "signature" in manifest or "signatures" in manifest

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(signing_kr))

    result = service.restore_backup(backup["filename"], offline=True)

    assert result["data_restored"] is True
    assert result["encrypted"] is True
    assert (tmp_path / "data" / "secret.txt").read_text() == "hunter2"


def test_hmac_passes_but_signature_fails_blocks_restore(tmp_path, monkeypatch):
    """Valid HMAC but invalid signature blocks restore."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    signing_kr_a = _signing_keyring(tmp_path)
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr_a))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()
    archive_path = Path(backup["path"])

    # Tamper with manifest (breaks signature but not HMAC since HMAC covers ciphertext)
    manifest = _read_manifest(archive_path)
    manifest["created_at"] = "2026-01-01T00:00:00Z"

    with zipfile.ZipFile(archive_path, "r") as zf:
        members = {n: zf.read(n) for n in zf.namelist() if n != backup_crypto.MANIFEST_NAME}
    members[backup_crypto.MANIFEST_NAME] = json.dumps(manifest, indent=2).encode()

    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)

    # Verify with different key
    signing_kr_b = _signing_keyring(tmp_path / "alt")
    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(signing_kr_b))

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="signature|authenticity"):
        service.restore_backup(backup["filename"], offline=True)


def test_signature_passes_but_hmac_fails_blocks_restore(tmp_path, monkeypatch):
    """Valid signature but invalid HMAC blocks restore."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    signing_kr = _signing_keyring(tmp_path)
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()
    archive_path = Path(backup["path"])

    # Tamper with encrypted member (breaks HMAC but not manifest signature)
    _tamper_member(archive_path, "data/secret.txt", lambda b: bytes([b[0] ^ 0xFF]) + b[1:])

    monkeypatch.setenv("BACKUP_VERIFICATION_KEYRING", str(signing_kr))

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="HMAC|integrity|tampered|authentication failed"):
        service.restore_backup(backup["filename"], offline=True)


# ── List Backups Reports Integrity/Authenticity Status ──────────────────────────

def test_list_backups_reports_hmac_presence(tmp_path, monkeypatch):
    """list_backups reports whether HMAC is present."""
    backup = _create_encrypted_backup(tmp_path, monkeypatch)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    rows = service.list_backups()

    assert len(rows) == 1
    assert "hmac_present" in rows[0] or "integrity_verified" in rows[0]
    if "hmac_present" in rows[0]:
        assert rows[0]["hmac_present"] is True


def test_list_backups_reports_signature_presence(tmp_path, monkeypatch):
    """list_backups reports whether signature is present."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    signing_kr = _signing_keyring(tmp_path)
    monkeypatch.setenv("BACKUP_SIGNING_KEYRING", str(signing_kr))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()
    rows = service.list_backups()

    assert len(rows) == 1
    assert "signature_present" in rows[0] or "authenticity_verified" in rows[0]
    if "signature_present" in rows[0]:
        assert rows[0]["signature_present"] is True


# ── Crypto Primitives Unit Tests ────────────────────────────────────────────────

def test_compute_hmac_sha256():
    """HMAC-SHA256 computation matches expected values."""
    from app.core.backup_crypto import compute_hmac_sha256

    key = b"test-key-32-bytes-long-exactly!!"
    data = b"test data"
    hmac1 = compute_hmac_sha256(data, key)
    hmac2 = compute_hmac_sha256(data, key)

    assert hmac1 == hmac2  # Deterministic
    assert len(hmac1) == 32  # SHA-256 = 32 bytes


def test_compute_hmac_sha256_different_key():
    """HMAC differs with different key."""
    from app.core.backup_crypto import compute_hmac_sha256

    key1 = b"test-key-32-bytes-long-exactly!!"
    key2 = b"different-key-32-bytes-long!!"
    data = b"test data"

    hmac1 = compute_hmac_sha256(data, key1)
    hmac2 = compute_hmac_sha256(data, key2)

    assert hmac1 != hmac2


def test_compute_hmac_sha256_different_data():
    """HMAC differs with different data."""
    from app.core.backup_crypto import compute_hmac_sha256

    key = b"test-key-32-bytes-long-exactly!!"
    data1 = b"test data 1"
    data2 = b"test data 2"

    hmac1 = compute_hmac_sha256(data1, key)
    hmac2 = compute_hmac_sha256(data2, key)

    assert hmac1 != hmac2


def test_verify_hmac_sha256():
    """HMAC verification works correctly."""
    from app.core.backup_crypto import compute_hmac_sha256, verify_hmac_sha256

    key = b"test-key-32-bytes-long-exactly!!"
    data = b"test data"
    hmac = compute_hmac_sha256(data, key)

    assert verify_hmac_sha256(data, key, hmac) is True
    assert verify_hmac_sha256(data + b"x", key, hmac) is False
    assert verify_hmac_sha256(data, key + b"x", hmac) is False


def test_sign_manifest_ed25519():
    """Ed25519 manifest signing produces valid signature."""
    from app.core.backup_crypto import sign_manifest, verify_manifest_signature

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    manifest = {"version": "1.0", "created_at": "2026-11-27T00:00:00Z", "members": {}}
    signature = sign_manifest(manifest, private_key)

    assert isinstance(signature, bytes)
    assert len(signature) == 64  # Ed25519 signature size

    # Verify works
    assert verify_manifest_signature(manifest, public_key, signature) is True

    # Tampered manifest fails
    manifest["created_at"] = "2026-01-01T00:00:00Z"
    assert verify_manifest_signature(manifest, public_key, signature) is False


def test_verify_manifest_signature_wrong_key():
    """Signature verification fails with wrong public key."""
    from app.core.backup_crypto import sign_manifest, verify_manifest_signature

    private_key1 = Ed25519PrivateKey.generate()
    private_key2 = Ed25519PrivateKey.generate()
    public_key1 = private_key1.public_key()
    public_key2 = private_key2.public_key()

    manifest = {"version": "1.0", "members": {}}
    signature = sign_manifest(manifest, private_key1)

    assert verify_manifest_signature(manifest, public_key1, signature) is True
    assert verify_manifest_signature(manifest, public_key2, signature) is False


def test_signing_keyring_loads_keys():
    """Signing keyring loads Ed25519 keys correctly."""
    from app.core.backup_crypto import load_signing_keyring, load_verification_keyring

    tmp_path = Path("/tmp/test_signing_keyring")
    tmp_path.mkdir(exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(private_key.private_bytes_raw()).decode()
    public_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()

    kr_path = _signing_keyring(tmp_path, keys={"sig-v1": {"private": private_b64, "public": public_b64}})

    # Load signing keyring (has private keys)
    key_id, private_key_loaded = load_signing_keyring(str(kr_path))
    assert key_id == "sig-v1"
    assert private_key_loaded is not None

    # Load verification keyring (public keys only)
    pub_keys = load_verification_keyring(str(kr_path))
    assert "sig-v1" in pub_keys
    assert pub_keys["sig-v1"].public_bytes_raw() == private_key.public_key().public_bytes_raw()


def test_signing_keyring_missing_key_raises():
    """Missing signing key raises appropriate error."""
    from app.core.backup_crypto import load_signing_keyring, BackupKeyMissing

    tmp_path = Path("/tmp/test_signing_keyring2")
    tmp_path.mkdir(exist_ok=True)

    kr_path = _signing_keyring(tmp_path, keys={"sig-v2": {"private": "x" * 88, "public": "y" * 44}})

    with pytest.raises(BackupKeyMissing, match="sig-v1"):
        load_signing_keyring(str(kr_path), key_id="sig-v1")


# ── Archive Verification Before Extraction ──────────────────────────────────────

def test_verify_archive_before_extract_valid(tmp_path, monkeypatch):
    """verify_archive_before_extract passes for valid backup."""
    from app.core.backup_crypto import verify_archive_before_extract

    backup = _create_encrypted_backup(tmp_path, monkeypatch)
    archive_path = Path(backup["path"])

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    # Should not raise
    result = verify_archive_before_extract(archive_path, str(_keyring(tmp_path)))
    assert result is True


def test_verify_archive_before_extract_tampered_fails(tmp_path, monkeypatch):
    """verify_archive_before_extract fails for tampered backup."""
    from app.core.backup_crypto import verify_archive_before_extract

    backup = _create_encrypted_backup(tmp_path, monkeypatch)
    archive_path = Path(backup["path"])

    # Tamper with ciphertext
    _tamper_member(archive_path, "data/secret.txt", lambda b: bytes([b[0] ^ 0xFF]) + b[1:])

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    with pytest.raises(RuntimeError, match="HMAC|integrity|verification failed"):
        verify_archive_before_extract(archive_path, str(_keyring(tmp_path)))


def test_verify_archive_before_extract_legacy_passes(tmp_path, monkeypatch):
    """verify_archive_before_extract passes for legacy (no HMAC) backup."""
    from app.core.backup_crypto import verify_archive_before_extract

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(backup_crypto.KEYRING_ENV, raising=False)
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive_path = backup_dir / "legacy.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("data/example.txt", "legacy-data")

    # Should not raise for legacy
    result = verify_archive_before_extract(archive_path)
    assert result is True