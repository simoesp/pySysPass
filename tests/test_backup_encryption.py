"""ADR-0013 IMPL-007/009 tests: AES-256-GCM mandatory backup encryption + Ed25519 manifest signing.

Covers:
- Keyring configuration and validation
- Encrypted archive round-trip
- Unencrypted admin exception + audit event
- Missing key -> fail (no plaintext published by default)
- Wrong key -> decryption error
- Tampered ciphertext -> authentication failure
- Legacy (pre-ADR-0013) archive still restorable
- Ed25519 manifest signing for authenticity (IMPL-009)
"""
import base64
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from app.core import backup_crypto
from app.services.backup_service import BackupService
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


# ── Helpers ──────────────────────────────────────────────────────────────────

KEY_HEX_A = "a" * 64
KEY_HEX_B = "b" * 64


def _keyring(tmp_path: Path, *, current="v1", keys=None, mode=0o400) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "backup-keyring.json"
    data = {"current": current, "keys": keys or {"v1": KEY_HEX_A}}
    path.write_text(json.dumps(data))
    os.chmod(path, mode)
    return path


def _data_dir(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "secret.txt").write_text("hunter2", encoding="utf-8")
    return data


# ── Keyring ──────────────────────────────────────────────────────────────────

def test_keyring_loads_current_key(tmp_path):
    kr = _keyring(tmp_path)
    key_id, key = backup_crypto.current_key(str(kr))
    assert key_id == "v1"
    assert key == bytes.fromhex(KEY_HEX_A)


def test_keyring_historical_key_available(tmp_path):
    kr = _keyring(tmp_path, keys={"v1": KEY_HEX_A, "v2": KEY_HEX_B})
    assert backup_crypto.key_for_id("v1", str(kr)) == bytes.fromhex(KEY_HEX_A)
    assert backup_crypto.key_for_id("v2", str(kr)) == bytes.fromhex(KEY_HEX_B)


def test_keyring_invalid_hex_rejected(tmp_path):
    kr = _keyring(tmp_path, keys={"v1": "zz" * 32})
    with pytest.raises(backup_crypto.BackupKeyUnreadable, match="not valid hex"):
        backup_crypto.current_key(str(kr))


def test_keyring_short_key_rejected(tmp_path):
    kr = _keyring(tmp_path, keys={"v1": "abcd"})
    with pytest.raises(backup_crypto.BackupKeyUnreadable, match="32 bytes"):
        backup_crypto.current_key(str(kr))


def test_keyring_world_readable_refused(tmp_path):
    kr = _keyring(tmp_path, mode=0o644)
    with pytest.raises(backup_crypto.BackupKeyUnreadable, match="0400"):
        backup_crypto.current_key(str(kr))


def test_keyring_missing_current_id_rejected(tmp_path):
    kr = _keyring(tmp_path, current="v9", keys={"v1": KEY_HEX_A})
    with pytest.raises(backup_crypto.BackupKeyUnreadable, match="current"):
        backup_crypto.current_key(str(kr))


def test_keyring_historical_key_required_for_old_backup(tmp_path):
    """Restore a v1 archive after the keyring current has moved to v2 (v1 retained)."""
    kr = _keyring(tmp_path, keys={"v1": KEY_HEX_A, "v2": KEY_HEX_B})
    key = backup_crypto.key_for_id("v1", str(kr))
    assert key == bytes.fromhex(KEY_HEX_A)


def test_keyring_historical_key_retired_raises(tmp_path):
    kr = _keyring(tmp_path, keys={"v2": KEY_HEX_B})
    with pytest.raises(backup_crypto.BackupKeyMissing, match="not in keyring"):
        backup_crypto.key_for_id("v1", str(kr))


def test_no_keyring_raises_backup_key_missing(tmp_path, monkeypatch):
    monkeypatch.delenv(backup_crypto.KEYRING_ENV, raising=False)
    monkeypatch.setattr(
        backup_crypto, "DEFAULT_KEYRING_PATHS", (tmp_path / "absent.json",)
    )
    with pytest.raises(backup_crypto.BackupKeyMissing):
        backup_crypto.current_key()


# ── Seal / open round-trip ───────────────────────────────────────────────────

def test_seal_open_round_trip():
    key = bytes.fromhex(KEY_HEX_A)
    ct, nonce, tag = backup_crypto.seal_bytes(b"hello world", key)
    assert backup_crypto.open_bytes(ct, nonce, tag, key) == b"hello world"


def test_open_wrong_key_raises():
    key_a = bytes.fromhex(KEY_HEX_A)
    key_b = bytes.fromhex(KEY_HEX_B)
    ct, nonce, tag = backup_crypto.seal_bytes(b"secret", key_a)
    with pytest.raises(backup_crypto.BackupDecryptionFailed, match="wrong key"):
        backup_crypto.open_bytes(ct, nonce, tag, key_b)


def test_open_tampered_ciphertext_raises():
    key = bytes.fromhex(KEY_HEX_A)
    ct, nonce, tag = backup_crypto.seal_bytes(b"secret", key)
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    with pytest.raises(backup_crypto.BackupDecryptionFailed, match="tampered"):
        backup_crypto.open_bytes(tampered, nonce, tag, key)


# ── BackupService: encrypted create + restore round-trip ─────────────────────

def test_backup_encrypts_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    result = service.create_full_backup()  # no db_url: data only

    assert result["encryption"]["encrypted"] is True
    assert result["encryption"]["algorithm"] == "AES-256-GCM"
    assert result["encryption"]["audit_required"] is False

    # Verify the archive manifest
    with zipfile.ZipFile(result["path"]) as zf:
        assert "manifest.json" in zf.namelist()
        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["encrypted"] is True
        assert manifest["algorithm"] == "AES-256-GCM"
        assert manifest["key_id"] == "v1"
        # ciphertext member is not the raw plaintext
        raw = zf.read("data/secret.txt")
        assert raw != b"hunter2"


def test_list_backups_reports_encrypted_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    service.create_full_backup()
    rows = service.list_backups()
    assert len(rows) == 1
    assert rows[0]["encrypted"] is True


def test_encrypted_backup_round_trips_to_plaintext(tmp_path, monkeypatch):
    """Restore decrypts and the payload is the original plaintext."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Wipe data dir then restore
    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    result = service.restore_backup(backup["filename"], offline=True)
    assert result["data_restored"] is True
    assert result["encrypted"] is True
    assert (tmp_path / "data" / "secret.txt").read_text() == "hunter2"


# ── Missing key: encryption is fail-closed ───────────────────────────────────

def test_backup_fails_without_keyring(tmp_path, monkeypatch):
    """ADR-0013: missing key must refuse to publish plaintext."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(backup_crypto.KEYRING_ENV, raising=False)
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    monkeypatch.setattr(
        backup_crypto, "DEFAULT_KEYRING_PATHS", (tmp_path / "nope.json",)
    )
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    with pytest.raises(RuntimeError, match="Backup failed"):
        service.create_full_backup()
    # Nothing published
    assert list(Path("backups").glob("*.zip")) == []


# ── Admin exception ──────────────────────────────────────────────────────────

def test_exception_env_allows_plaintext_backup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(backup_crypto.KEYRING_ENV, raising=False)
    monkeypatch.setenv(backup_crypto.EXCEPTION_ENV, "true")
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    result = service.create_full_backup()

    assert result["encryption"]["encrypted"] is False
    assert result["encryption"]["exception"] is True
    assert result["encryption"]["audit_required"] is True

    # Plaintext bytes in archive
    with zipfile.ZipFile(result["path"]) as zf:
        assert zf.read("data/secret.txt") == b"hunter2"
        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["algorithm"] == "none"


def test_exception_round_trips_to_plaintext(tmp_path, monkeypatch):
    """Exception-mode archives can be restored without a keyring."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(backup_crypto.KEYRING_ENV, raising=False)
    monkeypatch.setenv(backup_crypto.EXCEPTION_ENV, "true")
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()

    result = service.restore_backup(backup["filename"], offline=True)
    assert result["data_restored"] is True
    assert result["encrypted"] is False
    assert (tmp_path / "data" / "secret.txt").read_text() == "hunter2"


# ── Wrong key at restore time ────────────────────────────────────────────────

def test_restore_wrong_key_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path, keys={"v1": KEY_HEX_A})))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Point at a different key (same key_id, different bytes)
    monkeypatch.setenv(
        backup_crypto.KEYRING_ENV,
        str(_keyring(tmp_path / "alt", keys={"v1": KEY_HEX_B})),
    )

    with pytest.raises(RuntimeError, match="wrong key"):
        service.restore_backup(backup["filename"], offline=True)


def test_restore_missing_historical_key_fails(tmp_path, monkeypatch):
    """After key rotation the old key must remain in the keyring."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        backup_crypto.KEYRING_ENV,
        str(_keyring(tmp_path, keys={"v1": KEY_HEX_A, "v2": KEY_HEX_B})),
    )
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Simulate key rotation: v1 retired from keyring
    monkeypatch.setenv(
        backup_crypto.KEYRING_ENV,
        str(_keyring(tmp_path / "rotated", current="v2", keys={"v2": KEY_HEX_B})),
    )
    with pytest.raises(RuntimeError, match="not in keyring"):
        service.restore_backup(backup["filename"], offline=True)


# ── Tampered archive ──────────────────────────────────────────────────────────

def test_tampered_backup_fails_restore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Flip a byte in the ciphertext member (data/secret.txt)
    archive_path = Path(backup["path"])
    with zipfile.ZipFile(archive_path, "r") as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    tampered = bytearray(members["data/secret.txt"])
    tampered[0] ^= 0xFF
    members["data/secret.txt"] = bytes(tampered)
    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)

    with pytest.raises(RuntimeError, match="tampered|authentication failed"):
        service.restore_backup(backup["filename"], offline=True)


# ── Legacy (pre-ADR-0013) archives still restorable ─────────────────────────

def test_legacy_plain_archive_still_restorable(tmp_path, monkeypatch):
    """Backups created before encryption enforcement remain restorable."""
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


def test_list_backups_marks_legacy_as_unencrypted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    with zipfile.ZipFile(backup_dir / "legacy.zip", "w") as zf:
        zf.writestr("data/example.txt", "x")

    service = BackupService(backup_dir=str(backup_dir))
    rows = service.list_backups()
    assert rows[0]["encrypted"] is False


# ── API audit event ───────────────────────────────────────────────────────────

def test_create_backup_route_emits_audit_event_on_exception(tmp_path, monkeypatch):
    """When BACKUP_ALLOW_UNENCRYPTED is set the route records a WARNING EventLog."""
    from unittest.mock import MagicMock, patch as vpatch
    from app.api.v1.backup import create_backup

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(backup_crypto.KEYRING_ENV, raising=False)
    monkeypatch.setenv(backup_crypto.EXCEPTION_ENV, "1")
    _data_dir(tmp_path)

    captured_rows = []

    class FakeDB:
        def add(self, row):
            captured_rows.append(row)
        def commit(self):
            pass

    with vpatch("app.api.v1.backup.PluginService", return_value=MagicMock()):
        result = create_backup(include_db=False, db=FakeDB(), current_user={"id": 7, "login": "admin"})
    assert result["encryption"]["audit_required"] is True
    assert len(captured_rows) == 1
    row = captured_rows[0]
    assert row.action == "backup.exception.unencrypted"
    assert row.level == "WARNING"
    assert row.userId == 7
    assert "admin" in (row.login or "")


def test_create_backup_route_no_audit_when_encrypted(tmp_path, monkeypatch):
    """Normal (encrypted) backups do not generate an exception audit event."""
    from unittest.mock import MagicMock, patch as vpatch
    from app.api.v1.backup import create_backup

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)
    _data_dir(tmp_path)

    add_calls = []

    class FakeDB:
        def add(self, row):
            add_calls.append(row)
        def commit(self):
            pass

    with vpatch("app.api.v1.backup.PluginService", return_value=MagicMock()):
        result = create_backup(include_db=False, db=FakeDB(), current_user={"id": 3, "login": "admin"})
    assert result["encryption"]["audit_required"] is False
    assert add_calls == []


# ── IMPL-009: Ed25519 Manifest Signing for Authenticity ──────────────────────


def _signing_keyring(tmp_path: Path, *, current="sig-v1", keys=None, mode=0o400) -> Path:
    """Create a signing keyring with Ed25519 key pair."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "backup-signing-keyring.json"

    if keys is None:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_b64 = base64.b64encode(private_key.private_bytes_raw()).decode("ascii")
        public_b64 = base64.b64encode(public_key.public_bytes_raw()).decode("ascii")
        keys = {current: {"private": private_b64, "public": public_b64}}

    data = {"current": current, "keys": keys}
    path.write_text(json.dumps(data))
    os.chmod(path, mode)
    return path


def _verification_keyring(tmp_path: Path, *, current="sig-v1", keys=None, mode=0o400) -> Path:
    """Create a verification keyring (public keys only)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "backup-verification-keyring.json"

    if keys is None:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_b64 = base64.b64encode(public_key.public_bytes_raw()).decode("ascii")
        keys = {current: {"public": public_b64}}

    data = {"current": current, "keys": keys}
    path.write_text(json.dumps(data))
    os.chmod(path, mode)
    return path


def test_signing_keyring_loads_private_key(tmp_path):
    kr = _signing_keyring(tmp_path)
    key_id, private_key = backup_crypto.load_signing_keyring(str(kr))
    assert key_id == "sig-v1"
    assert isinstance(private_key, Ed25519PrivateKey)


def test_signing_keyring_historical_key_available(tmp_path):
    key1 = Ed25519PrivateKey.generate()
    key2 = Ed25519PrivateKey.generate()
    keys = {
        "sig-v1": {
            "private": base64.b64encode(key1.private_bytes_raw()).decode("ascii"),
            "public": base64.b64encode(key1.public_key().public_bytes_raw()).decode("ascii"),
        },
        "sig-v2": {
            "private": base64.b64encode(key2.private_bytes_raw()).decode("ascii"),
            "public": base64.b64encode(key2.public_key().public_bytes_raw()).decode("ascii"),
        },
    }
    kr = _signing_keyring(tmp_path, keys=keys)
    _, pk1 = backup_crypto.load_signing_keyring(str(kr), key_id="sig-v1")
    _, pk2 = backup_crypto.load_signing_keyring(str(kr), key_id="sig-v2")
    assert pk1.private_bytes_raw() == key1.private_bytes_raw()
    assert pk2.private_bytes_raw() == key2.private_bytes_raw()


def test_signing_keyring_invalid_private_rejected(tmp_path):
    kr = _signing_keyring(tmp_path, keys={"sig-v1": {"private": "not-valid-base64", "public": "dGVzdA=="}})
    with pytest.raises(backup_crypto.BackupKeyUnreadable, match="not valid Ed25519 private key"):
        backup_crypto.load_signing_keyring(str(kr))


def test_signing_keyring_missing_private_rejected(tmp_path):
    kr = _signing_keyring(tmp_path, keys={"sig-v1": {"public": "dGVzdA=="}})
    with pytest.raises(backup_crypto.BackupKeyUnreadable, match="missing 'private' field"):
        backup_crypto.load_signing_keyring(str(kr))


def test_signing_keyring_world_readable_refused(tmp_path):
    kr = _signing_keyring(tmp_path, mode=0o644)
    with pytest.raises(backup_crypto.BackupKeyUnreadable):
        backup_crypto.load_signing_keyring(str(kr))


def test_verification_keyring_loads_public_keys(tmp_path):
    kr = _verification_keyring(tmp_path)
    pub_keys = backup_crypto.load_verification_keyring(str(kr))
    assert "sig-v1" in pub_keys
    assert isinstance(pub_keys["sig-v1"], Ed25519PublicKey)


def test_verification_keyring_multiple_keys(tmp_path):
    key1 = Ed25519PrivateKey.generate()
    key2 = Ed25519PrivateKey.generate()
    keys = {
        "sig-v1": {"public": base64.b64encode(key1.public_key().public_bytes_raw()).decode("ascii")},
        "sig-v2": {"public": base64.b64encode(key2.public_key().public_bytes_raw()).decode("ascii")},
    }
    kr = _verification_keyring(tmp_path, keys=keys)
    pub_keys = backup_crypto.load_verification_keyring(str(kr))
    assert set(pub_keys.keys()) == {"sig-v1", "sig-v2"}


def test_verification_keyring_invalid_key_skipped(tmp_path):
    kr = _verification_keyring(tmp_path, keys={"sig-v1": {"public": "not-valid-base64"}})
    with pytest.raises(backup_crypto.BackupKeyUnreadable, match="no valid public keys"):
        backup_crypto.load_verification_keyring(str(kr))


def test_sign_verify_manifest_round_trip():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    manifest = {
        "version": "1.0",
        "algorithm": "AES-256-GCM",
        "encrypted": True,
        "created_at": "2026-11-27T00:00:00Z",
        "members": {"data/test.txt": {"encrypted": True, "nonce": "00" * 12, "tag": "00" * 16, "size": 100}},
        "key_id": "v1",
        "hmac": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    }

    signature = backup_crypto.sign_manifest(manifest, private_key)
    assert len(signature) == 64  # Ed25519 signature is 64 bytes

    assert backup_crypto.verify_manifest_signature(manifest, public_key, signature) is True

    # Tampered manifest should fail
    tampered = dict(manifest)
    tampered["members"]["data/test.txt"]["size"] = 999
    assert backup_crypto.verify_manifest_signature(tampered, public_key, signature) is False

    # Wrong key should fail
    other_key = Ed25519PrivateKey.generate().public_key()
    assert backup_crypto.verify_manifest_signature(manifest, other_key, signature) is False


def test_backup_signing_and_verification_round_trip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    signing_kr = _signing_keyring(tmp_path / "signing")
    verify_kr = _verification_keyring(tmp_path / "verify", keys={
        "sig-v1": {"public": json.loads(signing_kr.read_text())["keys"]["sig-v1"]["public"]}
    })

    monkeypatch.setenv(backup_crypto.SIGNING_KEYRING_ENV, str(signing_kr))
    monkeypatch.setenv(backup_crypto.VERIFICATION_KEYRING_ENV, str(verify_kr))
    monkeypatch.setenv(backup_crypto.REQUIRE_SIGNATURE_ENV, "true")

    _data_dir(tmp_path)
    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Verify manifest has signature
    with zipfile.ZipFile(backup["path"]) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        assert "signature" in manifest
        assert "signing_key_id" in manifest
        assert manifest["signing_key_id"] == "sig-v1"

    # Restore should succeed
    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()
    result = service.restore_backup(backup["filename"], offline=True)
    assert result["data_restored"] is True
    assert result["encrypted"] is True


def test_backup_tampered_signature_fails_restore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    signing_kr = _signing_keyring(tmp_path / "signing")
    verify_kr = _verification_keyring(tmp_path / "verify", keys={
        "sig-v1": {"public": json.loads(signing_kr.read_text())["keys"]["sig-v1"]["public"]}
    })

    monkeypatch.setenv(backup_crypto.SIGNING_KEYRING_ENV, str(signing_kr))
    monkeypatch.setenv(backup_crypto.VERIFICATION_KEYRING_ENV, str(verify_kr))
    monkeypatch.setenv(backup_crypto.REQUIRE_SIGNATURE_ENV, "true")

    _data_dir(tmp_path)
    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    # Tamper with signature
    archive_path = Path(backup["path"])
    with zipfile.ZipFile(archive_path, "r") as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    manifest = json.loads(members["manifest.json"])
    manifest["signature"] = base64.b64encode(b"tampered").decode("ascii")
    members["manifest.json"] = json.dumps(manifest, indent=2).encode()
    with zipfile.ZipFile(archive_path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()
    with pytest.raises(RuntimeError, match="signature verification failed|tampered"):
        service.restore_backup(backup["filename"], offline=True)


def test_backup_require_signature_without_verification_keyring_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    signing_kr = _signing_keyring(tmp_path / "signing")
    monkeypatch.setenv(backup_crypto.SIGNING_KEYRING_ENV, str(signing_kr))
    # NO verification keyring
    monkeypatch.setenv(backup_crypto.REQUIRE_SIGNATURE_ENV, "true")

    _data_dir(tmp_path)
    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()
    with pytest.raises(RuntimeError, match="verification keyring"):
        service.restore_backup(backup["filename"], offline=True)


def test_backup_unsigned_when_required_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    verify_kr = _verification_keyring(tmp_path / "verify")
    monkeypatch.setenv(backup_crypto.VERIFICATION_KEYRING_ENV, str(verify_kr))
    monkeypatch.setenv(backup_crypto.REQUIRE_SIGNATURE_ENV, "true")

    _data_dir(tmp_path)
    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()
    with pytest.raises(RuntimeError, match="missing signature"):
        service.restore_backup(backup["filename"], offline=True)


def test_backup_legacy_unsigned_restores_when_not_required(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    verify_kr = _verification_keyring(tmp_path / "verify")
    monkeypatch.setenv(backup_crypto.VERIFICATION_KEYRING_ENV, str(verify_kr))
    monkeypatch.setenv(backup_crypto.REQUIRE_SIGNATURE_ENV, "false")

    _data_dir(tmp_path)
    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()
    result = service.restore_backup(backup["filename"], offline=True)
    assert result["data_restored"] is True
    assert result["encrypted"] is True


def test_backup_signed_optional_verification_succeeds(tmp_path, monkeypatch):
    """Signed backup restores successfully when verification keyring provided but not required."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    signing_kr = _signing_keyring(tmp_path / "signing")
    verify_kr = _verification_keyring(tmp_path / "verify", keys={
        "sig-v1": {"public": json.loads(signing_kr.read_text())["keys"]["sig-v1"]["public"]}
    })

    monkeypatch.setenv(backup_crypto.SIGNING_KEYRING_ENV, str(signing_kr))
    monkeypatch.setenv(backup_crypto.VERIFICATION_KEYRING_ENV, str(verify_kr))
    # REQUIRE_SIGNATURE not set (defaults to false)

    _data_dir(tmp_path)
    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    import shutil
    shutil.rmtree(tmp_path / "data")
    (tmp_path / "data").mkdir()
    result = service.restore_backup(backup["filename"], offline=True)
    assert result["data_restored"] is True
    assert result["encrypted"] is True


def test_list_backups_reports_signature_info(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(backup_crypto.KEYRING_ENV, str(_keyring(tmp_path)))
    monkeypatch.delenv(backup_crypto.EXCEPTION_ENV, raising=False)

    signing_kr = _signing_keyring(tmp_path / "signing")
    monkeypatch.setenv(backup_crypto.SIGNING_KEYRING_ENV, str(signing_kr))

    _data_dir(tmp_path)
    service = BackupService(backup_dir=str(tmp_path / "backups"))
    backup = service.create_full_backup()

    rows = service.list_backups()
    assert len(rows) == 1
    assert rows[0]["signature_present"] is True
    assert rows[0]["hmac_present"] is True
    assert rows[0]["signing_key_id"] == "sig-v1"
