"""Backup encryption primitives (ADR-0013: mandatory AES-256-GCM backups).

The published ``.zip`` keeps the pre-ADR-0013 payload members (``database.sql``,
``data/...``) but each member's bytes are AES-256-GCM sealed, and an added
plaintext ``manifest.json`` records the algorithm, key version and per-member
nonces/tags. Restoration is transparent: the service decrypts the payload in a
staging tree before the restore pipeline sees it, so path-traversal and
symlink defenses keep running against *authenticated* plaintext.

The encryption key lives OUTSIDE the backup (ADR-0013: "Backup Encryption Key
... Stored in separate location"): a keyring JSON file. The keyring path comes
from an environment variable so it survives ``python -m`` CLI invocations,
unlike the runtime JSON config store which is relative to the process CWD.

Keyring format::

    {"current": "v1", "keys": {"v1": "<64 hex chars>"}}

The file should be owned by the service account with mode ``0400`` (ADR-0013
restrictive-permissions policy); looser permissions are refused.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "AES-256-GCM"
MANIFEST_NAME = "manifest.json"
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
NONCE_SIZE = 12  # 96-bit, AES-GCM standard
KEYRING_ENV = "BACKUP_KEYRING_PATH"
EXCEPTION_ENV = "BACKUP_ALLOW_UNENCRYPTED"
BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_KEYRING_PATHS = (
    Path("/etc/syspass/backup-keyring.json"),
    BASE_DIR / "config" / "backup-keyring.json",
)


class BackupCryptoError(RuntimeError):
    """Base error for backup encryption failures."""


class BackupKeyMissingError(BackupCryptoError):
    """No usable backup encryption key is configured."""


class BackupKeyUnreadableError(BackupCryptoError):
    """The key file exists but cannot be parsed or is insufficiently protected."""


class BackupDecryptionFailedError(BackupCryptoError):
    """Authentication tag mismatch: wrong key or tampered/corrupted backup."""


def exception_allowed() -> bool:
    """True when an admin set the explicit unencrypted-backup exception."""
    return os.environ.get(EXCEPTION_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _keyring_path(explicit: Optional[str] = None) -> Path:
    candidate = explicit or os.environ.get(KEYRING_ENV)
    if candidate:
        return Path(candidate)
    for path in DEFAULT_KEYRING_PATHS:
        if path.is_file():
            return path
    raise BackupKeyMissingError(
        "No backup encryption key configured: set "
        f"{KEYRING_ENV} to a keyring file (checked {', '.join(str(p) for p in DEFAULT_KEYRING_PATHS)})"
    )


def _check_keyring_permissions(path: Path) -> None:
    if os.name != "posix":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise BackupKeyUnreadableError(
            f"Backup keyring {path} is readable/writable by group or others "
            f"(mode {mode:04o}); ADR-0013 requires 0400"
        )


def _load_keyring(path: Path) -> dict:
    _check_keyring_permissions(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupKeyUnreadableError(f"Backup keyring {path} is unreadable: {exc}") from exc
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, dict) or not keys:
        raise BackupKeyUnreadableError(
            f"Backup keyring {path} has no 'keys' map (expected "
            '{"current": "<id>", "keys": {"<id>": "<64 hex>"}})'
        )
    return data


def _decode_key(key_id: str, raw: object, *, path: Path) -> bytes:
    if not KEY_ID_PATTERN.match(key_id):
        raise BackupKeyUnreadableError(f"Backup keyring {path} has an invalid key id {key_id!r}")
    if not isinstance(raw, str) or len(raw) != 64:
        raise BackupKeyUnreadableError(
            f"Backup key {key_id!r} in {path} must be 32 bytes (64 hex characters)"
        )
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise BackupKeyUnreadableError(f"Backup key {key_id!r} in {path} is not valid hex") from exc
    if len(key) != 32:
        raise BackupKeyUnreadableError(f"Backup key {key_id!r} in {path} must be exactly 32 bytes")
    return key


def current_key(keyring_path: Optional[str] = None) -> tuple[str, bytes]:
    """Return ``(key_id, key)`` for the keyring's current key."""
    path = _keyring_path(keyring_path)
    data = _load_keyring(path)
    key_id = data.get("current")
    if not isinstance(key_id, str) or key_id not in data["keys"]:
        raise BackupKeyUnreadableError(
            f"Backup keyring {path} 'current' id is missing or not present in 'keys'"
        )
    return key_id, _decode_key(key_id, data["keys"][key_id], path=path)


def key_for_id(key_id: str, keyring_path: Optional[str] = None) -> bytes:
    """Return the key stored under ``key_id`` (historical keys stay usable)."""
    path = _keyring_path(keyring_path)
    data = _load_keyring(path)
    keys = data["keys"]
    if key_id not in keys:
        raise BackupKeyMissingError(
            f"Backup key {key_id!r} is not in keyring {path}; historical backups "
            "need their original key retained"
        )
    return _decode_key(key_id, keys[key_id], path=path)


def seal_bytes(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """AES-256-GCM seal. Returns ``(ciphertext, nonce, tag)``."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    sealed = aesgcm.encrypt(nonce, plaintext, None)
    return sealed[:-16], nonce, sealed[-16:]


def open_bytes(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes:
    """AES-256-GCM open. Raises BackupDecryptionFailedError on tag mismatch."""
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except InvalidTag as exc:
        raise BackupDecryptionFailedError(
            "Backup authentication failed: wrong key or the archive was "
            "tampered with or corrupted"
        ) from exc
