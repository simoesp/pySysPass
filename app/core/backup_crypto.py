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

HMAC-SHA256 integrity verification (IMPL-008):
- Computed over concatenated encrypted member ciphertexts (sorted by name)
- Included in manifest as base64-encoded ``hmac`` field
- Verified on restore before any decryption

Ed25519 manifest signing (IMPL-009):
- Optional signing keyring via ``BACKUP_SIGNING_KEYRING``
- Signature over canonical JSON manifest (excluding ``signature`` field)
- Included in manifest as base64-encoded ``signature`` field
- Verified on restore when ``BACKUP_VERIFICATION_KEYRING`` provided
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import zipfile
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
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


class BackupKeyMissing(BackupCryptoError):
    """No usable backup encryption key is configured."""


class BackupKeyUnreadable(BackupCryptoError):
    """The key file exists but cannot be parsed or is insufficiently protected."""


class BackupDecryptionFailed(BackupCryptoError):
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
    raise BackupKeyMissing(
        "No backup encryption key configured: set "
        f"{KEYRING_ENV} to a keyring file (checked {', '.join(str(p) for p in DEFAULT_KEYRING_PATHS)})"
    )


def _check_keyring_permissions(path: Path) -> None:
    if os.name != "posix":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise BackupKeyUnreadable(
            f"Backup keyring {path} is readable/writable by group or others "
            f"(mode {mode:04o}); ADR-0013 requires 0400"
        )


def _load_keyring(path: Path) -> dict:
    _check_keyring_permissions(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupKeyUnreadable(f"Backup keyring {path} is unreadable: {exc}") from exc
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, dict) or not keys:
        raise BackupKeyUnreadable(
            f"Backup keyring {path} has no 'keys' map (expected "
            '{"current": "<id>", "keys": {"<id>": "<64 hex>"}})'
        )
    return data


def _decode_key(key_id: str, raw: object, *, path: Path) -> bytes:
    if not KEY_ID_PATTERN.match(key_id):
        raise BackupKeyUnreadable(f"Backup keyring {path} has an invalid key id {key_id!r}")
    if not isinstance(raw, str) or len(raw) != 64:
        raise BackupKeyUnreadable(
            f"Backup key {key_id!r} in {path} must be 32 bytes (64 hex characters)"
        )
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise BackupKeyUnreadable(f"Backup key {key_id!r} in {path} is not valid hex") from exc
    if len(key) != 32:
        raise BackupKeyUnreadable(f"Backup key {key_id!r} in {path} must be exactly 32 bytes")
    return key


def current_key(keyring_path: Optional[str] = None) -> tuple[str, bytes]:
    """Return ``(key_id, key)`` for the keyring's current key."""
    path = _keyring_path(keyring_path)
    data = _load_keyring(path)
    key_id = data.get("current")
    if not isinstance(key_id, str) or key_id not in data["keys"]:
        raise BackupKeyUnreadable(
            f"Backup keyring {path} 'current' id is missing or not present in 'keys'"
        )
    return key_id, _decode_key(key_id, data["keys"][key_id], path=path)


def key_for_id(key_id: str, keyring_path: Optional[str] = None) -> bytes:
    """Return the key stored under ``key_id`` (historical keys stay usable)."""
    path = _keyring_path(keyring_path)
    data = _load_keyring(path)
    keys = data["keys"]
    if key_id not in keys:
        raise BackupKeyMissing(
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
    """AES-256-GCM open. Raises BackupDecryptionFailed on tag mismatch."""
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except InvalidTag as exc:
        raise BackupDecryptionFailed(
            "Backup authentication failed: wrong key or the archive was "
            "tampered with or corrupted"
        ) from exc


# ── HMAC-SHA256 Integrity (IMPL-008) ─────────────────────────────────────────

HMAC_ALGORITHM = "SHA256"
SIGNING_KEYRING_ENV = "BACKUP_SIGNING_KEYRING"
VERIFICATION_KEYRING_ENV = "BACKUP_VERIFICATION_KEYRING"
REQUIRE_SIGNATURE_ENV = "BACKUP_REQUIRE_SIGNATURE"


def compute_hmac_sha256(data: bytes, key: bytes) -> bytes:
    """Compute HMAC-SHA256 of ``data`` using ``key``. Returns 32-byte digest."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac_sha256(data: bytes, key: bytes, expected_hmac: bytes) -> bool:
    """Constant-time HMAC-SHA256 verification."""
    computed = compute_hmac_sha256(data, key)
    return hmac.compare_digest(computed, expected_hmac)


def _collect_encrypted_member_ciphertexts(archive_path: Path) -> bytes:
    """Collect all encrypted member ciphertexts concatenated in sorted order.
    
    Only members marked as encrypted in the manifest are included.
    Returns empty bytes if no manifest or no encrypted members.
    """
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            if MANIFEST_NAME not in archive.namelist():
                return b""
            manifest = json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
            members = manifest.get("members", {})
            encrypted_names = sorted(
                name for name, info in members.items() if info.get("encrypted")
            )
            if not encrypted_names:
                return b""
            ciphertexts = []
            for name in encrypted_names:
                ciphertexts.append(archive.read(name))
            return b"".join(ciphertexts)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError):
        return b""


def _load_signing_keyring(path: str, *, key_id: Optional[str] = None) -> tuple[str, Ed25519PrivateKey]:
    """Load Ed25519 private signing key from keyring.
    
    Keyring format: {"current": "sig-v1", "keys": {"sig-v1": {"private": "<base64>", "public": "<base64>"}}}
    """
    _check_keyring_permissions(Path(path))
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupKeyUnreadable(f"Signing keyring {path} is unreadable: {exc}") from exc
    
    keys = data.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise BackupKeyUnreadable(f"Signing keyring {path} has no 'keys' map")
    
    target_id = key_id or data.get("current")
    if not isinstance(target_id, str) or target_id not in keys:
        raise BackupKeyMissing(f"Signing key {target_id!r} not found in keyring {path}")
    
    key_data = keys[target_id]
    if not isinstance(key_data, dict) or "private" not in key_data:
        raise BackupKeyUnreadable(f"Signing key {target_id!r} missing 'private' field")
    
    try:
        private_bytes = base64.b64decode(key_data["private"])
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    except (ValueError, Exception) as exc:
        raise BackupKeyUnreadable(f"Signing key {target_id!r} is not valid Ed25519 private key: {exc}") from exc
    
    return target_id, private_key


def _load_verification_keyring(path: str) -> dict[str, Ed25519PublicKey]:
    """Load Ed25519 public verification keys from keyring."""
    _check_keyring_permissions(Path(path))
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupKeyUnreadable(f"Verification keyring {path} is unreadable: {exc}") from exc
    
    keys = data.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise BackupKeyUnreadable(f"Verification keyring {path} has no 'keys' map")
    
    public_keys = {}
    for key_id, key_data in keys.items():
        if not isinstance(key_data, dict) or "public" not in key_data:
            continue
        try:
            public_bytes = base64.b64decode(key_data["public"])
            public_keys[key_id] = Ed25519PublicKey.from_public_bytes(public_bytes)
        except (ValueError, Exception):
            continue
    
    if not public_keys:
        raise BackupKeyUnreadable(f"Verification keyring {path} has no valid public keys")
    
    return public_keys


def _canonical_manifest_bytes(manifest: dict) -> bytes:
    """Serialize manifest to canonical JSON for signing (excludes signature, signing_key_id, and backup_size fields)."""
    # Create a copy without signature, signing_key_id, and backup_size fields
    # backup_size is added after the archive is written, so it can't be included in the signature
    signing_manifest = {k: v for k, v in manifest.items() if k not in ("signature", "signing_key_id", "backup_size")}
    return json.dumps(signing_manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_manifest(manifest: dict, private_key: Ed25519PrivateKey) -> bytes:
    """Sign canonical manifest with Ed25519 private key. Returns 64-byte signature."""
    data = _canonical_manifest_bytes(manifest)
    return private_key.sign(data)


def verify_manifest_signature(manifest: dict, public_key: Ed25519PublicKey, signature: bytes) -> bool:
    """Verify Ed25519 signature over canonical manifest."""
    data = _canonical_manifest_bytes(manifest)
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def verify_archive_before_extract(
    archive_path: Path,
    encryption_keyring: Optional[str] = None,
    verification_keyring: Optional[str] = None,
    require_signature: Optional[bool] = None,
) -> bool:
    """Verify archive integrity and authenticity before extraction.
    
    Checks:
    1. HMAC-SHA256 over encrypted member ciphertexts (if encrypted backup)
    2. AES-256-GCM authentication of every encrypted member (confirms the
       encryption key itself, so a wrong key reports "wrong key" rather than
       surfacing later as an HMAC mismatch)
    3. Ed25519 signature over manifest. A verification keyring is an explicit
       authenticity policy: when one is configured (or a signature is
       required), the manifest must carry a valid signature — a missing
       signature fails closed.
    
    Raises RuntimeError on verification failure. Returns True on success.
    """
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            if MANIFEST_NAME not in archive.namelist():
                # Legacy archive - no manifest, no HMAC, no signature
                return True
            
            manifest = json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
            encrypted = manifest.get("encrypted", False)
            
            # 1. Verify encrypted backup authenticity and integrity, in the
            # causally correct order.
            if encrypted:
                hmac_b64 = manifest.get("hmac")
                if not hmac_b64:
                    raise RuntimeError("Backup manifest missing HMAC (integrity verification failed)")
                try:
                    expected_hmac = base64.b64decode(hmac_b64)
                except Exception as exc:
                    raise RuntimeError(f"Backup manifest HMAC is not valid base64: {exc}") from exc
                
                ciphertexts = _collect_encrypted_member_ciphertexts(archive_path)
                
                # Load the HMAC key using the key_id from the manifest (same key used for encryption)
                key_id = manifest.get("key_id")
                if not key_id:
                    raise RuntimeError("Backup manifest missing key_id for HMAC verification")
                hmac_key = key_for_id(key_id, encryption_keyring)
                
                # a) AES-256-GCM authentication of each member, keyed by the
                # manifest key_id. This is the only check that can prove the
                # encryption key itself is correct, and it runs BEFORE the
                # HMAC comparison so a wrong key — which also breaks the HMAC
                # match, because the HMAC key is the same keyring key — is
                # reported as "wrong key" instead of masquerading as
                # tampering. On failure the two signals are cross-checked to
                # name the true cause:
                #   - GCM fails + the stored HMAC still matches under the
                #     key that produced it -> the ciphertexts are provably the
                #     originals, so only the key can be wrong: report
                #     "wrong key".
                #   - otherwise (HMAC also mismatches, or no oracle is
                #     available) -> report as a verification failure without
                #     blaming the key.
                # Malformed or missing entries are skipped here so the
                # dedicated extraction errors still surface.
                members = manifest.get("members", {})
                gcm_evidence: Optional[BackupDecryptionFailed] = None
                with zipfile.ZipFile(archive_path, "r") as data_archive:
                    for name, info in members.items():
                        if not info.get("encrypted"):
                            continue
                        try:
                            nonce = bytes.fromhex(info["nonce"])
                            tag = bytes.fromhex(info["tag"])
                            raw = data_archive.read(name)
                        except (KeyError, TypeError, ValueError):
                            continue  # extraction checks report malformed entries
                        try:
                            open_bytes(raw, nonce, tag, hmac_key)
                        except BackupDecryptionFailed as exc:
                            if gcm_evidence is None:
                                gcm_evidence = exc
                if gcm_evidence is not None:
                    oracle_key: Optional[bytes] = None
                    oracle_keyring = os.environ.get(KEYRING_ENV)
                    try:
                        if oracle_keyring and Path(oracle_keyring) != _keyring_path(encryption_keyring):
                            oracle_key = key_for_id(key_id, oracle_keyring)
                    except BackupCryptoError:
                        oracle_key = None
                    if oracle_key is not None and verify_hmac_sha256(
                        ciphertexts, oracle_key, expected_hmac
                    ):
                        raise gcm_evidence
                    raise RuntimeError(
                        "Backup archive verification failed: "
                        f"{gcm_evidence}"
                    )
                
                # b) HMAC over the concatenated ciphertexts (chain-of-custody
                # check; also covers member set/truncation anomalies) once the
                # key itself has been authenticated.
                if not verify_hmac_sha256(ciphertexts, hmac_key, expected_hmac):
                    raise RuntimeError("Backup HMAC verification failed: archive tampered or corrupted")
            
            # 3. Ed25519 signature verification (authenticity policy):
            #   - an explicit requirement (BACKUP_REQUIRE_SIGNATURE) fails
            #     closed: a keyring must exist and the manifest must carry a
            #     valid signature;
            #   - otherwise, if a verification keyring is configured, the
            #     signature is optional in spirit but never weakly accepted:
            #     present signatures must verify (and their key must be
            #     known), so a tampered or foreign signature blocks restore
            #     instead of being skipped.
            sig_required = require_signature or os.environ.get(REQUIRE_SIGNATURE_ENV, "").strip().lower() in ("1", "true", "yes", "on")
            verify_kr_path = verification_keyring or os.environ.get(VERIFICATION_KEYRING_ENV)
            
            signature_b64 = manifest.get("signature")
            has_signature = signature_b64 is not None
            
            if sig_required:
                # Explicit policy: the manifest must be signed and verifiable.
                if not has_signature:
                    raise RuntimeError("Backup manifest missing signature (authenticity verification failed)")
                if not verify_kr_path:
                    raise RuntimeError("Signature verification required but no verification keyring provided")
            
            if verify_kr_path and (has_signature or "signing_key_id" in manifest):
                # A configured verification keyring never weakly accepts a
                # signature: when the manifest declares a signing key, the
                # signature must be present, resolve to a known key and
                # verify — a stripped, tampered or foreign signature blocks
                # restore instead of being silently skipped. Archives that
                # were never signed (no signing keyring at creation, hence no
                # signing_key_id) pass unless the explicit requirement above
                # rejects them.
                if not has_signature:
                    raise RuntimeError("Backup manifest missing signature (authenticity verification failed)")
                
                try:
                    signature = base64.b64decode(signature_b64)
                except Exception as exc:
                    raise RuntimeError(f"Backup manifest signature is not valid base64: {exc}") from exc
                
                pub_keys = load_verification_keyring(verify_kr_path)
                key_id = manifest.get("signing_key_id")
                if not key_id or key_id not in pub_keys:
                    raise RuntimeError(f"Backup signing key '{key_id}' not found in verification keyring")
                
                if not verify_manifest_signature(manifest, pub_keys[key_id], signature):
                    raise RuntimeError("Backup signature verification failed: manifest tampered or wrong key")
            # else: no verification keyring configured - nothing to
            # authenticate against
            
            return True
            
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        if isinstance(exc, zipfile.BadZipFile):
            raise RuntimeError(f"Backup archive verification failed: BadZipFile - {exc}") from exc
        raise RuntimeError(f"Backup archive verification failed: {exc}") from exc


# ── Public Keyring Loaders ───────────────────────────────────────────────────

def load_signing_keyring(path: str, *, key_id: Optional[str] = None) -> tuple[str, Ed25519PrivateKey]:
    """Load Ed25519 private signing key from keyring.
    
    Keyring format: {"current": "sig-v1", "keys": {"sig-v1": {"private": "<base64>", "public": "<base64>"}}}
    
    Args:
        path: Path to the signing keyring file
        key_id: Optional specific key ID to load (defaults to "current" in keyring)
    
    Returns:
        Tuple of (key_id, Ed25519PrivateKey)
    
    Raises:
        BackupKeyUnreadable: If keyring cannot be read or parsed
        BackupKeyMissing: If specified key_id not found
    """
    return _load_signing_keyring(path, key_id=key_id)


def load_verification_keyring(path: str) -> dict[str, Ed25519PublicKey]:
    """Load Ed25519 public verification keys from keyring.
    
    Keyring format: {"current": "sig-v1", "keys": {"sig-v1": {"private": "<base64>", "public": "<base64>"}}}
    Only the "public" field is used.
    
    Args:
        path: Path to the verification keyring file
    
    Returns:
        Dict mapping key_id to Ed25519PublicKey
    
    Raises:
        BackupKeyUnreadable: If keyring cannot be read or has no valid public keys
    """
    return _load_verification_keyring(path)
