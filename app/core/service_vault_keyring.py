"""Service vault key hierarchy per ADR-0010 as amended by §17 (IMPL-014).

The service vault key hierarchy provides:
- A versioned keyring for the master SERVICE_VAULT_KEY (root key)
- Per-service DEKs (Data Encryption Keys) wrapped by the master key
- Independent rotation of per-service DEKs
- AAD binding to service identity

Keyring format (JSON file):
{
    "current": "v1",
    "keys": {
        "v1": {"key": "<64 hex chars>", "created_at": "ISO timestamp"},
        "v2": {"key": "<64 hex chars>", "created_at": "ISO timestamp"}
    },
    "service_deks": {
        "<service_id>": {
            "current_version": "v1",
            "versions": {
                "v1": {"wrapped_key": "<base64>", "wrapped_with_key_id": "v1", "created_at": "ISO timestamp"},
                "v2": {"wrapped_key": "<base64>", "wrapped_with_key_id": "v2", "created_at": "ISO timestamp"}
            }
        }
    }
}
"""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import BASE_DIR, settings

# Constants
_KEY_LENGTH = 32  # AES-256
_IV_LENGTH = 12   # AES-GCM standard nonce
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
KEYRING_ENV = "SERVICE_VAULT_KEYRING_PATH"
DEFAULT_KEYRING_PATHS = (
    Path("/etc/syspass/service-vault-keyring.json"),
    BASE_DIR / "config" / "service-vault-keyring.json",
)

# Process-local cache
_keyring_cache: Optional[dict] = None
_keyring_lock = threading.Lock()
_keyring_path_cache: Optional[Path] = None


class ServiceVaultKeyringError(RuntimeError):
    """Base error for service vault keyring failures."""


class ServiceVaultKeyMissing(ServiceVaultKeyringError):
    """No usable service vault key is configured."""


class ServiceVaultKeyUnreadable(ServiceVaultKeyringError):
    """The keyring file exists but cannot be parsed or is insufficiently protected."""


class ServiceVaultDecryptError(ServiceVaultKeyringError):
    """A wrapped DEK failed authenticated decryption."""


def keyring_configured() -> bool:
    """Public gate for the additive key-hierarchy layer (IMPL-010 ruling).

    The §13 DEK hierarchy is operator opt-in: active only with an explicit
    SERVICE_VAULT_KEYRING_PATH. Otherwise the environment/settings SERVICE_VAULT_KEY
    stays authoritative for context sealing (ADR-0010 §3/§5/§12).

    Default paths are NOT auto-discovered for activation; they are only used
    when the operator explicitly initializes a keyring there via CLI.
    """
    return bool(os.environ.get(KEYRING_ENV))


def _keyring_path(explicit: Optional[str] = None) -> Path:
    """Resolve the keyring file path.

    Only returns a path when explicitly requested via argument or
    SERVICE_VAULT_KEYRING_PATH env var. Default paths are not auto-discovered
    for activation (see keyring_configured()).
    """
    global _keyring_path_cache
    if _keyring_path_cache is not None:
        return _keyring_path_cache

    candidate = explicit or os.environ.get(KEYRING_ENV)
    if candidate:
        _keyring_path_cache = Path(candidate)
        return _keyring_path_cache

    # No explicit configuration - return the first default path for creation
    # but this path is NOT considered "configured" for keyring_configured()
    _keyring_path_cache = DEFAULT_KEYRING_PATHS[0]
    return _keyring_path_cache


def _file_has_key_material(path: Path) -> bool:
    """A keyring file counts as adopted only once it holds real key material."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    keys = data.get("keys")
    current = data.get("current")
    return isinstance(keys, dict) and bool(keys) and current in keys


def _check_keyring_permissions(path: Path) -> None:
    """Verify keyring file has restrictive permissions (0400 on POSIX)."""
    if os.name != "posix":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ServiceVaultKeyUnreadable(
            f"Service vault keyring {path} is readable/writable by group or others "
            f"(mode {mode:04o}); ADR-0010 requires 0400"
        )


def _load_keyring(path: Path) -> dict:
    """Load and validate the keyring JSON."""
    _check_keyring_permissions(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ServiceVaultKeyUnreadable(
            f"Service vault keyring {path} is unreadable: {exc}"
        ) from exc

    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, dict) or not keys:
        expected = '{"current": "<id>", "keys": {"<id>": {"key": "<64 hex>"}}}'
        raise ServiceVaultKeyUnreadable(
            f"Service vault keyring {path} has no 'keys' map "
            f"(expected {expected})"
        )
    return data


def _save_keyring(path: Path, data: dict) -> None:
    """Atomically save the keyring JSON with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o400)
    tmp.replace(path)
    # Invalidate cache
    global _keyring_cache
    with _keyring_lock:
        _keyring_cache = None


def _decode_key(key_id: str, key_data: dict, *, path: Path) -> bytes:
    """Decode a key from the keyring."""
    if not _KEY_ID_PATTERN.match(key_id):
        raise ServiceVaultKeyUnreadable(
            f"Service vault keyring {path} has an invalid key id {key_id!r}"
        )
    if not isinstance(key_data, dict) or "key" not in key_data:
        raise ServiceVaultKeyUnreadable(
            f"Service vault key {key_id!r} in {path} missing 'key' field"
        )
    raw = key_data["key"]
    if not isinstance(raw, str) or len(raw) != 64:
        raise ServiceVaultKeyUnreadable(
            f"Service vault key {key_id!r} in {path} must be 32 bytes (64 hex characters)"
        )
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ServiceVaultKeyUnreadable(
            f"Service vault key {key_id!r} in {path} is not valid hex"
        ) from exc
    if len(key) != _KEY_LENGTH:
        raise ServiceVaultKeyUnreadable(
            f"Service vault key {key_id!r} in {path} must be exactly {_KEY_LENGTH} bytes"
        )
    return key


def _get_keyring() -> dict:
    """Get the cached keyring, loading if necessary."""
    global _keyring_cache
    with _keyring_lock:
        if _keyring_cache is not None:
            return _keyring_cache
        path = _keyring_path()
        if not path.is_file():
            raise ServiceVaultKeyMissing(
                "No service vault keyring configured: set "
                f"{KEYRING_ENV} to a keyring file (checked {', '.join(str(p) for p in DEFAULT_KEYRING_PATHS)})"
            )
        _keyring_cache = _load_keyring(path)
        return _keyring_cache


def current_master_key(keyring_path: Optional[str] = None) -> tuple[str, bytes]:
    """Return (key_id, key) for the keyring's current master key.

    ADR-0010 §3 acceptance ruling (IMPL-010): the keyring hierarchy is an
    additive, operator-opt-in layer. With no explicit configuration and no
    keyring file carrying real key material, a caller holding only this
    entry point (e.g. the unlock-artifact seal) falls back to the
    environment/settings SERVICE_VAULT_KEY — which stays authoritative for
    everything else, since the SEAM derives its keys from the environment
    directly (get_service_dek with master_key_override / the flat path).
    """
    if keyring_path:
        # Temporarily override cache
        global _keyring_path_cache, _keyring_cache
        old_path = _keyring_path_cache
        old_cache = _keyring_cache
        _keyring_path_cache = Path(keyring_path)
        _keyring_cache = None
        try:
            return _current_master_key_impl()
        finally:
            _keyring_path_cache = old_path
            _keyring_cache = old_cache
    try:
        return _current_master_key_impl()
    except ServiceVaultKeyMissing:
        if keyring_configured():
            raise
        raw = os.environ.get("SERVICE_VAULT_KEY")
        if raw:
            candidate = _normalize_key_material(raw)
            if (isinstance(raw, str) and len(raw) == _KEY_LENGTH * 2
                    and all(c in "0123456789abcdefABCDEF" for c in raw)):
                candidate = bytes.fromhex(raw)
            if len(candidate) >= _KEY_LENGTH:
                return "env:SERVICE_VAULT_KEY", candidate[:_KEY_LENGTH]
        raise


def _current_master_key_impl() -> tuple[str, bytes]:
    data = _get_keyring()
    key_id = data.get("current")
    if not isinstance(key_id, str) or key_id not in data["keys"]:
        raise ServiceVaultKeyUnreadable(
            f"Service vault keyring {_keyring_path()} 'current' id is missing or not present in 'keys'"
        )
    return key_id, _decode_key(key_id, data["keys"][key_id], path=_keyring_path())


def _master_key_for_id_impl(key_id: str) -> bytes:
    data = _get_keyring()
    keys = data["keys"]
    if key_id not in keys:
        raise ServiceVaultKeyMissing(
            f"Service vault master key {key_id!r} is not in keyring {_keyring_path()}; "
            "historical contexts need their original key retained"
        )
    return _decode_key(key_id, keys[key_id], path=_keyring_path())


def master_key_for_id(key_id: str, keyring_path: Optional[str] = None) -> bytes:
    """Return the master key stored under key_id (historical keys stay usable)."""
    if keyring_path:
        global _keyring_path_cache, _keyring_cache
        old_path = _keyring_path_cache
        old_cache = _keyring_cache
        _keyring_path_cache = Path(keyring_path)
        _keyring_cache = None
        try:
            return _master_key_for_id_impl(key_id)
        finally:
            _keyring_path_cache = old_path
            _keyring_cache = old_cache
    return _master_key_for_id_impl(key_id)


def _list_master_key_versions_impl() -> list[str]:
    data = _get_keyring()
    return sorted(data["keys"].keys())


def list_master_key_versions(keyring_path: Optional[str] = None) -> list[str]:
    """List all master key versions in the keyring."""
    if keyring_path:
        global _keyring_path_cache, _keyring_cache
        old_path = _keyring_path_cache
        old_cache = _keyring_cache
        _keyring_path_cache = Path(keyring_path)
        _keyring_cache = None
        try:
            return _list_master_key_versions_impl()
        finally:
            _keyring_path_cache = old_path
            _keyring_cache = old_cache
    return _list_master_key_versions_impl()


def _normalize_key_material(raw: Any) -> bytes:
    """Coerce configured key material to bytes (str utf-8, base64/hex 32B, bytes)."""
    if isinstance(raw, bytes):
        return raw[:_KEY_LENGTH] if len(raw) > _KEY_LENGTH else raw
    text = str(raw).strip()
    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception:
        decoded = b""
    if decoded and len(decoded) == _KEY_LENGTH and len(text) == 44:
        return decoded
    encoded = text.encode("utf-8")
    return encoded[:_KEY_LENGTH] if len(encoded) > _KEY_LENGTH else encoded


def init_keyring(key_id: str = "v1", keyring_path: Optional[str] = None) -> dict:
    """Initialize a new keyring with the first master key."""
    path = Path(keyring_path) if keyring_path else _keyring_path()
    if path.is_file():
        data = _load_keyring(path)
        if data.get("current") in data.get("keys", {}):
            raise ServiceVaultKeyUnreadable(
                f"Keyring {path} already has current key {data['current']!r}; use rotate"
            )

    if not _KEY_ID_PATTERN.match(key_id):
        raise ServiceVaultKeyUnreadable(f"Invalid key id {key_id!r}")

    # Check for SERVICE_VAULT_KEY environment variable for backward compatibility
    env_key = os.environ.get("SERVICE_VAULT_KEY")
    if env_key:
        candidate = _normalize_key_material(env_key)
        if (isinstance(env_key, str) and len(env_key) == _KEY_LENGTH * 2
                and all(c in "0123456789abcdefABCDEF" for c in env_key)):
            candidate = bytes.fromhex(env_key)
        if len(candidate) >= _KEY_LENGTH:
            key = candidate[:_KEY_LENGTH].hex()
        else:
            key = os.urandom(_KEY_LENGTH).hex()
    else:
        key = os.urandom(_KEY_LENGTH).hex()
    
    now = datetime.now(UTC).isoformat()
    data = {
        "current": key_id,
        "keys": {key_id: {"key": key, "created_at": now}},
        "service_deks": {},
    }
    _save_keyring(path, data)
    return {"initialized": True, "keyring": str(path), "key_id": key_id}


def rotate_master_key(key_id: str, keyring_path: Optional[str] = None) -> dict:
    """Add a new current master key version, retaining old versions."""
    path = Path(keyring_path) if keyring_path else _keyring_path()
    data = _get_keyring() if path.is_file() else {"current": None, "keys": {}, "service_deks": {}}

    if not _KEY_ID_PATTERN.match(key_id):
        raise ServiceVaultKeyUnreadable(f"Invalid key id {key_id!r}")
    if key_id in data["keys"]:
        raise ServiceVaultKeyUnreadable(f"Version {key_id!r} already in keyring")

    key = os.urandom(_KEY_LENGTH).hex()
    now = datetime.now(UTC).isoformat()
    data["keys"][key_id] = {"key": key, "created_at": now}
    data["current"] = key_id
    _save_keyring(path, data)

    retained = sorted(k for k in data["keys"] if k != key_id)
    return {"rotated": True, "keyring": str(path), "key_id": key_id, "retained": retained}


# ─── Per-Service DEK Management ────────────────────────────────────────────

def _wrap_dek(dek: bytes, master_key: bytes, service_id: str) -> tuple[bytes, bytes]:
    """Wrap (encrypt) a DEK with the master key using AES-256-GCM.
    Returns (wrapped_key, nonce).
    """
    # Use HKDF to derive a wrapping key from master_key + service_id
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        info=b"pysyspass-service-dek-wrap-v1",
        salt=service_id.encode("utf-8"),
    ).derive(master_key)

    aesgcm = AESGCM(wrapping_key)
    nonce = os.urandom(_IV_LENGTH)
    # AAD binds to service_id
    aad = f"dek-wrap|{service_id}".encode("utf-8")
    wrapped = aesgcm.encrypt(nonce, dek, aad)
    # Return nonce + ciphertext+tag (AESGCM returns ciphertext+tag concatenated)
    return nonce + wrapped, nonce


def _unwrap_dek(wrapped_blob: bytes, master_key: bytes, service_id: str) -> bytes:
    """Unwrap (decrypt) a DEK with the master key using AES-256-GCM."""
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        info=b"pysyspass-service-dek-wrap-v1",
        salt=service_id.encode("utf-8"),
    ).derive(master_key)

    aesgcm = AESGCM(wrapping_key)
    nonce = wrapped_blob[:_IV_LENGTH]
    ciphertext = wrapped_blob[_IV_LENGTH:]
    aad = f"dek-wrap|{service_id}".encode("utf-8")
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise ServiceVaultDecryptError(
            f"Failed to unwrap DEK for service {service_id}: {exc}"
        ) from exc


def _unwrap_dek_with_candidates(
    wrapped_blob: bytes,
    service_id: str,
    master_keys: "list[tuple[str, bytes]]",
) -> bytes:
    """Unwrap only with a master that provably wrapped this DEK.

    The recorded ``wrapped_with_key_id`` is part of the keyring's integrity
    metadata: a caller-supplied SERVICE_VAULT_KEY (env authority, ADR-0010
    §3/§5/§12) that is not the deployment keyring master must NOT unlock the
    DEK — "master password cannot open the vault" is a security contract
    (IMPL-010 ruling item 2: the keyring may decrypt compatibly only with its
    own recorded master; the caller key never silently unlocks foreign DEKs).
    """
    for _label, mk in master_keys:
        try:
            return _unwrap_dek(wrapped_blob, mk, service_id)
        except ServiceVaultDecryptError:
            continue
    raise ServiceVaultDecryptError(
        f"Failed to unwrap DEK for service {service_id}: "
        "no configured master key matches the recorded wrapping key"
    )


def get_service_dek(
    service_id: str,
    *,
    keyring_path: Optional[str] = None,
    master_key_override: Optional[bytes] = None,
) -> tuple[str, bytes]:
    """Get the current DEK for a service, unwrapping it from the keyring.
    Returns (dek_version, dek_bytes).
    """
    path = Path(keyring_path) if keyring_path else _keyring_path()
    data = _get_keyring() if path.is_file() else {"service_deks": {}}

    service_deks = data.get("service_deks", {}).get(service_id)
    if not service_deks:
        raise ServiceVaultKeyMissing(f"No DEK found for service {service_id}")

    current_version = service_deks.get("current_version")
    versions = service_deks.get("versions", {})
    if not current_version or current_version not in versions:
        raise ServiceVaultKeyMissing(f"No current DEK version for service {service_id}")

    version_info = versions[current_version]
    wrapped_key_b64 = version_info["wrapped_key"]
    wrapped_with_key_id = version_info["wrapped_with_key_id"]

    wrapped_key = base64.b64decode(wrapped_key_b64)

    if master_key_override is not None:
        # A caller-supplied SERVICE_VAULT_KEY is checked against the keyring's
        # *recorded* master for this DEK: an env key that is not the deployment
        # keyring master must not silently unlock foreign DEKs. The vault
        # context AEAD tag remains the final decision either way.
        candidates: list = []
        try:
            recorded = master_key_for_id(wrapped_with_key_id, keyring_path)
        except (ServiceVaultKeyMissing, ServiceVaultKeyUnreadable):
            recorded = None
        if recorded is not None and recorded == master_key_override:
            candidates.append(("override", master_key_override))
        # No match: fall through to the generic raise below via empty list —
        # but honor the override when the keyring has no recorded master for
        # the DEK (hand-written keyrings); the tag still discriminates.
        if not candidates and recorded is None:
            candidates.append(("override-only", master_key_override))
        if not candidates:
            raise ServiceVaultDecryptError(
                f"Failed to unwrap DEK for service {service_id}: caller key "
                "does not match the recorded wrapping key"
            )
        dek = _unwrap_dek_with_candidates(wrapped_key, service_id, candidates)
    else:
        master_key = master_key_for_id(wrapped_with_key_id, keyring_path)
        dek = _unwrap_dek(wrapped_key, master_key, service_id)
    return current_version, dek


def provision_service_dek(
    service_id: str,
    *,
    keyring_path: Optional[str] = None,
    master_key_id: Optional[str] = None,
) -> dict:
    """Generate a new DEK for a service and wrap it with the current master key.
    Returns info about the provisioned DEK.
    """
    path = Path(keyring_path) if keyring_path else _keyring_path()
    data = _get_keyring() if path.is_file() else {"current": None, "keys": {}, "service_deks": {}}

    # Determine which master key to use
    if master_key_id is None:
        master_key_id, master_key = current_master_key(keyring_path)
    else:
        master_key = master_key_for_id(master_key_id, keyring_path)

    # Generate new DEK
    dek = os.urandom(_KEY_LENGTH)
    dek_version = f"dek-{int(datetime.now(UTC).timestamp() * 1000)}"

    # Wrap the DEK
    wrapped_blob, _ = _wrap_dek(dek, master_key, service_id)
    wrapped_b64 = base64.b64encode(wrapped_blob).decode("ascii")

    now = datetime.now(UTC).isoformat()

    # Update service DEKs
    if "service_deks" not in data:
        data["service_deks"] = {}
    if service_id not in data["service_deks"]:
        data["service_deks"][service_id] = {"current_version": None, "versions": {}}

    data["service_deks"][service_id]["versions"][dek_version] = {
        "wrapped_key": wrapped_b64,
        "wrapped_with_key_id": master_key_id,
        "created_at": now,
    }
    data["service_deks"][service_id]["current_version"] = dek_version

    _save_keyring(path, data)

    return {
        "service_id": service_id,
        "dek_version": dek_version,
        "wrapped_with_key_id": master_key_id,
        "created_at": now,
    }


def rotate_service_dek(
    service_id: str,
    *,
    keyring_path: Optional[str] = None,
    master_key_id: Optional[str] = None,
) -> dict:
    """Rotate the DEK for a specific service (independent rotation).
    Generates a new DEK wrapped with the current (or specified) master key.
    """
    return provision_service_dek(
        service_id, keyring_path=keyring_path, master_key_id=master_key_id
    )


def rewrap_service_deks(
    service_id: str,
    new_master_key_id: str,
    *,
    keyring_path: Optional[str] = None,
) -> dict:
    """Rewrap a service's current DEK with a new master key version.
    Used during master key rotation to migrate DEKs to the new key.
    """
    path = Path(keyring_path) if keyring_path else _keyring_path()
    data = _get_keyring()

    service_deks = data.get("service_deks", {}).get(service_id)
    if not service_deks:
        raise ServiceVaultKeyMissing(f"No DEK found for service {service_id}")

    current_version = service_deks.get("current_version")
    versions = service_deks.get("versions", {})
    if not current_version or current_version not in versions:
        raise ServiceVaultKeyMissing(f"No current DEK version for service {service_id}")

    version_info = versions[current_version]
    old_wrapped_b64 = version_info["wrapped_key"]
    old_master_key_id = version_info["wrapped_with_key_id"]

    # Unwrap with old master key
    old_master_key = master_key_for_id(old_master_key_id, keyring_path)
    wrapped_blob = base64.b64decode(old_wrapped_b64)
    dek = _unwrap_dek(wrapped_blob, old_master_key, service_id)

    # Rewrap with new master key
    new_master_key = master_key_for_id(new_master_key_id, keyring_path)
    new_wrapped_blob, _ = _wrap_dek(dek, new_master_key, service_id)
    new_wrapped_b64 = base64.b64encode(new_wrapped_blob).decode("ascii")

    # Update version info
    now = datetime.now(UTC).isoformat()
    versions[current_version] = {
        "wrapped_key": new_wrapped_b64,
        "wrapped_with_key_id": new_master_key_id,
        "created_at": now,
        "rewrapped_from": old_master_key_id,
    }

    _save_keyring(path, data)

    return {
        "service_id": service_id,
        "dek_version": current_version,
        "rewrapped_from": old_master_key_id,
        "rewrapped_to": new_master_key_id,
        "created_at": now,
    }


def rewrap_all_service_deks(
    new_master_key_id: str,
    *,
    keyring_path: Optional[str] = None,
) -> dict:
    """Rewrap all service DEKs with a new master key version.
    Called during master key rotation to migrate all DEKs.
    """
    path = Path(keyring_path) if keyring_path else _keyring_path()
    data = _get_keyring()

    service_deks = data.get("service_deks", {})
    rewrapped = []
    failed = []

    for service_id in service_deks:
        try:
            result = rewrap_service_deks(
                service_id, new_master_key_id, keyring_path=keyring_path
            )
            rewrapped.append(result)
        except Exception as exc:
            failed.append({"service_id": service_id, "error": str(exc)})

    return {
        "rewrapped": rewrapped,
        "failed": failed,
        "total": len(service_deks),
    }


def delete_service_dek(service_id: str, *, keyring_path: Optional[str] = None) -> bool:
    """Delete all DEK versions for a service (e.g., on service account deletion)."""
    path = Path(keyring_path) if keyring_path else _keyring_path()
    data = _get_keyring()

    if "service_deks" in data and service_id in data["service_deks"]:
        del data["service_deks"][service_id]
        _save_keyring(path, data)
        return True
    return False


# ─── CLI Interface ────────────────────────────────────────────────────────

def _cli_keyring_path() -> Path:
    """Get keyring path for CLI, respecting env var."""
    return _keyring_path()


def cli_status() -> int:
    """Report keyring state."""
    path = _cli_keyring_path()
    if not path.is_file():
        print(json.dumps({
            "keyring": str(path),
            "usable": False,
            "detail": "keyring file does not exist",
        }))
        return 1
    try:
        data = _load_keyring(path)
        print(json.dumps({
            "keyring": str(path),
            "usable": True,
            "current_master_key": data.get("current"),
            "master_key_versions": sorted(data["keys"].keys()),
            "service_deks_count": len(data.get("service_deks", {})),
        }))
        return 0
    except ServiceVaultKeyUnreadable as exc:
        print(json.dumps({
            "keyring": str(path),
            "usable": False,
            "detail": str(exc),
        }))
        return 1


def cli_init(args) -> int:
    """Initialize the keyring."""
    try:
        result = init_keyring(args.key_id, args.keyring_path)
        print(json.dumps(result))
        return 0
    except ServiceVaultKeyUnreadable as exc:
        print(json.dumps({"initialized": False, "error": str(exc)}), file=sys.stderr)
        return 1


def cli_rotate(args) -> int:
    """Rotate the master key."""
    try:
        result = rotate_master_key(args.key_id, args.keyring_path)
        print(json.dumps(result))
        return 0
    except ServiceVaultKeyUnreadable as exc:
        print(json.dumps({"rotated": False, "error": str(exc)}), file=sys.stderr)
        return 1


def cli_provision_dek(args) -> int:
    """Provision a DEK for a service."""
    try:
        result = provision_service_dek(args.service_id, keyring_path=args.keyring_path)
        print(json.dumps(result))
        return 0
    except ServiceVaultKeyringError as exc:
        print(json.dumps({"provisioned": False, "error": str(exc)}), file=sys.stderr)
        return 1


def cli_rotate_dek(args) -> int:
    """Rotate a service's DEK."""
    try:
        result = rotate_service_dek(args.service_id, keyring_path=args.keyring_path)
        print(json.dumps(result))
        return 0
    except ServiceVaultKeyringError as exc:
        print(json.dumps({"rotated": False, "error": str(exc)}), file=sys.stderr)
        return 1


def cli_rewrap_all(args) -> int:
    """Rewrap all DEKs with a new master key."""
    try:
        result = rewrap_all_service_deks(args.new_master_key_id, keyring_path=args.keyring_path)
        print(json.dumps(result))
        return 0
    except ServiceVaultKeyringError as exc:
        print(json.dumps({"rewrapped": False, "error": str(exc)}), file=sys.stderr)
        return 1


def cli_delete_dek(args) -> int:
    """Delete a service's DEK."""
    try:
        result = delete_service_dek(args.service_id, keyring_path=args.keyring_path)
        print(json.dumps({"deleted": result}))
        return 0
    except ServiceVaultKeyringError as exc:
        print(json.dumps({"deleted": False, "error": str(exc)}), file=sys.stderr)
        return 1


def main(argv=None) -> int:
    """CLI entry point for service vault keyring management."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Manage the ADR-0010 service vault key hierarchy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--keyring-path",
        help=f"Path to keyring file (default: {KEYRING_ENV} or {DEFAULT_KEYRING_PATHS[0]})",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("status", help="Report keyring state")

    p_init = commands.add_parser("init", help="Generate the first master key")
    p_init.add_argument("--key-id", default="v1")

    p_rot = commands.add_parser("rotate", help="Add a new current master key version")
    p_rot.add_argument("--key-id", required=True)

    p_prov = commands.add_parser("provision-dek", help="Provision a DEK for a service")
    p_prov.add_argument("service_id")

    p_rot_dek = commands.add_parser("rotate-dek", help="Rotate a service's DEK")
    p_rot_dek.add_argument("service_id")

    p_rewrap = commands.add_parser("rewrap-all", help="Rewrap all DEKs with a new master key")
    p_rewrap.add_argument("new_master_key_id")

    p_del = commands.add_parser("delete-dek", help="Delete a service's DEK")
    p_del.add_argument("service_id")

    args = parser.parse_args(argv)

    if args.command == "status":
        return cli_status()
    if args.command == "init":
        return cli_init(args)
    if args.command == "rotate":
        return cli_rotate(args)
    if args.command == "provision-dek":
        return cli_provision_dek(args)
    if args.command == "rotate-dek":
        return cli_rotate_dek(args)
    if args.command == "rewrap-all":
        return cli_rewrap_all(args)
    if args.command == "delete-dek":
        return cli_delete_dek(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())