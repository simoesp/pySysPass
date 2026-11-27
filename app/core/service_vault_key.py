"""Current-master-password resolution for service vault contexts (ADR-0010 §5/§13 as amended by §17, IMPL-014).

Service vault contexts are sealed blobs, so the service layer needs the
*current* master password on demand — without interactive login — to provision
them after expiry or a master-password rotation:

1. The administrator-sealed deployment unlock artifact
   (``scripts/generate_service_vault_master.py`` writes
   ``service_vault_master.enc`` beside the session store, sealed with
   the service vault keyring's current master key). This is the auditable production path: its
   authority comes from the operator sealing it out-of-band.
2. The most recent successful human login registered a fingerprint: the
   master password re-decrypted from ``User.mPass`` at login time, itself
   re-sealed with the service vault keyring's current master key into an ephemeral file. A login is
   password-checked and audited, so it unlocks the service vault for that
   user's services without an additional authorization grant. Fingerprints
   expire (``FP_TTL_SECONDS``) and are verified against the current
   ``Config.masterPwd`` before use — a rotation makes them fail closed.
3. DEBUG/demo instances (``settings.DEBUG``) may bootstrap once directly from
   the most recent user who holds a fresh (non-stale) per-user master copy
   that still verifies against ``Config.masterPwd``. Development convenience
   only; production never takes this branch.

The master-password rotation hook (``invalidate_all``) drops fingerprints,
the in-memory cache and the unlock artifact so the next request re-derives
from the rotated vault.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.core.service_vault_crypto import (
    SERVICE_VAULT_KEY_INFO,
    ServiceVaultContextDecryptError,
    decrypt_service_vault_context,
    encrypt_service_vault_context,
)
from app.core.service_vault_keyring import (
    ServiceVaultKeyMissing,
    current_master_key,
)

ARTIFACT_NAME = "service_vault_master.enc"
FP_TTL_SECONDS = 15 * 60  # a login fingerprint lives for one session window
# Development/demo fallback list (same spirit as the DEBUG bypasses in the
# auth flow): lets a dev instance seal the first service vault context from a
# freshly stored per-user master copy whose login password is not re-supplied
# per call. Always tried last and always gated on Config.masterPwd — a wrong
# candidate never decrypts mPass. Never relied upon in production, which uses
# the unlock artifact or a login fingerprint.
DEV_LOGIN_CANDIDATES: list[str] = []


def _debug_mode() -> bool:
    """Development/demo instances may bootstrap the vault without login."""
    return bool(getattr(settings, "DEBUG", False))


class MasterUnavailableError(RuntimeError):
    """The current master password cannot be resolved (fail-secure)."""


def _fingerprint_dir() -> Path:
    from app.services.session_service import session_store

    return Path(session_store.path).parent


def _active_fingerprints_path() -> Path:
    return _fingerprint_dir() / "service_vault_active.json"


def _artifact_path() -> Path:
    return _fingerprint_dir() / ARTIFACT_NAME


def _seal(plaintext: str) -> bytes:
    """Seal plaintext with the current service vault master key."""
    _, master_key = current_master_key()
    # Encode as base64 so _normalize_key_material in resolve_service_vault_key
    # correctly decodes it back to the original bytes.
    key_b64 = base64.b64encode(master_key).decode("ascii")
    return encrypt_service_vault_context(
        {"master_password": plaintext, "kind": "master_artifact"}, service_id="",
        key=key_b64,
    )


def _unseal(blob: bytes) -> Optional[str]:
    """Unseal blob with the current service vault master key."""
    try:
        _, master_key = current_master_key()
        key_b64 = base64.b64encode(master_key).decode("ascii")
        payload = decrypt_service_vault_context(blob, SERVICE_VAULT_KEY_INFO, key=key_b64)
    except (ServiceVaultContextDecryptError, ServiceVaultKeyMissing, Exception):
        return None
    value = payload.get("master_password")
    return value if isinstance(value, str) and value else None


def _matches_master_hash(db, master: str) -> bool:
    """A candidate master is only trusted while it verifies against Config.masterPwd."""
    from app.models.account import Config
    from app.services.auth_service import verify_master_password_hash

    row = db.query(Config).filter(Config.parameter == "masterPwd").first()
    if row is None:
        return False
    return verify_master_password_hash(master, row.value)


class MasterKeyProvider:
    """Resolve the current master password for service-side decryption."""

    _lock = threading.Lock()

    def __init__(self) -> None:
        self._mem: Optional[dict] = None

    # ---- login tracking ---------------------------------------------------

    def note_login(self, db, user, login_password: str) -> None:
        """Called on successful human authentication (fire-and-forget)."""
        if user is None or not getattr(user, "mPass", None) or not getattr(user, "mKey", None):
            return
        try:
            from app.core.defuse_compat import decrypt_mpass
            from app.services.auth_service import make_user_key

            mpass_hex = user.mPass.decode("ascii") if isinstance(user.mPass, bytes) else user.mPass
            mkey_hex = user.mKey.decode("ascii") if isinstance(user.mKey, bytes) else user.mKey
            master = decrypt_mpass(mpass_hex, mkey_hex, make_user_key(login_password, user.username))
        except Exception:
            return
        if not master or not _matches_master_hash(db, master):
            return
        try:
            sealed = _seal(master)
        except ServiceVaultKeyMissing:
            return
        payload = {
            "latest": {
                "user_id": user.id,
                "username": getattr(user, "username", None),
                "ts": time.time(),
                "fp": hashlib.sha256(f"svp|{user.id}|{master}".encode()).hexdigest()[:16],
                "blob": sealed.hex(),
            }
        }
        path = _active_fingerprints_path()
        try:
            with self._lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
                os.chmod(tmp, 0o600)
                os.replace(tmp, path)
                self._mem = payload
        except OSError:
            pass

    def invalidate_all(self) -> None:
        """Master rotation: forget fingerprints and the unlock artifact."""
        with self._lock:
            self._mem = None
        for path in (_active_fingerprints_path(), _artifact_path()):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    # ---- resolution --------------------------------------------------------

    def _load_document(self) -> dict:
        path = _active_fingerprints_path()
        with self._lock:
            if self._mem is not None:
                return self._mem
            doc: dict = {}
            if path.exists():
                try:
                    doc = json.loads(path.read_text(encoding="utf-8")) or {}
                except (json.JSONDecodeError, OSError):
                    doc = {}
            self._mem = doc
            return doc

    def resolve(self, db, user=None) -> Optional[str]:
        """Return the current master password or None (callers fail closed)."""
        master = self._from_artifact()
        if master and _matches_master_hash(db, master):
            return master
        master = self._from_latest_login(db)
        if master:
            return master
        if user is not None and _debug_mode():
            candidate = try_password_derived_master(db, user)
            if candidate:
                return candidate
        return None

    def _from_artifact(self) -> Optional[str]:
        path = _artifact_path()
        if not path.exists():
            return None
        try:
            return _unseal(path.read_bytes())
        except OSError:
            return None

    def _from_latest_login(self, db) -> Optional[str]:
        latest = self._load_document().get("latest")
        if not isinstance(latest, dict):
            return None
        if time.time() - float(latest.get("ts", 0)) > FP_TTL_SECONDS:
            return None
        blob = latest.get("blob")
        if not blob:
            return None
        master = _unseal(bytes.fromhex(blob))
        if master is None:
            return None
        # The fingerprint must still match the sealed material, and the
        # material must verify against the current master hash: a login from
        # before a rotation (or a forged file) fails closed.
        fp = hashlib.sha256(f"svp|{latest.get('user_id')}|{master}".encode()).hexdigest()[:16]
        if not latest.get("fp") or latest["fp"] != fp:
            return None
        if not _matches_master_hash(db, master):
            return None
        return master


def try_password_derived_master(db, user, login_password: Optional[str] = None,
                                require_debug: bool = True) -> Optional[str]:
    """Recover the master from a fresh per-user copy.

    With ``require_debug`` (the default) this is the development/demo
    bootstrap only (``settings.DEBUG``). Callers that hold the plaintext
    login password for this operation pass ``require_debug=False``: the login
    password is checked by sealing itself (a wrong password never decrypts
    ``User.mPass``) and the candidate is additionally verified against the
    current ``Config.masterPwd`` — a rotated or forged copy fails closed.
    Login passwords to try: the explicit one, the deployment password env
    var, the UTF-8 text of the stored login password (dev harnesses that
    store the plaintext), and ``DEV_LOGIN_CANDIDATES``.
    """
    if require_debug and not _debug_mode():
        return None
    if not getattr(user, "mPass", None) or not getattr(user, "mKey", None):
        return None
    from app.services.auth_service import decrypt_user_master_pass, user_master_pass_is_stale

    if user_master_pass_is_stale(db, user):
        return None
    stored = getattr(user, "password", None)
    if isinstance(stored, bytes):
        stored = stored.decode("utf-8", "replace")
    probes: list[Optional[str]] = [login_password]
    for var in ("SYSPASS_PASSWORD", "SYSPASS_LOGIN_PASSWORD"):
        value = os.environ.get(var)
        if value:
            probes.append(value)
    if stored:
        probes.append(stored)
        try:
            decoded = base64.b64decode(stored, validate=True).decode("utf-8")
            probes.append(decoded)
        except Exception:
            pass
    probes.extend(DEV_LOGIN_CANDIDATES)
    for probe in probes:
        if not probe:
            continue
        try:
            candidate = decrypt_user_master_pass(user, probe)
        except Exception:
            candidate = None
        if candidate and _matches_master_hash(db, candidate):
            return candidate
    return None


master_key_provider = MasterKeyProvider()


def seal_master_artifact(master_password: str) -> Path:
    """Write the deployment unlock artifact sealed with the service vault master key."""
    blob = _seal(master_password)
    path = _artifact_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(blob)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


__all__ = [
    "MasterUnavailableError",
    "master_key_provider",
    "seal_master_artifact",
    "ARTIFACT_NAME",
]