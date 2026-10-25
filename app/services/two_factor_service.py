import json
from pathlib import Path
import time
from typing import List, Optional, Tuple

import pyotp

from app.core.config import BASE_DIR
from app.core.php_authenticator import (
    PLUGIN_NAME, PLUGIN_VERSION_LEVEL, AuthenticatorState, decrypt_state, encrypt_state,
    generate_recovery_codes, is_native_row, make_initialization_key,
)
from app.core.runtime_json_config import locked_path, write_text_atomically
from app.models.account import Plugin, PluginData
from app.services.account_service import VaultRequiredError

class TwoFactorService:
    """TOTP-based two-factor authentication service"""

    @staticmethod
    def generate_secret() -> str:
        """Base32 TOTP seed in the PHP Authenticator format (16 characters)."""
        return make_initialization_key()

    @staticmethod
    def generate_provisioning_uri(secret: str, username: str, issuer: str = "sysPass") -> str:
        """Generate a QR code provisioning URI for Google Authenticator, etc."""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)

    @staticmethod
    def verify_token(secret: str, token: str, window: int = 1) -> bool:
        """Verify a TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)

    @staticmethod
    def generate_backup_codes(count: int = 10) -> list:
        """Recovery codes in the PHP Authenticator format (10-byte hex)."""
        return generate_recovery_codes()[:count]

    @staticmethod
    def verify_backup_code(codes: list, code: str) -> Tuple[bool, Optional[str]]:
        """Verify a backup code and return remaining codes"""
        if code in codes:
            codes.remove(code)
            return True, codes
        return False, None


# Storage key for built-in 2FA state in the Plugin/PluginData tables.
# The name matches the sysPass PHP Authenticator plugin; 2FA itself is a
# built-in feature here (the plugins API hides and refuses this reserved row).
TWO_FACTOR_STORE_NAME = PLUGIN_NAME
PENDING_SETUP_SECONDS = 900


class _PendingSetups:
    """Unconfirmed enrollment secrets, outside the PHP tables.

    PHP's Authenticator writes PluginData only when 2FA is enabled, so a
    PluginData row means "enrolled" to both applications. Pending secrets
    live in data/two-factor-pending.json (mode 0600, encrypted with
    ENCRYPTION_KEY, expire after PENDING_SETUP_SECONDS).
    """

    def __init__(self, encryption):
        self.encryption = encryption

    @staticmethod
    def _path() -> Path:
        return BASE_DIR / "data" / "two-factor-pending.json"

    def _read(self) -> dict:
        try:
            document = json.loads(self._path().read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}
        now = time.time()
        return {k: v for k, v in document.items() if isinstance(v, dict) and v.get("expires", 0) > now}

    def _update(self, change) -> None:
        path = self._path()
        with locked_path(path):
            document = self._read()
            change(document)
            write_text_atomically(path, json.dumps(document, sort_keys=True) + "\n")

    def put(self, user_id: int, secret: str) -> None:
        entry = {"secret": self.encryption.encrypt(secret), "expires": time.time() + PENDING_SETUP_SECONDS}
        self._update(lambda doc: doc.__setitem__(str(user_id), entry))

    def get(self, user_id: int) -> Optional[str]:
        entry = self._read().get(str(user_id))
        if not entry:
            return None
        try:
            return self.encryption.decrypt(entry["secret"])
        except Exception:
            return None

    def clear(self, user_id: int) -> None:
        self._update(lambda doc: doc.pop(str(user_id), None))


class TwoFactorStore:
    """Per-user 2FA state in the PHP Authenticator plugin's native format.

    New and updated rows are PHP ``AuthenticatorData`` encrypted under the vault
    master password (see app.core.php_authenticator), so sysPass PHP's plugin
    reads them. Rows written by earlier pySysPass releases (JSON with an
    ENCRYPTION_KEY vault) remain readable; disabling 2FA removes them.
    """

    def __init__(self, db, encryption, master_pass: Optional[str] = None):
        self.db = db
        self.encryption = encryption
        self.master_pass = master_pass
        self.pending = _PendingSetups(encryption)

    # -- Internal helpers ---------------------------------------------------

    def _ensure_plugin_row(self) -> None:
        if not self.db.query(Plugin).filter(Plugin.name == TWO_FACTOR_STORE_NAME).first():
            # Record PHP's current upgrade level so its plugin upgrade never
            # tries to unserialize Plugin.data.
            self.db.add(Plugin(name=TWO_FACTOR_STORE_NAME, enabled=True, available=True,
                               versionLevel=PLUGIN_VERSION_LEVEL))
            self.db.flush()

    def _row(self, user_id: int) -> Optional[PluginData]:
        return self.db.query(PluginData).filter(
            PluginData.name == TWO_FACTOR_STORE_NAME,
            PluginData.itemId == user_id,
        ).first()

    def _native(self, row) -> Optional[AuthenticatorState]:
        if row is None or not is_native_row(row.key):
            return None
        if not self.master_pass:
            raise VaultRequiredError("Master password required to read two-factor settings")
        data = row.data if isinstance(row.data, bytes) else str(row.data or "").encode()
        key = row.key if isinstance(row.key, bytes) else str(row.key).encode()
        return decrypt_state(data, key, self.master_pass)

    def _legacy(self, row) -> dict:
        """Legacy pySysPass JSON document: plaintext flag plus ENCRYPTION_KEY vault."""
        if row is None or not row.data or is_native_row(row.key):
            return {"enabled": False, "vault": {}}
        raw = row.data
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="ignore")
        try:
            doc = json.loads(raw)
        except ValueError:
            return {"enabled": False, "vault": {}}
        vault = {}
        if doc.get("vault"):
            try:
                vault = json.loads(self.encryption.decrypt(doc["vault"]))
            except Exception:
                vault = {}
        return {"enabled": bool(doc.get("enabled")), "vault": vault, "doc": doc}

    def _save_native(self, user_id: int, state: AuthenticatorState) -> None:
        if not self.master_pass:
            raise VaultRequiredError("Master password required to change two-factor settings")
        data, key = encrypt_state(state, self.master_pass)
        row = self._row(user_id)
        if row:
            row.data, row.key = data, key
        else:
            self._ensure_plugin_row()
            self.db.add(PluginData(name=TWO_FACTOR_STORE_NAME, itemId=user_id, data=data, key=key))
        self.db.commit()

    # -- Public API ---------------------------------------------------------

    def is_enabled(self, user_id: int) -> bool:
        row = self._row(user_id)
        if row is None:
            return False
        if is_native_row(row.key):
            # PHP stores a row only for enrolled users; decode when possible.
            return self._native(row).enabled if self.master_pass else True
        return self._legacy(row)["enabled"]

    def start_setup(self, user_id: int, secret: str) -> None:
        """Remember a pending secret; 2FA stays disabled until enable() confirms."""
        self.pending.put(user_id, secret)

    def get_pending_secret(self, user_id: int) -> Optional[str]:
        return self.pending.get(user_id)

    def enable(self, user_id: int, backup_codes: List[str]) -> None:
        """Promote the pending secret (PHP AuthenticatorController::save2FAStatus)."""
        secret = self.pending.get(user_id)
        if not secret:
            raise ValueError("No 2FA setup in progress")
        self._save_native(user_id, AuthenticatorState(
            user_id=user_id, enabled=True, date=int(time.time()), expire_days=0,
            iv=secret, recovery_codes=list(backup_codes),
        ))
        self.pending.clear(user_id)

    def disable(self, user_id: int) -> None:
        row = self._row(user_id)
        if row:
            self.db.delete(row)
            self.db.commit()

    def get_secret(self, user_id: int) -> Optional[str]:
        row = self._row(user_id)
        state = self._native(row)
        if state is not None:
            return state.iv if state.enabled else None
        return self._legacy(row)["vault"].get("secret")

    def get_backup_codes(self, user_id: int) -> List[str]:
        row = self._row(user_id)
        state = self._native(row)
        if state is not None:
            return list(state.recovery_codes)
        return self._legacy(row)["vault"].get("backup_codes") or []

    def set_backup_codes(self, user_id: int, codes: List[str]) -> None:
        row = self._row(user_id)
        state = self._native(row)
        if state is not None:
            state.recovery_codes = list(codes)
            state.last_recovery_time = int(time.time())
            self._save_native(user_id, state)
            return
        legacy = self._legacy(row)
        if row is None or "doc" not in legacy:
            return
        vault = legacy["vault"]
        vault["backup_codes"] = codes
        doc = {"enabled": legacy["enabled"], "vault": self.encryption.encrypt(json.dumps(vault))}
        row.data = json.dumps(doc).encode("utf-8")
        self.db.commit()


TWO_FACTOR_MODES = ("disabled", "enabled", "enforced")


class TwoFactorConfig:
    """Global policy for the built-in 2FA feature.

    Mode is a tri-state:
      - disabled: 2FA feature off; no enrollment, no login challenge
      - enabled:  users may enroll; enrolled users must pass a code at login
      - enforced: like enabled, plus non-enrolled users are told to enroll

    Plugin.enabled maps disabled/non-disabled and the mode detail lives in
    Plugin.data JSON, so only upstream schema is used. Plugin sync never
    touches either field for rows without a disk manifest.
    """

    def __init__(self, db):
        self.db = db

    def _row(self) -> Optional[Plugin]:
        return self.db.query(Plugin).filter(Plugin.name == TWO_FACTOR_STORE_NAME).first()

    def get_mode(self) -> str:
        row = self._row()
        if row is None or not row.enabled:
            return "disabled"
        from app.services.config_service import ConfigService

        stored = ConfigService(self.db).get("two_factor_mode")
        if stored in TWO_FACTOR_MODES and stored != "disabled":
            return stored
        if row.data:
            # Earlier pySysPass releases kept the mode as JSON in Plugin.data.
            raw = row.data
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", errors="ignore")
            try:
                mode = json.loads(raw).get("mode")
                if mode in TWO_FACTOR_MODES:
                    return mode
            except ValueError:
                pass
        return "enabled"

    def set_mode(self, mode: str) -> str:
        if mode not in TWO_FACTOR_MODES:
            raise ValueError(f"Invalid 2FA mode: {mode!r}")
        from app.services.config_service import ConfigService

        row = self._row()
        if row is None:
            row = Plugin(name=TWO_FACTOR_STORE_NAME, available=True, versionLevel=PLUGIN_VERSION_LEVEL)
            self.db.add(row)
        # PHP enables/disables the plugin through Plugin.enabled. Plugin.data
        # must stay NULL: PHP's plugin upgrade unserializes it.
        row.enabled = mode != "disabled"
        row.data = None
        if not row.versionLevel:
            row.versionLevel = PLUGIN_VERSION_LEVEL
        ConfigService(self.db).set("two_factor_mode", mode)
        self.db.commit()
        return self.get_mode()
