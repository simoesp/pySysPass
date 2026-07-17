import json
import pyotp
import secrets
from typing import List, Optional, Tuple

from app.models.account import Plugin, PluginData

class TwoFactorService:
    """TOTP-based two-factor authentication service"""

    @staticmethod
    def generate_secret() -> str:
        """Generate a new base32 secret for TOTP"""
        return pyotp.random_base32()

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
    def generate_backup_codes(count: int = 8) -> list:
        """Generate backup codes for 2FA recovery"""
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice('0123456789') for _ in range(10))
            codes.append(code)
        return codes

    @staticmethod
    def verify_backup_code(codes: list, code: str) -> Tuple[bool, Optional[str]]:
        """Verify a backup code and return remaining codes"""
        if code in codes:
            codes.remove(code)
            return True, codes
        return False, None


# Storage key for built-in 2FA state in the Plugin/PluginData tables.
# The name matches what the sysPass PHP Authenticator plugin used, so
# existing rows keep working; 2FA itself is a built-in feature here,
# not a plugin (the plugins API hides and refuses this reserved row).
TWO_FACTOR_STORE_NAME = "Authenticator"


class TwoFactorStore:
    """Persist per-user state for the built-in 2FA feature.

    Rows live in PluginData under TWO_FACTOR_STORE_NAME with itemId=<user
    id>; the upstream tables double as generic key/value storage, so no
    Python-only schema is introduced. The row data is JSON: a plaintext
    "enabled" flag for cheap reads plus a "vault" string holding the
    encrypted secret, pending setup secret, and backup codes.
    """

    def __init__(self, db, encryption):
        self.db = db
        self.encryption = encryption

    # -- Internal helpers ---------------------------------------------------

    def _ensure_plugin_row(self) -> None:
        if not self.db.query(Plugin).filter(Plugin.name == TWO_FACTOR_STORE_NAME).first():
            self.db.add(Plugin(name=TWO_FACTOR_STORE_NAME, enabled=True, available=True))
            self.db.flush()

    def _row(self, user_id: int) -> Optional[PluginData]:
        return self.db.query(PluginData).filter(
            PluginData.name == TWO_FACTOR_STORE_NAME,
            PluginData.itemId == user_id,
        ).first()

    def _load(self, user_id: int) -> dict:
        row = self._row(user_id)
        if not row or not row.data:
            return {"enabled": False, "vault": None}
        raw = row.data
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="ignore")
        try:
            return json.loads(raw)
        except ValueError:
            return {"enabled": False, "vault": None}

    def _vault(self, doc: dict) -> dict:
        if not doc.get("vault"):
            return {}
        try:
            return json.loads(self.encryption.decrypt(doc["vault"]))
        except Exception:
            return {}

    def _save(self, user_id: int, enabled: bool, vault: dict) -> None:
        doc = {"enabled": enabled, "vault": self.encryption.encrypt(json.dumps(vault))}
        payload = json.dumps(doc).encode("utf-8")
        row = self._row(user_id)
        if row:
            row.data = payload
        else:
            self._ensure_plugin_row()
            self.db.add(PluginData(
                name=TWO_FACTOR_STORE_NAME, itemId=user_id, data=payload, key=b"",
            ))
        self.db.commit()

    # -- Public API ---------------------------------------------------------

    def is_enabled(self, user_id: int) -> bool:
        return bool(self._load(user_id).get("enabled"))

    def start_setup(self, user_id: int, secret: str) -> None:
        """Store a pending secret; 2FA stays disabled until enable() confirms."""
        doc = self._load(user_id)
        vault = self._vault(doc)
        vault["pending_secret"] = secret
        self._save(user_id, bool(doc.get("enabled")), vault)

    def get_pending_secret(self, user_id: int) -> Optional[str]:
        return self._vault(self._load(user_id)).get("pending_secret")

    def enable(self, user_id: int, backup_codes: List[str]) -> None:
        """Promote the pending secret and store backup codes."""
        vault = self._vault(self._load(user_id))
        vault["secret"] = vault.pop("pending_secret")
        vault["backup_codes"] = backup_codes
        self._save(user_id, True, vault)

    def disable(self, user_id: int) -> None:
        row = self._row(user_id)
        if row:
            self.db.delete(row)
            self.db.commit()

    def get_secret(self, user_id: int) -> Optional[str]:
        return self._vault(self._load(user_id)).get("secret")

    def get_backup_codes(self, user_id: int) -> List[str]:
        return self._vault(self._load(user_id)).get("backup_codes") or []

    def set_backup_codes(self, user_id: int, codes: List[str]) -> None:
        doc = self._load(user_id)
        vault = self._vault(doc)
        vault["backup_codes"] = codes
        self._save(user_id, bool(doc.get("enabled")), vault)


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
        if row.data:
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
        row = self._row()
        if row is None:
            row = Plugin(name=TWO_FACTOR_STORE_NAME, available=True)
            self.db.add(row)
        row.enabled = mode != "disabled"
        row.data = json.dumps({"mode": mode}).encode("utf-8")
        self.db.commit()
        return self.get_mode()
