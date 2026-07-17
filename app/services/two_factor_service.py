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


AUTHENTICATOR_PLUGIN = "Authenticator"


class TwoFactorStore:
    """Persist per-user 2FA state in PluginData, like PHP's Authenticator plugin.

    Rows use name='Authenticator' and itemId=<user id> — the same location the
    sysPass PHP plugin uses — so no Python-only schema is introduced. The row
    data is JSON: a plaintext "enabled" flag for cheap reads plus a "vault"
    string holding the encrypted secret, pending setup secret, and backup
    codes.
    """

    def __init__(self, db, encryption):
        self.db = db
        self.encryption = encryption

    # -- Internal helpers ---------------------------------------------------

    def _ensure_plugin_row(self) -> None:
        if not self.db.query(Plugin).filter(Plugin.name == AUTHENTICATOR_PLUGIN).first():
            self.db.add(Plugin(name=AUTHENTICATOR_PLUGIN, enabled=True, available=True))
            self.db.flush()

    def _row(self, user_id: int) -> Optional[PluginData]:
        return self.db.query(PluginData).filter(
            PluginData.name == AUTHENTICATOR_PLUGIN,
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
                name=AUTHENTICATOR_PLUGIN, itemId=user_id, data=payload, key=b"",
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
