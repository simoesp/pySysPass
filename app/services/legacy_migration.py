"""Retire the legacy pySysPass storage formats (R5 / #56, R8 / #58).

Earlier pySysPass releases stored some values with ``ENCRYPTION_KEY`` in
formats sysPass PHP cannot read: account and history passwords with an empty
``key``, 2FA state as a JSON document, and public links whose ``data`` is an
optional encrypted access password. Current releases read them but never
write them. This migration rewrites them as PHP does:

* account/history passwords: Defuse ciphertext under the vault master
  password (history rows get the current ``masterPwd`` as ``mPassHash``);
* 2FA: the Authenticator plugin's ``AuthenticatorData`` under the master;
* public links: NOT converted. A legacy link shows metadata only, while a
  native PHP link reveals the password, so converting would widen exposure.
  They are reported, and removed only with ``drop_links=True`` so owners can
  recreate them deliberately.

Once nothing persisted depends on ``ENCRYPTION_KEY``, the key can be rotated
by changing the setting and ending all sessions (``docs/backup-recovery.md``).
"""
from dataclasses import dataclass, field
import json
import time
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.core.defuse_compat import decrypt_account_pass, encrypt_account_pass
from app.core.php_authenticator import AuthenticatorState, decrypt_state, encrypt_state, is_native_row
from app.core.php_public_link import is_php_object
from app.models.account import Account, AccountHistory, Config, PluginData, PublicLink
from app.services.auth_service import verify_master_password_hash
from app.services.two_factor_service import TWO_FACTOR_STORE_NAME


class LegacyMigrationError(RuntimeError):
    """The migration was refused or aborted; nothing was written."""


@dataclass
class LegacyInventory:
    accounts: list = field(default_factory=list)
    history: list = field(default_factory=list)
    two_factor: list = field(default_factory=list)
    links: list = field(default_factory=list)
    failures: list = field(default_factory=list)

    @property
    def remaining(self) -> int:
        return len(self.accounts) + len(self.history) + len(self.two_factor) + len(self.links)

    def summary(self) -> dict:
        return {
            "accounts": len(self.accounts), "history": len(self.history),
            "two_factor": len(self.two_factor), "public_links": len(self.links),
            "failures": self.failures[:20],
        }


def _text(value) -> str:
    if value is None:
        return ""
    return value.decode("ascii", "replace") if isinstance(value, (bytes, bytearray)) else str(value)


def _is_legacy_credential(data, key) -> bool:
    # Native rows carry a Defuse password-protected key; empty rows hold nothing.
    return bool(_text(data)) and not _text(key).startswith("def10000")


class LegacyFormatMigration:
    def __init__(self, db: Session, legacy_decrypt: Callable[[str], str]):
        self.db = db
        self.legacy_decrypt = legacy_decrypt

    def inventory(self) -> LegacyInventory:
        found = LegacyInventory()
        found.accounts = [a for a in self.db.query(Account).all() if _is_legacy_credential(a.pass_, a.key)]
        found.history = [h for h in self.db.query(AccountHistory).all() if _is_legacy_credential(h.pass_, h.key)]
        found.two_factor = [
            row for row in self.db.query(PluginData).filter(PluginData.name == TWO_FACTOR_STORE_NAME).all()
            if row.data and not is_native_row(row.key)
        ]
        found.links = [link for link in self.db.query(PublicLink).all() if not is_php_object(link.data)]
        return found

    def _decrypt_legacy(self, value, label: str, found: LegacyInventory) -> Optional[str]:
        try:
            return self.legacy_decrypt(_text(value))
        except Exception:
            found.failures.append(label)
            return None

    def _legacy_two_factor(self, row, found: LegacyInventory) -> Optional[AuthenticatorState]:
        try:
            raw = row.data.decode("utf-8") if isinstance(row.data, (bytes, bytearray)) else row.data
            doc = json.loads(raw)
            vault = json.loads(self.legacy_decrypt(doc["vault"])) if doc.get("vault") else {}
        except Exception:
            found.failures.append(f"PluginData Authenticator/{row.itemId}")
            return None
        if not doc.get("enabled") or not vault.get("secret"):
            return None  # an unconfirmed setup: PHP would have no row at all
        return AuthenticatorState(
            user_id=row.itemId, enabled=True, date=int(time.time()), expire_days=0,
            iv=vault["secret"], recovery_codes=list(vault.get("backup_codes") or []),
        )

    def check_master(self, master: str) -> str:
        row = self.db.query(Config).filter(Config.parameter == "masterPwd").first()
        if not row or not row.value:
            raise LegacyMigrationError("No master password hash (Config.masterPwd) is set")
        if not verify_master_password_hash(master, row.value):
            raise LegacyMigrationError("The master password does not match")
        return row.value

    def migrate(self, master: str, drop_links: bool = False) -> LegacyInventory:
        """Rewrite every legacy value in one transaction, verifying each."""
        master_hash = self.check_master(master)
        found = self.inventory()
        plaintexts = {}
        for account in found.accounts:
            plaintexts[("a", account.id)] = self._decrypt_legacy(account.pass_, f"Account {account.id}", found)
        for row in found.history:
            plaintexts[("h", row.id)] = self._decrypt_legacy(row.pass_, f"AccountHistory {row.id}", found)
        states = {row.itemId: self._legacy_two_factor(row, found) for row in found.two_factor}
        if found.failures:
            raise LegacyMigrationError(f"{len(found.failures)} legacy value(s) do not decrypt with ENCRYPTION_KEY: "
                                       + ", ".join(found.failures[:10]))
        if found.links and not drop_links:
            raise LegacyMigrationError(
                f"{len(found.links)} legacy public link(s) cannot be converted without exposing passwords; "
                "rerun with link removal and ask owners to recreate them"
            )
        try:
            for account in found.accounts:
                pass_hex, key_hex = encrypt_account_pass(plaintexts[("a", account.id)], master)
                account.pass_, account.key = pass_hex.encode(), key_hex.encode()
                if decrypt_account_pass(pass_hex, key_hex, master) != plaintexts[("a", account.id)]:
                    raise LegacyMigrationError(f"Verification failed for Account {account.id}")
            for row in found.history:
                pass_hex, key_hex = encrypt_account_pass(plaintexts[("h", row.id)], master)
                row.pass_, row.key = pass_hex.encode(), key_hex.encode()
                row.mPassHash = master_hash.encode() if isinstance(master_hash, str) else master_hash
                if decrypt_account_pass(pass_hex, key_hex, master) != plaintexts[("h", row.id)]:
                    raise LegacyMigrationError(f"Verification failed for AccountHistory {row.id}")
            for row in found.two_factor:
                state = states[row.itemId]
                if state is None:
                    self.db.delete(row)
                    continue
                row.data, row.key = encrypt_state(state, master)
                if decrypt_state(row.data, row.key, master).iv != state.iv:
                    raise LegacyMigrationError(f"Verification failed for PluginData Authenticator/{row.itemId}")
            for link in found.links:
                self.db.delete(link)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return found
