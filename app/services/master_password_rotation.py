"""Offline vault master password change (R8 / #58), as sysPass PHP performs it.

Mirrors PHP ``MasterPassService::changeMasterPassword()``: re-encrypt
``Account.pass/key``, the ``AccountHistory`` rows whose ``mPassHash`` equals the
current ``Config.masterPwd``, and every ``CustomFieldData`` row with a key, then
store ``masterPwd = Hash::hashKey(new)`` and ``lastupdatempass = time()``.
Users then re-enter the master password once at sign-in (PHP MPASS_CHANGED).

Stricter than PHP, deliberately:

* every candidate row is decrypted with the current master before anything is
  written, and any failure aborts the whole change (PHP skips failing rows and
  commits the rest);
* all writes happen in one database transaction and every rewritten value is
  decrypted again with the new master before commit;
* rows in the legacy pySysPass AES format are refused unless explicitly
  converted (``include_legacy``);
* the caller must take a verified backup first and stop every writer.

Public-link Vaults (keyed by the password salt and link hash), user login
hashes, and the built-in 2FA state do not depend on the master password.
"""
from dataclasses import dataclass, field
import time
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.core.defuse_compat import decrypt_account_pass, encrypt_account_pass
from app.models.account import Account, AccountHistory, Config
from app.models.custom_field import CustomFieldValue
from app.services.auth_service import hash_master_key, verify_master_password_hash
from app.services.config_service import ConfigService
from app.services.temporary_master_password_service import TemporaryMasterPasswordService


class RotationError(RuntimeError):
    """The change was refused or aborted; nothing was written."""


@dataclass
class RotationPlan:
    accounts: int = 0
    history: int = 0
    history_skipped: int = 0
    custom_fields: int = 0
    legacy: list = field(default_factory=list)
    failures: list = field(default_factory=list)


def _text(value) -> str:
    if value is None:
        return ""
    return value.decode("ascii") if isinstance(value, (bytes, bytearray)) else str(value)


def _is_native(key) -> bool:
    # Defuse KeyProtectedByPassword ASCII header (\xDE\xF1\x00\x00).
    return _text(key).startswith("def10000")


class MasterPasswordRotation:
    def __init__(self, db: Session, legacy_decrypt: Optional[Callable[[str], str]] = None):
        self.db = db
        self.legacy_decrypt = legacy_decrypt

    def _config(self, parameter: str) -> Optional[Config]:
        return self.db.query(Config).filter(Config.parameter == parameter).first()

    def _set_config(self, parameter: str, value: str) -> None:
        row = self._config(parameter)
        if row:
            row.value = value
        else:
            self.db.add(Config(parameter=parameter, value=value))

    def check_preconditions(self, current: str, new: str) -> str:
        """PHP ConfigEncryptionController::saveAction() checks. Returns the current hash."""
        if not current or not new:
            raise RotationError("Both the current and the new master password are required")
        if current == new:
            raise RotationError("The new master password is the same as the current one")
        row = self._config("masterPwd")
        if not row or not row.value:
            raise RotationError("No master password hash (Config.masterPwd) is set")
        if not verify_master_password_hash(current, row.value):
            raise RotationError("The current master password does not match")
        if not ConfigService(self.db)._bool_val("maintenance"):
            # Same prerequisite as PHP; it also blocks pySysPass non-admin users.
            raise RotationError("Enable maintenance mode before changing the master password")
        return row.value

    def _candidates(self, current_hash: str):
        accounts = self.db.query(Account).filter(Account.pass_.isnot(None)).all()
        history = self.db.query(AccountHistory).all()
        custom = self.db.query(CustomFieldValue).filter(CustomFieldValue.key.isnot(None)).all()
        current_hash_bytes = current_hash.encode() if isinstance(current_hash, str) else current_hash
        rotated_history = [h for h in history if (h.mPassHash or b"") == current_hash_bytes]
        return accounts, rotated_history, len(history) - len(rotated_history), custom

    def _decrypt(self, data, key, master: str, label: str, plan: RotationPlan, include_legacy: bool):
        if _is_native(key):
            try:
                return decrypt_account_pass(_text(data), _text(key), master)
            except Exception:
                plan.failures.append(label)
                return None
        if not _text(data) and not _text(key):
            return ""
        plan.legacy.append(label)
        if not include_legacy or self.legacy_decrypt is None:
            return None
        try:
            return self.legacy_decrypt(_text(data))
        except Exception:
            plan.failures.append(label)
            return None

    def plan(self, current: str, include_legacy: bool = False) -> RotationPlan:
        """Read-only dry run: prove every candidate decrypts with ``current``."""
        current_hash = self._config("masterPwd").value
        accounts, history, skipped, custom = self._candidates(current_hash)
        plan = RotationPlan(len(accounts), len(history), skipped, len(custom))
        for account in accounts:
            self._decrypt(account.pass_, account.key, current, f"Account {account.id}", plan, include_legacy)
        for row in history:
            self._decrypt(row.pass_, row.key, current, f"AccountHistory {row.id}", plan, include_legacy)
        for row in custom:
            self._decrypt(row.data, row.key, current, f"CustomFieldData {row.id}", plan, include_legacy)
        return plan

    def rotate(self, current: str, new: str, include_legacy: bool = False, now: Optional[int] = None) -> RotationPlan:
        """Re-encrypt everything and switch the master hash in one transaction."""
        current_hash = self.check_preconditions(current, new)
        plan = self.plan(current, include_legacy)
        if plan.failures:
            raise RotationError(f"{len(plan.failures)} value(s) do not decrypt with the current master: "
                                + ", ".join(plan.failures[:10]))
        if plan.legacy and not include_legacy:
            raise RotationError(f"{len(plan.legacy)} value(s) use the legacy pySysPass format; "
                                "rerun with legacy conversion to rewrite them natively")
        new_hash = hash_master_key(new)
        rewritten = []
        try:
            accounts, history, _, custom = self._candidates(current_hash)
            scratch = RotationPlan()
            for account in accounts:
                plaintext = self._decrypt(account.pass_, account.key, current, "", scratch, include_legacy)
                pass_hex, key_hex = encrypt_account_pass(plaintext or "", new)
                account.pass_, account.key = pass_hex.encode(), key_hex.encode()
                rewritten.append((account.pass_, account.key, plaintext or ""))
            for row in history:
                plaintext = self._decrypt(row.pass_, row.key, current, "", scratch, include_legacy)
                pass_hex, key_hex = encrypt_account_pass(plaintext or "", new)
                row.pass_, row.key, row.mPassHash = pass_hex.encode(), key_hex.encode(), new_hash.encode()
                rewritten.append((row.pass_, row.key, plaintext or ""))
            for row in custom:
                plaintext = self._decrypt(row.data, row.key, current, "", scratch, include_legacy)
                data_hex, key_hex = encrypt_account_pass(plaintext or "", new)
                row.data, row.key = data_hex.encode(), key_hex.encode()
                rewritten.append((row.data, row.key, plaintext or ""))
            if scratch.failures:
                raise RotationError("Data changed while rotating; aborted")
            for data, key, plaintext in rewritten:
                if decrypt_account_pass(_text(data), _text(key), new) != plaintext:
                    raise RotationError("Verification with the new master password failed; aborted")
            self._set_config("masterPwd", new_hash)
            self._set_config("lastupdatempass", str(int(now or time.time())))
            # A temporary master password unlocks the old master; retire it.
            TemporaryMasterPasswordService(self.db).expire_pending()
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return plan
