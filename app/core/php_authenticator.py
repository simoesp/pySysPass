"""Native sysPass Authenticator plugin data (R5 / #56).

The PHP plugin (sysPass/plugin-Authenticator, commit b304661) stores one
``PluginData`` row per user: ``name='Authenticator'``, ``itemId=<user id>``,
``data = Crypt::encrypt(serialize(AuthenticatorData))`` and ``key`` the
password-protected key, both under the vault master password
(``PluginOperation`` + ``EncryptedModel``). This module reads and writes that
format without instantiating PHP objects.
"""
from dataclasses import dataclass, field
import base64
import secrets
from typing import List, Optional

from app.core.defuse_compat import decrypt_with_password, encrypt_with_password
from app.core.php_public_link import AUTHENTICATOR_CLASS, _object, _php_object

PLUGIN_NAME = "Authenticator"
# Plugin::RECOVERY_GRACE_TIME and the upgrade level PHP records for the
# current data format (UpgradeService::upgrade_310_19012201).
PLUGIN_VERSION_LEVEL = "310.19012201"


@dataclass
class AuthenticatorState:
    user_id: Optional[int] = None
    enabled: bool = False
    date: Optional[int] = None
    expire_days: Optional[int] = None
    iv: Optional[str] = None  # Base32 TOTP seed
    recovery_codes: List[str] = field(default_factory=list)
    last_recovery_time: int = 0


def make_initialization_key() -> str:
    """AuthenticatorService::makeInitializationKey(): Base32 of 32 random bytes as hex, 16 chars."""
    hex_bytes = secrets.token_hex(32).encode("ascii")
    return base64.b32encode(hex_bytes).decode("ascii")[:16]


def generate_recovery_codes() -> List[str]:
    """AuthenticatorService::generateRecoveryCodes(): ten 10-byte hex codes."""
    return [secrets.token_hex(10) for _ in range(10)]


def serialize_state(state: AuthenticatorState) -> bytes:
    # Property order and types follow AuthenticatorData's declarations.
    return _php_object(AUTHENTICATOR_CLASS, [
        ("userId", state.user_id),
        ("twofaEnabled", int(bool(state.enabled))),  # setTwofaEnabled() casts to int
        ("date", state.date),
        ("expireDays", state.expire_days),
        ("IV", state.iv),
        ("recoveryCodes", list(state.recovery_codes)),
        ("lastRecoveryTime", int(state.last_recovery_time or 0)),
    ])


def parse_state(serialized: bytes) -> AuthenticatorState:
    props = _object(serialized, AUTHENTICATOR_CLASS)

    def text(name: bytes) -> Optional[str]:
        value = props.get(name)
        return value.decode("utf-8") if isinstance(value, bytes) else None

    def number(name: bytes) -> Optional[int]:
        value = props.get(name)
        if isinstance(value, bytes) and value.isdigit():
            return int(value)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    codes = props.get(b"recoveryCodes") or {}
    if not isinstance(codes, dict):
        raise ValueError("Invalid Authenticator recovery codes")
    enabled = props.get(b"twofaEnabled")
    return AuthenticatorState(
        user_id=number(b"userId"),
        enabled=bool(enabled) and enabled not in (b"0", b""),
        date=number(b"date"),
        expire_days=number(b"expireDays"),
        iv=text(b"IV"),
        recovery_codes=[c.decode("utf-8") for _, c in sorted(codes.items()) if isinstance(c, bytes)],
        last_recovery_time=number(b"lastRecoveryTime") or 0,
    )


def encrypt_state(state: AuthenticatorState, master_password: str) -> tuple[bytes, bytes]:
    """PluginData.data / PluginData.key, as EncryptedModel::encrypt() writes them."""
    data_hex, key_hex = encrypt_with_password(serialize_state(state).decode("utf-8"), master_password)
    return data_hex.encode("ascii"), key_hex.encode("ascii")


def decrypt_state(data: bytes, key: bytes, master_password: str) -> AuthenticatorState:
    plaintext = decrypt_with_password(data.decode("ascii"), key.decode("ascii"), master_password)
    return parse_state(plaintext.encode("utf-8"))


def is_native_row(key) -> bool:
    raw = key.decode("ascii", "ignore") if isinstance(key, (bytes, bytearray)) else str(key or "")
    return raw.startswith("def10000")
