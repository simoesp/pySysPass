"""Native sysPass item presets (``ItemPreset`` rows) and their PHP rules.

sysPass PHP 3.2 stores each preset as ``type`` (``account.permission``,
``account.private``, ``session.timeout``, ``account.password``), ``data`` =
``serialize()`` of an ``SP\\DataModel\\ItemPreset\\*`` object with private
properties, and ``hash`` = ``sha1(type . userId . userGroupId . userProfileId .
priority)``. This module converts between that format and the JSON shape the
pySysPass API exposes, and implements the checks PHP performs with presets.

Earlier pySysPass releases stored ``AccountPermission``-style type names with
JSON data. Those rows are read as legacy (shown, never applied) and are
rewritten natively when edited.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Optional

from app.core.php_public_link import _object, _php_object

ACCOUNT_PERMISSION = "account.permission"
ACCOUNT_PRIVATE = "account.private"
SESSION_TIMEOUT = "session.timeout"
ACCOUNT_PASSWORD = "account.password"
TYPES = (ACCOUNT_PERMISSION, ACCOUNT_PRIVATE, SESSION_TIMEOUT, ACCOUNT_PASSWORD)
LEGACY_TYPES = {
    "AccountPermission": ACCOUNT_PERMISSION,
    "AccountPrivate": ACCOUNT_PRIVATE,
    "SessionTimeout": SESSION_TIMEOUT,
    "Password": ACCOUNT_PASSWORD,
}
_CLASSES = {
    ACCOUNT_PERMISSION: b"SP\\DataModel\\ItemPreset\\AccountPermission",
    ACCOUNT_PRIVATE: b"SP\\DataModel\\ItemPreset\\AccountPrivate",
    SESSION_TIMEOUT: b"SP\\DataModel\\ItemPreset\\SessionTimeout",
    ACCOUNT_PASSWORD: b"SP\\DataModel\\ItemPreset\\Password",
}
EXPIRE_TIME_MULTIPLIER = 86400  # Password::EXPIRE_TIME_MULTIPLIER (days -> seconds)
_IP = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
_ADDRESS = re.compile(rf"^(?P<address>{_IP})(?:/(?:(?P<mask>{_IP})|(?P<cidr>\d{{1,2}})))?$")


class PresetError(ValueError):
    """Invalid preset type or data (PHP ItemsPresetForm validation)."""


def canonical_type(preset_type: str) -> str:
    preset_type = LEGACY_TYPES.get(preset_type, preset_type)
    if preset_type not in TYPES:
        raise PresetError(f"Invalid preset type: {preset_type!r}")
    return preset_type


def preset_hash(preset_type: str, user_id, user_group_id, user_profile_id, priority) -> bytes:
    """ItemPresetData::getHash()."""
    key = f"{preset_type}{int(user_id or 0)}{int(user_group_id or 0)}{int(user_profile_id or 0)}{int(priority or 0)}"
    return hashlib.sha1(key.encode("utf-8"), usedforsecurity=False).hexdigest().encode("ascii")


def _ids(value) -> list:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, int) and not isinstance(v, bool) for v in value):
        raise PresetError("Permission lists must contain user or group IDs")
    return list(dict.fromkeys(value))


def _parse_address(value: str) -> tuple:
    """SessionTimeout::__construct(): address plus mask from CIDR, mask, or /32."""
    match = _ADDRESS.match(value or "")
    if not match:
        raise PresetError("Invalid IP")
    try:
        ipaddress.IPv4Address(match["address"])
        if match["cidr"] is not None:
            bits = int(match["cidr"])
            if bits > 32:
                raise ValueError
            mask = str(ipaddress.IPv4Network(f"0.0.0.0/{bits}").netmask)
        elif match["mask"] is not None:
            mask = str(ipaddress.IPv4Address(match["mask"]))
        else:
            mask = "255.255.255.255"
    except ValueError:
        raise PresetError("Invalid IP")
    return match["address"], mask


def to_native(preset_type: str, data: dict) -> list:
    """API JSON -> ordered (property, value) pairs of the PHP object."""
    data = data or {}
    if preset_type == ACCOUNT_PERMISSION:
        return [
            ("usersView", _ids(data.get("users_view"))), ("usersEdit", _ids(data.get("users_edit"))),
            ("userGroupsView", _ids(data.get("user_groups_view"))),
            ("userGroupsEdit", _ids(data.get("user_groups_edit"))),
        ]
    if preset_type == ACCOUNT_PRIVATE:
        return [("privateUser", bool(data.get("private_user"))), ("privateGroup", bool(data.get("private_group")))]
    if preset_type == SESSION_TIMEOUT:
        address, mask = _parse_address(str(data.get("ip_address", "")))
        timeout = data.get("timeout", 0)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 0:
            raise PresetError("timeout must be a number of seconds")
        return [("address", address), ("mask", mask), ("timeout", timeout)]
    regex = data.get("regex") or None
    if regex is not None:
        try:
            re.compile(regex)
        except re.error:
            raise PresetError("Invalid regular expression")
    numbers = {k: data.get(k, default) for k, default in (("length", 1), ("expire_days", 0), ("score", 0))}
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in numbers.values()):
        raise PresetError("length, expire_days and score must be non-negative integers")
    return [
        ("length", numbers["length"]), ("useNumbers", bool(data.get("use_numbers"))),
        ("useLetters", bool(data.get("use_letters"))), ("useSymbols", bool(data.get("use_symbols"))),
        ("useUpper", bool(data.get("use_upper"))), ("useLower", bool(data.get("use_lower"))),
        ("useImage", bool(data.get("use_image"))), ("expireTime", numbers["expire_days"] * EXPIRE_TIME_MULTIPLIER),
        ("score", numbers["score"]), ("regex", regex),
    ]


def serialize(preset_type: str, data: dict) -> bytes:
    """``serialize($presetObject)`` with PHP's private-property names."""
    class_name = _CLASSES[preset_type]
    private = b"\x00" + class_name + b"\x00"
    return _php_object(class_name, [(private + name.encode(), value) for name, value in to_native(preset_type, data)])


def _plain(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, dict):
        return [_plain(v) for _, v in sorted(value.items())]
    return value


def deserialize(preset_type: str, raw: bytes) -> dict:
    """PHP-serialized preset -> API JSON. Raises ValueError for other data."""
    class_name = _CLASSES[preset_type]
    private = b"\x00" + class_name + b"\x00"
    props = {k[len(private):].decode(): _plain(v) for k, v in _object(raw, class_name).items()
             if isinstance(k, bytes) and k.startswith(private)}
    if preset_type == ACCOUNT_PERMISSION:
        return {"users_view": props.get("usersView") or [], "users_edit": props.get("usersEdit") or [],
                "user_groups_view": props.get("userGroupsView") or [],
                "user_groups_edit": props.get("userGroupsEdit") or []}
    if preset_type == ACCOUNT_PRIVATE:
        return {"private_user": bool(props.get("privateUser")), "private_group": bool(props.get("privateGroup"))}
    if preset_type == SESSION_TIMEOUT:
        address, mask = props.get("address"), props.get("mask")
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen if mask else 32
        return {"ip_address": f"{address}/{prefix}", "address": address, "mask": mask,
                "timeout": int(props.get("timeout") or 0)}
    return {"length": int(props.get("length") or 0), "use_numbers": bool(props.get("useNumbers")),
            "use_letters": bool(props.get("useLetters")), "use_symbols": bool(props.get("useSymbols")),
            "use_upper": bool(props.get("useUpper")), "use_lower": bool(props.get("useLower")),
            "use_image": bool(props.get("useImage")),
            "expire_days": int(props.get("expireTime") or 0) // EXPIRE_TIME_MULTIPLIER,
            "score": int(props.get("score") or 0), "regex": props.get("regex")}


def decode_row(preset_type: str, raw) -> tuple:
    """(canonical type, data, legacy flag) for a stored ItemPreset row."""
    raw = raw if isinstance(raw, (bytes, bytearray)) else (raw or "").encode("utf-8")
    if preset_type in TYPES:
        try:
            return preset_type, deserialize(preset_type, bytes(raw)), False
        except (ValueError, KeyError):
            return preset_type, {}, True
    try:
        data = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
        data = {}
    return LEGACY_TYPES.get(preset_type, preset_type), data if isinstance(data, dict) else {}, True


def address_matches(client_ip: Optional[str], address: str, mask: str) -> bool:
    """Address::check(): same subnet under ``mask`` (IPv4 only, like PHP)."""
    try:
        client = int(ipaddress.IPv4Address(client_ip))
        network = int(ipaddress.IPv4Address(address))
        netmask = int(ipaddress.IPv4Address(mask))
    except (ipaddress.AddressValueError, TypeError, ValueError):
        return False
    return client & netmask == network & netmask


# PasswordValidator / Validator character classes, translated from PCRE.
_SYMBOLS = re.compile(r"[$-/:-?{-~!\"^_`\[\]]")


def password_errors(policy: dict, password: str) -> Optional[str]:
    """PasswordValidator::validate(): the first unmet rule, or None."""
    if len(password) < int(policy.get("length") or 0):
        return f"Password needs to be {policy['length']} characters long"
    regex = policy.get("regex")
    if regex and not re.search(regex, password):
        return "Password does not contain the required characters"
    if policy.get("use_letters"):
        if not re.search(r"[a-z]", password, re.IGNORECASE):
            return "Password needs to contain letters"
        if policy.get("use_lower") and not re.search(r"[a-z]", password):
            return "Password needs to contain lower case letters"
        if policy.get("use_upper") and not re.search(r"[A-Z]", password):
            return "Password needs to contain upper case letters"
    if policy.get("use_numbers") and not re.search(r"\d", password):
        return "Password needs to contain numbers"
    if policy.get("use_symbols") and not _SYMBOLS.search(password):
        return "Password needs to contain symbols"
    return None


@dataclass
class ResolvedPreset:
    id: int
    type: str
    fixed: bool
    priority: int
    data: dict
