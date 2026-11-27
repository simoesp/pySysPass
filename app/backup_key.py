"""Manage the ADR-0013 backup encryption keyring (AES-256-GCM, mandatory).

    python -m app.backup_key status
        Report the keyring location, the current key id and the retained key
        versions. Exit status 1 when no usable keyring exists and the
        administrator exception (BACKUP_ALLOW_UNENCRYPTED) is not set.

    python -m app.backup_key init [--key-id v1]
        Generate a new random key into the keyring as the current version.
        Fails if a current key already exists: rotation must be explicit.
        Writes the file with mode 0400.

    python -m app.backup_key rotate --key-id v2
        Add a new current version, retaining every old version so historical
        backups stay decryptable (ADR-0013: "Never silently replace missing
        encryption key").

The key lives outside the backup: keep an independent recovery copy, and never
delete a version while a backup encrypted under it still exists.
"""

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from app.core import backup_crypto


def _keyring_file() -> Path:
    return backup_crypto._keyring_path()


def _load_or_none(path: Path):
    if not path.is_file():
        return None
    return backup_crypto._load_keyring(path)


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o400)
    tmp.replace(path)


def status() -> int:
    try:
        path = _keyring_file()
    except backup_crypto.BackupKeyMissingError as exc:
        allowed = backup_crypto.exception_allowed()
        print(json.dumps({
            "keyring": None,
            "usable": False,
            "exception_active": allowed,
            "detail": str(exc),
        }))
        return 0 if allowed else 1
    data = _load_or_none(path)
    if data is None:
        print(json.dumps({"keyring": str(path), "usable": False,
                          "detail": "keyring file does not exist"}))
        return 0 if backup_crypto.exception_allowed() else 1
    print(json.dumps({
        "keyring": str(path),
        "usable": True,
        "current": data.get("current"),
        "versions": sorted(data.get("keys", {})),
        "exception_active": backup_crypto.exception_allowed(),
    }))
    return 0


def init(args) -> int:
    path = _keyring_file()
    data = _load_or_none(path) or {"current": None, "keys": {}}
    if data.get("current") in data.get("keys", {}):
        print(json.dumps({"initialized": False,
                          "error": f"keyring {path} already has current key {data['current']!r}; use rotate"}),
              file=sys.stderr)
        return 1
    if not backup_crypto.KEY_ID_PATTERN.match(args.key_id):
        print(json.dumps({"initialized": False, "error": "invalid --key-id"}), file=sys.stderr)
        return 1
    if args.key_id in data["keys"]:
        print(json.dumps({"initialized": False,
                          "error": f"version {args.key_id!r} already in keyring"}), file=sys.stderr)
        return 1
    data["keys"][args.key_id] = secrets.token_hex(32)
    data["current"] = args.key_id
    _save(path, data)
    print(json.dumps({"initialized": True, "keyring": str(path), "key_id": args.key_id}))
    return 0


def rotate(args) -> int:
    path = _keyring_file()
    data = _load_or_none(path)
    if data is None:
        print(json.dumps({"rotated": False, "error": f"no keyring at {path}; run init first"}),
              file=sys.stderr)
        return 1
    if not backup_crypto.KEY_ID_PATTERN.match(args.key_id):
        print(json.dumps({"rotated": False, "error": "invalid --key-id"}), file=sys.stderr)
        return 1
    if args.key_id in data["keys"]:
        print(json.dumps({"rotated": False,
                          "error": f"version {args.key_id!r} already in keyring"}), file=sys.stderr)
        return 1
    data["keys"][args.key_id] = secrets.token_hex(32)
    data["current"] = args.key_id
    _save(path, data)
    print(json.dumps({
        "rotated": True, "keyring": str(path), "key_id": args.key_id,
        "retained": sorted(k for k in data["keys"] if k != args.key_id),
    }))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage the ADR-0013 backup encryption keyring")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Report keyring state")
    p_init = commands.add_parser("init", help="Generate the first key")
    p_init.add_argument("--key-id", default="v1")
    p_rot = commands.add_parser("rotate", help="Add a new current key version")
    p_rot.add_argument("--key-id", required=True)
    args = parser.parse_args()
    if args.command == "status":
        return status()
    if args.command == "init":
        return init(args)
    return rotate(args)


if __name__ == "__main__":
    sys.exit(main())
