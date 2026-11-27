#!/usr/bin/env python3
"""CLI for managing the ADR-0010 service vault key hierarchy (IMPL-014).

    python -m app.service_vault_keyring status
        Report the keyring state: location, current master key version,
        all master key versions, and number of service DEKs.

    python -m app.service_vault_keyring init [--key-id v1]
        Generate a new random master key into the keyring as the current version.
        Fails if a current key already exists: rotation must be explicit.
        Writes the file with mode 0400.

    python -m app.service_vault_keyring rotate --key-id v2
        Add a new current master key version, retaining every old version so
        historical contexts stay decryptable (ADR-0010 §13: "Grace period for key rotation").

    python -m app.service_vault_keyring provision-dek <service_id>
        Provision a DEK for a service (wrapped with current master key).

    python -m app.service_vault_keyring rotate-dek <service_id>
        Rotate a service's DEK (generates new DEK wrapped with current master key).

    python -m app.service_vault_keyring rewrap-all <new_master_key_id>
        Rewrap all service DEKs with a new master key version.
        Used during master key rotation to migrate DEKs.

    python -m app.service_vault_keyring delete-dek <service_id>
        Delete a service's DEK (e.g., on service account deletion).

The keyring lives outside the database: keep an independent recovery copy,
and never delete a master key version while a context encrypted under it still exists.
"""
from __future__ import annotations

import argparse
import json
import sys

from app.core.service_vault_keyring import (
    ServiceVaultKeyMissing,
    ServiceVaultKeyUnreadable,
    ServiceVaultKeyringError,
    cli_status,
    init_keyring,
    rotate_master_key,
    provision_service_dek,
    rotate_service_dek,
    rewrap_all_service_deks,
    delete_service_dek,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Manage the ADR-0010 service vault key hierarchy (IMPL-014)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--keyring-path",
        help="Path to keyring file (default: SERVICE_VAULT_KEYRING_PATH or /etc/syspass/service-vault-keyring.json)",
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

    # Override keyring path if provided
    if args.keyring_path:
        import os
        os.environ["SERVICE_VAULT_KEYRING_PATH"] = args.keyring_path
        # Invalidate caches
        from app.core.service_vault_keyring import _keyring_cache, _keyring_path_cache, _keyring_lock
        with _keyring_lock:
            _keyring_cache = None
            _keyring_path_cache = None

    try:
        if args.command == "status":
            return cli_status()
        if args.command == "init":
            result = init_keyring(args.key_id, args.keyring_path)
            print(json.dumps(result))
            return 0
        if args.command == "rotate":
            result = rotate_master_key(args.key_id, args.keyring_path)
            print(json.dumps(result))
            return 0
        if args.command == "provision-dek":
            result = provision_service_dek(args.service_id, keyring_path=args.keyring_path)
            print(json.dumps(result))
            return 0
        if args.command == "rotate-dek":
            result = rotate_service_dek(args.service_id, keyring_path=args.keyring_path)
            print(json.dumps(result))
            return 0
        if args.command == "rewrap-all":
            result = rewrap_all_service_deks(args.new_master_key_id, keyring_path=args.keyring_path)
            print(json.dumps(result))
            return 0
        if args.command == "delete-dek":
            result = delete_service_dek(args.service_id, keyring_path=args.keyring_path)
            print(json.dumps({"deleted": result}))
            return 0
    except ServiceVaultKeyUnreadable as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    except ServiceVaultKeyMissing as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    except ServiceVaultKeyringError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())