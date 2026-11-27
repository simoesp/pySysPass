#!/usr/bin/env python3
"""Generate Ed25519 signing key pair for backup manifest authenticity (ADR-0013, IMPL-009).

Usage:
    python scripts/generate_backup_signing_key.py [--output PATH] [--key-id ID]

Outputs a signing keyring JSON with both private and public keys.
The private key must be kept secure (0400 permissions) on the production host.
The public key can be distributed to recovery environments for verification.

Keyring format:
{
    "current": "sig-v1",
    "keys": {
        "sig-v1": {
            "private": "<base64-encoded 32-byte private key>",
            "public": "<base64-encoded 32-byte public key>"
        }
    }
}
"""
import argparse
import base64
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 backup signing key pair")
    parser.add_argument(
        "--output", "-o",
        default="/etc/syspass/backup-signing-keyring.json",
        help="Output path for signing keyring (default: /etc/syspass/backup-signing-keyring.json)"
    )
    parser.add_argument(
        "--key-id",
        default="sig-v1",
        help="Key identifier (default: sig-v1)"
    )
    parser.add_argument(
        "--verification-output",
        help="Also write a verification keyring (public keys only) to this path"
    )
    args = parser.parse_args()

    # Generate key pair
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes_raw()

    private_b64 = base64.b64encode(private_bytes).decode("ascii")
    public_b64 = base64.b64encode(public_bytes).decode("ascii")

    # Build signing keyring (with private key)
    signing_keyring = {
        "current": args.key_id,
        "keys": {
            args.key_id: {
                "private": private_b64,
                "public": public_b64,
            }
        }
    }

    # Write signing keyring
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(signing_keyring, indent=2))
    os.chmod(output_path, 0o400)  # Restrictive permissions per ADR-0013

    print(f"Signing keyring written to: {output_path}")
    print(f"Key ID: {args.key_id}")
    print(f"Public key (base64): {public_b64}")
    print()
    print("IMPORTANT: Keep the signing keyring secure (0400 permissions).")
    print("Set BACKUP_SIGNING_KEYRING environment variable to this path to enable backup signing.")

    # Optionally write verification keyring (public keys only)
    if args.verification_output:
        verification_keyring = {
            "current": args.key_id,
            "keys": {
                args.key_id: {
                    "public": public_b64,
                }
            }
        }
        verify_path = Path(args.verification_output)
        verify_path.parent.mkdir(parents=True, exist_ok=True)
        verify_path.write_text(json.dumps(verification_keyring, indent=2))
        os.chmod(verify_path, 0o400)  # Restrictive permissions per ADR-0013
        print(f"Verification keyring written to: {verify_path}")
        print("Set BACKUP_VERIFICATION_KEYRING environment variable to this path to enable signature verification.")


if __name__ == "__main__":
    main()
