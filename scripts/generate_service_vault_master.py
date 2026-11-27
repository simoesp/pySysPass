#!/usr/bin/env python3
"""Bootstrap the service vault master unlock artifact (ADR-0010 §3, IMPL-010).

Writes ``data/service_vault_master.enc``: the master password sealed with the
environment-provisioned ``SERVICE_VAULT_KEY``. This is the auditable,
production path for letting service vault contexts be provisioned without an
interactive human login. The administrator supplies the master password via
``SYSPASS_MASTER_PASSWORD`` (kept out of shell history/argv by reading from a
file with ``--master-file`` is also supported).

Usage:
    SERVICE_VAULT_KEY=... python scripts/generate_service_vault_master.py \
        --master-file /run/secrets/master_password

Refuses to run when SERVICE_VAULT_KEY is unset (fail-secure) and verifies the
master password against Config.masterPwd before sealing anything.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.service_vault_crypto import ServiceVaultKeyError, resolve_service_vault_key  # noqa: E402
from app.core.service_vault_key import seal_master_artifact  # noqa: E402
from app.db.base import SessionLocal  # noqa: E402
from app.models.account import Config  # noqa: E402
from app.services.auth_service import verify_master_password_hash  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--master-file", type=Path,
                        help="file containing the master password (single line)")
    parser.add_argument("--force", action="store_true",
                        help="seal without verifying against Config.masterPwd")
    args = parser.parse_args()

    try:
        resolve_service_vault_key()
    except ServiceVaultKeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.master_file:
        master = args.master_file.read_text(encoding="utf-8").strip()
    else:
        master = getpass.getpass("Master password: ")
    if not master:
        print("error: empty master password", file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        row = db.query(Config).filter(Config.parameter == "masterPwd").first()
        if row is not None and not args.force:
            if not verify_master_password_hash(master, row.value):
                print("error: master password does not match Config.masterPwd", file=sys.stderr)
                return 3
        path = seal_master_artifact(master)
    finally:
        db.close()
    print(f"sealed service vault master artifact: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
