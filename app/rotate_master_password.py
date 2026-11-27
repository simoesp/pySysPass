"""Change the vault master password offline, as sysPass PHP does (R8 / #58).

Stop every Python and PHP application writer and enable maintenance mode
first. The command proves that every encrypted value opens with the current
master password, takes a full backup (fail closed), rewrites all values in one
database transaction, verifies them with the new password, then ends every
pySysPass session. Users re-enter the new master password once at sign-in.

Passwords are read from PYSYSPASS_CURRENT_MASTER_PASSWORD and
PYSYSPASS_NEW_MASTER_PASSWORD, or prompted for; never pass them as arguments.
"""

import argparse
import getpass
import json
import os
import sys

from app.core.config import settings
from app.core.security import EncryptionService
from app.services.backup_service import BackupService
from app.services.master_password_rotation import MasterPasswordRotation, RotationError
from app.services.session_service import session_store


def _passwords() -> tuple[str, str]:
    current = os.environ.get("PYSYSPASS_CURRENT_MASTER_PASSWORD")
    new = os.environ.get("PYSYSPASS_NEW_MASTER_PASSWORD")
    if current is None:
        current = getpass.getpass("Current master password: ")
    if new is None:
        new = getpass.getpass("New master password: ")
        if getpass.getpass("Repeat new master password: ") != new:
            raise RotationError("The new master passwords do not match")
    return current, new


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--confirm-stopped", action="store_true", help="Confirm every application writer is stopped")
    parser.add_argument("--dry-run", action="store_true", help="Only check that every value can be rotated")
    parser.add_argument("--include-legacy", action="store_true",
                        help="Also rewrite legacy pySysPass AES values in the native sysPass format")
    parser.add_argument("--backup-dir", default="./backups")
    args = parser.parse_args(argv)
    if not args.confirm_stopped:
        parser.error("Stop all Python/PHP application writers, then supply --confirm-stopped")
    if not settings.DATABASE_URL:
        parser.error("DATABASE_URL is not configured")

    from app.db.base import SessionLocal

    db = SessionLocal()
    backup = None
    try:
        current, new = _passwords()
        rotation = MasterPasswordRotation(db, legacy_decrypt=EncryptionService(settings.ENCRYPTION_KEY).decrypt)
        rotation.check_preconditions(current, new)
        plan = rotation.plan(current, include_legacy=args.include_legacy)
        summary = {
            "accounts": plan.accounts, "history": plan.history, "history_skipped": plan.history_skipped,
            "custom_fields": plan.custom_fields, "legacy": len(plan.legacy), "failures": plan.failures[:20],
        }
        if args.dry_run or plan.failures or (plan.legacy and not args.include_legacy):
            print(json.dumps({"dry_run": True, **summary}))
            return 1 if plan.failures or (plan.legacy and not args.include_legacy) else 0
        db.rollback()  # end the read transaction before the dump runs
        backup = BackupService(args.backup_dir).create_full_backup(settings.DATABASE_URL, include_files=True)
        if not backup.get("db_included"):
            raise RotationError("The pre-rotation backup does not contain the database")
        rotation.rotate(current, new, include_legacy=args.include_legacy)
        # Sessions carry the old master password; none may write with it.
        session_store.revoke_all()
        print(json.dumps({"rotated": True, "backup": backup.get("filename"), **summary}))
        return 0
    except RotationError as exc:
        print(json.dumps({"rotated": False, "error": str(exc), "backup": backup and backup.get("filename"),
                          "note": "No encrypted values or master password hash were changed."}), file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
