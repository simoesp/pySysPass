"""Prepare and complete an ENCRYPTION_KEY rotation (R8 / #58).

    python -m app.encryption_key check
        Report persisted values that still depend on ENCRYPTION_KEY (legacy
        pySysPass formats). Exit status 1 while any remain.

    python -m app.encryption_key migrate --confirm-stopped [--drop-legacy-links]
        Rewrite them in the native sysPass formats under the vault master
        password, after a fail-closed backup, in one transaction. Requires
        maintenance mode and stopped writers, like a master password change.

    python -m app.encryption_key end-sessions
        End every pySysPass session. Run it when ENCRYPTION_KEY or SECRET_KEY
        changes: session tokens carry the vault key encrypted with
        ENCRYPTION_KEY.

The master password is read from PYSYSPASS_CURRENT_MASTER_PASSWORD or prompted.
"""

import argparse
import getpass
import json
import os
import sys

from app.core.config import BASE_DIR, settings
from app.core.security import EncryptionService
from app.services.backup_service import BackupService
from app.services.config_service import ConfigService
from app.services.legacy_migration import LegacyFormatMigration, LegacyMigrationError
from app.services.session_service import session_store


def _session():
    from app.db.base import SessionLocal

    if not settings.DATABASE_URL:
        raise LegacyMigrationError("DATABASE_URL is not configured")
    return SessionLocal()


def _migration(db) -> LegacyFormatMigration:
    return LegacyFormatMigration(db, EncryptionService(settings.ENCRYPTION_KEY).decrypt)


def check() -> int:
    db = _session()
    try:
        found = _migration(db).inventory()
        print(json.dumps({"legacy_remaining": found.remaining, **found.summary()}))
        return 1 if found.remaining else 0
    finally:
        db.close()


def migrate(args) -> int:
    db = _session()
    backup = None
    try:
        if not ConfigService(db)._bool_val("maintenance"):
            raise LegacyMigrationError("Enable maintenance mode first")
        master = os.environ.get("PYSYSPASS_CURRENT_MASTER_PASSWORD")
        if master is None:
            master = getpass.getpass("Vault master password: ")
        migration = _migration(db)
        migration.check_master(master)
        if not migration.inventory().remaining:
            print(json.dumps({"migrated": False, "legacy_remaining": 0}))
            return 0
        db.rollback()  # end the read transaction before the dump runs
        backup = BackupService(args.backup_dir).create_full_backup(settings.DATABASE_URL, include_files=True)
        if not backup.get("db_included"):
            raise LegacyMigrationError("The pre-migration backup does not contain the database")
        found = migration.migrate(master, drop_links=args.drop_legacy_links)
        print(json.dumps({"migrated": True, "backup": backup.get("filename"), **found.summary()}))
        return 0
    except LegacyMigrationError as exc:
        print(json.dumps({"migrated": False, "error": str(exc), "backup": backup and backup.get("filename"),
                          "note": "No values were changed."}), file=sys.stderr)
        return 1
    finally:
        db.close()


def end_sessions() -> int:
    session_store.revoke_all()
    # Pending 2FA enrollment secrets are encrypted with ENCRYPTION_KEY.
    (BASE_DIR / "data" / "two-factor-pending.json").unlink(missing_ok=True)
    print(json.dumps({"sessions_ended": True}))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="Report values that still depend on ENCRYPTION_KEY")
    run = commands.add_parser("migrate", help="Rewrite legacy values in native sysPass formats")
    run.add_argument("--confirm-stopped", action="store_true", help="Confirm every application writer is stopped")
    run.add_argument("--drop-legacy-links", action="store_true",
                     help="Delete legacy public links (they cannot be converted without exposing passwords)")
    run.add_argument("--backup-dir", default="./backups")
    commands.add_parser("end-sessions", help="End every pySysPass session")
    args = parser.parse_args(argv)
    if args.command == "check":
        try:
            return check()
        except LegacyMigrationError as exc:
            parser.error(str(exc))
    if args.command == "migrate":
        if not args.confirm_stopped:
            parser.error("Stop all Python/PHP application writers, then supply --confirm-stopped")
        return migrate(args)
    return end_sessions()


if __name__ == "__main__":
    sys.exit(main())
