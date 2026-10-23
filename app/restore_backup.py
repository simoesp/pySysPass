"""Restore an archive while every Python/PHP application writer is stopped."""

import argparse
import json

from app.core.config import settings
from app.services.backup_service import BackupService


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("filename", help="Existing ZIP filename in the backup directory")
    parser.add_argument("--backup-dir", default="./backups")
    parser.add_argument("--confirm-stopped", action="store_true", help="Confirm every application writer is stopped")
    args = parser.parse_args()
    if not args.confirm_stopped:
        parser.error("Stop all Python/PHP application writers, then supply --confirm-stopped")
    result = BackupService(args.backup_dir).restore_backup(args.filename, settings.DATABASE_URL, offline=True)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
