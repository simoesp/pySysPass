"""Backup Service - Database and file backups"""
from typing import Optional, Dict
import os
import re
import subprocess
import zipfile
import shutil
from datetime import datetime
from pathlib import Path


def _parse_db_url(db_url: str) -> Optional[Dict]:
    """Extract host/port/user/password/dbname from a SQLAlchemy URL."""
    m = re.match(
        r"[^:]+://(?P<user>[^:]+):(?P<password>[^@]*)@(?P<host>[^:/]+)(?::(?P<port>\d+))?/(?P<db>[^?]+)",
        db_url,
    )
    if not m:
        return None
    return {
        "user": m.group("user"),
        "password": m.group("password"),
        "host": m.group("host"),
        "port": int(m.group("port") or 3306),
        "db": m.group("db"),
    }


class BackupService:
    """Service for creating and managing backups"""

    def __init__(self, backup_dir: str = "./backups"):
        self.backup_dir = Path(backup_dir).resolve()
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def resolve_backup_path(self, filename: str) -> Path:
        """Select an existing direct-child ZIP without building a user path."""
        allowed = frozenset(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        )
        if (
            not filename
            or len(filename) > 255
            or not filename[0].isalnum()
            or not filename.endswith(".zip")
            or any(character not in allowed for character in filename)
        ):
            raise ValueError("Invalid backup filename")
        for candidate in self.backup_dir.iterdir():
            if candidate.name != filename:
                continue
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError("Invalid backup filename")
            path = candidate.resolve()
            if path.parent != self.backup_dir:
                raise ValueError("Invalid backup filename")
            return path
        raise FileNotFoundError("Backup not found")

    # ── DB dump ──────────────────────────────────────────────────────────────

    def _try_mysqldump(self, db_url: str, dest: Path) -> bool:
        """Run mysqldump if available. Returns True on success."""
        params = _parse_db_url(db_url)
        if not params or not shutil.which("mysqldump"):
            return False
        env = {**os.environ, "MYSQL_PWD": params["password"]}
        cmd = [
            "mysqldump",
            f"-h{params['host']}",
            f"-P{params['port']}",
            f"-u{params['user']}",
            params["db"],
        ]
        try:
            result = subprocess.run(  # nosec B603
                cmd, capture_output=True, text=True, timeout=120, env=env
            )
            if result.returncode == 0:
                dest.write_text(result.stdout, encoding="utf-8")
                return True
        except (subprocess.TimeoutExpired, OSError):
            pass
        return False

    def _try_mysql_restore(self, db_url: str, source: Path) -> bool:
        """Restore a MySQL dump if the mysql client is available."""
        params = _parse_db_url(db_url)
        if not params or not shutil.which("mysql") or not source.exists():
            return False
        env = {**os.environ, "MYSQL_PWD": params["password"]}
        cmd = [
            "mysql",
            f"-h{params['host']}",
            f"-P{params['port']}",
            f"-u{params['user']}",
            params["db"],
        ]
        try:
            with source.open("rb") as dump_file:
                result = subprocess.run(  # nosec B603
                    cmd, stdin=dump_file, capture_output=True, timeout=120, env=env
                )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _inspect_archive(self, archive_path: Path) -> Dict[str, bool]:
        """Report whether an archive contains DB and/or data payloads."""
        db_included = False
        data_included = False
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                for name in archive.namelist():
                    normalized = name.strip("/")
                    if normalized == "database.sql":
                        db_included = True
                    if normalized.startswith("data/"):
                        data_included = True
                    if db_included and data_included:
                        break
        except (OSError, zipfile.BadZipFile):
            pass
        return {"db_included": db_included, "data_included": data_included}

    def _extract_archive(self, archive_path: Path, target_dir: Path) -> None:
        """Extract an archive while blocking path traversal entries."""
        target_dir = target_dir.resolve()
        with zipfile.ZipFile(archive_path, "r") as archive:
            for member in archive.infolist():
                member_path = Path(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RuntimeError("Backup archive contains invalid paths")
                dest_path = (target_dir / member_path).resolve()
                try:
                    dest_path.relative_to(target_dir)
                except ValueError as exc:
                    raise RuntimeError("Backup archive contains invalid paths") from exc
                # ZIP symlinks can redirect later members outside the staging tree.
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise RuntimeError("Backup archive contains symbolic links")
                if member.is_dir():
                    dest_path.mkdir(parents=True, exist_ok=True)
                    continue
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as source, dest_path.open("wb") as dest:
                    shutil.copyfileobj(source, dest)

    # ── Public API ───────────────────────────────────────────────────────────

    def create_full_backup(self, db_url: str = None, include_files: bool = True) -> Dict:
        """Create a full backup (DB dump if possible + data directory)."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"syspass_full_backup_{timestamp}"
        staging = self.backup_dir / backup_name
        staging.mkdir(parents=True, exist_ok=True)

        db_included = False
        try:
            if db_url:
                dump_dest = staging / "database.sql"
                db_included = self._try_mysqldump(db_url, dump_dest)

            data_dir = Path("./data")
            if include_files and data_dir.exists():
                shutil.copytree(data_dir, staging / "data", dirs_exist_ok=True)

            archive_path = self.backup_dir / f"{backup_name}.zip"
            shutil.make_archive(str(staging), "zip", staging)
            shutil.rmtree(staging)

            stat = archive_path.stat()
            return {
                "filename": archive_path.name,
                "path": str(archive_path),
                "size": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "db_included": db_included,
            }
        except Exception as exc:
            if staging.exists():
                shutil.rmtree(staging)
            raise RuntimeError(f"Backup failed: {exc}") from exc

    def create_database_backup(self, db_dump_path: str) -> str:
        """Create a database-only backup"""
        if not os.path.exists(db_dump_path):
            raise FileNotFoundError(f"Database dump not found: {db_dump_path}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"syspass_db_backup_{timestamp}.sql"
        backup_path = self.backup_dir / backup_name

        shutil.copy2(db_dump_path, backup_path)
        return str(backup_path)

    def create_data_backup(self) -> str:
        """Backup data directory (RSA keys, etc.)"""
        data_dir = Path("./data")
        if not data_dir.exists():
            raise FileNotFoundError("Data directory not found")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"syspass_data_backup_{timestamp}"
        backup_path = self.backup_dir / backup_name

        try:
            shutil.copytree(data_dir, backup_path)

            # Create archive
            archive_path = self.backup_dir / f"{backup_name}.zip"
            shutil.make_archive(str(backup_path), 'zip', backup_path)

            # Clean up
            shutil.rmtree(backup_path)

            return str(archive_path)

        except Exception as e:
            if backup_path.exists():
                shutil.rmtree(backup_path)
            raise Exception(f"Data backup failed: {str(e)}")

    def list_backups(self) -> list:
        """List all available backups"""
        backups = []

        for file in self.backup_dir.glob("*.zip"):
            stat = file.stat()
            contents = self._inspect_archive(file)
            backups.append({
                'filename': file.name,
                'path': str(file),
                'size': stat.st_size,
                'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'db_included': contents["db_included"],
                'data_included': contents["data_included"],
            })

        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created_at'], reverse=True)
        return backups

    def restore_backup(self, filename: str, db_url: Optional[str] = None) -> Dict:
        """Restore from a backup archive."""
        archive_path = self.resolve_backup_path(filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        restore_dir = self.backup_dir / f"restore_{timestamp}"
        staged_data_dir = self.backup_dir / f"data_restore_{timestamp}"
        rollback_data_dir = self.backup_dir / f"data_rollback_{timestamp}"
        target_data = Path("./data")

        try:
            restore_dir.mkdir(parents=True, exist_ok=True)
            self._extract_archive(archive_path, restore_dir)

            db_file = restore_dir / "database.sql"
            data_dir = restore_dir / "data"
            db_restored = False
            data_restored = False

            if db_file.exists():
                if not db_url:
                    raise RuntimeError("Database restore requires a configured DATABASE_URL")
                if not self._try_mysql_restore(db_url, db_file):
                    raise RuntimeError("Failed to restore database dump with mysql client")
                db_restored = True

            if data_dir.exists():
                shutil.copytree(data_dir, staged_data_dir)
                if target_data.exists():
                    target_data.replace(rollback_data_dir)
                staged_data_dir.replace(target_data)
                data_restored = True
                if rollback_data_dir.exists():
                    shutil.rmtree(rollback_data_dir)

            return {
                "filename": archive_path.name,
                "db_restored": db_restored,
                "data_restored": data_restored,
            }

        except Exception as exc:
            if staged_data_dir.exists():
                shutil.rmtree(staged_data_dir, ignore_errors=True)
            if rollback_data_dir.exists() and not target_data.exists():
                rollback_data_dir.replace(target_data)
            raise RuntimeError(f"Restore failed: {exc}") from exc
        finally:
            if restore_dir.exists():
                shutil.rmtree(restore_dir, ignore_errors=True)
            if rollback_data_dir.exists():
                shutil.rmtree(rollback_data_dir, ignore_errors=True)

    def delete_backup(self, filename: str) -> bool:
        """Delete a backup file"""
        backup_path = self.resolve_backup_path(filename)
        backup_path.unlink()
        return True

    def cleanup_old_backups(self, days: int = 30) -> int:
        """Delete backups older than specified days"""
        from datetime import timedelta

        cutoff_date = datetime.now() - timedelta(days=days)
        deleted_count = 0

        for file in self.backup_dir.glob("*.zip"):
            stat = file.stat()
            file_date = datetime.fromtimestamp(stat.st_ctime)

            if file_date < cutoff_date:
                os.remove(file)
                deleted_count += 1

        return deleted_count
