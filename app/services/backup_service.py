"""Backup Service - Database and file backups"""
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


def _parse_db_url(db_url: str) -> Optional[Dict]:
    """Extract host/port/user/password/dbname from a SQLAlchemy URL."""
    try:
        url = make_url(db_url)
    except (ArgumentError, TypeError):
        return None
    if url.get_backend_name() not in ("mysql", "mariadb") or not url.host or not url.database or not url.username:
        return None
    # Never silently drop TLS or connection options when handing off to a CLI.
    if set(url.query) - {"charset"}:
        return None
    return {
        "user": url.username,
        "password": url.password or "",
        "host": url.host,
        "port": url.port or 3306,
        "db": url.database,
    }


def _mysql_client(*names: str) -> Optional[str]:
    return next((path for name in names if (path := shutil.which(name))), None)


class BackupService:
    """Service for creating and managing backups"""

    def __init__(self, backup_dir: str = "./backups"):
        self.backup_dir = Path(backup_dir).resolve()
        self.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

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
        binary = _mysql_client("mysqldump", "mariadb-dump")
        if not params or not binary:
            return False
        env = {**os.environ, "MYSQL_PWD": params["password"]}
        cmd = [
            binary,
            "--single-transaction", "--quick", "--skip-lock-tables", "--hex-blob",
            f"-h{params['host']}",
            f"-P{params['port']}",
            f"-u{params['user']}",
            "--", params["db"],
        ]
        try:
            with dest.open("wb") as output:
                os.chmod(dest, 0o600)
                result = subprocess.run(  # nosec B603
                    cmd, stdout=output, stderr=subprocess.DEVNULL, timeout=120, env=env
                )
            if result.returncode == 0 and dest.stat().st_size > 0:
                return True
            dest.unlink(missing_ok=True)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return False

    def _try_mysql_restore(self, db_url: str, source: Path) -> bool:
        """Restore a MySQL dump if the mysql client is available."""
        params = _parse_db_url(db_url)
        binary = _mysql_client("mysql", "mariadb")
        if not params or not binary or not source.exists():
            return False
        env = {**os.environ, "MYSQL_PWD": params["password"]}
        cmd = [
            binary,
            f"-h{params['host']}",
            f"-P{params['port']}",
            f"-u{params['user']}",
            "--", params["db"],
        ]
        try:
            with source.open("rb") as dump_file:
                result = subprocess.run(  # nosec B603
                    cmd, stdin=dump_file, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, env=env
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
                    if normalized == "data" or normalized.startswith("data/"):
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
                    dest_path.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                dest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.open(member, "r") as source, dest_path.open("wb") as dest:
                    os.chmod(dest_path, 0o600)
                    shutil.copyfileobj(source, dest)

    # ── Public API ───────────────────────────────────────────────────────────

    def create_full_backup(self, db_url: str = None, include_files: bool = True) -> Dict:
        """Publish an archive only after every requested payload succeeds."""
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"syspass_full_backup_{stamp}_{uuid.uuid4().hex}"
        staging = Path(tempfile.mkdtemp(prefix=".backup-", dir=self.backup_dir))
        partial_archive = Path(str(staging) + ".zip")
        try:
            if db_url and not self._try_mysqldump(db_url, staging / "database.sql"):
                raise RuntimeError("Requested database dump failed; no backup was published")
            data_dir = Path("./data")
            data_included = include_files and data_dir.is_dir()
            if data_included:
                if data_dir.is_symlink() or any(path.is_symlink() for path in data_dir.rglob("*")):
                    raise RuntimeError("Runtime data contains symbolic links; backup refused")
                shutil.copytree(data_dir, staging / "data")
            if not db_url and not data_included:
                raise RuntimeError("No database or runtime data to back up")
            partial_archive.touch(mode=0o600, exist_ok=False)
            shutil.make_archive(str(staging), "zip", staging)
            os.chmod(partial_archive, 0o600)
            with zipfile.ZipFile(partial_archive) as archive:
                if archive.testzip() is not None:
                    raise RuntimeError("Backup archive verification failed")
            archive_path = self.backup_dir / f"{backup_name}.zip"
            partial_archive.replace(archive_path)
            stat = archive_path.stat()
            return {
                "filename": archive_path.name,
                "path": str(archive_path),
                "size": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "db_included": bool(db_url),
                "data_included": data_included,
            }
        except Exception as exc:
            raise RuntimeError(f"Backup failed: {exc}") from exc
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            partial_archive.unlink(missing_ok=True)

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
        return self.create_full_backup(include_files=True)["path"]

    def list_backups(self) -> list:
        """List all available backups"""
        backups = []

        for file in self.backup_dir.glob("*.zip"):
            if file.name.startswith(".") or file.is_symlink():
                continue
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

    def restore_backup(self, filename: str, db_url: Optional[str] = None, *, offline: bool = False) -> Dict:
        """Restore with writers stopped; preserve the mounted data directory."""
        if not offline:
            raise RuntimeError("Restore requires the offline recovery command with all application writers stopped")
        archive_path = self.resolve_backup_path(filename)
        work = Path(tempfile.mkdtemp(prefix=".restore-", dir=self.backup_dir))
        target = Path("./data")
        data_work = None
        moved_original = []
        installed = []
        database_attempted = False
        keep_recovery = False
        try:
            payload = work / "payload"
            self._extract_archive(archive_path, payload)
            dump = payload / "database.sql"
            data = payload / "data"
            if not dump.is_file() and not data.is_dir():
                raise RuntimeError("Archive contains no database or runtime data")
            if dump.is_file():
                if not db_url:
                    raise RuntimeError("Database restore requires a configured DATABASE_URL")
                if not self._try_mysqldump(db_url, work / "rollback.sql"):
                    raise RuntimeError("Cannot capture recovery database snapshot; nothing was restored")
            if data.is_dir():
                if target.is_symlink():
                    raise RuntimeError("Runtime data directory must not be a symbolic link")
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                # Stage on the same filesystem as the mounted directory's contents.
                data_work = Path(tempfile.mkdtemp(prefix=".restore-", dir=target)).resolve()
                shutil.copytree(data, data_work / "new")
                (data_work / "original").mkdir()
                for child in list(target.iterdir()):
                    if child.name == data_work.name:
                        continue
                    child.replace(data_work / "original" / child.name)
                    moved_original.append(child.name)
                for child in (data_work / "new").iterdir():
                    child.replace(target / child.name)
                    installed.append(child.name)
            if dump.is_file():
                database_attempted = True
                if not self._try_mysql_restore(db_url, dump):
                    raise RuntimeError("Failed to restore database dump with mysql client")
            return {
                "filename": archive_path.name,
                "db_restored": dump.is_file(),
                "data_restored": data.is_dir(),
            }
        except Exception as exc:
            rollback_errors = []
            if database_attempted:
                try:
                    if not self._try_mysql_restore(db_url, work / "rollback.sql"):
                        rollback_errors.append("database rollback failed")
                except Exception:
                    rollback_errors.append("database rollback failed")
            if data_work is not None:
                try:
                    for name in installed:
                        path = target / name
                        if path.is_dir() and not path.is_symlink():
                            shutil.rmtree(path)
                        else:
                            path.unlink(missing_ok=True)
                    for name in moved_original:
                        (data_work / "original" / name).replace(target / name)
                except OSError:
                    rollback_errors.append("runtime data rollback failed")
            if rollback_errors:
                keep_recovery = True
                raise RuntimeError(
                    f"Restore failed; {'; '.join(rollback_errors)}. Keep applications stopped. "
                    f"Recovery material retained at {work} and {data_work}"
                ) from exc
            raise RuntimeError(f"Restore failed; original state recovered where modified: {exc}") from exc
        finally:
            if not keep_recovery:
                shutil.rmtree(work, ignore_errors=True)
                if data_work is not None:
                    shutil.rmtree(data_work, ignore_errors=True)

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
            if file.name.startswith(".") or file.is_symlink():
                continue
            stat = file.stat()
            file_date = datetime.fromtimestamp(stat.st_ctime)

            if file_date < cutoff_date:
                os.remove(file)
                deleted_count += 1

        return deleted_count
