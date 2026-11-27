"""Backup Service - Database and file backups

ADR-0013: every published backup is encrypted with AES-256-GCM by default.
An unencrypted backup is produced only under an explicit administrator
exception (``BACKUP_ALLOW_UNENCRYPTED``); the API records an audit event for
it (``backup.exception.unencrypted``).

Encrypted archive layout: the payload members (``database.sql``, ``data/...``)
are unchanged in name, but each member's bytes are sealed and an added
plaintext ``manifest.json`` records the key version and per-member nonces/tags.
Restore decrypts transparently into the staging tree, so the path-traversal
and symlink defenses validate authenticated plaintext. Pre-encryption archives
(no manifest) remain restorable and are reported as ``encrypted=False``.

IMPL-008: HMAC-SHA256 integrity verification over encrypted member ciphertexts.
IMPL-009: Optional Ed25519 manifest signing for authenticity verification.
"""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core import backup_crypto


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


def _write_member(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.external_attr = 0o600 << 16
    zf.writestr(info, data)


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

    # ── Archive inspection, encryption and extraction ────────────────────────

    def _inspect_archive(self, archive_path: Path) -> Dict[str, bool]:
        """Report whether an archive contains DB and/or data payloads."""
        db_included = False
        data_included = False
        encrypted = False
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                encrypted = backup_crypto.MANIFEST_NAME in archive.namelist()
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
        result = {"db_included": db_included, "data_included": data_included}
        if encrypted:
            manifest = self._read_manifest(archive_path)
            result["encrypted"] = bool(manifest and manifest.get("encrypted"))
        else:
            result["encrypted"] = False
        return result

    def _read_manifest(self, archive_path: Path) -> Optional[Dict]:
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                if backup_crypto.MANIFEST_NAME not in archive.namelist():
                    return None
                return json.loads(archive.read(backup_crypto.MANIFEST_NAME).decode("utf-8"))
        except (OSError, ValueError, zipfile.BadZipFile):
            return None

    def _build_archive(self, staging: Path, archive_path: Path) -> Tuple[Dict, Dict]:
        """Write the published ZIP from staged payload files, encrypting per ADR-0013.

        Returns ``(encryption_info, manifest)``. Raises on any encryption
        failure so no unencrypted archive is ever published by accident.
        """
        exception = backup_crypto.exception_allowed()
        manifest: Dict = {
            "version": "1.0",
            "algorithm": "none" if exception else backup_crypto.ALGORITHM,
            "encrypted": not exception,
            "created_at": datetime.now().isoformat(),
            "members": {},
        }
        key_id: Optional[str] = None
        key: Optional[bytes] = None
        if not exception:
            key_id, key = backup_crypto.current_key()
            manifest["key_id"] = key_id

        payload_files = sorted(
            path for path in staging.rglob("*") if path.is_file()
        )
        
        # Collect encrypted member ciphertexts for HMAC computation
        encrypted_ciphertexts = []
        
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in payload_files:
                name = path.relative_to(staging).as_posix()
                plaintext = path.read_bytes()
                if exception:
                    _write_member(zf, name, plaintext)
                    manifest["members"][name] = {"encrypted": False}
                else:
                    assert key is not None  # invariant: encrypted branch loads key above
                    ciphertext, nonce, tag = backup_crypto.seal_bytes(plaintext, key)
                    _write_member(zf, name, ciphertext)
                    manifest["members"][name] = {
                        "encrypted": True,
                        "nonce": nonce.hex(),
                        "tag": tag.hex(),
                        "size": len(plaintext),
                    }
                    encrypted_ciphertexts.append(ciphertext)
            
            # Compute HMAC-SHA256 over concatenated encrypted ciphertexts (IMPL-008)
            if not exception and encrypted_ciphertexts:
                hmac_key = key  # Use the current encryption key for HMAC
                hmac_data = b"".join(encrypted_ciphertexts)
                hmac_digest = backup_crypto.compute_hmac_sha256(hmac_data, hmac_key)
                manifest["hmac"] = base64.b64encode(hmac_digest).decode("ascii")
            
            # Sign manifest with Ed25519 if signing keyring provided (IMPL-009)
            signing_keyring = os.environ.get(backup_crypto.SIGNING_KEYRING_ENV)
            if signing_keyring and not exception:
                try:
                    signing_key_id, private_key = backup_crypto.load_signing_keyring(signing_keyring)
                    signature = backup_crypto.sign_manifest(manifest, private_key)
                    manifest["signature"] = base64.b64encode(signature).decode("ascii")
                    manifest["signing_key_id"] = signing_key_id
                except Exception as exc:
                    # Signing is optional; warn but don't fail backup creation
                    import logging
                    logging.getLogger(__name__).warning(
                        "Backup manifest signing failed (backup will be created without signature): %s", exc
                    )

            manifest["backup_size"] = archive_path.stat().st_size
            zf.writestr(backup_crypto.MANIFEST_NAME, json.dumps(manifest, indent=2))

        encryption_info = {
            "encrypted": not exception,
            "algorithm": manifest["algorithm"],
            "key_id": key_id,
            "exception": exception,
            "audit_required": exception,
        }
        return encryption_info, manifest

    def _extract_archive(self, archive_path: Path, target_dir: Path) -> Dict:
        """Extract an archive to plaintext, decrypting when the manifest says so.

        Path-traversal and symlink defenses run on the manifest member names —
        the plaintext view — before any ciphertext is opened, so untrusted
        archives cannot steer writes. Returns the manifest (``{}`` for legacy
        plaintext archives).
        """
        target_dir = target_dir.resolve()
        
        # Verify archive integrity and authenticity before extraction (IMPL-008/009)
        encryption_keyring = os.environ.get(backup_crypto.KEYRING_ENV)
        verification_keyring = os.environ.get(backup_crypto.VERIFICATION_KEYRING_ENV)
        require_signature = os.environ.get(backup_crypto.REQUIRE_SIGNATURE_ENV, "").strip().lower() in ("1", "true", "yes", "on")
        
        backup_crypto.verify_archive_before_extract(
            archive_path,
            encryption_keyring=encryption_keyring,
            verification_keyring=verification_keyring,
            require_signature=require_signature,
        )
        
        with zipfile.ZipFile(archive_path, "r") as archive:
            names = [n for n in archive.namelist() if n.strip("/") != backup_crypto.MANIFEST_NAME]
            manifest = self._read_manifest(archive_path) or {}
            manifest_members = manifest.get("members", {})
            encrypted = bool(manifest.get("encrypted"))
            key: Optional[bytes] = None
            if encrypted:
                key = backup_crypto.key_for_id(manifest.get("key_id", ""))

            # Validate every name up front (before any decryption/copy).
            for name in names:
                member_path = Path(name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RuntimeError("Backup archive contains invalid paths")
                dest_path = (target_dir / member_path).resolve()
                try:
                    dest_path.relative_to(target_dir)
                except ValueError as exc:
                    raise RuntimeError("Backup archive contains invalid paths") from exc
                if self._member_is_symlink(archive, name):
                    raise RuntimeError("Backup archive contains symbolic links")

            for name in names:
                dest_path = target_dir / name
                raw = archive.read(name)
                entry = manifest_members.get(name, {})
                if encrypted:
                    assert key is not None  # invariant: encrypted archives load key above
                    if not entry.get("encrypted"):
                        raise RuntimeError(
                            f"Backup manifest marks {name!r} as unencrypted in an encrypted archive"
                        )
                    try:
                        plaintext = backup_crypto.open_bytes(
                            raw, bytes.fromhex(entry["nonce"]), bytes.fromhex(entry["tag"]), key
                        )
                    except (KeyError, ValueError) as exc:
                        raise RuntimeError(
                            f"Backup manifest for {name!r} is malformed"
                        ) from exc
                else:
                    plaintext = raw
                dest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with dest_path.open("wb") as dest:
                    os.chmod(dest_path, 0o600)
                    dest.write(plaintext)
        return manifest

    @staticmethod
    def _member_is_symlink(archive: zipfile.ZipFile, name: str) -> bool:
        member = archive.getinfo(name)
        return (member.external_attr >> 16) & 0o170000 == 0o120000

    # ── Public API ───────────────────────────────────────────────────────────

    def create_full_backup(self, db_url: str = None, include_files: bool = True) -> Dict:
        """Publish an encrypted archive only after every payload succeeds."""
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
            encryption, _manifest = self._build_archive(staging, partial_archive)
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
                "encryption": encryption,
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
            backup_info = {
                'filename': file.name,
                'path': str(file),
                'size': stat.st_size,
                'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'db_included': contents["db_included"],
                'data_included': contents["data_included"],
                'encrypted': contents["encrypted"],
            }
            # Add HMAC and signature presence info (IMPL-008/009)
            manifest = self._read_manifest(file)
            if manifest:
                backup_info['hmac_present'] = 'hmac' in manifest
                backup_info['signature_present'] = 'signature' in manifest
                if 'signing_key_id' in manifest:
                    backup_info['signing_key_id'] = manifest['signing_key_id']
            backups.append(backup_info)

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
            manifest = self._extract_archive(archive_path, payload)
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
                "encrypted": bool(manifest.get("encrypted", False)),
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
