"""Backup API — create, list, download, restore, and delete backups.

ADR-0013: all backups are AES-256-GCM encrypted by default. When the admin
exception ``BACKUP_ALLOW_UNENCRYPTED`` is active the service publishes a
plaintext archive and this endpoint records a WARNING-level ``EventLog``
audit event before returning (the event is recorded even if the response is
subsequently discarded).
"""
import logging
import time
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.config import settings
from app.db.base import get_db
from app.models.account import EventLog
from app.services.backup_service import BackupService
from app.services.plugin_service import PluginService

router = APIRouter(prefix="/backup", tags=["Backup"])

BACKUP_DIR = "./backups"
logger = logging.getLogger(__name__)

# Audit action name per ADR-0013 (recorded in EventLog.action).
AUDIT_ACTION_UNENCRYPTED_EXCEPTION = "backup.exception.unencrypted"


def _svc() -> BackupService:
    return BackupService(backup_dir=BACKUP_DIR)


def _safe_path(filename: str):
    """Resolve filename inside backup dir, reject path traversal."""
    try:
        return _svc().resolve_backup_path(filename)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Backup not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid backup filename") from exc


@router.get("/")
def list_backups(current_user=Depends(require_permission('config_backup'))) -> List[dict]:
    """List all available backup archives."""
    return _svc().list_backups()


def _log_unencrypted_exception(db: Session, current_user: dict, backup_result: dict) -> None:
    """Record the admin unencrypted-backup exception as an EventLog audit entry.

    ADR-0013 requires: security warning (logged at WARNING) + audit event.
    The event is committed immediately so it survives any later failure.
    """
    login = current_user.get("login") or current_user.get("username") or ""
    user_id = current_user.get("id")
    row = EventLog(
        date=int(time.time()),
        login=login,
        userId=user_id,
        ipAddress="0.0.0.0",  # nosec B104 - default log IP placeholder
        action=AUDIT_ACTION_UNENCRYPTED_EXCEPTION,
        description=(
            "Unencrypted backup published under administrator exception: "
            f"{backup_result['filename']}"
        ),
        level="WARNING",
    )
    db.add(row)
    db.commit()


@router.post("/create")
def create_backup(
    include_db: bool = True,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_backup')),
):
    """Publish an encrypted backup only when all requested components succeed.

    ADR-0013: AES-256-GCM encryption is mandatory. A 503 is returned when the
    backup keyring is absent and the admin exception is not set. When the
    exception is active the plaintext archive is published and an audit event
    is written to ``EventLog`` (action ``backup.exception.unencrypted``).
    """
    if include_db and not settings.DATABASE_URL:
        raise HTTPException(status_code=503, detail="Database backup requires DATABASE_URL")
    db_url = settings.DATABASE_URL if include_db else None
    try:
        result = _svc().create_full_backup(db_url=db_url, include_files=True)
    except RuntimeError as exc:
        logger.exception("Backup creation failed")
        # Distinguish a missing/unreadable key (operational config error) from
        # other failures so callers get a clear signal to fix the deployment.
        from app.core.backup_crypto import BackupKeyMissing, BackupKeyUnreadable
        cause = exc.__cause__ or exc
        if isinstance(cause, (BackupKeyMissing, BackupKeyUnreadable)):
            raise HTTPException(
                status_code=503,
                detail=(
                    "Backup encryption key is not configured. Provision the keyring "
                    "or set BACKUP_ALLOW_UNENCRYPTED=true (audited) to override."
                ),
            ) from exc
        raise HTTPException(status_code=500, detail="Backup creation failed") from exc
    encryption = result.get("encryption", {})
    if encryption.get("audit_required"):
        logger.warning(
            "Unencrypted backup %s published under BACKUP_ALLOW_UNENCRYPTED exception (user=%s)",
            result["filename"],
            current_user.get("id"),
        )
        _log_unencrypted_exception(db, current_user, result)
    PluginService(db).call_plugin_hook("on_backup_created", payload=result, actor_user_id=current_user.get("id"))
    return result


@router.get("/{filename}/download")
def download_backup(filename: str, current_user=Depends(require_permission('config_backup'))):
    """Download a backup archive by filename."""
    path = _safe_path(filename)
    return FileResponse(path=str(path), media_type="application/zip", filename=filename)


@router.post("/{filename}/restore")
def restore_backup(
    filename: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_backup')),
):
    """Recovery must run offline to avoid concurrent writes and cached keys."""
    raise HTTPException(
        status_code=409,
        detail="Stop all application writers and use the offline restore command documented in the recovery guide.",
    )


@router.delete("/{filename}")
def delete_backup(filename: str, current_user=Depends(require_permission('config_backup'))):
    """Delete a backup archive."""
    _safe_path(filename)
    _svc().delete_backup(filename)
    return {"message": "Backup deleted"}
