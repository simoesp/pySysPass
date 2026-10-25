"""Backup API — create, list, download, restore, and delete backups."""
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.base import get_db
from app.api.deps import require_permission
from app.services.backup_service import BackupService
from app.services.plugin_service import PluginService

router = APIRouter(prefix="/backup", tags=["Backup"])

BACKUP_DIR = "./backups"
logger = logging.getLogger(__name__)


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


@router.post("/create")
def create_backup(
    include_db: bool = True,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_backup')),
):
    """Publish a backup only when all requested components succeed."""
    if include_db and not settings.DATABASE_URL:
        raise HTTPException(status_code=503, detail="Database backup requires DATABASE_URL")
    db_url = settings.DATABASE_URL if include_db else None
    try:
        result = _svc().create_full_backup(db_url=db_url, include_files=True)
        PluginService(db).call_plugin_hook("on_backup_created", payload=result, actor_user_id=current_user.get("id"))
        return result
    except RuntimeError as exc:
        logger.exception("Backup creation failed")
        raise HTTPException(status_code=500, detail="Backup creation failed") from exc


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
