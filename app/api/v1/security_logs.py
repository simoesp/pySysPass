from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.db.base import get_db
from app.schemas.security_log import EventLogResponse, TrackResponse
from app.services.security_log_service import EventLogService, TrackService
from app.api.deps import require_permission

router = APIRouter()


# ── Event Log ──────────────────────────────────────────────────────────────

@router.get("/audit-log", response_model=List[EventLogResponse])
async def list_event_log(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    level: Optional[str] = Query(None),
    login: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('evl')),
):
    return EventLogService(db).list(skip=skip, limit=limit, level=level, login=login)


@router.get("/audit-log/count")
async def count_event_log(
    level: Optional[str] = Query(None),
    login: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('evl')),
):
    return {"count": EventLogService(db).count(level=level, login=login)}


@router.delete("/audit-log", status_code=status.HTTP_200_OK)
async def clear_event_log(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('evl')),
):
    n = EventLogService(db).clear()
    return {"deleted": n}


# ── Tracks ─────────────────────────────────────────────────────────────────

@router.get("/tracks", response_model=List[TrackResponse])
async def list_tracks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    locked_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('evl')),
):
    return TrackService(db).list(skip=skip, limit=limit, locked_only=locked_only)


@router.get("/tracks/count")
async def count_tracks(
    locked_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('evl')),
):
    return {"count": TrackService(db).count(locked_only=locked_only)}


@router.post("/tracks/{track_id}/unlock", status_code=status.HTTP_200_OK)
async def unlock_track(
    track_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('evl')),
):
    if not TrackService(db).unlock(track_id):
        raise HTTPException(status_code=404, detail="Track not found")
    return {"message": "Unlocked"}


@router.delete("/tracks/{track_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_track(
    track_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('evl')),
):
    if not TrackService(db).delete(track_id):
        raise HTTPException(status_code=404, detail="Track not found")


@router.delete("/tracks", status_code=status.HTTP_200_OK)
async def clear_tracks(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('evl')),
):
    n = TrackService(db).clear()
    return {"deleted": n}
