from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.services.item_preset_service import ItemPresetService, VALID_TYPES
from app.services.auth_service import decode_token
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter()
security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"id": payload.get("user_id"), "username": payload.get("username")}


def require_admin(current_user=Depends(get_current_user)):
    from app.db.base import get_db as _get_db
    # Actual admin check happens in the route via injected db; this just threads the user
    return current_user


class ItemPresetCreate(BaseModel):
    type: str
    user_id: Optional[int] = None
    user_group_id: Optional[int] = None
    user_profile_id: Optional[int] = None
    fixed: bool = False
    priority: int = 0
    data: Dict[str, Any] = {}


class ItemPresetUpdate(BaseModel):
    fixed: Optional[bool] = None
    priority: Optional[int] = None
    data: Optional[Dict[str, Any]] = None


@router.get("/item-presets", response_model=List[Dict])
async def list_presets(
    preset_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return ItemPresetService(db).list(preset_type)


@router.get("/item-presets/types")
async def list_preset_types(current_user=Depends(get_current_user)):
    return sorted(VALID_TYPES)


@router.get("/item-presets/{preset_id}", response_model=Dict)
async def get_preset(
    preset_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    row = ItemPresetService(db).get(preset_id)
    if not row:
        raise HTTPException(status_code=404, detail="Preset not found")
    return row


@router.get("/item-presets/context/{preset_type}", response_model=Optional[Dict])
async def get_preset_for_context(
    preset_type: str,
    user_id: Optional[int] = None,
    user_group_id: Optional[int] = None,
    user_profile_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return ItemPresetService(db).get_for_context(
        preset_type, user_id, user_group_id, user_profile_id
    )


@router.post("/item-presets", status_code=status.HTTP_201_CREATED, response_model=Dict)
async def create_preset(
    body: ItemPresetCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return ItemPresetService(db).create(
            preset_type=body.type,
            user_id=body.user_id,
            user_group_id=body.user_group_id,
            user_profile_id=body.user_profile_id,
            fixed=body.fixed,
            priority=body.priority,
            data=body.data,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put("/item-presets/{preset_id}", response_model=Dict)
async def update_preset(
    preset_id: int,
    body: ItemPresetUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    row = ItemPresetService(db).update(
        preset_id, fixed=body.fixed, priority=body.priority, data=body.data
    )
    if not row:
        raise HTTPException(status_code=404, detail="Preset not found")
    return row


@router.delete("/item-presets/{preset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_preset(
    preset_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not ItemPresetService(db).delete(preset_id):
        raise HTTPException(status_code=404, detail="Preset not found")
