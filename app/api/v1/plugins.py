from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.api.deps import require_admin
from app.services.plugin_service import PluginService


router = APIRouter()


class PluginConfigUpdate(BaseModel):
    config: Dict[str, Any] = Field(default_factory=dict)


@router.get("/plugins", response_model=List[Dict[str, Any]])
async def list_plugins(
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    return PluginService(db).get_all_plugins()


@router.post("/plugins/sync", response_model=List[Dict[str, Any]])
async def sync_plugins(
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    return PluginService(db).sync_plugins()


@router.get("/plugins/hooks", response_model=List[Dict[str, str]])
async def list_plugin_hooks(
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    return PluginService(db).get_platform_hooks()


@router.get("/plugins/{plugin_name}", response_model=Dict[str, Any])
async def get_plugin(
    plugin_name: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    plugin = PluginService(db).get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return plugin


@router.post("/plugins/{plugin_name}/enable")
async def enable_plugin(
    plugin_name: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    if not PluginService(db).enable_plugin(plugin_name):
        raise HTTPException(status_code=404, detail="Plugin not found or unavailable")
    return {"message": "Plugin enabled"}


@router.post("/plugins/{plugin_name}/disable")
async def disable_plugin(
    plugin_name: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    if not PluginService(db).disable_plugin(plugin_name):
        raise HTTPException(status_code=404, detail="Plugin not found")
    return {"message": "Plugin disabled"}


@router.put("/plugins/{plugin_name}/config", response_model=Dict[str, Any])
async def update_plugin_config(
    plugin_name: str,
    body: PluginConfigUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    service = PluginService(db)
    if not service.update_plugin_config(plugin_name, body.config):
        raise HTTPException(status_code=404, detail="Plugin not found")
    plugin = service.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return plugin
