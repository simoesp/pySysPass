"""Custom Fields API Endpoints"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select
from pydantic import BaseModel

from app.db.base import get_db
from app.core.security import get_encryption_service
from app.api.deps import enforce_permissions, get_current_user, require_permission
from app.services.account_service import AccountService
from app.services.custom_field_service import (
    CustomFieldTypeService,
    CustomFieldDefService,
    CustomFieldService,
    MODULE_ACCOUNT, MODULE_CATEGORY, MODULE_CLIENT, MODULE_USER, MODULE_USERGROUP,
    MODULE_LABELS,
)
from app.models.custom_field import CustomFieldType, CustomFieldDef, CustomFieldValue


router = APIRouter(prefix="/custom-fields", tags=["Custom Fields"])


def _require_value_access(
    db: Session,
    current_user: dict,
    module_id: int,
    item_id: int,
    *,
    write: bool = False,
) -> None:
    """Make custom-field values inherit their parent PHP resource ACL."""
    if module_id == MODULE_ACCOUNT:
        keys = ("acc_edit",) if write else ("acc_view", "acc_edit")
        enforce_permissions(current_user, db, *keys, account_admin=True)
        account_service = AccountService(db, get_encryption_service())
        allowed = (
            account_service.can_edit_account(item_id, current_user["id"])
            if write
            else account_service.can_access_account(item_id, current_user["id"])
        )
        if not allowed:
            raise HTTPException(status_code=404, detail="Account not found")
        return

    permission_by_module = {
        MODULE_CATEGORY: "mgm_categories",
        MODULE_CLIENT: "mgm_customers",
        MODULE_USER: "mgm_users",
        MODULE_USERGROUP: "mgm_groups",
    }
    permission = permission_by_module.get(module_id)
    if not permission:
        raise HTTPException(status_code=400, detail="Unsupported custom field module")
    enforce_permissions(current_user, db, permission)


# Pydantic schemas
class CustomFieldTypeCreate(BaseModel):
    name: str
    type: str  # text, password, url, email, phone, date, integer, textarea
    icon: str = 'text'
    is_encrypted: bool = False
    is_active: bool = True


class CustomFieldTypeUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    icon: Optional[str] = None
    is_encrypted: Optional[bool] = None
    is_active: Optional[bool] = None


class CustomFieldDefCreate(BaseModel):
    type_id: int
    name: str
    module_id: int = 1
    description: Optional[str] = None
    size: int = 50
    is_required: bool = False
    is_show: bool = True
    order_num: int = 0
    default_val: Optional[str] = None
    is_encrypted: bool = False


class CustomFieldDefUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    size: Optional[int] = None
    is_required: Optional[bool] = None
    is_show: Optional[bool] = None
    order_num: Optional[int] = None
    default_val: Optional[str] = None


class CustomFieldValueCreate(BaseModel):
    def_id: int
    item_id: int
    module_id: int = MODULE_ACCOUNT
    value: str


class CustomFieldValueResponse(BaseModel):
    id: int
    def_id: int
    account_id: int
    value: Optional[str]
    is_encrypted: bool
    definition_name: str
    field_type: str


# Custom Field Type Endpoints
@router.get("/types", response_model=List[dict])
async def get_custom_field_types(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """Get all custom field types"""
    service = CustomFieldTypeService(db, get_encryption_service())
    types = service.get_all()
    return [{
        'id': t.id,
        'name': t.name,
        'type': t.type,
        'icon': t.icon,
        'is_encrypted': t.is_encrypted,
        'is_active': t.is_active,
        'date_create': None
    } for t in types]


@router.post("/types", response_model=dict)
async def create_custom_field_type(
    data: CustomFieldTypeCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_custom_fields')),
):
    """Create a new custom field type"""
    service = CustomFieldTypeService(db, get_encryption_service())
    try:
        field_type = service.create(
            name=data.name,
            field_type=data.type,
            icon=data.icon,
            is_encrypted=data.is_encrypted,
            is_active=data.is_active
        )
        return {
            'id': field_type.id,
            'name': field_type.name,
            'type': field_type.type,
            'icon': field_type.icon,
            'is_encrypted': field_type.is_encrypted,
            'is_active': field_type.is_active
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/types/{type_id}", response_model=dict)
async def update_custom_field_type(
    type_id: int,
    data: CustomFieldTypeUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_custom_fields')),
):
    """Update a custom field type"""
    service = CustomFieldTypeService(db, get_encryption_service())
    try:
        field_type = service.update(
            type_id=type_id,
            name=data.name,
            field_type=data.type,
            icon=data.icon,
            is_encrypted=data.is_encrypted,
            is_active=data.is_active
        )
        return {
            'id': field_type.id,
            'name': field_type.name,
            'type': field_type.type,
            'icon': field_type.icon,
            'is_encrypted': field_type.is_encrypted,
            'is_active': field_type.is_active
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/types/{type_id}")
async def delete_custom_field_type(
    type_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_custom_fields')),
):
    """Delete a custom field type"""
    service = CustomFieldTypeService(db, get_encryption_service())
    success = service.delete(type_id)
    if not success:
        raise HTTPException(status_code=404, detail="Custom field type not found")
    return {"message": "Custom field type deleted"}


# Custom Field Definition Endpoints
@router.get("/definitions", response_model=List[dict])
async def get_custom_field_definitions(
    type_id: Optional[int] = None,
    module_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get custom field definitions"""
    q = select(CustomFieldDef).order_by(CustomFieldDef.moduleId, CustomFieldDef.id)
    if type_id:
        q = q.where(CustomFieldDef.typeId == type_id)
    if module_id is not None:
        q = q.where(CustomFieldDef.moduleId == module_id)
    definitions = db.execute(q).scalars().all()

    # build type lookup once
    type_ids = {d.typeId for d in definitions}
    types = {t.id: t for t in db.execute(
        select(CustomFieldType).where(CustomFieldType.id.in_(type_ids))
    ).scalars().all()} if type_ids else {}

    return [{
        'id': d.id,
        'type_id': d.typeId,
        'type_name': types[d.typeId].name if d.typeId in types else None,
        'type_text': types[d.typeId].text if d.typeId in types else None,
        'module_id': d.moduleId,
        'name': d.name,
        'description': d.description,
        'is_required': bool(d.required),
        'is_show': bool(d.showInList),
        'is_encrypted': bool(d.isEncrypted),
        'help': d.help,
    } for d in definitions]


@router.post("/definitions", response_model=dict)
async def create_custom_field_definition(
    data: CustomFieldDefCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_custom_fields')),
):
    """Create a new custom field definition"""
    service = CustomFieldDefService(db, get_encryption_service())
    try:
        definition = service.create(
            type_id=data.type_id,
            name=data.name,
            module_id=data.module_id,
            description=data.description,
            size=data.size,
            is_required=data.is_required,
            is_show=data.is_show,
            order_num=data.order_num,
            default_val=data.default_val,
            is_encrypted=data.is_encrypted,
        )
        ft = db.get(CustomFieldType, definition.typeId)
        return {
            'id': definition.id,
            'type_id': definition.typeId,
            'type_name': ft.name if ft else None,
            'type_text': ft.text if ft else None,
            'module_id': definition.moduleId,
            'name': definition.name,
            'description': definition.description,
            'is_required': bool(definition.required),
            'is_show': bool(definition.showInList),
            'is_encrypted': bool(definition.isEncrypted),
            'help': definition.help,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/definitions/{def_id}", response_model=dict)
async def update_custom_field_definition(
    def_id: int,
    data: CustomFieldDefUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_custom_fields')),
):
    """Update a custom field definition"""
    service = CustomFieldDefService(db, get_encryption_service())
    try:
        definition = service.update(
            def_id=def_id,
            name=data.name,
            description=data.description,
            size=data.size,
            is_required=data.is_required,
            is_show=data.is_show,
            order_num=data.order_num,
            default_val=data.default_val
        )
        ft = db.get(CustomFieldType, definition.typeId)
        return {
            'id': definition.id,
            'type_id': definition.typeId,
            'type_name': ft.name if ft else None,
            'type_text': ft.text if ft else None,
            'module_id': definition.moduleId,
            'name': definition.name,
            'description': definition.description,
            'is_required': bool(definition.required),
            'is_show': bool(definition.showInList),
            'is_encrypted': bool(definition.isEncrypted),
            'help': definition.help,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/definitions/{def_id}")
async def delete_custom_field_definition(
    def_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_custom_fields')),
):
    """Delete a custom field definition"""
    service = CustomFieldDefService(db, get_encryption_service())
    success = service.delete(def_id)
    if not success:
        raise HTTPException(status_code=404, detail="Custom field definition not found")
    return {"message": "Custom field definition deleted"}


# ── Module reference ──────────────────────────────────────────────────────────

@router.get("/modules")
async def get_modules(current_user=Depends(get_current_user)):
    """Return the module ID → label mapping so the frontend knows which ID to use per entity."""
    return [{"id": k, "label": v} for k, v in MODULE_LABELS.items()]


# ── Custom Field Value Endpoints ──────────────────────────────────────────────
# NOTE: literal-segment routes (/values/account/…) must come BEFORE wildcard
# routes (/values/{module_id}/{item_id}) to avoid shadowing.

@router.get("/values/account/{account_id}", response_model=List[dict])
async def get_account_custom_field_values(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Backward-compatible alias — equivalent to /values/1/{account_id}."""
    _require_value_access(db, current_user, MODULE_ACCOUNT, account_id)
    service = CustomFieldService(db, get_encryption_service())
    return list(service.get_all_values(MODULE_ACCOUNT, account_id).values())


@router.get("/values/{module_id}/{item_id}", response_model=List[dict])
async def get_item_custom_field_values(
    module_id: int,
    item_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get all custom field values for any module + item."""
    _require_value_access(db, current_user, module_id, item_id)
    service = CustomFieldService(db, get_encryption_service())
    return list(service.get_all_values(module_id, item_id).values())


@router.post("/values", response_model=dict)
async def set_custom_field_value(
    data: CustomFieldValueCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Set a custom field value for any module + item."""
    _require_value_access(
        db, current_user, data.module_id, data.item_id, write=True
    )
    service = CustomFieldService(db, get_encryption_service())
    try:
        value_obj = service.set_value(
            def_id=data.def_id,
            item_id=data.item_id,
            value=data.value,
            module_id=data.module_id,
        )
        definition = db.get(CustomFieldDef, data.def_id)
        field_type = db.get(CustomFieldType, definition.typeId) if definition else None
        return {
            'id': value_obj.id,
            'def_id': value_obj.definitionId,
            'module_id': value_obj.moduleId,
            'item_id': value_obj.itemId,
            'definition_name': definition.name if definition else None,
            'field_type': field_type.type if field_type else None,
            'is_encrypted': bool(definition.isEncrypted) if definition else False,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/values/account/{def_id}/{account_id}")
async def delete_account_custom_field_value(
    def_id: int,
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Backward-compatible alias for account custom field deletion."""
    _require_value_access(db, current_user, MODULE_ACCOUNT, account_id, write=True)
    service = CustomFieldService(db, get_encryption_service())
    success = service.delete_value(def_id, MODULE_ACCOUNT, account_id)
    if not success:
        raise HTTPException(status_code=404, detail="Custom field value not found")
    return {"message": "Custom field value deleted"}


@router.delete("/values/{def_id}/{module_id}/{item_id}")
async def delete_custom_field_value(
    def_id: int,
    module_id: int,
    item_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Delete a custom field value."""
    _require_value_access(db, current_user, module_id, item_id, write=True)
    service = CustomFieldService(db, get_encryption_service())
    success = service.delete_value(def_id, module_id, item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Custom field value not found")
    return {"message": "Custom field value deleted"}
