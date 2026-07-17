"""Custom Field Services - CRUD for custom field types, definitions, and values"""
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.custom_field import CustomFieldType, CustomFieldDef, CustomFieldValue
from app.core.security import EncryptionService


# PHP ActionsInterface module ID constants — must match the DB values written by sysPass PHP
MODULE_ACCOUNT   = 1
MODULE_CATEGORY  = 101
MODULE_CLIENT    = 301
MODULE_USER      = 701
MODULE_USERGROUP = 801

MODULE_LABELS = {
    MODULE_ACCOUNT:   "Account",
    MODULE_CATEGORY:  "Category",
    MODULE_CLIENT:    "Client",
    MODULE_USER:      "User",
    MODULE_USERGROUP: "User Group",
}

# Legacy alias
ACCOUNT_MODULE_ID = MODULE_ACCOUNT


class CustomFieldTypeService:
    """Service for custom field type definitions"""

    def __init__(self, db: Session, encryption_service: EncryptionService):
        self.db = db
        self.encryption = encryption_service

    def get_all(self) -> List[CustomFieldType]:
        """Get all custom field types"""
        return self.db.execute(
            select(CustomFieldType).order_by(CustomFieldType.name)
        ).scalars().all()

    def get_by_id(self, type_id: int) -> Optional[CustomFieldType]:
        """Get custom field type by ID"""
        return self.db.get(CustomFieldType, type_id)

    def create(self, name: str, field_type: str = None, icon: str = 'text',
               is_encrypted: bool = False, is_active: bool = True) -> CustomFieldType:
        """Create a new custom field type"""
        field_type_obj = CustomFieldType(
            name=name,
            text=field_type or name.title(),
        )
        self.db.add(field_type_obj)
        self.db.commit()
        self.db.refresh(field_type_obj)
        return field_type_obj

    def update(self, type_id: int, name: str = None, field_type: str = None,
               icon: str = None, is_encrypted: bool = None, is_active: bool = None) -> CustomFieldType:
        """Update custom field type"""
        field_type_obj = self.get_by_id(type_id)
        if not field_type_obj:
            raise ValueError(f"Custom field type {type_id} not found")

        if name is not None:
            field_type_obj.name = name
        if field_type is not None:
            field_type_obj.text = field_type

        self.db.commit()
        self.db.refresh(field_type_obj)
        return field_type_obj

    def delete(self, type_id: int) -> bool:
        """Delete custom field type"""
        field_type_obj = self.get_by_id(type_id)
        if not field_type_obj:
            return False
        self.db.delete(field_type_obj)
        self.db.commit()
        return True


class CustomFieldDefService:
    """Service for custom field definitions"""

    def __init__(self, db: Session, encryption_service: EncryptionService):
        self.db = db
        self.encryption = encryption_service

    def get_by_type(self, type_id: int) -> List[CustomFieldDef]:
        """Get all definitions for a field type"""
        return self.db.execute(
            select(CustomFieldDef)
            .where(CustomFieldDef.typeId == type_id)
            .order_by(CustomFieldDef.id)
        ).scalars().all()

    def get_by_id(self, def_id: int) -> Optional[CustomFieldDef]:
        """Get definition by ID"""
        return self.db.get(CustomFieldDef, def_id)

    def create(self, type_id: int, name: str, description: str = None,
               size: int = 50, is_required: bool = False, is_show: bool = True,
               order_num: int = 0, default_val: str = None, module_id: int = ACCOUNT_MODULE_ID,
               is_encrypted: bool = False) -> CustomFieldDef:
        """Create a new custom field definition"""
        definition = CustomFieldDef(
            typeId=type_id,
            name=name,
            moduleId=module_id,
            help=description,
            required=is_required,
            showInList=is_show,
            isEncrypted=is_encrypted,
        )
        self.db.add(definition)
        self.db.commit()
        self.db.refresh(definition)
        return definition

    def update(self, def_id: int, name: str = None, description: str = None,
               size: int = None, is_required: bool = None, is_show: bool = None,
               order_num: int = None, default_val: str = None) -> CustomFieldDef:
        """Update custom field definition"""
        definition = self.get_by_id(def_id)
        if not definition:
            raise ValueError(f"Custom field definition {def_id} not found")

        if name is not None:
            definition.name = name
        if description is not None:
            definition.help = description
        if is_required is not None:
            definition.required = is_required
        if is_show is not None:
            definition.showInList = is_show

        self.db.commit()
        self.db.refresh(definition)
        return definition

    def delete(self, def_id: int) -> bool:
        """Delete custom field definition"""
        definition = self.get_by_id(def_id)
        if not definition:
            return False
        self.db.delete(definition)
        self.db.commit()
        return True


class CustomFieldService:
    """Service for custom field values — works for any module (Account, Category, Client, User, Group)."""

    def __init__(self, db: Session, encryption_service: EncryptionService):
        self.db = db
        self.encryption = encryption_service

    def get_values(self, module_id: int, item_id: int) -> List[CustomFieldValue]:
        """Get all custom field values for any module + item."""
        return self.db.execute(
            select(CustomFieldValue)
            .where(
                CustomFieldValue.moduleId == module_id,
                CustomFieldValue.itemId == item_id,
            )
            .order_by(CustomFieldValue.id)
        ).scalars().all()

    def get_value(self, def_id: int, module_id: int, item_id: int) -> Optional[CustomFieldValue]:
        """Get a specific custom field value."""
        return self.db.execute(
            select(CustomFieldValue)
            .where(
                CustomFieldValue.definitionId == def_id,
                CustomFieldValue.moduleId == module_id,
                CustomFieldValue.itemId == item_id,
            )
        ).scalars().first()

    def set_value(self, def_id: int, item_id: int, value: str,
                  module_id: int = MODULE_ACCOUNT) -> CustomFieldValue:
        """Set a custom field value for any module + item."""
        definition = self.db.get(CustomFieldDef, def_id)
        if not definition:
            raise ValueError(f"Custom field definition {def_id} not found")
        if definition.isEncrypted:
            raise ValueError("Encrypted PHP custom fields must be written by sysPass PHP")

        existing = self.get_value(def_id, module_id, item_id)
        if existing:
            existing.value = value
            existing.key = None
        else:
            existing = CustomFieldValue(
                moduleId=module_id,
                itemId=item_id,
                definitionId=def_id,
                value=value,
                key=None,
            )
            self.db.add(existing)

        self.db.commit()
        self.db.refresh(existing)
        return existing

    def get_decrypted_value(self, value_obj: CustomFieldValue) -> Optional[str]:
        if value_obj.value and not value_obj.key:
            return value_obj.value
        return None

    def delete_value(self, def_id: int, module_id: int, item_id: int) -> bool:
        """Delete a custom field value."""
        value = self.get_value(def_id, module_id, item_id)
        if not value:
            return False
        self.db.delete(value)
        self.db.commit()
        return True

    def delete_item_values(self, module_id: int, item_id: int) -> int:
        """Delete ALL custom field values for an item (use on item deletion)."""
        values = self.get_values(module_id, item_id)
        for v in values:
            self.db.delete(v)
        self.db.commit()
        return len(values)

    def get_all_values(self, module_id: int, item_id: int) -> Dict[str, Any]:
        """Get all custom field values for a module + item, enriched with definition metadata."""
        values = self.get_values(module_id, item_id)
        result = {}
        for value in values:
            definition = self.db.get(CustomFieldDef, value.definitionId)
            if definition:
                field_type = self.db.get(CustomFieldType, definition.typeId)
                result[str(definition.id)] = {
                    'def_id': definition.id,
                    'type_id': definition.typeId,
                    'module_id': module_id,
                    'item_id': item_id,
                    'name': definition.name,
                    'type': field_type.name if field_type else None,
                    'field_type': field_type.type if field_type else None,
                    'value': self.get_decrypted_value(value),
                    'is_encrypted': bool(definition.isEncrypted),
                }
        return result

    # ── Backward-compatible aliases (accounts only) ──────────────────────────

    def get_account_values(self, account_id: int) -> List[CustomFieldValue]:
        return self.get_values(MODULE_ACCOUNT, account_id)

    def get_account_all_values(self, account_id: int) -> Dict[str, Any]:
        return self.get_all_values(MODULE_ACCOUNT, account_id)
