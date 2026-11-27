"""Item presets: account defaults, password policy and session timeouts.

Rows use sysPass PHP's native format (see app.core.php_item_presets): PHP
type names, PHP-serialized data, and PHP's hash. Presets apply exactly as
in PHP ``ItemPresetRepository::getByFilter()``: a preset matches the user,
one of the user's groups (primary or secondary), or the user's profile, and
the highest ``priority`` plus scope bonus (user 3, group 2, profile 1) wins.
There are no global presets. Legacy rows from earlier pySysPass releases are
listed with ``legacy: true`` and never applied until they are saved again.
"""
from typing import Any, Dict, List, Optional

from sqlalchemy import false, or_
from sqlalchemy.orm import Session

from app.core import php_item_presets as presets
from app.core.php_item_presets import PresetError, ResolvedPreset
from app.models.account import ItemPreset, User, UserToUserGroup

VALID_TYPES = set(presets.TYPES)


def _to_dict(row: ItemPreset) -> Dict[str, Any]:
    preset_type, data, legacy = presets.decode_row(row.type, row.data)
    return {
        "id": row.id,
        "type": preset_type,
        "user_id": row.userId,
        "user_group_id": row.userGroupId,
        "user_profile_id": row.userProfileId,
        "fixed": bool(row.fixed),
        "priority": row.priority,
        "data": data,
        "legacy": legacy,
    }


class ItemPresetService:
    def __init__(self, db: Session):
        self.db = db

    def list(self, preset_type: Optional[str] = None) -> List[Dict[str, Any]]:
        q = self.db.query(ItemPreset)
        if preset_type:
            canonical = presets.canonical_type(preset_type)
            legacy_names = [name for name, value in presets.LEGACY_TYPES.items() if value == canonical]
            q = q.filter(ItemPreset.type.in_([canonical, *legacy_names]))
        return [_to_dict(r) for r in q.order_by(ItemPreset.priority.desc()).all()]

    def get(self, preset_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.query(ItemPreset).filter(ItemPreset.id == preset_id).first()
        return _to_dict(row) if row else None

    def get_for_user(self, preset_type: str, user_id: int) -> Optional[ResolvedPreset]:
        """ItemPresetService::getForUser(): the winning native preset, or None."""
        user = self.db.get(User, user_id)
        if user is None:
            return None
        preset_type = presets.canonical_type(preset_type)
        secondary = [row[0] for row in self.db.query(UserToUserGroup.userGroupId)
                     .filter(UserToUserGroup.userId == user_id).all()]
        rows = self.db.query(ItemPreset).filter(
            ItemPreset.type == preset_type,
            or_(
                ItemPreset.userId == user_id,
                ItemPreset.userGroupId == user.userGroupId,
                ItemPreset.userProfileId == user.userProfileId,
                ItemPreset.userGroupId.in_(secondary) if secondary else false(),
            ),
        ).all()

        def score(row):
            bonus = 3 if row.userId is not None else 2 if row.userGroupId is not None else \
                1 if row.userProfileId is not None else 0
            return (row.priority or 0) + bonus

        for row in sorted(rows, key=score, reverse=True)[:1]:
            _, data, legacy = presets.decode_row(row.type, row.data)
            if legacy:
                return None
            return ResolvedPreset(row.id, preset_type, bool(row.fixed), row.priority or 0, data)
        return None

    def password_as_image(self, user_id: int) -> bool:
        """AccountController::getPasswordPreset(): a fixed password preset with useImage."""
        preset = self.get_for_user(presets.ACCOUNT_PASSWORD, user_id)
        return bool(preset and preset.fixed and preset.data.get("use_image"))

    def create(self, preset_type: str,
               user_id: Optional[int] = None,
               user_group_id: Optional[int] = None,
               user_profile_id: Optional[int] = None,
               fixed: bool = False,
               priority: int = 0,
               data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        preset_type = presets.canonical_type(preset_type)
        if not (user_id or user_group_id or user_profile_id):
            # ItemsPresetForm::checkCommon()
            raise PresetError("An element of type user, group or profile need to be set")
        if not 0 <= int(priority) <= 255:
            raise PresetError("priority must be between 0 and 255")
        token_hash = presets.preset_hash(preset_type, user_id, user_group_id, user_profile_id, priority)
        if self.db.query(ItemPreset).filter(ItemPreset.hash == token_hash).first():
            raise PresetError("A preset for this type/scope/priority already exists.")

        row = ItemPreset(
            type=preset_type,
            userId=user_id,
            userGroupId=user_group_id,
            userProfileId=user_profile_id,
            fixed=1 if fixed else 0,
            priority=priority,
            data=presets.serialize(preset_type, data or {}),
            hash=token_hash,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return _to_dict(row)

    def update(self, preset_id: int,
               fixed: Optional[bool] = None,
               priority: Optional[int] = None,
               data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        row = self.db.query(ItemPreset).filter(ItemPreset.id == preset_id).first()
        if not row:
            return None
        preset_type, current, legacy = presets.decode_row(row.type, row.data)
        preset_type = presets.canonical_type(preset_type)
        if legacy and data is None:
            raise PresetError("Legacy preset: supply its data to save it in the sysPass format")
        if fixed is not None:
            row.fixed = 1 if fixed else 0
        if priority is not None:
            if not 0 <= int(priority) <= 255:
                raise PresetError("priority must be between 0 and 255")
            row.priority = priority
        row.type = preset_type
        row.data = presets.serialize(preset_type, data if data is not None else current)
        row.hash = presets.preset_hash(preset_type, row.userId, row.userGroupId, row.userProfileId, row.priority)
        clash = self.db.query(ItemPreset).filter(ItemPreset.hash == row.hash, ItemPreset.id != row.id).first()
        if clash:
            self.db.rollback()
            raise PresetError("A preset for this type/scope/priority already exists.")
        self.db.commit()
        return _to_dict(row)

    def delete(self, preset_id: int) -> bool:
        row = self.db.query(ItemPreset).filter(ItemPreset.id == preset_id).first()
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True
