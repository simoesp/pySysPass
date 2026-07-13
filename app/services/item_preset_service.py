"""Item Preset service — account default permissions and password policies."""
import hashlib
import json
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.account import ItemPreset

VALID_TYPES = {"AccountPermission", "AccountPrivate", "Password", "SessionTimeout"}


def _compute_hash(preset_type: str, user_id: Optional[int],
                  user_group_id: Optional[int], user_profile_id: Optional[int]) -> bytes:
    key = f"{preset_type}|{user_id}|{user_group_id}|{user_profile_id}"
    return hashlib.sha1(key.encode()).digest()  # nosec B324 — non-crypto fingerprint


def _to_dict(row: ItemPreset) -> Dict[str, Any]:
    try:
        data = json.loads(row.data.decode() if isinstance(row.data, bytes) else row.data) if row.data else {}
    except Exception:
        data = {}
    return {
        "id": row.id,
        "type": row.type,
        "user_id": row.userId,
        "user_group_id": row.userGroupId,
        "user_profile_id": row.userProfileId,
        "fixed": bool(row.fixed),
        "priority": row.priority,
        "data": data,
    }


class ItemPresetService:
    def __init__(self, db: Session):
        self.db = db

    def list(self, preset_type: Optional[str] = None) -> List[Dict[str, Any]]:
        q = self.db.query(ItemPreset)
        if preset_type:
            q = q.filter(ItemPreset.type == preset_type)
        return [_to_dict(r) for r in q.order_by(ItemPreset.priority.desc()).all()]

    def get(self, preset_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.query(ItemPreset).filter(ItemPreset.id == preset_id).first()
        return _to_dict(row) if row else None

    def get_for_context(self, preset_type: str,
                        user_id: Optional[int] = None,
                        user_group_id: Optional[int] = None,
                        user_profile_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Return the highest-priority preset that matches the given context.
        Priority: user-specific > group-specific > profile-specific > global.
        """
        q = self.db.query(ItemPreset).filter(ItemPreset.type == preset_type)
        rows = q.order_by(ItemPreset.priority.desc()).all()
        for row in rows:
            if user_id and row.userId == user_id:
                return _to_dict(row)
        for row in rows:
            if user_group_id and row.userGroupId == user_group_id:
                return _to_dict(row)
        for row in rows:
            if user_profile_id and row.userProfileId == user_profile_id:
                return _to_dict(row)
        for row in rows:
            if row.userId is None and row.userGroupId is None and row.userProfileId is None:
                return _to_dict(row)
        return None

    def create(self, preset_type: str,
               user_id: Optional[int] = None,
               user_group_id: Optional[int] = None,
               user_profile_id: Optional[int] = None,
               fixed: bool = False,
               priority: int = 0,
               data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if preset_type not in VALID_TYPES:
            raise ValueError(f"Invalid type. Must be one of: {', '.join(sorted(VALID_TYPES))}")

        token_hash = _compute_hash(preset_type, user_id, user_group_id, user_profile_id)
        existing = self.db.query(ItemPreset).filter(ItemPreset.hash == token_hash).first()
        if existing:
            raise ValueError("A preset for this type/scope combination already exists.")

        row = ItemPreset(
            type=preset_type,
            userId=user_id,
            userGroupId=user_group_id,
            userProfileId=user_profile_id,
            fixed=1 if fixed else 0,
            priority=priority,
            data=json.dumps(data or {}).encode(),
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
        if fixed is not None:
            row.fixed = 1 if fixed else 0
        if priority is not None:
            row.priority = priority
        if data is not None:
            row.data = json.dumps(data).encode()
        self.db.commit()
        return _to_dict(row)

    def delete(self, preset_id: int) -> bool:
        row = self.db.query(ItemPreset).filter(ItemPreset.id == preset_id).first()
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True
