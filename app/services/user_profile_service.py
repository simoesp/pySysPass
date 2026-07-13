import json
import re
from typing import List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.account import User, UserProfile
from app.schemas.user_profile import ProfilePermissions, UserProfileCreate, UserProfileUpdate


def _camel_to_snake(name: str) -> str:
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    s = re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s)
    return s.lower()


def _parse_php_serialized_profile(raw: bytes) -> Optional[dict]:
    """Parse PHP serialized ProfileData object into a dict of bool values."""
    try:
        text = raw.decode('latin-1')
    except Exception:
        return None
    # Match: s:<n>:"<optional \0*\0><propName>";b:<0|1>;
    # Null bytes appear as literal \x00 in latin-1 decoded string
    pattern = re.compile(r's:\d+:"(?:[^\x00]*\x00\*\x00)?([^"]+)";\s*b:([01]);')
    result = {}
    for m in pattern.finditer(text):
        php_name = m.group(1)   # e.g. "accView"
        value = m.group(2) == '1'
        snake = _camel_to_snake(php_name)  # e.g. "acc_view"
        result[snake] = value
    return result if result else None


class UserProfileService:
    def __init__(self, db: Session):
        self.db = db

    def _next_profile_id(self) -> int:
        current = self.db.query(func.max(UserProfile.id)).scalar()
        return (current or 0) + 1

    def get_user_profiles(self) -> List[dict]:
        profiles = self.db.query(UserProfile).order_by(UserProfile.name.asc()).all()
        return [self._to_response(profile) for profile in profiles]

    def get_user_profile(self, profile_id: int) -> Optional[dict]:
        profile = self.db.query(UserProfile).filter(UserProfile.id == profile_id).first()
        if not profile:
            return None
        return self._to_response(profile)

    def create_user_profile(self, profile_data: UserProfileCreate) -> dict:
        profile = UserProfile(
            id=self._next_profile_id(),
            name=profile_data.name,
            profile=self._encode_permissions(profile_data.permissions),
        )
        self.db.add(profile)
        self.db.commit()
        self.db.refresh(profile)
        return self._to_response(profile)

    def update_user_profile(self, profile_id: int, profile_data: UserProfileUpdate) -> Optional[dict]:
        profile = self.db.query(UserProfile).filter(UserProfile.id == profile_id).first()
        if not profile:
            return None

        if profile_data.name is not None:
            profile.name = profile_data.name
        if profile_data.permissions is not None:
            profile.profile = self._encode_permissions(profile_data.permissions)

        self.db.commit()
        self.db.refresh(profile)
        return self._to_response(profile)

    def delete_user_profile(self, profile_id: int) -> bool:
        profile = self.db.query(UserProfile).filter(UserProfile.id == profile_id).first()
        if not profile:
            return False

        in_use = self.db.query(User).filter(User.userProfileId == profile_id).count()
        if in_use:
            raise ValueError("Profile is assigned to one or more users")

        self.db.delete(profile)
        self.db.commit()
        return True

    def ensure_default_profile(self) -> UserProfile:
        profile = self.db.query(UserProfile).order_by(UserProfile.id.asc()).first()
        if profile:
            return profile

        profile = UserProfile(
            id=self._next_profile_id(),
            name="Default",
            profile=self._encode_permissions(ProfilePermissions()),
        )
        self.db.add(profile)
        self.db.commit()
        self.db.refresh(profile)
        return profile

    def _to_response(self, profile: UserProfile) -> dict:
        return {
            "id": profile.id,
            "user_id": None,
            "name": profile.name,
            "permissions": self._decode_permissions(profile.profile),
            "assigned_user_count": len(profile.assignedUsers or []),
            "created_at": None,
            "updated_at": None,
        }

    def _encode_permissions(self, permissions: ProfilePermissions) -> bytes:
        return json.dumps(permissions.model_dump()).encode("utf-8")

    def _decode_permissions(self, raw: Optional[bytes]) -> ProfilePermissions:
        if not raw:
            return ProfilePermissions()

        raw_bytes = raw if isinstance(raw, bytes) else raw.encode("latin-1")
        payload = raw_bytes.decode("utf-8", errors="ignore")

        # Try JSON first (Python-created profiles)
        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                return ProfilePermissions(**data)
        except (json.JSONDecodeError, Exception):
            pass

        # Try PHP serialized format (PHP-created profiles)
        php_data = _parse_php_serialized_profile(raw_bytes)
        if php_data:
            valid = set(ProfilePermissions.model_fields.keys())
            return ProfilePermissions(**{k: v for k, v in php_data.items() if k in valid})

        return ProfilePermissions()
