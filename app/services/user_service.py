from typing import List, Optional
import secrets
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models.account import User
from app.schemas.user import UserCreate, UserUpdate
from app.services.auth_service import get_password_hash, verify_password
from app.services.user_profile_service import UserProfileService

class UserService:
    def __init__(self, db: Session):
        self.db = db

    def next_user_id(self) -> int:
        current = self.db.query(func.max(User.id)).scalar()
        return (current or 0) + 1

    def get_users(self) -> List[User]:
        return self.db.query(User).all()

    def get_user(self, user_id: int) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id).first()

    def get_user_by_username(self, username: str) -> Optional[User]:
        return self.db.query(User).filter(User.username == username).first()

    def get_user_by_email(self, email: str) -> Optional[User]:
        if not email:
            return None
        return self.db.query(User).filter(User.email == email).first()

    def create_user(self, user_data: UserCreate, user_group_id: int = 1) -> User:
        existing = self.get_user_by_username(user_data.username)
        if existing is not None:
            raise ValueError(f"Username '{user_data.username}' already exists")
        hashed_password = get_password_hash(user_data.password)
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode("utf-8")
        default_profile = UserProfileService(self.db).ensure_default_profile()
        user = User(
            id=self.next_user_id(),
            name=user_data.name or user_data.username,
            username=user_data.username,
            email=user_data.email or '',
            password=hashed_password,
            isUserAdmin=user_data.is_admin,
            isUserEnabled=user_data.is_active,
            userGroupId=user_group_id,
            userProfileId=user_data.user_profile_id or default_profile.id,
            hashSalt=secrets.token_bytes(32),
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update_user(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        user = self.get_user(user_id)
        if not user:
            return None

        update_data = user_data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            if field == "username":
                user.username = value
            elif field == "email":
                user.email = value
            elif field == "password" and value:
                user.password = get_password_hash(value)
            elif field == "is_admin":
                user.isUserAdmin = value
            elif field == "is_active":
                user.isUserEnabled = value
            elif field == "user_profile_id":
                user.userProfileId = value
            elif field == "two_factor_enabled":
                user.twoFactorAuth = value
            elif field == "two_factor_secret":
                user.twoFactorSecret = value.encode() if value else None
            # name is not stored in the ORM (no DB column)

        self.db.commit()
        self.db.refresh(user)
        return user

    def delete_user(self, user_id: int) -> bool:
        user = self.get_user(user_id)
        if not user:
            return False

        self.db.delete(user)
        self.db.commit()
        return True

    def verify_user_password(self, user: User, password: str) -> bool:
        return verify_password(password, user.password)

    def update_user_password(self, user_id: int, new_password: str) -> Optional[User]:
        user = self.get_user(user_id)
        if not user:
            return None

        hashed = get_password_hash(new_password)
        user.password = hashed.encode() if isinstance(hashed, str) else hashed
        user.isChangePass = False
        user.isChangedPass = True
        user.isMigrate = False
        self.db.commit()
        self.db.refresh(user)
        return user

    def to_response(self, user: User) -> dict:
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "name": None,
            "is_admin": user.isUserAdmin,
            "is_active": user.isUserEnabled,
            "is_ldap": bool(user.isLdap),
            "user_profile_id": user.userProfileId,
            "two_factor_enabled": user.twoFactorAuth,
            "created_at": user.dateCreate,
        }
