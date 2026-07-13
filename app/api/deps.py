"""Centralized FastAPI dependencies for auth and role checks."""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.services.auth_service import decode_token

security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    legacy_admin = bool(payload.get("is_admin", False))
    is_admin_app = bool(payload.get("is_admin_app", legacy_admin))
    is_admin_acc = bool(payload.get("is_admin_acc", legacy_admin))
    return {
        "id": payload.get("user_id"),
        "username": payload.get("username"),
        "master_pass": payload.get("master_pass"),
        # is_admin remains the application-wide scope for existing callers.
        "is_admin": is_admin_app,
        "is_admin_app": is_admin_app,
        "is_admin_acc": is_admin_acc,
    }


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if not current_user.get("is_admin_app"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


def _profile_permissions(db: Session, user_id: int) -> dict[str, bool]:
    from app.models.account import User
    from app.services.user_profile_service import UserProfileService

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.userProfileId:
        return {}
    profile = UserProfileService(db).get_user_profile(user.userProfileId)
    return profile["permissions"].model_dump() if profile else {}


def has_permissions(
    current_user: dict,
    db: Session,
    keys: tuple[str, ...],
    *,
    require_all: bool = False,
    account_admin: bool = False,
) -> bool:
    """Apply PHP's profile gate before an object-level ACL decision."""
    if current_user.get("is_admin_app"):
        return True
    if account_admin and current_user.get("is_admin_acc"):
        return True
    permissions = _profile_permissions(db, current_user["id"])
    checks = (bool(permissions.get(key, False)) for key in keys)
    return all(checks) if require_all else any(checks)


def enforce_permissions(
    current_user: dict,
    db: Session,
    *keys: str,
    require_all: bool = False,
    account_admin: bool = False,
) -> dict:
    if has_permissions(
        current_user,
        db,
        tuple(keys),
        require_all=require_all,
        account_admin=account_admin,
    ):
        return current_user
    mode = " and ".join(keys) if require_all else " or ".join(keys)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Your profile does not grant '{mode}' permission",
    )


def require_any_permission(*keys: str, account_admin: bool = False):
    def _dep(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict:
        return enforce_permissions(
            current_user, db, *keys, account_admin=account_admin
        )

    _dep.__name__ = f"require_any_permission_{'_or_'.join(keys)}"
    return _dep


def require_all_permissions(*keys: str, account_admin: bool = False):
    def _dep(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict:
        return enforce_permissions(
            current_user,
            db,
            *keys,
            require_all=True,
            account_admin=account_admin,
        )

    _dep.__name__ = f"require_all_permissions_{'_and_'.join(keys)}"
    return _dep


def require_permission(key: str):
    """Return a FastAPI dependency that passes admins through and otherwise checks
    that the caller's profile grants the named ProfilePermissions flag."""
    def _dep(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict:
        return enforce_permissions(current_user, db, key)
    # Give FastAPI a stable identity so it can deduplicate the dependency.
    _dep.__name__ = f"require_permission_{key}"
    return _dep
