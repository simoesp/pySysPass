from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel

from app.db.base import get_db
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.services.user_service import UserService
from app.services.user_profile_service import UserProfileService
from app.services.auth_service import verify_password
from app.models.account import User
from app.api.deps import get_current_user, require_permission


class PasswordChangeRequest(BaseModel):
    current_password: Optional[str] = None
    new_password: str


router = APIRouter()


def _has_perm(db: Session, user_id: int, key: str) -> bool:
    """Check if user's profile grants the given permission key."""
    u = db.query(User).filter(User.id == user_id).first()
    if u and u.userProfileId:
        profile = UserProfileService(db).get_user_profile(u.userProfileId)
        if profile:
            return profile["permissions"].model_dump().get(key, False)
    return False


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: Optional[int] = Query(None, ge=1, le=500),
    q: Optional[str] = Query(None),
    sort_by: Optional[str] = Query(None),
    descending: bool = Query(False),
    current_user=Depends(require_permission('mgm_users')),
    db: Session = Depends(get_db),
):
    service = UserService(db)
    users = service.get_users(skip, limit, q, sort_by, descending)
    return [service.to_response(user) for user in users]


@router.get("/users/count")
async def count_users(
    q: Optional[str] = Query(None),
    current_user=Depends(require_permission('mgm_users')),
    db: Session = Depends(get_db),
):
    return {"count": UserService(db).count_users(q)}


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_users')),
):
    service = UserService(db)
    if service.get_user_by_username(user.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    if user.email and service.get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already exists")
    return service.create_user(user)


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    is_self = current_user.get("id") == user_id
    if not is_self and not current_user.get("is_admin") and not _has_perm(db, current_user["id"], "mgm_users"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    service = UserService(db)
    user = service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return service.to_response(user)


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user: UserUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    is_self = current_user.get("id") == user_id
    if not is_self and not current_user.get("is_admin") and not _has_perm(db, current_user["id"], "mgm_users"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    service = UserService(db)
    updated = service.update_user(user_id, user)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    return service.to_response(updated)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_users')),
):
    if not UserService(db).delete_user(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    return None


@router.post("/users/{user_id}/password", status_code=status.HTTP_200_OK)
async def change_password(
    user_id: int,
    body: PasswordChangeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Change user password. Non-admins must supply current_password."""
    is_self = current_user.get("id") == user_id
    if not is_self and not current_user.get("is_admin") and not _has_perm(db, current_user["id"], "mgm_users"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    if is_self and body.current_password is not None:
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not verify_password(body.current_password, user.password):
            raise HTTPException(status_code=403, detail="Current password is incorrect")
    service = UserService(db)
    updated = service.update_user_password(user_id, body.new_password)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Password updated successfully"}
