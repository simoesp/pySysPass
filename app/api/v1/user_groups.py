from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db.base import get_db
from app.schemas.user_group import (
    UserGroupCreate, UserGroupResponse, UserGroupUpdate,
    UserGroupWithMembers, UserGroupMember,
)
from app.services.user_group_service import UserGroupService
from app.api.deps import get_current_user, require_permission

router = APIRouter()


@router.get("/user-groups", response_model=List[UserGroupResponse])
async def list_user_groups(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return UserGroupService(db).get_user_groups()


@router.post("/user-groups", response_model=UserGroupResponse, status_code=status.HTTP_201_CREATED)
async def create_user_group(
    group: UserGroupCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_groups')),
):
    return UserGroupService(db).create_user_group(group)


@router.get("/user-groups/{group_id}", response_model=UserGroupWithMembers)
async def get_user_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    service = UserGroupService(db)
    group = service.get_user_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="User group not found")
    members_data = service.get_group_members_with_details(group_id)
    members = [UserGroupMember(**m) for m in members_data]
    return UserGroupWithMembers(
        id=group.id,
        name=group.name,
        description=group.description,
        is_user_admin=group.isUserAdmin,
        is_user_enabled=group.isUserEnabled,
        is_user_force_pwd_change=group.isUserForcePwdChange,
        date_create=group.dateCreate,
        date_update=group.dateUpdate,
        members=members,
    )


@router.put("/user-groups/{group_id}", response_model=UserGroupResponse)
async def update_user_group(
    group_id: int,
    group: UserGroupUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_groups')),
):
    service = UserGroupService(db)
    updated = service.update_user_group(group_id, group)
    if not updated:
        raise HTTPException(status_code=404, detail="User group not found")
    return updated


@router.delete("/user-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_groups')),
):
    if not UserGroupService(db).delete_user_group(group_id):
        raise HTTPException(status_code=404, detail="User group not found")
    return None


@router.get("/user-groups/{group_id}/members", response_model=List[UserGroupMember])
async def get_group_members(
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    service = UserGroupService(db)
    if not service.get_user_group(group_id):
        raise HTTPException(status_code=404, detail="User group not found")
    members_data = service.get_group_members_with_details(group_id)
    return [UserGroupMember(**m) for m in members_data]


@router.post("/user-groups/{group_id}/members/{user_id}")
async def add_user_to_group(
    group_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_groups')),
):
    from app.models.account import User
    service = UserGroupService(db)
    if not db.query(User).filter(User.id == user_id).first():
        raise HTTPException(status_code=404, detail="User not found")
    if not service.get_user_group(group_id):
        raise HTTPException(status_code=404, detail="User group not found")
    if not service.add_user_to_group(user_id, group_id):
        raise HTTPException(status_code=409, detail="User already in group")
    return {"message": "User added to group successfully"}


@router.delete("/user-groups/{group_id}/members/{user_id}")
async def remove_user_from_group(
    group_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_groups')),
):
    if not UserGroupService(db).remove_user_from_group(user_id, group_id):
        raise HTTPException(status_code=404, detail="User not found in group")
    return {"message": "User removed from group successfully"}


@router.get("/users/{user_id}/groups", response_model=List[UserGroupResponse])
async def get_user_groups(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.get("id") != user_id and not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return UserGroupService(db).get_user_groups_for_user(user_id)
