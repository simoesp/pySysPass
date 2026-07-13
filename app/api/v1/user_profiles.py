from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db.base import get_db
from app.schemas.user_profile import UserProfileCreate, UserProfileResponse, UserProfileUpdate
from app.services.user_profile_service import UserProfileService
from app.api.deps import get_current_user, require_permission

router = APIRouter()


@router.get("/user-profiles", response_model=List[UserProfileResponse])
async def list_user_profiles(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return UserProfileService(db).get_user_profiles()


@router.post("/user-profiles", response_model=UserProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_user_profile(
    profile: UserProfileCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_profiles')),
):
    return UserProfileService(db).create_user_profile(profile)


@router.get("/user-profiles/{profile_id}", response_model=UserProfileResponse)
async def get_user_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    profile = UserProfileService(db).get_user_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")
    return profile


@router.put("/user-profiles/{profile_id}", response_model=UserProfileResponse)
async def update_user_profile(
    profile_id: int,
    profile: UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_profiles')),
):
    updated = UserProfileService(db).update_user_profile(profile_id, profile)
    if not updated:
        raise HTTPException(status_code=404, detail="User profile not found")
    return updated


@router.delete("/user-profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_profiles')),
):
    try:
        deleted = UserProfileService(db).delete_user_profile(profile_id)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error))
    if not deleted:
        raise HTTPException(status_code=404, detail="User profile not found")
    return None
