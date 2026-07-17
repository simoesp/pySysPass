from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class UserGroupBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    is_user_admin: bool = False
    is_user_enabled: bool = True
    is_user_force_pwd_change: bool = False

class UserGroupCreate(UserGroupBase):
    pass

class UserGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_user_admin: Optional[bool] = None
    is_user_enabled: Optional[bool] = None
    is_user_force_pwd_change: Optional[bool] = None

class UserGroupResponse(UserGroupBase):
    id: int
    date_create: Optional[datetime] = None
    date_update: Optional[datetime] = None

    model_config = {"from_attributes": True}

class UserGroupMember(BaseModel):
    user_id: int
    username: str
    email: str

class UserGroupWithMembers(UserGroupResponse):
    members: list[UserGroupMember] = []
