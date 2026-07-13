from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from app.schemas.user_profile import ProfilePermissions

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)

class UserCreate(UserBase):
    email: Optional[str] = None
    name: Optional[str] = None
    password: str
    is_admin: bool = False
    is_active: bool = True
    user_profile_id: Optional[int] = None

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    password: Optional[str] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None
    user_profile_id: Optional[int] = None
    two_factor_enabled: Optional[bool] = None
    two_factor_secret: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    name: Optional[str] = None
    is_admin: bool
    is_active: bool
    user_profile_id: Optional[int] = None
    two_factor_enabled: bool
    created_at: Optional[datetime] = None
    permissions: Optional[ProfilePermissions] = None

    model_config = {"from_attributes": True}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[int] = None
