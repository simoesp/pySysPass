from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional


class ProfilePermissions(BaseModel):
    acc_view: bool = False
    acc_view_pass: bool = False
    acc_view_history: bool = False
    acc_edit: bool = False
    acc_edit_pass: bool = False
    acc_add: bool = False
    acc_delete: bool = False
    acc_files: bool = False
    acc_private: bool = False
    acc_private_group: bool = False
    acc_permission: bool = False
    acc_public_links: bool = False
    acc_global_search: bool = False
    config_general: bool = False
    config_encryption: bool = False
    config_backup: bool = False
    config_import: bool = False
    mgm_users: bool = False
    mgm_groups: bool = False
    mgm_profiles: bool = False
    mgm_categories: bool = False
    mgm_customers: bool = False
    mgm_api_tokens: bool = False
    mgm_public_links: bool = False
    mgm_accounts: bool = False
    mgm_tags: bool = False
    mgm_files: bool = False
    mgm_items_preset: bool = False
    mgm_custom_fields: bool = False
    evl: bool = False


class UserProfileBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    permissions: ProfilePermissions = Field(default_factory=ProfilePermissions)


class UserProfileCreate(UserProfileBase):
    user_id: Optional[int] = None


class UserProfileUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    permissions: Optional[ProfilePermissions] = None


class UserProfileResponse(UserProfileBase):
    id: int
    user_id: Optional[int] = None
    assigned_user_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
