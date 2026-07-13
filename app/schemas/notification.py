from pydantic import BaseModel, Field
from typing import Optional

class NotificationBase(BaseModel):
    type: str = Field(..., min_length=1, max_length=50)
    message: str = Field(..., min_length=1)

class NotificationCreate(NotificationBase):
    user_id: int = Field(..., gt=0)

class NotificationResponse(NotificationBase):
    id: int
    user_id: int
    is_read: bool
    date_add: int
    
    model_config = {"from_attributes": True}

class NotificationType:
    """Standard notification types"""
    ACCOUNT_CREATED: str = "account_created"
    ACCOUNT_UPDATED: str = "account_updated"
    ACCOUNT_DELETED: str = "account_deleted"
    PASSWORD_CHANGED: str = "password_changed"
    FILE_UPLOADED: str = "file_uploaded"
    FILE_DOWNLOADED: str = "file_downloaded"
    LOGIN_SUCCESS: str = "login_success"
    LOGIN_FAILED: str = "login_failed"
    TWO_FACTOR_ENABLED: str = "two_factor_enabled"
    TWO_FACTOR_DISABLED: str = "two_factor_disabled"
    PUBLIC_LINK_CREATED: str = "public_link_created"
    SYSTEM_WARNING: str = "system_warning"
    SYSTEM_ERROR: str = "system_error"
