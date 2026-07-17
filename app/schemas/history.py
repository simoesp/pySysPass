from pydantic import BaseModel, Field
from typing import Optional, ClassVar
from datetime import datetime

class AccountHistoryBase(BaseModel):
    action: str = Field(..., min_length=1, max_length=50)
    old_value: Optional[str] = None
    new_value: Optional[str] = None

class AccountHistoryCreate(AccountHistoryBase):
    pass

class AccountHistoryResponse(AccountHistoryBase):
    id: int
    account_id: int
    user_id: int
    date_add: Optional[datetime] = None

    model_config = {"from_attributes": True}

class HistoryAction:
    """Standard action types"""
    CREATE: ClassVar[str] = "create"
    UPDATE: ClassVar[str] = "update"
    DELETE: ClassVar[str] = "delete"
    VIEW: ClassVar[str] = "view"
    DECRYPT: ClassVar[str] = "decrypt"
    PASSWORD_CHANGE: ClassVar[str] = "password_change"
    FILE_UPLOAD: ClassVar[str] = "file_upload"
    FILE_DOWNLOAD: ClassVar[str] = "file_download"
