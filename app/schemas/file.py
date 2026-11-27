from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

# Base64 of the largest upload sysPass PHP allows (16384 KB * 1000 bytes).
MAX_BASE64_LENGTH = 4 * -(-16384 * 1000 // 3)


class FileBase(BaseModel):
    # Lengths follow the canonical PHP AccountFile columns.
    name: str = Field(..., min_length=1, max_length=100)
    type: str = Field(..., min_length=1, max_length=100)
    size: int = Field(..., gt=0)
    extension: str = Field(..., max_length=10)

class FileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    type: str = Field(..., min_length=1, max_length=100)
    # Ignored: the server measures the decoded content and derives the
    # extension from the name, as sysPass PHP does. Kept for API compatibility.
    size: Optional[int] = None
    extension: Optional[str] = None
    content: str = Field(..., min_length=1, max_length=MAX_BASE64_LENGTH)  # Base64 encoded content

class FileResponse(FileBase):
    id: int
    account_id: int
    date_add: Optional[datetime] = None

    model_config = {"from_attributes": True}

class FileUploadResponse(BaseModel):
    id: int
    account_id: int
    name: str
    type: str
    size: int
    extension: str
    date_add: Optional[datetime] = None
    message: str
