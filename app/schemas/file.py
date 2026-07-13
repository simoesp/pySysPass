from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class FileBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., min_length=1, max_length=100)
    size: int = Field(..., gt=0)
    extension: str = Field(..., max_length=10)

class FileCreate(FileBase):
    content: str = Field(..., min_length=1)  # Base64 encoded content

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
