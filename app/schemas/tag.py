from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class TagBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    color: str = "#000000"

class TagCreate(TagBase):
    pass

class TagUpdate(BaseModel):
    name: Optional[str] = None
    color: Optional[str] = None

class TagResponse(TagBase):
    id: int
    user_id: Optional[int] = None
    created_at: Optional[datetime] = None
    
    model_config = {"from_attributes": True}

class AccountWithTag(BaseModel):
    account_id: int
    account_title: str
    tag_id: int
    tag_name: str
    tag_color: str
