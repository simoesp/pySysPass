from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class PublicLinkBase(BaseModel):
    account_id: int = Field(..., gt=0)
    expire: Optional[int] = None  # Expiration time in seconds

class PublicLinkCreate(PublicLinkBase):
    password: Optional[str] = Field(None, min_length=1)

class PublicLinkResponse(BaseModel):
    id: int
    account_id: int
    hash: str
    expire: Optional[int] = None
    has_password: bool = False
    date_add: Optional[datetime] = None

    model_config = {"from_attributes": True}

class PublicLinkAccess(BaseModel):
    """Response for public link access"""
    account_id: int
    account_title: str
    login: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    category_id: Optional[int] = None
    client_id: Optional[int] = None
