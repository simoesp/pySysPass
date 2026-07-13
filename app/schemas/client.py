from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class ClientBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    contact: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = None
    is_global: bool = False

class ClientCreate(ClientBase):
    pass

class ClientUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    contact: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = None
    is_global: Optional[bool] = None

class ClientResponse(ClientBase):
    id: int
    dateCreate: Optional[datetime] = None
    dateUpdate: Optional[datetime] = None
    
    model_config = {"from_attributes": True}
