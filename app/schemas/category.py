from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class CategoryBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=255)
    icon: str = Field(default="folder", max_length=50)

class CategoryCreate(CategoryBase):
    pass

class CategoryUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=255)
    icon: Optional[str] = Field(None, max_length=50)

class CategoryResponse(CategoryBase):
    id: int
    dateCreate: Optional[datetime] = None
    dateUpdate: Optional[datetime] = None

    model_config = {"from_attributes": True}
