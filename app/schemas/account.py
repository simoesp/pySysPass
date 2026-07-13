from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class TagInfo(BaseModel):
    id: int
    name: str
    color: str = '#000000'


class SharedUserInfo(BaseModel):
    user_id: int
    username: str
    is_edit: bool = False


class SharedGroupInfo(BaseModel):
    group_id: int
    name: str
    is_edit: bool = False


class SharedUserEntry(BaseModel):
    user_id: int
    is_edit: bool = False


class SharedGroupEntry(BaseModel):
    group_id: int
    is_edit: bool = False


class AccountCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    login: Optional[str] = None
    password: str = Field(..., min_length=1)
    url: Optional[str] = None
    notes: Optional[str] = None
    category_id: Optional[int] = None
    client_id: Optional[int] = None
    is_public: bool = False
    is_private_group: bool = False
    other_user_edit: bool = False
    other_user_group_edit: bool = False
    pass_date_change: Optional[int] = None
    tag_ids: List[int] = Field(default_factory=list)
    shared_users: List[SharedUserEntry] = Field(default_factory=list)
    shared_groups: List[SharedGroupEntry] = Field(default_factory=list)


class AccountUpdate(BaseModel):
    title: Optional[str] = None
    login: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    category_id: Optional[int] = None
    client_id: Optional[int] = None
    is_public: Optional[bool] = None
    is_favorite: Optional[bool] = None
    is_private_group: Optional[bool] = None
    other_user_edit: Optional[bool] = None
    other_user_group_edit: Optional[bool] = None
    pass_date_change: Optional[int] = None
    tag_ids: Optional[List[int]] = None
    shared_users: Optional[List[SharedUserEntry]] = None
    shared_groups: Optional[List[SharedGroupEntry]] = None


class AccountResponse(BaseModel):
    id: int
    user_id: int
    user_group_id: Optional[int] = None
    is_owner: bool = False
    can_edit: bool = False
    title: str
    login: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    category_id: Optional[int] = None
    client_id: Optional[int] = None
    is_public: bool = False
    is_private_group: bool = False
    is_favorite: bool = False
    other_user_edit: bool = False
    other_user_group_edit: bool = False
    tags: List[TagInfo] = []
    shared_users: List[SharedUserInfo] = []
    shared_groups: List[SharedGroupInfo] = []
    count_view: int = 0
    count_decrypt: int = 0
    pass_date_change: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PasswordResponse(BaseModel):
    password: str
