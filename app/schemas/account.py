from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime


MYSQL_TEXT_MAX_BYTES = 65535


def _check_text_bytes(value: Optional[str]) -> Optional[str]:
    # MySQL TEXT limits bytes, not characters.
    if value is not None and len(value.encode("utf-8")) > MYSQL_TEXT_MAX_BYTES:
        raise ValueError(f"must be at most {MYSQL_TEXT_MAX_BYTES} bytes")
    return value


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
    # Lengths follow the canonical PHP Account columns (name varchar(100),
    # login varchar(50), url varchar(255), notes TEXT).
    title: str = Field(..., min_length=1, max_length=100)
    login: Optional[str] = Field(None, max_length=50)
    password: str = Field(..., min_length=1)
    url: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = None
    # sysPass PHP AccountForm::checkCommon() rejects accounts without a client
    # or category, and the canonical schema makes both NOT NULL foreign keys.
    category_id: int = Field(..., gt=0)
    client_id: int = Field(..., gt=0)
    is_public: bool = False
    is_private_group: bool = False
    other_user_edit: bool = False
    other_user_group_edit: bool = False
    pass_date_change: Optional[int] = None
    tag_ids: List[int] = Field(default_factory=list)
    shared_users: List[SharedUserEntry] = Field(default_factory=list)
    shared_groups: List[SharedGroupEntry] = Field(default_factory=list)

    _notes_bytes = field_validator("notes")(_check_text_bytes)


class AccountUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=100)
    login: Optional[str] = Field(None, max_length=50)
    password: Optional[str] = None
    url: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = None
    # Omitted keeps the current value; PHP never allows clearing either one.
    category_id: Optional[int] = Field(None, gt=0)
    client_id: Optional[int] = Field(None, gt=0)
    is_public: Optional[bool] = None
    is_favorite: Optional[bool] = None
    is_private_group: Optional[bool] = None
    other_user_edit: Optional[bool] = None
    other_user_group_edit: Optional[bool] = None
    pass_date_change: Optional[int] = None
    tag_ids: Optional[List[int]] = None
    shared_users: Optional[List[SharedUserEntry]] = None
    shared_groups: Optional[List[SharedGroupEntry]] = None

    _notes_bytes = field_validator("notes")(_check_text_bytes)


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
    # sysPass PHP AccountForm::checkCommon() rejects accounts without a client
    # or category, and the canonical schema makes both NOT NULL foreign keys.
    category_id: int = Field(..., gt=0)
    client_id: int = Field(..., gt=0)
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
    # With purpose=view and a password-as-image rule, only the image is sent.
    password: Optional[str] = None
    use_image: bool = False
    password_image: Optional[str] = None  # base64 PNG


class AccountAuditEntry(BaseModel):
    id: int
    action: str
    action_label: str
    user_id: Optional[int] = None
    username: Optional[str] = None
    ip: Optional[str] = None
    date: int
