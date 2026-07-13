from pydantic import BaseModel
from typing import Optional


class EventLogResponse(BaseModel):
    id: int
    date: Optional[int] = None
    login: Optional[str] = None
    user_id: Optional[int] = None
    ip_address: Optional[str] = None
    action: Optional[str] = None
    description: Optional[str] = None
    level: Optional[str] = None

    model_config = {"from_attributes": True}


class TrackResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    source: Optional[str] = None
    time: Optional[int] = None
    time_unlock: Optional[int] = None
    ip: Optional[str] = None
    is_locked: bool = False

    model_config = {"from_attributes": True}
