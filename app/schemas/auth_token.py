from pydantic import BaseModel
from typing import Optional

# PHP sysPass actionId → human label mapping
ACTION_LABELS = {
    3:   "Account Search",
    4:   "Account View Password",
    5:   "Account Add",
    6:   "Account Edit",
    7:   "Account Delete",
    8:   "Account View",
    102: "Category Search",
    103: "Category Add",
    104: "Category Edit",
    106: "Category Delete",
    202: "Client Search",
    203: "Client Add",
    204: "Client Edit",
    205: "Client Delete",
    206: "Client View",
    302: "Tag Search",
    304: "Tag Add",
    305: "Tag Edit",
    306: "Tag Delete",
    802: "API Token Search",
    803: "API Token Add",
    804: "API Token Edit",
    805: "API Token Delete",
    806: "API Token View",
}


class AuthTokenResponse(BaseModel):
    id: int
    user_id: int
    username: Optional[str] = None
    action_id: int
    action_label: Optional[str] = None
    # Only populated on create/regenerate; list responses omit the secret.
    token: Optional[str] = None
    start_date: Optional[int] = None
    has_vault: bool = False

    model_config = {"from_attributes": True}


class AuthTokenCreate(BaseModel):
    user_id: int
    action_id: int
