from typing import Optional

from pydantic import BaseModel, Field, model_validator


class InstallRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8)
    email: Optional[str] = None
    name: Optional[str] = None
    master_password: Optional[str] = Field(default=None, min_length=12)
    generate_master_password: bool = True

    @model_validator(mode="after")
    def validate_master_password_strategy(self):
        if self.master_password and self.generate_master_password:
            raise ValueError("Provide master_password or set generate_master_password, not both.")
        if not self.master_password and not self.generate_master_password:
            raise ValueError("Either master_password must be provided or generate_master_password must be true.")
        return self


class InstallStatusResponse(BaseModel):
    installed: bool
    user_count: int
    has_master_password: bool


class InstallResponse(BaseModel):
    user_id: int
    username: str
    master_password_generated: bool
    master_password: Optional[str] = None
    message: str
