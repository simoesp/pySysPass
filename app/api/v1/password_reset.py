from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.services.password_reset_service import PasswordResetService

router = APIRouter()


class ResetRequestBody(BaseModel):
    email: EmailStr


class ResetConfirmBody(BaseModel):
    token: str
    new_password: str


class VerifyResponse(BaseModel):
    valid: bool
    username: str | None = None


@router.post("/password-reset/request", status_code=status.HTTP_200_OK)
async def request_reset(body: ResetRequestBody, db: Session = Depends(get_db)):
    """Send a password-reset email. Always returns 200 to avoid user enumeration."""
    PasswordResetService(db).request_reset(body.email)
    return {"detail": "If that email is registered you will receive a reset link."}


@router.get("/password-reset/verify/{token}", response_model=VerifyResponse)
async def verify_token(token: str, db: Session = Depends(get_db)):
    """Check whether a reset token is valid without consuming it."""
    user = PasswordResetService(db).verify_token(token)
    if not user:
        return VerifyResponse(valid=False)
    return VerifyResponse(valid=True, username=user.username)


@router.post("/password-reset/confirm", status_code=status.HTTP_200_OK)
async def confirm_reset(body: ResetConfirmBody, db: Session = Depends(get_db)):
    """Set a new password using a valid reset token."""
    ok = PasswordResetService(db).confirm_reset(body.token, body.new_password)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )
    return {"detail": "Password reset successfully."}
