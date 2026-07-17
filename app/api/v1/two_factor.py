from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.base import get_db
from app.core.security import get_encryption_service
from app.services.user_service import UserService
from app.services.two_factor_service import TwoFactorConfig, TwoFactorService, TwoFactorStore
from app.services.auth_service import decode_token
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter()
security = HTTPBearer()


class TwoFactorRequest(BaseModel):
    password: str


class TwoFactorEnableResponse(BaseModel):
    secret: str
    provisioning_uri: str


class TwoFactorVerifyRequest(BaseModel):
    code: str


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"id": payload.get("user_id"), "username": payload.get("username")}


def _store(db: Session) -> TwoFactorStore:
    return TwoFactorStore(db, get_encryption_service())


def _get_user_or_404(db: Session, user_id: int):
    user = UserService(db).get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/2fa/status")
async def two_factor_status(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Global 2FA mode plus the calling user's enrollment state."""
    user = _get_user_or_404(db, current_user["id"])
    mode = TwoFactorConfig(db).get_mode()
    enrolled = _store(db).is_enabled(user.id)
    return {
        "mode": mode,
        "enrolled": enrolled,
        "setup_required": mode == "enforced" and not enrolled,
    }


@router.post("/2fa/setup", response_model=TwoFactorEnableResponse)
async def setup_two_factor(
    request: TwoFactorRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Step 1: verify the password, generate and persist a pending secret,
    and return the provisioning URI for the QR code. 2FA is not active
    until the code is confirmed via /2fa/enable."""
    if TwoFactorConfig(db).get_mode() == "disabled":
        raise HTTPException(status_code=400, detail="Two-factor authentication is disabled by the administrator")
    user = _get_user_or_404(db, current_user["id"])
    if not UserService(db).verify_user_password(user, request.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    secret = TwoFactorService.generate_secret()
    _store(db).start_setup(user.id, secret)
    return {
        "secret": secret,
        "provisioning_uri": TwoFactorService.generate_provisioning_uri(
            secret, user.username, issuer="sysPass"
        ),
    }


@router.post("/2fa/enable")
async def enable_two_factor(
    request: TwoFactorVerifyRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Step 2: confirm the TOTP code generated from the pending secret;
    on success 2FA is enabled and backup codes are issued."""
    user = _get_user_or_404(db, current_user["id"])
    store = _store(db)

    pending = store.get_pending_secret(user.id)
    if not pending:
        raise HTTPException(status_code=400, detail="No 2FA setup in progress. Call /2fa/setup first.")
    if not TwoFactorService.verify_token(pending, request.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    backup_codes = TwoFactorService.generate_backup_codes(8)
    store.enable(user.id, backup_codes)
    return {
        "message": "2FA enabled successfully",
        "backup_codes": backup_codes,
        "warning": "Save these backup codes in a safe place. They cannot be shown again.",
    }


@router.post("/2fa/disable")
async def disable_two_factor(
    request: TwoFactorRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Disable 2FA for the user"""
    user = _get_user_or_404(db, current_user["id"])
    store = _store(db)

    if not store.is_enabled(user.id):
        raise HTTPException(status_code=400, detail="2FA is not enabled")
    if not UserService(db).verify_user_password(user, request.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    store.disable(user.id)
    return {"message": "2FA disabled successfully"}


@router.post("/2fa/verify")
async def verify_two_factor_code(
    request: TwoFactorVerifyRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Verify a 2FA code"""
    user = _get_user_or_404(db, current_user["id"])
    store = _store(db)

    if not store.is_enabled(user.id):
        raise HTTPException(status_code=400, detail="2FA is not enabled for this user")

    secret = store.get_secret(user.id)
    if not secret or not TwoFactorService.verify_token(secret, request.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")
    return {"message": "2FA verification successful"}


@router.post("/2fa/backup-code")
async def use_backup_code(
    request: TwoFactorVerifyRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Use a backup code when the 2FA device is unavailable"""
    user = _get_user_or_404(db, current_user["id"])
    store = _store(db)

    if not store.is_enabled(user.id):
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    codes = store.get_backup_codes(user.id)
    if not codes:
        raise HTTPException(status_code=400, detail="No backup codes available")

    success, remaining = TwoFactorService.verify_backup_code(codes, request.code)
    if not success:
        raise HTTPException(status_code=401, detail="Invalid backup code")

    store.set_backup_codes(user.id, remaining)
    return {
        "message": "Backup code used successfully",
        "remaining_codes": len(remaining),
    }
