from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.base import get_db
from app.services.user_service import UserService
from app.services.two_factor_service import TwoFactorService
from app.services.auth_service import decode_token
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import base64

router = APIRouter()
security = HTTPBearer()

class TwoFactorRequest(BaseModel):
    password: str

class TwoFactorEnableResponse(BaseModel):
    secret: str
    provisioning_uri: str

class TwoFactorVerifyRequest(BaseModel):
    code: str

class TwoFactorSetupRequest(BaseModel):
    code: str

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"id": payload.get("user_id"), "username": payload.get("username")}

@router.get("/2fa/setup", response_model=TwoFactorEnableResponse)
async def setup_two_factor(
    request: TwoFactorRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Step 1: Initialize 2FA setup
    - Verify current password
    - Generate new secret
    - Return provisioning URI for QR code
    """
    service = UserService(db)
    user = service.get_user(current_user["id"])

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify password
    if not service.verify_user_password(user, request.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    # Generate new secret
    secret = TwoFactorService.generate_secret()
    provisioning_uri = TwoFactorService.generate_provisioning_uri(
        secret,
        user.username,
        issuer="sysPass"
    )

    # In production, store secret temporarily in session/Redis
    # For now, return it (client should store temporarily)
    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri
    }

@router.post("/2fa/enable")
async def enable_two_factor(
    request: TwoFactorSetupRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Step 2: Enable 2FA after user scans QR code
    - Verify the TOTP code
    - Enable 2FA for the user
    - Generate backup codes
    """
    service = UserService(db)
    user = service.get_user(current_user["id"])

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # In production, get secret from session/Redis
    # For demo, we expect the client to pass the secret
    # This is a simplified version - production should use session storage
    secret = request.code  # Placeholder - real impl needs session storage

    # Generate backup codes
    backup_codes = TwoFactorService.generate_backup_codes(8)
    user.twoFactorAuth = True
    user.twoFactorSecret = base64.b64encode(secret.encode()).decode() if secret else None
    user.twoFactorBackupCodes = '\n'.join(backup_codes)

    db.commit()
    db.refresh(user)

    return {
        "message": "2FA enabled successfully",
        "backup_codes": backup_codes,
        "warning": "Save these backup codes in a safe place. They cannot be shown again."
    }

@router.post("/2fa/disable")
async def disable_two_factor(
    request: TwoFactorRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Disable 2FA for the user"""
    service = UserService(db)
    user = service.get_user(current_user["id"])

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.twoFactorAuth:
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    # Verify password
    if not service.verify_user_password(user, request.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    # Disable 2FA
    user.twoFactorAuth = False
    user.twoFactorSecret = None
    user.twoFactorBackupCodes = None

    db.commit()
    db.refresh(user)

    return {"message": "2FA disabled successfully"}

@router.post("/2fa/verify")
async def verify_two_factor_code(
    request: TwoFactorVerifyRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Verify a 2FA code (used during login)
    """
    service = UserService(db)
    user = service.get_user(current_user["id"])

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.twoFactorAuth:
        raise HTTPException(status_code=400, detail="2FA is not enabled for this user")

    # Decode the secret
    secret = base64.b64decode(user.twoFactorSecret).decode()

    # Verify the code
    if not TwoFactorService.verify_token(secret, request.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    return {"message": "2FA verification successful"}

@router.post("/2fa/backup-code")
async def use_backup_code(
    request: TwoFactorVerifyRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Use a backup code when 2FA device is unavailable
    """
    service = UserService(db)
    user = service.get_user(current_user["id"])

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.twoFactorAuth:
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    if not user.twoFactorBackupCodes:
        raise HTTPException(status_code=400, detail="No backup codes available")

    codes = user.twoFactorBackupCodes.strip().split('\n')
    success, remaining_codes = TwoFactorService.verify_backup_code(codes, request.code)

    if not success:
        raise HTTPException(status_code=401, detail="Invalid backup code")

    # Update backup codes
    user.twoFactorBackupCodes = '\n'.join(remaining_codes)
    db.commit()

    return {
        "message": "Backup code used successfully",
        "remaining_codes": len(remaining_codes)
    }
