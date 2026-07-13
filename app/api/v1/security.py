from fastapi import APIRouter

from app.core.rsa_service import get_public_key_pem

router = APIRouter()


@router.get("/security/public-key")
async def public_key():
    """Return the RSA public key used for client-side password encryption."""
    return {"public_key": get_public_key_pem()}
