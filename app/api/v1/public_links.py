from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.base import get_db
from app.schemas.public_link import PublicLinkCreate, PublicLinkResponse, PublicLinkAccess
from app.services.public_link_service import PublicLinkService
from app.services.auth_service import decode_token
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter()
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"id": payload.get("user_id")}

@router.get("/accounts/{account_id}/public-links", response_model=List[PublicLinkResponse])
async def list_public_links(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all public links for an account"""
    from app.models.account import Account
    
    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    service = PublicLinkService(db)
    return service.get_public_links_for_account(account_id, current_user["id"])

@router.post("/accounts/{account_id}/public-links", response_model=PublicLinkResponse, status_code=status.HTTP_201_CREATED)
async def create_public_link(
    account_id: int,
    link_data: PublicLinkCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new public link for an account"""
    from app.models.account import Account
    
    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    service = PublicLinkService(db)
    
    try:
        link = service.create_public_link(
            account_id=account_id,
            user_id=current_user["id"],
            expire_seconds=link_data.expire,
            password=link_data.password
        )
        return link
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/public-links/{link_hash}/access")
async def access_public_link(
    link_hash: str,
    password: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Access an account via a public link"""
    service = PublicLinkService(db)
    
    result = service.get_public_link(link_hash, password)
    
    if not result:
        raise HTTPException(status_code=404, detail="Invalid or expired link")
    
    link, account = result
    
    # Check if expired
    if service.is_link_expired(link):
        raise HTTPException(status_code=410, detail="Link has expired")
    
    # Return account data (without sensitive fields)
    return PublicLinkAccess(
        account_id=account.id,
        account_title=account.name,
        login=account.login,
        url=account.url,
        notes=account.notes,
        category_id=account.categoryId,
        client_id=account.clientId
    )

@router.delete("/accounts/{account_id}/public-links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_public_link(
    account_id: int,
    link_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete a public link"""
    from app.models.account import Account
    
    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    service = PublicLinkService(db)
    
    if not service.delete_public_link(link_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Public link not found")
    
    return None

@router.get("/accounts/{account_id}/public-links/{link_id}")
async def get_public_link(
    account_id: int,
    link_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get a specific public link"""
    from app.models.account import Account
    
    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    service = PublicLinkService(db)
    link = service.get_public_link_by_id(link_id, current_user["id"])
    
    if not link:
        raise HTTPException(status_code=404, detail="Public link not found")
    
    return link
