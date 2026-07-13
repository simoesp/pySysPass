from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.db.base import get_db
from app.schemas.history import AccountHistoryResponse
from app.services.history_service import HistoryService
from app.api.deps import get_current_user, require_admin

router = APIRouter()

@router.get("/accounts/{account_id}/history", response_model=List[AccountHistoryResponse])
async def get_account_history(
    account_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get the history of changes for an account"""
    service = HistoryService(db)
    
    # Verify user has access to this account
    from app.models.account import Account
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    return service.get_account_history(account_id, current_user["id"], limit, skip)

@router.get("/users/{user_id}/history", response_model=List[AccountHistoryResponse])
async def get_user_history(
    user_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all history entries for a specific user (admin only)"""
    if current_user.get("id") != user_id and not current_user.get("is_admin"):
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    service = HistoryService(db)
    return service.get_user_history(user_id, limit, skip)

@router.get("/accounts/{account_id}/history/decrypt-count")
async def get_decrypt_count(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get the number of times an account's password has been decrypted"""
    from app.models.account import Account
    
    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    service = HistoryService(db)
    count = service.get_account_decrypt_count(account_id)
    
    return {"account_id": account_id, "decrypt_count": count}

@router.get("/accounts/{account_id}/history/view-count")
async def get_view_count(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get the number of times an account has been viewed"""
    from app.models.account import Account
    
    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    service = HistoryService(db)
    count = service.get_account_view_count(account_id)
    
    return {"account_id": account_id, "view_count": count}
