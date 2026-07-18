from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.db.base import get_db
from app.schemas.history import AccountHistoryResponse
from app.core.security import get_encryption_service
from app.services.account_service import AccountService
from app.services.history_service import HistoryService
from app.api.deps import get_current_user, require_any_permission

router = APIRouter()
account_history_view = require_any_permission("acc_view_history", account_admin=True)

@router.get("/accounts/{account_id}/history", response_model=List[AccountHistoryResponse])
async def get_account_history(
    account_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(account_history_view)
):
    """Get the history of changes for an account"""
    account_service = AccountService(db, get_encryption_service())
    if not account_service.can_access_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")

    return HistoryService(db).get_account_history(
        account_id, None, limit, skip,
        access_filter=account_service.history_access_filter(current_user["id"]),
    )

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
    current_user = Depends(account_history_view)
):
    """Get the number of times an account's password has been decrypted"""
    if not AccountService(db, get_encryption_service()).can_access_account(
        account_id, current_user["id"]
    ):
        raise HTTPException(status_code=404, detail="Account not found")

    service = HistoryService(db)
    count = service.get_account_decrypt_count(account_id)

    return {"account_id": account_id, "decrypt_count": count}

@router.get("/accounts/{account_id}/history/view-count")
async def get_view_count(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(account_history_view)
):
    """Get the number of times an account has been viewed"""
    if not AccountService(db, get_encryption_service()).can_access_account(
        account_id, current_user["id"]
    ):
        raise HTTPException(status_code=404, detail="Account not found")

    service = HistoryService(db)
    count = service.get_account_view_count(account_id)

    return {"account_id": account_id, "view_count": count}
