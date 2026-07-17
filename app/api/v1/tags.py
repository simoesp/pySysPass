from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.db.base import get_db
from app.schemas.tag import TagCreate, TagResponse, TagUpdate, AccountWithTag
from app.services.tag_service import TagService
from app.api.deps import get_current_user

router = APIRouter()

@router.get("/tags", response_model=List[TagResponse])
async def list_tags(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all tags for the current user"""
    service = TagService(db)
    return service.get_tags(current_user["id"])

@router.post("/tags", response_model=TagResponse, status_code=status.HTTP_201_CREATED)
async def create_tag(
    tag: TagCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new tag"""
    service = TagService(db)
    return service.create_tag(tag, current_user["id"])

@router.get("/tags/{tag_id}", response_model=TagResponse)
async def get_tag(
    tag_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific tag"""
    service = TagService(db)
    tag = service.get_tag(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    return tag

@router.put("/tags/{tag_id}", response_model=TagResponse)
async def update_tag(
    tag_id: int,
    tag: TagUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update a tag"""
    service = TagService(db)
    updated = service.update_tag(tag_id, tag, current_user["id"])
    if not updated:
        raise HTTPException(status_code=404, detail="Tag not found")
    return updated

@router.delete("/tags/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tag(
    tag_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete a tag"""
    service = TagService(db)
    if not service.delete_tag(tag_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Tag not found")
    return None

@router.get("/tags/{tag_id}/accounts", response_model=List[AccountWithTag])
async def get_accounts_by_tag(
    tag_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all accounts with a specific tag"""
    service = TagService(db)
    tag = service.get_tag(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")

    accounts = service.search_accounts_by_tag(tag_id, current_user["id"])

    # Format response
    result = []
    for account in accounts:
        result.append(AccountWithTag(
            account_id=account.id,
            account_title=account.name,
            tag_id=tag_id,
            tag_name=tag.name,
            tag_color=tag.color
        ))
    return result

@router.post("/accounts/{account_id}/tags/{tag_id}")
async def add_tag_to_account(
    account_id: int,
    tag_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Add a tag to an account"""
    service = TagService(db)

    # Verify account exists and belongs to user
    from app.models.account import Account
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # Verify tag exists
    tag = service.get_tag(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")

    if not service.add_tag_to_account(account_id, tag_id):
        raise HTTPException(status_code=409, detail="Tag already added to this account")

    return {"message": "Tag added successfully"}

@router.delete("/accounts/{account_id}/tags/{tag_id}")
async def remove_tag_from_account(
    account_id: int,
    tag_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Remove a tag from an account"""
    service = TagService(db)

    # Verify account exists and belongs to user
    from app.models.account import Account
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    if not service.remove_tag_from_account(account_id, tag_id):
        raise HTTPException(status_code=404, detail="Tag not associated with this account")

    return {"message": "Tag removed successfully"}

@router.get("/accounts/{account_id}/tags", response_model=List[TagResponse])
async def get_account_tags(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all tags for an account"""
    from app.models.account import Account
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    service = TagService(db)
    return service.get_account_tags(account_id)
