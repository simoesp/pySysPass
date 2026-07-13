"""Account Sharing API Endpoints"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import require_any_permission
from app.db.base import get_db
from app.models.account import Account, User, UserGroup, UserToUserGroup
from app.services.account_sharing_service import AccountSharingService
from app.services.email_service import email_service_from_config

router = APIRouter(prefix="/accounts", tags=["Account Sharing"])
account_view = require_any_permission("acc_view", "acc_edit", account_admin=True)
account_permission = require_any_permission("acc_permission", account_admin=True)


def _is_account_admin(current_user: dict) -> bool:
    return bool(current_user.get("is_admin_app") or current_user.get("is_admin_acc"))


def _fire_share_email(db: Session, account_id: int, user_id: int, shared_by: str):
    """Best-effort: send 'account shared' email. Never raises."""
    try:
        svc = email_service_from_config(db)
        if not svc:
            return
        account = db.get(Account, account_id)
        user = db.get(User, user_id)
        if account and user and user.email:
            svc.send_account_shared(user.email, account.name, shared_by)
    except Exception:
        pass


def _require_account_owner(db: Session, account_id: int, current_user: dict) -> Account:
    account = db.get(Account, account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    if account.userId != current_user.get("id") and not _is_account_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    return account


def _require_same_user_or_admin(current_user: dict, user_id: int) -> None:
    if current_user.get("id") != user_id and not _is_account_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


def _require_group_member_or_admin(db: Session, user_group_id: int, current_user: dict) -> None:
    if _is_account_admin(current_user):
        return
    current_user_id = current_user.get("id")
    user = db.get(User, current_user_id)
    if user and user.userGroupId == user_group_id:
        return
    membership = db.query(UserToUserGroup).filter(
        UserToUserGroup.userId == current_user_id,
        UserToUserGroup.userGroupId == user_group_id,
    ).first()
    if membership:
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


@router.post("/{account_id}/share/users")
async def share_account_with_user(
    account_id: int,
    user_id: int,
    is_edit: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Share an account with a specific user"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    try:
        share = service.share_with_user(account_id, user_id, is_edit)
        shared_by = current_user.get("username", "sysPass")
        _fire_share_email(db, account_id, user_id, shared_by)
        return {
            'account_id': share.accountId,
            'user_id': share.userId,
            'is_edit': share.isEdit,
            'date_add': share.date_add.isoformat() if share.date_add else None
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/{account_id}/share/users/{user_id}")
async def unshare_account_with_user(
    account_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Remove sharing with a specific user"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    success = service.unshare_with_user(account_id, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Sharing relationship not found")
    return {"message": "Account unshared from user"}


@router.get("/{account_id}/share/users", response_model=List[dict])
async def get_account_shared_users(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Get all users an account is shared with"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    return service.get_shared_users(account_id)


@router.put("/{account_id}/share/users/{user_id}/permission")
async def update_user_permission(
    account_id: int,
    user_id: int,
    is_edit: bool,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Update edit permission for a shared account"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    success = service.update_user_permission(account_id, user_id, is_edit)
    if not success:
        raise HTTPException(status_code=404, detail="Sharing relationship not found")
    return {"message": "Permission updated", "is_edit": is_edit}


@router.get("/users/{user_id}/shared-accounts", response_model=List[dict])
async def get_user_shared_accounts(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    """Get all accounts accessible by a user"""
    _require_same_user_or_admin(current_user, user_id)
    service = AccountSharingService(db)
    return service.get_user_accounts(user_id)


@router.post("/{account_id}/share/groups")
async def share_account_with_user_group(
    account_id: int,
    user_group_id: int,
    is_edit: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Share an account with a user group"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    try:
        share = service.share_with_user_group(account_id, user_group_id, is_edit)
        return {
            'account_id': share.accountId,
            'user_group_id': share.userGroupId,
            'is_edit': share.isEdit,
            'date_add': share.date_add.isoformat() if share.date_add else None
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/{account_id}/share/groups/{user_group_id}")
async def unshare_account_with_user_group(
    account_id: int,
    user_group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Remove sharing with a user group"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    success = service.unshare_with_user_group(account_id, user_group_id)
    if not success:
        raise HTTPException(status_code=404, detail="Sharing relationship not found")
    return {"message": "Account unshared from user group"}


@router.get("/{account_id}/share/groups", response_model=List[dict])
async def get_account_shared_user_groups(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Get all user groups an account is shared with"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    return service.get_shared_user_groups(account_id)


@router.put("/{account_id}/share/groups/{user_group_id}/permission")
async def update_user_group_permission(
    account_id: int,
    user_group_id: int,
    is_edit: bool,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Update edit permission for a shared account with user group"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    success = service.update_user_group_permission(account_id, user_group_id, is_edit)
    if not success:
        raise HTTPException(status_code=404, detail="Sharing relationship not found")
    return {"message": "Permission updated", "is_edit": is_edit}


@router.get("/user-groups/{user_group_id}/accounts", response_model=List[dict])
async def get_user_group_accounts(
    user_group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    """Get all accounts accessible by a user group"""
    _require_group_member_or_admin(db, user_group_id, current_user)
    service = AccountSharingService(db)
    return service.get_user_group_accounts(user_group_id)


@router.post("/{account_id}/share/users/bulk")
async def share_account_with_multiple_users(
    account_id: int,
    user_ids: List[int],
    is_edit: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Share an account with multiple users"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    shares = service.share_with_multiple_users(account_id, user_ids, is_edit)
    shared_by = current_user.get("username", "sysPass")
    for uid in user_ids:
        _fire_share_email(db, account_id, uid, shared_by)
    return {
        'account_id': account_id,
        'shared_with': [s.userId for s in shares],
        'count': len(shares),
        'is_edit': is_edit
    }


@router.post("/{account_id}/share/groups/bulk")
async def share_account_with_multiple_groups(
    account_id: int,
    group_ids: List[int],
    is_edit: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Share an account with multiple user groups"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    shares = service.share_with_multiple_groups(account_id, group_ids, is_edit)
    return {
        'account_id': account_id,
        'shared_with': [s.userGroupId for s in shares],
        'count': len(shares),
        'is_edit': is_edit
    }


@router.delete("/{account_id}/share/all")
async def remove_all_shares(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    """Remove all sharing relationships for an account"""
    _require_account_owner(db, account_id, current_user)
    service = AccountSharingService(db)
    count = service.remove_all_shares(account_id)
    return {"message": f"Removed {count} sharing relationships"}
