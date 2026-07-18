from fastapi import APIRouter, Depends, HTTPException, status, Body, Query, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.base import get_db
from app.schemas.account import (
    AccountCreate, AccountResponse, AccountUpdate, PasswordResponse,
    SharedUserInfo, SharedGroupInfo, AccountAuditEntry,
)
from app.services.account_service import AccountService
from app.services.account_audit_service import AccountAuditService
from app.core.security import get_encryption_service
from app.api.deps import (
    enforce_permissions,
    require_all_permissions,
    require_any_permission,
)

router = APIRouter()


def _client_ip(request: Request) -> str:
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"

account_view = require_any_permission("acc_view", "acc_edit", account_admin=True)
account_create = require_any_permission("acc_add", account_admin=True)
account_edit = require_any_permission("acc_edit", account_admin=True)
account_delete = require_any_permission("acc_delete", account_admin=True)
account_view_pass = require_any_permission("acc_view_pass", account_admin=True)
account_copy = require_all_permissions("acc_add", "acc_view", account_admin=True)
account_permission = require_any_permission("acc_permission", account_admin=True)


@router.get("/accounts", response_model=List[AccountResponse])
async def list_accounts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    q: Optional[str] = Query(None),
    category_id: Optional[int] = Query(None),
    client_id: Optional[int] = Query(None),
    tag_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    return AccountService(db, get_encryption_service()).get_accounts(
        current_user["id"], skip, limit,
        q=q, category_id=category_id, client_id=client_id, tag_id=tag_id,
    )


@router.get("/accounts/count")
async def count_accounts(
    q: Optional[str] = Query(None),
    category_id: Optional[int] = Query(None),
    client_id: Optional[int] = Query(None),
    tag_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    count = AccountService(db, get_encryption_service()).count_accounts(
        current_user["id"],
        q=q, category_id=category_id, client_id=client_id, tag_id=tag_id,
    )
    return {"count": count}


@router.get("/accounts/search", response_model=List[AccountResponse])
async def search_accounts(
    q: str,
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    return AccountService(db, get_encryption_service()).search_accounts(current_user["id"], q)


@router.post("/accounts", response_model=AccountResponse, status_code=status.HTTP_201_CREATED)
async def create_account(
    account: AccountCreate,
    db: Session = Depends(get_db),
    current_user=Depends(account_create),
):
    if not account.is_public:
        enforce_permissions(
            current_user, db, "acc_private", account_admin=True
        )
    if account.is_private_group:
        enforce_permissions(
            current_user, db, "acc_private_group", account_admin=True
        )
    if account.shared_users or account.shared_groups:
        enforce_permissions(
            current_user, db, "acc_permission", account_admin=True
        )
    try:
        return AccountService(db, get_encryption_service()).create_account(
            account, current_user["id"], master_pass=current_user.get("master_pass")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/accounts/{account_id}/audit", response_model=List[AccountAuditEntry])
async def get_account_audit(
    account_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    """Who opened this account / viewed its password / edited it. Restricted
    to the owner, the account's main group, and admins (can_edit_account)."""
    svc = AccountService(db, get_encryption_service())
    if not svc.can_edit_account(account_id, current_user["id"]):
        raise HTTPException(
            status_code=403,
            detail="Only the account owner or its main group can audit this account",
        )
    return AccountAuditService(db).list_for_account(account_id, skip, limit)


@router.get("/accounts/{account_id}", response_model=AccountResponse)
async def get_account(
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    result = AccountService(db, get_encryption_service()).get_account(account_id, current_user["id"])
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    AccountAuditService(db).log(
        account_id, "account.view", current_user["id"],
        current_user.get("username"), _client_ip(request),
    )
    return result


@router.put("/accounts/{account_id}", response_model=AccountResponse)
async def update_account(
    account_id: int,
    account: AccountUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(account_edit),
):
    if account.password is not None:
        enforce_permissions(
            current_user, db, "acc_edit_pass", account_admin=True
        )
    if account.is_public is False:
        enforce_permissions(
            current_user, db, "acc_private", account_admin=True
        )
    if account.is_private_group:
        enforce_permissions(
            current_user, db, "acc_private_group", account_admin=True
        )
    if account.shared_users is not None or account.shared_groups is not None:
        enforce_permissions(
            current_user, db, "acc_permission", account_admin=True
        )
    result = AccountService(db, get_encryption_service()).update_account(
        account_id, account, current_user["id"], master_pass=current_user.get("master_pass")
    )
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    # account.edit is recorded by the global audit middleware (with the
    # [acc:<id>] marker), so no per-route logging is needed here.
    return result


@router.delete("/accounts/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_delete),
):
    # account.delete is recorded by the global audit middleware.
    if not AccountService(db, get_encryption_service()).delete_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")


@router.get("/accounts/{account_id}/password")
async def get_account_password(
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(account_view_pass),
):
    password = AccountService(db, get_encryption_service()).get_decrypted_password(
        account_id, current_user["id"], master_pass=current_user.get("master_pass")
    )
    if password is None:
        raise HTTPException(status_code=404, detail="Account not found or no password")
    AccountAuditService(db).log(
        account_id, "account.view.pass", current_user["id"],
        current_user.get("username"), _client_ip(request),
    )
    return PasswordResponse(password=password)


@router.post("/accounts/{account_id}/favorite")
async def toggle_favorite(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    try:
        is_now_favorite = AccountService(db, get_encryption_service()).toggle_favorite(account_id, current_user["id"])
    except ValueError:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"is_favorite": is_now_favorite}


@router.post("/accounts/{account_id}/copy", response_model=AccountResponse, status_code=status.HTTP_201_CREATED)
async def copy_account(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_copy),
):
    result = AccountService(db, get_encryption_service()).copy_account(
        account_id, current_user["id"], master_pass=current_user.get("master_pass")
    )
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    return result


# ── ACL: shared users ─────────────────────────────────────────────────────

@router.put("/accounts/{account_id}/users/{target_user_id}")
async def set_user_access(
    account_id: int,
    target_user_id: int,
    is_edit: bool = Body(False, embed=True),
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    ok = AccountService(db, get_encryption_service()).set_user_access(
        account_id, current_user["id"], target_user_id, is_edit
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"ok": True}


@router.delete("/accounts/{account_id}/users/{target_user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_user_access(
    account_id: int,
    target_user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    if not AccountService(db, get_encryption_service()).remove_user_access(
        account_id, current_user["id"], target_user_id
    ):
        raise HTTPException(status_code=404, detail="Account or user access not found")


# ── ACL: shared groups ────────────────────────────────────────────────────

@router.put("/accounts/{account_id}/groups/{group_id}")
async def set_group_access(
    account_id: int,
    group_id: int,
    is_edit: bool = Body(False, embed=True),
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    ok = AccountService(db, get_encryption_service()).set_group_access(
        account_id, current_user["id"], group_id, is_edit
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"ok": True}


@router.delete("/accounts/{account_id}/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_group_access(
    account_id: int,
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    if not AccountService(db, get_encryption_service()).remove_group_access(
        account_id, current_user["id"], group_id
    ):
        raise HTTPException(status_code=404, detail="Account or group access not found")
