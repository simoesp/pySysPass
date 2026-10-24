from fastapi import APIRouter, Depends, HTTPException, status, Body, Query, Request
from sqlalchemy.orm import Session
from typing import List, Literal, Optional
from app.db.base import get_db
from app.schemas.account import (
    AccountCreate, AccountResponse, AccountUpdate, PasswordResponse,
    SharedUserInfo, SharedGroupInfo, AccountAuditEntry,
)
from app.services.account_service import AccountService, AccountValidationError, VaultRequiredError
from app.services.account_audit_service import AccountAuditService
from app.core.security import get_encryption_service
from app.core.password_image import text_to_png_base64
from app.services.item_preset_service import ItemPresetService
from app.services.runtime_policy import get_policy
from app.api.deps import (
    enforce_permissions,
    require_all_permissions,
    require_any_permission,
)

router = APIRouter()


def _vault_required(exc: VaultRequiredError) -> HTTPException:
    # Same code the login flow uses when the vault cannot be unlocked.
    return HTTPException(status_code=428, detail={"code": "MASTER_PASSWORD_REQUIRED", "message": str(exc)})


def _client_ip(request: Request) -> str:
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"  # nosec B104

account_view = require_any_permission("acc_view", "acc_edit", account_admin=True)
account_create = require_any_permission("acc_add", account_admin=True)
account_edit = require_any_permission("acc_edit", account_admin=True)
account_delete = require_any_permission("acc_delete", account_admin=True)
account_view_pass = require_any_permission("acc_view_pass", account_admin=True)
account_copy = require_all_permissions("acc_add", "acc_view", account_admin=True)
account_permission = require_any_permission("acc_permission", account_admin=True)


@router.get("/accounts", response_model=List[AccountResponse])
def list_accounts(
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
def count_accounts(
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
def search_accounts(
    q: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user=Depends(account_view),
):
    # Paged like /accounts (and PHP's account search); unbounded results cost
    # seconds per request on large vaults.
    return AccountService(db, get_encryption_service()).search_accounts(current_user["id"], q, skip, limit)


@router.post("/accounts", response_model=AccountResponse, status_code=status.HTTP_201_CREATED)
def create_account(
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
    except AccountValidationError as e:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    except VaultRequiredError as e:
        db.rollback()
        raise _vault_required(e)


@router.get("/accounts/{account_id}/audit", response_model=List[AccountAuditEntry])
def get_account_audit(
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
def get_account(
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
def update_account(
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
    try:
        result = AccountService(db, get_encryption_service()).update_account(
            account_id, account, current_user["id"], master_pass=current_user.get("master_pass")
        )
    except AccountValidationError as e:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    except VaultRequiredError as e:
        db.rollback()
        raise _vault_required(e)
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    # account.edit is recorded by the global audit middleware (with the
    # [acc:<id>] marker), so no per-route logging is needed here.
    return result


@router.delete("/accounts/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_delete),
):
    # account.delete is recorded by the global audit middleware.
    if not AccountService(db, get_encryption_service()).delete_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")


@router.get("/accounts/{account_id}/password")
def get_account_password(
    account_id: int,
    request: Request,
    purpose: Literal["copy", "view"] = "copy",
    db: Session = Depends(get_db),
    current_user=Depends(account_view_pass),
):
    """The password; ``purpose=view`` follows PHP viewPass's image rule, copy returns text as copyPass does."""
    try:
        password = AccountService(db, get_encryption_service()).get_decrypted_password(
            account_id, current_user["id"], master_pass=current_user.get("master_pass")
        )
    except VaultRequiredError as e:
        raise _vault_required(e)
    if password is None:
        raise HTTPException(status_code=404, detail="Account not found or no password")
    AccountAuditService(db).log(
        account_id, "account.view.pass", current_user["id"],
        current_user.get("username"), _client_ip(request),
    )
    if purpose == "view" and (get_policy(db).account_pass_to_image
                              or ItemPresetService(db).password_as_image(current_user["id"])):
        return PasswordResponse(use_image=True, password_image=text_to_png_base64(password))
    return PasswordResponse(password=password)


@router.post("/accounts/{account_id}/favorite")
def toggle_favorite(
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
def copy_account(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_copy),
):
    try:
        result = AccountService(db, get_encryption_service()).copy_account(
            account_id, current_user["id"], master_pass=current_user.get("master_pass")
        )
    except VaultRequiredError as e:
        raise _vault_required(e)
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    return result


# ── ACL: shared users ─────────────────────────────────────────────────────

@router.put("/accounts/{account_id}/users/{target_user_id}")
def set_user_access(
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
def remove_user_access(
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
def set_group_access(
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
def remove_group_access(
    account_id: int,
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(account_permission),
):
    if not AccountService(db, get_encryption_service()).remove_group_access(
        account_id, current_user["id"], group_id
    ):
        raise HTTPException(status_code=404, detail="Account or group access not found")
