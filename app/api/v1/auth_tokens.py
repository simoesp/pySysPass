from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.db.base import get_db
from app.schemas.auth_token import AuthTokenResponse, AuthTokenCreate, ACTION_LABELS
from app.services.auth_token_service import AuthTokenService
from app.api.deps import get_current_user
from app.models.account import User

router = APIRouter()


def _is_admin(db: Session, user_id: int) -> bool:
    user = db.query(User).filter(User.id == user_id).first()
    return bool(user and user.isUserAdmin)


@router.get("/auth-tokens/actions")
async def list_actions():
    """Return the full actionId → label map."""
    return [{"id": k, "label": v} for k, v in sorted(ACTION_LABELS.items())]


@router.get("/auth-tokens", response_model=List[AuthTokenResponse])
async def list_auth_tokens(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    svc = AuthTokenService(db)
    if _is_admin(db, current_user["id"]):
        return svc.list_tokens()
    return svc.list_tokens(user_id=current_user["id"])


@router.post("/auth-tokens", response_model=AuthTokenResponse, status_code=status.HTTP_201_CREATED)
async def create_auth_token(
    body: AuthTokenCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if body.user_id != current_user["id"] and not _is_admin(db, current_user["id"]):
        raise HTTPException(status_code=403, detail="Cannot create tokens for other users")
    return AuthTokenService(db).create_token(body.user_id, body.action_id, current_user["id"])


@router.post("/auth-tokens/{token_id}/regenerate", response_model=AuthTokenResponse)
async def regenerate_auth_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    svc = AuthTokenService(db)
    uid = None if _is_admin(db, current_user["id"]) else current_user["id"]
    result = svc.regenerate_token(token_id, user_id=uid)
    if not result:
        raise HTTPException(status_code=404, detail="Token not found")
    return result


@router.delete("/auth-tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_auth_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    svc = AuthTokenService(db)
    uid = None if _is_admin(db, current_user["id"]) else current_user["id"]
    if not svc.delete_token(token_id, user_id=uid):
        raise HTTPException(status_code=404, detail="Token not found")
