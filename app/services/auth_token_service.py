import secrets
import time
from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.account import AuthToken, User
from app.schemas.auth_token import AuthTokenResponse, ACTION_LABELS


class AuthTokenService:
    def __init__(self, db: Session):
        self.db = db

    def _to_response(self, token: AuthToken) -> AuthTokenResponse:
        raw = token.token.decode('ascii') if isinstance(token.token, bytes) else token.token
        username = token.user.username if token.user else None
        return AuthTokenResponse(
            id=token.id,
            user_id=token.userId,
            username=username,
            action_id=token.actionId,
            action_label=ACTION_LABELS.get(token.actionId),
            token=raw,
            start_date=token.startDate,
            has_vault=token.vault is not None,
        )

    def list_tokens(self, user_id: Optional[int] = None) -> List[AuthTokenResponse]:
        q = self.db.query(AuthToken)
        if user_id is not None:
            q = q.filter(AuthToken.userId == user_id)
        return [self._to_response(t) for t in q.order_by(AuthToken.startDate.desc()).all()]

    def create_token(self, user_id: int, action_id: int, created_by: int) -> AuthTokenResponse:
        token_str = secrets.token_hex(32)  # 64 hex chars, same length as PHP tokens
        token = AuthToken(
            userId=user_id,
            token=token_str.encode('ascii'),
            actionId=action_id,
            createdBy=created_by,
            startDate=int(time.time()),
        )
        self.db.add(token)
        self.db.commit()
        self.db.refresh(token)
        return self._to_response(token)

    def regenerate_token(self, token_id: int, user_id: Optional[int] = None) -> Optional[AuthTokenResponse]:
        q = self.db.query(AuthToken).filter(AuthToken.id == token_id)
        if user_id is not None:
            q = q.filter(AuthToken.userId == user_id)
        token = q.first()
        if not token:
            return None
        token.token = secrets.token_hex(32).encode('ascii')
        token.startDate = int(time.time())
        self.db.commit()
        self.db.refresh(token)
        return self._to_response(token)

    def delete_token(self, token_id: int, user_id: Optional[int] = None) -> bool:
        q = self.db.query(AuthToken).filter(AuthToken.id == token_id)
        if user_id is not None:
            q = q.filter(AuthToken.userId == user_id)
        token = q.first()
        if not token:
            return False
        self.db.delete(token)
        self.db.commit()
        return True
