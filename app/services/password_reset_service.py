"""Self-service password reset (request → email → confirm)."""
import hashlib
import secrets
import time
from typing import Optional
from sqlalchemy.orm import Session

from app.models.account import User, UserPassRecover
from app.services.auth_service import get_password_hash
from app.services.config_service import ConfigService
from app.services.email_service import EmailService

# Tokens expire after 1 hour
TOKEN_TTL_SECS = 3600


class PasswordResetService:
    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hash_token(self, token: str) -> bytes:
        return hashlib.sha256(token.encode()).digest()

    def _email_service(self) -> Optional[EmailService]:
        cfg = ConfigService(self.db).get_mail_settings()
        if not cfg.mail_enabled or not cfg.mail_server:
            return None
        return EmailService(
            smtp_host=cfg.mail_server,
            smtp_port=cfg.mail_port or 25,
            username=cfg.mail_user if cfg.mail_auth_enabled else None,
            password=cfg.mail_pass if cfg.mail_auth_enabled else None,
            security=(cfg.mail_security or "tls").lower(),
            from_email=cfg.mail_from or "syspass@localhost",
        )

    def _app_url(self) -> str:
        url = ConfigService(self.db).get("app_url") or "http://localhost"
        return url.rstrip("/")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_reset(self, email: str) -> bool:
        """
        Create a reset token for the user with this email and send the link.
        Always returns True so callers cannot enumerate valid emails.
        """
        user = self.db.query(User).filter(User.email == email).first()
        if not user or not user.isUserEnabled:
            return True  # silent: don't reveal whether the email exists

        # Invalidate old tokens for this user
        self.db.query(UserPassRecover).filter(
            UserPassRecover.userId == user.id,
            UserPassRecover.used == False,  # noqa: E712
        ).delete(synchronize_session=False)

        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)

        self.db.add(UserPassRecover(
            userId=user.id,
            hash=token_hash,
            date=int(time.time()),
            used=False,
        ))
        self.db.commit()

        reset_url = f"{self._app_url()}/password-reset/confirm?token={token}"
        email_svc = self._email_service()
        if email_svc:
            try:
                email_svc.send_password_reset(
                    user_email=user.email,
                    reset_link=reset_url,
                    username=user.username,
                )
            except Exception:
                pass  # log in production; don't fail the request

        return True

    def verify_token(self, token: str) -> Optional[User]:
        """Return the User if the token is valid and not expired, else None."""
        token_hash = self._hash_token(token)
        cutoff = int(time.time()) - TOKEN_TTL_SECS
        row = (
            self.db.query(UserPassRecover)
            .filter(
                UserPassRecover.hash == token_hash,
                UserPassRecover.used == False,  # noqa: E712
                UserPassRecover.date >= cutoff,
            )
            .first()
        )
        if not row:
            return None
        return self.db.query(User).filter(User.id == row.userId).first()

    def confirm_reset(self, token: str, new_password: str) -> bool:
        """Reset the password if the token is valid.  Returns True on success."""
        token_hash = self._hash_token(token)
        cutoff = int(time.time()) - TOKEN_TTL_SECS
        row = (
            self.db.query(UserPassRecover)
            .filter(
                UserPassRecover.hash == token_hash,
                UserPassRecover.used == False,  # noqa: E712
                UserPassRecover.date >= cutoff,
            )
            .first()
        )
        if not row:
            return False

        user = self.db.query(User).filter(User.id == row.userId).first()
        if not user:
            return False

        user.password = get_password_hash(new_password)
        row.used = True
        self.db.commit()
        return True
