import secrets
import time
from typing import Optional

from sqlalchemy.orm import Session

from app.core.defuse_compat import decrypt_mpass, encrypt_user_master_pass
from app.models.account import Config, User
from app.services.auth_service import get_password_hash, verify_password
from app.services.email_service import email_service_from_config


class TemporaryMasterPasswordService:
    MAX_ATTEMPTS = 50

    PARAM_PASS = "tempmaster_pass"
    PARAM_KEY = "tempmaster_passkey"
    PARAM_HASH = "tempmaster_passhash"
    PARAM_TIME = "tempmaster_passtime"
    PARAM_MAX_TIME = "tempmaster_maxtime"
    PARAM_ATTEMPTS = "tempmaster_attempts"

    def __init__(self, db: Session):
        self.db = db

    def _get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.db.query(Config).filter(Config.parameter == key).first()
        return row.value if row else default

    def _set(self, key: str, value: str) -> None:
        row = self.db.query(Config).filter(Config.parameter == key).first()
        if row:
            row.value = value
        else:
            self.db.add(Config(parameter=key, value=value))

    def _set_many(self, values: dict[str, str]) -> None:
        for key, value in values.items():
            self._set(key, value)

    def _recipient_emails(self, group_id: Optional[int]) -> list[str]:
        query = self.db.query(User.email).filter(User.email != None, User.email != "")  # noqa: E711
        if group_id:
            from app.models.account import UserToUserGroup

            query = (
                query.join(UserToUserGroup, User.id == UserToUserGroup.userId)
                .filter(UserToUserGroup.userGroupId == group_id)
            )
        return [email for (email,) in query.distinct().all() if email]

    def create(
        self,
        master_password: str,
        max_time: int = 14400,
        send_email: bool = False,
        group_id: Optional[int] = None,
    ) -> tuple[str, dict]:
        now = int(time.time())
        expires_at = now + max(60, max_time)
        temp_password = secrets.token_urlsafe(24)
        encrypted_pass, encrypted_key = encrypt_user_master_pass(master_password, temp_password)

        self._set_many({
            self.PARAM_PASS: encrypted_pass,
            self.PARAM_KEY: encrypted_key,
            self.PARAM_HASH: get_password_hash(temp_password),
            self.PARAM_TIME: str(now),
            self.PARAM_MAX_TIME: str(expires_at),
            self.PARAM_ATTEMPTS: "0",
        })
        self.db.commit()

        emailed_to = 0
        email_error = None
        if send_email:
            emailed_to = self.send_by_email(temp_password, expires_at, group_id)
            if emailed_to == 0:
                email_error = "Email sending failed or no recipients were available"

        return temp_password, {
            "created_at": now,
            "expires_at": expires_at,
            "emailed_to": emailed_to,
            "email_error": email_error,
        }

    def expire(self) -> None:
        self._set_many({
            self.PARAM_PASS: "",
            self.PARAM_KEY: "",
            self.PARAM_HASH: "",
            self.PARAM_TIME: "0",
            self.PARAM_MAX_TIME: "0",
            self.PARAM_ATTEMPTS: "0",
        })
        self.db.commit()

    def _is_expired(self, now: Optional[int] = None) -> bool:
        now = now or int(time.time())
        expires_at = int(self._get(self.PARAM_MAX_TIME, "0") or 0)
        attempts = int(self._get(self.PARAM_ATTEMPTS, "0") or 0)
        if expires_at == 0:
            return True
        if now > expires_at or attempts >= self.MAX_ATTEMPTS:
            self.expire()
            return True
        return False

    def check_temp_master_pass(self, password: str) -> bool:
        if self._is_expired():
            return False

        hashed = self._get(self.PARAM_HASH)
        attempts = int(self._get(self.PARAM_ATTEMPTS, "0") or 0)
        if not hashed or not verify_password(password, hashed):
            self._set(self.PARAM_ATTEMPTS, str(attempts + 1))
            self.db.commit()
            if attempts + 1 >= self.MAX_ATTEMPTS:
                self.expire()
            return False
        return True

    def get_using_key(self, password: str) -> str:
        encrypted_pass = self._get(self.PARAM_PASS) or ""
        encrypted_key = self._get(self.PARAM_KEY) or ""
        return decrypt_mpass(encrypted_pass, encrypted_key, password)

    def resolve_master_password(self, password: str) -> Optional[str]:
        if not self.check_temp_master_pass(password):
            return None
        try:
            return self.get_using_key(password)
        except Exception:
            return None

    def get_status(self) -> dict:
        now = int(time.time())
        created_at = int(self._get(self.PARAM_TIME, "0") or 0)
        expires_at = int(self._get(self.PARAM_MAX_TIME, "0") or 0)
        attempts = int(self._get(self.PARAM_ATTEMPTS, "0") or 0)

        if self._is_expired(now):
            created_at = 0
            expires_at = 0
            attempts = 0

        remaining = max(0, expires_at - now) if expires_at else 0
        return {
            "is_active": bool(expires_at and remaining > 0),
            "created_at": created_at or None,
            "expires_at": expires_at or None,
            "attempts": attempts,
            "max_attempts": self.MAX_ATTEMPTS,
            "remaining_seconds": remaining,
        }

    def send_by_email(self, password: str, expires_at: int, group_id: Optional[int]) -> int:
        service = email_service_from_config(self.db)
        if service is None:
            return 0

        recipients = self._recipient_emails(group_id)
        if not recipients:
            return 0

        body = "\n".join([
            "A new sysPass master password has been generated.",
            "The temporary master password is:",
            password,
            f"This password will be valid until: {time.ctime(expires_at)}",
            "Please log in as soon as possible to save the changes.",
        ])
        results = service.send_email_to_multiple(
            recipients,
            "sysPass Temporary Master Password",
            body,
            is_html=False,
        )
        return sum(1 for ok in results if ok)
