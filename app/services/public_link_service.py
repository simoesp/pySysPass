from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from app.models.account import PublicLink, Account
from app.schemas.public_link import PublicLinkCreate
from datetime import datetime, timedelta
import time
import hashlib
import secrets

class PublicLinkService:
    def __init__(self, db: Session):
        self.db = db

    def create_public_link(
        self,
        account_id: int,
        user_id: int,
        expire_seconds: Optional[int] = None,
        password: Optional[str] = None
    ) -> PublicLink:
        """Create a new public link for an account"""
        # Verify user has access to this account
        account = self.db.query(Account).filter(
            Account.id == account_id,
            Account.userId == user_id
        ).first()

        if not account:
            raise ValueError("Account not found or access denied")

        existing = self.db.query(PublicLink.id).filter(
            PublicLink.accountId == account_id
        ).first()
        if existing:
            raise ValueError("Account already has a public link")

        # Generate unique hash
        link_hash = self._generate_hash()

        # Calculate expiration
        now = int(time.time())
        date_expire = now + int(expire_seconds) if expire_seconds else now + 86400

        # Encrypt password if provided
        encrypted_password = None
        if password:
            from app.core.security import EncryptionService
            from app.core.config import settings
            encryption = EncryptionService(settings.ENCRYPTION_KEY)
            encrypted_password = encryption.encrypt(password).encode()

        link = PublicLink(
            accountId=account_id,
            hash=link_hash.encode("ascii"),
            userId=user_id,
            typeId=1,
            notify=False,
            dateAdd=now,
            dateExpire=date_expire,
            dateUpdate=0,
            maxCountViews=0,
            password=encrypted_password,
        )

        self.db.add(link)
        self.db.commit()
        self.db.refresh(link)
        return link

    def get_public_link(
        self, hash_value: str | bytes, password: Optional[str] = None
    ) -> Optional[Tuple[PublicLink, Account]]:
        """Get a public link by hash and verify access"""
        if isinstance(hash_value, bytes):
            encoded_hash = hash_value
        else:
            encoded_hash = hash_value.encode("ascii")

        link = self.db.query(PublicLink).filter(
            PublicLink.hash == encoded_hash
        ).first()

        if not link:
            return None

        # Check if expired
        if self.is_link_expired(link):
            return None

        # Verify password if required
        if link.password:
            if not password:
                return None

            from app.core.security import EncryptionService
            from app.core.config import settings
            encryption = EncryptionService(settings.ENCRYPTION_KEY)

            try:
                decrypted_password = encryption.decrypt(link.password.decode())
                if decrypted_password != password:
                    return None
            except Exception:
                return None

        # Get the account
        account = self.db.query(Account).filter(
            Account.id == link.accountId
        ).first()

        if not account:
            return None

        return (link, account)

    def delete_public_link(self, link_id: int, user_id: int) -> bool:
        """Delete a public link"""
        link = self.db.query(PublicLink).filter(
            PublicLink.id == link_id
        ).first()

        if not link:
            return False

        # Verify user owns the account
        account = self.db.query(Account).filter(
            Account.id == link.accountId,
            Account.userId == user_id
        ).first()

        if not account:
            return False

        self.db.delete(link)
        self.db.commit()
        return True

    def get_public_links_for_account(self, account_id: int, user_id: int) -> List[PublicLink]:
        """Get all public links for an account"""
        # Verify user has access
        account = self.db.query(Account).filter(
            Account.id == account_id,
            Account.userId == user_id
        ).first()

        if not account:
            return []

        return self.db.query(PublicLink).filter(
            PublicLink.accountId == account_id
        ).all()

    def get_public_link_by_id(self, link_id: int, user_id: int) -> Optional[PublicLink]:
        """Get a specific public link"""
        link = self.db.query(PublicLink).filter(
            PublicLink.id == link_id
        ).first()

        if not link:
            return None

        # Verify user owns the account
        account = self.db.query(Account).filter(
            Account.id == link.accountId,
            Account.userId == user_id
        ).first()

        if not account:
            return None

        return link

    def _generate_hash(self) -> str:
        """Generate a unique hash for the public link"""
        random_bytes = secrets.token_bytes(32)
        return hashlib.sha256(random_bytes).hexdigest()

    def is_link_expired(self, link: PublicLink) -> bool:
        """Check if a public link has expired"""
        if not link.expire:
            return False

        return int(time.time()) > link.dateExpire
