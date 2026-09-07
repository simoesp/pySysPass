from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.account import PublicLink, Account
from app.core.security import get_encryption_service
from app.services.account_service import AccountService
from app.services.config_service import ConfigService
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
        if not AccountService(self.db, get_encryption_service()).can_access_account(account_id, user_id):
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
            maxCountViews=ConfigService(self.db).get_accounts_settings().publinks_max_views,
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
            try:
                encoded_hash = hash_value.encode("ascii")
            except UnicodeEncodeError:
                return None

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

        # Atomically consume one view so simultaneous requests cannot exceed
        # the PHP countViews < maxCountViews and time < dateExpire gates.
        consumed = self.db.query(PublicLink).filter(
            PublicLink.id == link.id,
            PublicLink.dateExpire > int(time.time()),
            PublicLink.countViews < PublicLink.maxCountViews,
        ).update({
            PublicLink.countViews: PublicLink.countViews + 1,
            PublicLink.totalCountViews: func.coalesce(PublicLink.totalCountViews, 0) + 1,
        }, synchronize_session=False)
        if not consumed:
            self.db.rollback()
            return None
        self.db.commit()
        self.db.refresh(link)
        return (link, account)

    def delete_public_link(self, link_id: int, user_id: int, account_id: Optional[int] = None) -> bool:
        """Delete a public link"""
        link = self.db.query(PublicLink).filter(
            PublicLink.id == link_id
        ).first()

        if not link or (account_id is not None and link.accountId != account_id):
            return False

        # Verify the account ACL
        if not AccountService(self.db, get_encryption_service()).can_access_account(link.accountId, user_id):
            return False

        self.db.delete(link)
        self.db.commit()
        return True

    def get_public_links_for_account(self, account_id: int, user_id: int) -> List[PublicLink]:
        """Get all public links for an account"""
        # Verify user has access
        if not AccountService(self.db, get_encryption_service()).can_access_account(account_id, user_id):
            return []

        return self.db.query(PublicLink).filter(
            PublicLink.accountId == account_id
        ).all()

    def get_public_link_by_id(
        self, link_id: int, user_id: int, account_id: Optional[int] = None
    ) -> Optional[PublicLink]:
        """Get a specific public link"""
        link = self.db.query(PublicLink).filter(
            PublicLink.id == link_id
        ).first()

        if not link or (account_id is not None and link.accountId != account_id):
            return None

        # Verify the account ACL
        if not AccountService(self.db, get_encryption_service()).can_access_account(link.accountId, user_id):
            return None

        return link

    def _generate_hash(self) -> str:
        """Generate a unique hash for the public link"""
        random_bytes = secrets.token_bytes(32)
        return hashlib.sha256(random_bytes).hexdigest()

    def is_link_expired(self, link: PublicLink) -> bool:
        """Check if a public link has expired"""
        return link.dateExpire is None or int(time.time()) >= link.dateExpire
