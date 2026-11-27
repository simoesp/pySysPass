from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.account import Account, Category, Client, PublicLink
from app.core.security import get_encryption_service
from app.core.php_public_link import (
    PublicLinkSnapshot, build_link_snapshot, is_php_object, read_public_link_snapshot, write_public_link_vault,
)
from app.core.syspass_runtime_config import get_password_salt
from app.services.account_service import AccountService, VaultRequiredError
from app.services.config_service import ConfigService
import time
import secrets

class PublicLinksDisabledError(PermissionError):
    """publinks_enabled is off (PHP hides the create action)."""


class PublicLinkService:
    def __init__(self, db: Session):
        self.db = db

    def create_public_link(
        self,
        account_id: int,
        user_id: int,
        expire_seconds: Optional[int] = None,
        password: Optional[str] = None,
        master_pass: Optional[str] = None,
    ) -> PublicLink:
        """Create a link in the native sysPass format (PHP PublicLinkService::create).

        PublicLink.data holds a Vault-wrapped AccountExtData snapshot that the
        sysPass PHP reader can open. PHP links have no access password, so one
        cannot be stored without a Python-only format.
        """
        if password:
            raise ValueError("sysPass public links do not support access passwords")
        accounts = AccountService(self.db, get_encryption_service())
        if not accounts.can_access_account(account_id, user_id):
            raise ValueError("Account not found or access denied")
        settings = ConfigService(self.db).get_accounts_settings()
        if not settings.publinks_enabled:
            raise PublicLinksDisabledError("Public links are disabled")

        existing = self.db.query(PublicLink.id).filter(
            PublicLink.accountId == account_id
        ).first()
        if existing:
            raise ValueError("Account already has a public link")

        if not master_pass:
            raise VaultRequiredError("Master password required to create a public link")
        salt = get_password_salt()
        if not salt:
            raise ValueError("The sysPass password salt is not configured")
        # PHP getDataForLink(): INNER JOIN Client/Category for their names.
        row = self.db.query(Account, Client.name, Category.name).join(
            Client, Account.clientId == Client.id
        ).join(Category, Account.categoryId == Category.id).filter(Account.id == account_id).first()
        if row is None:
            raise ValueError("Account not found or access denied")
        account, client_name, category_name = row
        plaintext = accounts._decrypt_account_pass(account, master_pass) if account.pass_ else ''
        if plaintext is None:
            raise ValueError("The account password could not be decrypted with this vault key")

        link_hash = self._generate_hash()
        now = int(time.time())
        lifetime = int(expire_seconds) if expire_seconds else int(settings.publinks_max_time or 600)
        snapshot = build_link_snapshot(
            account_id=account.id, name=account.name, login=account.login, url=account.url,
            notes=account.notes, password=plaintext, client_name=client_name, category_name=category_name,
        )
        link = PublicLink(
            accountId=account_id,
            hash=link_hash.encode("ascii"),
            data=write_public_link_vault(snapshot, link_hash.encode("ascii"), salt, now),
            userId=user_id,
            typeId=1,  # PublicLinkService::TYPE_ACCOUNT
            notify=False,
            dateAdd=now,
            dateExpire=now + lifetime,
            dateUpdate=0,
            maxCountViews=settings.publinks_max_views,
        )

        self.db.add(link)
        self.db.commit()
        self.db.refresh(link)
        return link

    def get_public_link(
        self, hash_value: str | bytes, password: Optional[str] = None
    ) -> Optional[Tuple[PublicLink, Account | PublicLinkSnapshot]]:
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
        if self.is_link_expired(link) or (link.countViews or 0) >= link.maxCountViews:
            return None

        if link.typeId != 1:
            return None

        native_snapshot = is_php_object(link.data)
        if native_snapshot:
            try:
                raw_data = link.data.encode('utf-8') if isinstance(link.data, str) else link.data
                account = read_public_link_snapshot(raw_data, encoded_hash, get_password_salt(), link.accountId)
            except (ValueError, UnicodeError, TypeError):
                return None
        else:
            # Legacy Python links store a separate encrypted access password.
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
            account = self.db.query(Account).filter(Account.id == link.accountId).first()
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
        if native_snapshot:
            self.db.query(Account).filter(Account.id == link.accountId).update({
                Account.countView: func.coalesce(Account.countView, 0) + 1,
                Account.countDecrypt: func.coalesce(Account.countDecrypt, 0) + 1,
            }, synchronize_session=False)
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
        """PHP PasswordUtil::generateRandomBytes(): 30 random bytes as hex."""
        return secrets.token_hex(30)

    def is_link_expired(self, link: PublicLink) -> bool:
        """Check if a public link has expired"""
        return link.dateExpire is None or int(time.time()) >= link.dateExpire
