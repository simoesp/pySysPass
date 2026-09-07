from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from app.models.account import AccountFile
from app.core.security import get_encryption_service
from app.services.account_service import AccountService

class FileService:
    def __init__(self, db: Session):
        self.db = db

    def create_file(
        self,
        account_id: int,
        name: str,
        file_type: str,
        size: int,
        content: bytes,
        extension: str
    ) -> AccountFile:
        """Create a new file attachment for an account"""
        file = AccountFile(
            accountId=account_id,
            name=name,
            type=file_type,
            size=size,
            content=content,
            extension=extension,
        )
        self.db.add(file)
        self.db.commit()
        self.db.refresh(file)
        return file

    def get_files(self, account_id: int, user_id: int) -> List[AccountFile]:
        """Get all files for an account"""
        # Verify user has access to this account
        if not AccountService(self.db, get_encryption_service()).can_access_account(account_id, user_id):
            return []

        return self.db.query(AccountFile).filter(
            AccountFile.accountId == account_id
        ).all()

    def get_file(self, file_id: int, user_id: int, account_id: Optional[int] = None) -> Optional[AccountFile]:
        """Get a specific file by ID"""
        file = self.db.query(AccountFile).filter(
            AccountFile.id == file_id
        ).first()

        if not file or (account_id is not None and file.accountId != account_id):
            return None

        # Verify user has access to the account
        if not AccountService(self.db, get_encryption_service()).can_access_account(file.accountId, user_id):
            return None

        return file

    def delete_file(self, file_id: int, user_id: int, account_id: Optional[int] = None) -> bool:
        """Delete a file"""
        file = self.get_file(file_id, user_id, account_id=account_id)

        if not file or not AccountService(self.db, get_encryption_service()).can_edit_account(file.accountId, user_id):
            return False

        self.db.delete(file)
        self.db.commit()
        return True

    def get_file_content(self, file_id: int, user_id: int) -> Optional[Tuple[bytes, str]]:
        """Get file content and type"""
        file = self.get_file(file_id, user_id)

        if not file:
            return None

        return (file.content, file.type)

    def file_exists(self, account_id: int, user_id: int) -> bool:
        """Check if account has any files"""
        if not AccountService(self.db, get_encryption_service()).can_access_account(account_id, user_id):
            return False

        count = self.db.query(AccountFile).filter(
            AccountFile.accountId == account_id
        ).count()

        return count > 0

    def get_file_count(self, account_id: int, user_id: int) -> int:
        """Get the number of files for an account"""
        if not AccountService(self.db, get_encryption_service()).can_access_account(account_id, user_id):
            return 0

        return self.db.query(AccountFile).filter(
            AccountFile.accountId == account_id
        ).count()
