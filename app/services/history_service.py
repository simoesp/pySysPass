from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.account import AccountHistory, Account
from datetime import UTC, datetime


class HistoryService:
    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def _utc_now_naive() -> datetime:
        return datetime.now(UTC).replace(tzinfo=None)

    def _snapshot(self, account: Account, action: str,
                  old_value: Optional[str] = None,
                  new_value: Optional[str] = None,
                  is_modify: bool = False,
                  is_deleted: bool = False) -> AccountHistory:
        """Build an AccountHistory row from an Account instance.

        For modification events (create / update / delete) the full account
        state is captured so the record can be used to restore data.
        For audit-only events (view / decrypt) pass_/key/mPassHash are left
        null and is_modify stays False.
        """
        entry = AccountHistory(
            accountId=account.id,
            userGroupId=account.userGroupId,
            userId=account.userId,
            userEditId=account.userEditId or account.userId,
            clientId=account.clientId,
            name=account.name,
            categoryId=account.categoryId,
            login=account.login,
            url=account.url,
            notes=account.notes or "",
            pass_=account.pass_ or b"",
            key=account.key or b"",
            mPassHash=b"",
            countView=account.countView or 0,
            countDecrypt=account.countDecrypt or 0,
            dateAdd=account.dateAdd or self._utc_now_naive(),
            dateEdit=account.dateEdit,
            otherUserEdit=account.otherUserEdit or False,
            otherUserGroupEdit=account.otherUserGroupEdit or False,
            passDate=account.passDate,
            passDateChange=account.passDateChange,
            parentId=account.parentId,
            isPrivate=account.isPrivate or False,
            isPrivateGroup=account.isPrivateGroup or False,
            isModify=is_modify,
            isDeleted=is_deleted,
            actionName=action,
            oldValue=old_value,
            newValue=new_value,
        )
        return entry

    def _save(self, entry: AccountHistory) -> AccountHistory:
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    # ------------------------------------------------------------------
    # Low-level creation (used when caller already has an Account object)
    # ------------------------------------------------------------------

    def create_snapshot(self, account: Account, action: str,
                        old_value: Optional[str] = None,
                        new_value: Optional[str] = None,
                        is_modify: bool = False,
                        is_deleted: bool = False) -> AccountHistory:
        return self._save(self._snapshot(account, action, old_value, new_value,
                                         is_modify, is_deleted))

    def create_history(self, account_id: int, user_id: int, action: str,
                       old_value: Optional[str] = None,
                       new_value: Optional[str] = None) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account or account.userId != user_id:
            return None
        return self.create_snapshot(
            account,
            action=action,
            old_value=old_value,
            new_value=new_value,
            is_modify=action in {'create', 'update', 'delete', 'password_change'},
            is_deleted=action == 'delete',
        )

    # ------------------------------------------------------------------
    # Helper methods (fetch account then snapshot)
    # ------------------------------------------------------------------

    def _get_account(self, account_id: int) -> Optional[Account]:
        return self.db.query(Account).filter(Account.id == account_id).first()

    def log_view(self, account_id: int, user_id: int) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(account, action='view')

    def log_decrypt(self, account_id: int, user_id: int) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(account, action='decrypt')

    def log_create(self, account_id: int, user_id: int,
                   details: str) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(account, action='create',
                                    new_value=details, is_modify=True)

    def log_update(self, account_id: int, user_id: int,
                   field: str, old_value: str,
                   new_value: str) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(
            account, action='update',
            old_value=f'{field}: {old_value}',
            new_value=f'{field}: {new_value}',
            is_modify=True
        )

    def log_password_change(self, account_id: int,
                            user_id: int) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(account, action='password_change', is_modify=True)

    def log_delete(self, account: Account, user_id: int) -> AccountHistory:
        """Call before deleting the account so the snapshot can capture its data."""
        return self.create_snapshot(account, action='delete',
                                    is_modify=True, is_deleted=True)

    def log_file_upload(self, account_id: int, user_id: int,
                        filename: str) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(account, action='file_upload', new_value=filename)

    def log_file_download(self, account_id: int, user_id: int,
                          filename: str) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(account, action='file_download', new_value=filename)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_account_history(self, account_id: int,
                             user_id: Optional[int] = None,
                             limit: int = 100,
                             skip: int = 0) -> List[AccountHistory]:
        if user_id is not None:
            access = self.db.query(Account).filter(
                Account.id == account_id,
                Account.userId == user_id
            ).first()
            if not access:
                return []

        return (
            self.db.query(AccountHistory)
            .filter(AccountHistory.accountId == account_id)
            .order_by(AccountHistory.dateAdd.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_user_history(self, user_id: int,
                          limit: int = 100,
                          skip: int = 0) -> List[AccountHistory]:
        return (
            self.db.query(AccountHistory)
            .filter(AccountHistory.userId == user_id)
            .order_by(AccountHistory.dateAdd.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_account_decrypt_count(self, account_id: int) -> int:
        return (
            self.db.query(AccountHistory)
            .filter(AccountHistory.accountId == account_id,
                    AccountHistory.actionName == 'decrypt')
            .count()
        )

    def get_account_view_count(self, account_id: int) -> int:
        return (
            self.db.query(AccountHistory)
            .filter(AccountHistory.accountId == account_id,
                    AccountHistory.actionName == 'view')
            .count()
        )
