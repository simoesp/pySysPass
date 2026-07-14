from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.account import AccountHistory, Account, Config
from datetime import UTC, datetime


class HistoryService:
    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def _utc_now_naive() -> datetime:
        return datetime.now(UTC).replace(tzinfo=None)

    def _master_password_hash(self) -> bytes:
        row = self.db.query(Config).filter(Config.parameter == "masterPwd").first()
        value = row.value if row and row.value else ""
        return value.encode("utf-8") if isinstance(value, str) else value

    def _snapshot(self, account: Account, is_modify: bool = False,
                  is_deleted: bool = False) -> AccountHistory:
        """Build the pre-mutation snapshot persisted by sysPass PHP."""
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
            mPassHash=self._master_password_hash(),
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
        )
        return entry

    def stage_snapshot(self, account: Account, is_modify: bool = False,
                       is_deleted: bool = False) -> AccountHistory:
        """Add a snapshot to the current transaction without committing it."""
        entry = self._snapshot(account, is_modify, is_deleted)
        self.db.add(entry)
        return entry

    def _save(self, entry: AccountHistory) -> AccountHistory:
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    # ------------------------------------------------------------------
    # Low-level creation (used when caller already has an Account object)
    # ------------------------------------------------------------------

    def create_snapshot(self, account: Account, is_modify: bool = False,
                        is_deleted: bool = False) -> AccountHistory:
        return self._save(self._snapshot(account, is_modify, is_deleted))

    def create_history(self, account_id: int, user_id: int, action: str,
                       old_value: Optional[str] = None,
                       new_value: Optional[str] = None) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account or account.userId != user_id:
            return None
        if action not in {'update', 'delete', 'password_change'}:
            return None
        return self.create_snapshot(account, is_modify=action != 'delete',
                                    is_deleted=action == 'delete')

    # ------------------------------------------------------------------
    # Helper methods (fetch account then snapshot)
    # ------------------------------------------------------------------

    def _get_account(self, account_id: int) -> Optional[Account]:
        return self.db.query(Account).filter(Account.id == account_id).first()

    def log_view(self, account_id: int, user_id: int) -> Optional[AccountHistory]:
        # PHP stores view totals on Account; it does not create history rows.
        return None

    def log_decrypt(self, account_id: int, user_id: int) -> Optional[AccountHistory]:
        # PHP stores decrypt totals on Account; it does not create history rows.
        return None

    def log_create(self, account_id: int, user_id: int,
                   details: str) -> Optional[AccountHistory]:
        # PHP starts history when the account is first modified.
        return None

    def log_update(self, account_id: int, user_id: int,
                   field: str, old_value: str,
                   new_value: str) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(account, is_modify=True)

    def log_password_change(self, account_id: int,
                            user_id: int) -> Optional[AccountHistory]:
        account = self._get_account(account_id)
        if not account:
            return None
        return self.create_snapshot(account, is_modify=True)

    def log_delete(self, account: Account, user_id: int) -> AccountHistory:
        """Call before deleting the account so the snapshot can capture its data."""
        return self.create_snapshot(account, is_deleted=True)

    def log_file_upload(self, account_id: int, user_id: int,
                        filename: str) -> Optional[AccountHistory]:
        return None

    def log_file_download(self, account_id: int, user_id: int,
                          filename: str) -> Optional[AccountHistory]:
        return None

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
            .order_by(AccountHistory.id.desc())
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
            .order_by(AccountHistory.id.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_account_decrypt_count(self, account_id: int) -> int:
        account = self._get_account(account_id)
        return (account.countDecrypt or 0) if account else 0

    def get_account_view_count(self, account_id: int) -> int:
        account = self._get_account(account_id)
        return (account.countView or 0) if account else 0
