"""Account Sharing Services - Share accounts with users and user groups"""
from typing import List, Optional, Dict
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.account import AccountToUser, AccountToUserGroup, Account, User, UserGroup


class AccountSharingService:
    """Service for managing account sharing with users and groups"""

    def __init__(self, db: Session):
        self.db = db

    # Account to User sharing
    def share_with_user(self, account_id: int, user_id: int, is_edit: bool = False) -> AccountToUser:
        """Share an account with a specific user"""
        # Check if account exists
        account = self.db.get(Account, account_id)
        if not account:
            raise ValueError(f"Account {account_id} not found")

        # Check if user exists
        user = self.db.get(User, user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        # Check if already shared
        existing = self.db.execute(
            select(AccountToUser)
            .where(
                AccountToUser.accountId == account_id,
                AccountToUser.userId == user_id
            )
        ).scalars().first()

        if existing:
            existing.isEdit = is_edit
            self.db.commit()
            self.db.refresh(existing)
            return existing

        # Create new sharing relationship
        share = AccountToUser(
            accountId=account_id,
            userId=user_id,
            isEdit=is_edit
        )
        self.db.add(share)
        self.db.commit()
        self.db.refresh(share)
        return share

    def unshare_with_user(self, account_id: int, user_id: int) -> bool:
        """Remove sharing with a specific user"""
        share = self.db.execute(
            select(AccountToUser)
            .where(
                AccountToUser.accountId == account_id,
                AccountToUser.userId == user_id
            )
        ).scalars().first()

        if not share:
            return False

        self.db.delete(share)
        self.db.commit()
        return True

    def get_shared_users(self, account_id: int) -> List[Dict]:
        """Get all users an account is shared with"""
        shares = self.db.execute(
            select(AccountToUser, User)
            .join(User, AccountToUser.userId == User.id)
            .where(AccountToUser.accountId == account_id)
        ).all()

        return [{
            'user_id': share.User.id,
            'username': share.User.username,
            'email': share.User.email,
            'is_edit': bool(share.AccountToUser.isEdit),
            'date_add': share.AccountToUser.date_add.isoformat() if share.AccountToUser.date_add else None
        } for share in shares]

    def get_user_accounts(self, user_id: int, include_edit: bool = True) -> List[Dict]:
        """Get all accounts accessible by a user (including shared)"""
        query = select(AccountToUser).where(AccountToUser.userId == user_id)
        shares = self.db.execute(query).scalars().all()

        accounts = []
        for share in shares:
            account = self.db.get(Account, share.accountId)
            if account:
                accounts.append({
                    'account_id': account.id,
                    'name': account.name,
                    'is_owner': account.userId == user_id,
                    'is_edit': bool(share.isEdit),
                    'date_add': share.date_add.isoformat() if share.date_add else None
                })

        return accounts

    def update_user_permission(self, account_id: int, user_id: int, is_edit: bool) -> bool:
        """Update edit permission for a shared account"""
        share = self.db.execute(
            select(AccountToUser)
            .where(
                AccountToUser.accountId == account_id,
                AccountToUser.userId == user_id
            )
        ).scalars().first()

        if not share:
            return False

        share.isEdit = is_edit
        self.db.commit()
        self.db.refresh(share)
        return True

    # Account to User Group sharing
    def share_with_user_group(self, account_id: int, user_group_id: int, is_edit: bool = False) -> AccountToUserGroup:
        """Share an account with a user group"""
        # Check if account exists
        account = self.db.get(Account, account_id)
        if not account:
            raise ValueError(f"Account {account_id} not found")

        # Check if user group exists
        user_group = self.db.get(UserGroup, user_group_id)
        if not user_group:
            raise ValueError(f"User group {user_group_id} not found")

        # Check if already shared
        existing = self.db.execute(
            select(AccountToUserGroup)
            .where(
                AccountToUserGroup.accountId == account_id,
                AccountToUserGroup.userGroupId == user_group_id
            )
        ).scalars().first()

        if existing:
            existing.isEdit = is_edit
            self.db.commit()
            self.db.refresh(existing)
            return existing

        # Create new sharing relationship
        share = AccountToUserGroup(
            accountId=account_id,
            userGroupId=user_group_id,
            isEdit=is_edit
        )
        self.db.add(share)
        self.db.commit()
        self.db.refresh(share)
        return share

    def unshare_with_user_group(self, account_id: int, user_group_id: int) -> bool:
        """Remove sharing with a user group"""
        share = self.db.execute(
            select(AccountToUserGroup)
            .where(
                AccountToUserGroup.accountId == account_id,
                AccountToUserGroup.userGroupId == user_group_id
            )
        ).scalars().first()

        if not share:
            return False

        self.db.delete(share)
        self.db.commit()
        return True

    def get_shared_user_groups(self, account_id: int) -> List[Dict]:
        """Get all user groups an account is shared with"""
        shares = self.db.execute(
            select(AccountToUserGroup, UserGroup)
            .join(UserGroup, AccountToUserGroup.userGroupId == UserGroup.id)
            .where(AccountToUserGroup.accountId == account_id)
        ).all()

        return [{
            'user_group_id': share.UserGroup.id,
            'name': share.UserGroup.name,
            'description': share.UserGroup.description,
            'is_edit': bool(share.AccountToUserGroup.isEdit),
            'date_add': share.AccountToUserGroup.date_add.isoformat() if share.AccountToUserGroup.date_add else None
        } for share in shares]

    def get_user_group_accounts(self, user_group_id: int) -> List[Dict]:
        """Get all accounts accessible by a user group"""
        shares = self.db.execute(
            select(AccountToUserGroup)
            .where(AccountToUserGroup.userGroupId == user_group_id)
        ).scalars().all()

        accounts = []
        for share in shares:
            account = self.db.get(Account, share.accountId)
            if account:
                accounts.append({
                    'account_id': account.id,
                    'name': account.name,
                    'is_edit': bool(share.isEdit),
                    'date_add': share.date_add.isoformat() if share.date_add else None
                })

        return accounts

    def update_user_group_permission(self, account_id: int, user_group_id: int, is_edit: bool) -> bool:
        """Update edit permission for a shared account with user group"""
        share = self.db.execute(
            select(AccountToUserGroup)
            .where(
                AccountToUserGroup.accountId == account_id,
                AccountToUserGroup.userGroupId == user_group_id
            )
        ).scalars().first()

        if not share:
            return False

        share.isEdit = is_edit
        self.db.commit()
        self.db.refresh(share)
        return True

    # Bulk operations
    def share_with_multiple_users(
        self, account_id: int, user_ids: List[int], is_edit: bool = False
    ) -> List[AccountToUser]:
        """Share an account with multiple users"""
        shares = []
        for user_id in user_ids:
            try:
                share = self.share_with_user(account_id, user_id, is_edit)
                shares.append(share)
            except ValueError:
                continue  # Skip invalid users
        return shares

    def share_with_multiple_groups(
        self, account_id: int, group_ids: List[int], is_edit: bool = False
    ) -> List[AccountToUserGroup]:
        """Share an account with multiple user groups"""
        shares = []
        for group_id in group_ids:
            try:
                share = self.share_with_user_group(account_id, group_id, is_edit)
                shares.append(share)
            except ValueError:
                continue  # Skip invalid groups
        return shares

    def remove_all_shares(self, account_id: int) -> int:
        """Remove all sharing relationships for an account"""
        # Remove user shares
        user_shares = self.db.execute(
            select(AccountToUser).where(AccountToUser.accountId == account_id)
        ).scalars().all()

        for share in user_shares:
            self.db.delete(share)

        # Remove group shares
        group_shares = self.db.execute(
            select(AccountToUserGroup).where(AccountToUserGroup.accountId == account_id)
        ).scalars().all()

        for share in group_shares:
            self.db.delete(share)

        self.db.commit()
        return len(user_shares) + len(group_shares)
