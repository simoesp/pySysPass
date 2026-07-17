from typing import List, Optional, Set
from datetime import datetime
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session
from app.models.account import (
    Account, AccountToTag, AccountToFavorite, AccountToUser, AccountToUserGroup, User, UserGroup, UserToUserGroup
)
from app.schemas.account import (
    AccountCreate, AccountUpdate, AccountResponse,
    TagInfo, SharedUserInfo, SharedGroupInfo, SharedUserEntry, SharedGroupEntry,
)
from app.core.security import EncryptionService
from app.core.rsa_service import maybe_decrypt
from app.core.defuse_compat import encrypt_account_pass
from app.services.config_service import ConfigService
from app.services.history_service import HistoryService
from app.services.plugin_service import PluginService


class ServiceResult(dict):
    """Dict result that also supports ORM-style attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class AccountService:
    def __init__(self, db: Session, encryption: EncryptionService):
        self.db = db
        self.encryption = encryption
        self._full_group_access: Optional[bool] = None
        self._global_search: Optional[bool] = None

    # ── Internal helpers ──────────────────────────────────────────────────

    def _is_favorited(self, account_id: int, user_id: int) -> bool:
        return self.db.query(AccountToFavorite).filter(
            AccountToFavorite.accountId == account_id,
            AccountToFavorite.userId == user_id,
        ).first() is not None

    def _get_user(self, user_id: int) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id).first()

    def _get_user_group_ids(self, user_id: int) -> Set[int]:
        user = self._get_user(user_id)
        if not user:
            return set()

        group_ids = {user.userGroupId}
        memberships = self.db.query(UserToUserGroup).filter(UserToUserGroup.userId == user_id).all()
        group_ids.update(m.userGroupId for m in memberships)
        return {gid for gid in group_ids if gid is not None}

    def _get_group_share_ids(self, user_id: int, group_ids: Set[int]) -> Set[int]:
        """Return groups whose explicit account shares apply to this user.

        PHP always applies AccountToUserGroup shares for the user's primary
        group. Secondary memberships apply only when accountFullGroupAccess is
        enabled; they still confer main-group visibility regardless of that
        setting.
        """
        user = self._get_user(user_id)
        if not user or user.userGroupId is None:
            return set()

        if self._full_group_access is None:
            value = ConfigService(self.db).get("account_full_group_access")
            self._full_group_access = bool(
                value is not None and value.lower() in ("true", "1", "yes")
            )

        if self._full_group_access:
            return group_ids
        return {user.userGroupId}

    def _visibility_filter(self, user_id: int, group_ids: Set[int]):
        user = self._get_user(user_id)
        primary_group_id = user.userGroupId if user else None
        return and_(
            or_(
                Account.isPrivate.is_(None),
                Account.isPrivate.is_(False),
                and_(Account.isPrivate.is_(True), Account.userId == user_id),
            ),
            or_(
                Account.isPrivateGroup.is_(None),
                Account.isPrivateGroup.is_(False),
                and_(
                    Account.isPrivateGroup.is_(True),
                    Account.userGroupId == primary_group_id,
                ) if primary_group_id is not None else False,
            ),
        )

    def _is_admin(self, user_id: int) -> bool:
        user = self._get_user(user_id)
        return bool(user and (user.isAdminApp or user.isAdminAcc))

    def _global_search_allowed(self, user_id: int) -> bool:
        # PHP drops the ownership/group filter (privacy filter stays) when the
        # global_search config is enabled and the profile grants accGlobalSearch.
        if self._global_search is None:
            value = ConfigService(self.db).get("global_search")
            self._global_search = bool(value and value.lower() in ("true", "1", "yes"))
        if not self._global_search:
            return False
        user = self._get_user(user_id)
        if not user or not user.userProfileId:
            return False
        from app.services.user_profile_service import UserProfileService
        profile = UserProfileService(self.db).get_user_profile(user.userProfileId)
        if not profile:
            return False
        return bool(profile["permissions"].model_dump().get("acc_global_search", False))

    def _access_filter(self, user_id: int, group_ids: Set[int]):
        # PHP AccountFilterUser skips the ownership/group filter entirely for
        # isAdminApp/isAdminAcc users; only the private-account visibility
        # filter still applies to searches.
        if self._is_admin(user_id):
            return self._visibility_filter(user_id, group_ids)

        if self._global_search_allowed(user_id):
            return self._visibility_filter(user_id, group_ids)

        group_share_ids = self._get_group_share_ids(user_id, group_ids)
        filters = [
            Account.userId == user_id,
            Account.id.in_(
                self.db.query(AccountToUser.accountId).filter(AccountToUser.userId == user_id)
            ),
        ]

        if not group_ids:
            filters = [Account.userId == user_id]

        if group_ids:
            filters.append(Account.userGroupId.in_(group_ids))

        if group_share_ids:
            filters.append(
                Account.id.in_(
                    self.db.query(AccountToUserGroup.accountId).filter(
                        AccountToUserGroup.userGroupId.in_(group_share_ids)
                    )
                )
            )

        return and_(or_(*filters), self._visibility_filter(user_id, group_ids))

    def _can_edit_account(self, account: Account, user_id: int, group_ids: Set[int]) -> bool:
        # PHP compileAccountAccess grants admins view+edit before any other
        # check, including the private flags.
        if self._is_admin(user_id):
            return True
        if account.userId == user_id:
            return True
        if account.isPrivate:
            return False
        if account.isPrivateGroup:
            user = self._get_user(user_id)
            if not user or user.userGroupId != account.userGroupId:
                return False
        # PHP compileAccountAccess order: primary-group match grants edit
        # outright; an explicit AccountToUser share then short-circuits with
        # its own isEdit bit (even when a secondary group matches the main
        # group); secondary-membership main-group match follows; explicit
        # group shares come last, applying to secondary memberships only when
        # accountFullGroupAccess is enabled. Legacy otherUser* fields do not
        # override those share decisions.
        user = self._get_user(user_id)
        if user and account.userGroupId == user.userGroupId:
            return True
        user_share = next(
            (shared for shared in (account.sharedUsers or []) if shared.userId == user_id),
            None,
        )
        if user_share is not None:
            return bool(user_share.isEdit)
        if account.userGroupId in group_ids:
            return True
        group_share_ids = self._get_group_share_ids(user_id, group_ids)
        if any(shared.userGroupId in group_share_ids and shared.isEdit for shared in (account.sharedUserGroups or [])):
            return True
        return False

    def _get_tags(self, account: Account) -> List[TagInfo]:
        return [
            TagInfo(id=at.tag.id, name=at.tag.name, color=at.tag.color or '#000000')
            for at in (account.tags or [])
            if at.tag is not None
        ]

    def _get_shared_users(self, account: Account) -> List[SharedUserInfo]:
        result = []
        for atu in (account.sharedUsers or []):
            user = self.db.query(User).filter(User.id == atu.userId).first()
            if user:
                result.append(SharedUserInfo(
                    user_id=user.id,
                    username=user.username,
                    is_edit=bool(atu.isEdit),
                ))
        return result

    def _get_shared_groups(self, account: Account) -> List[SharedGroupInfo]:
        result = []
        for atg in (account.sharedUserGroups or []):
            group = self.db.query(UserGroup).filter(UserGroup.id == atg.userGroupId).first()
            if group:
                result.append(SharedGroupInfo(
                    group_id=group.id,
                    name=group.name,
                    is_edit=bool(atg.isEdit),
                ))
        return result

    def _sync_tags(self, account_id: int, tag_ids: List[int]):
        self.db.query(AccountToTag).filter(AccountToTag.accountId == account_id).delete()
        for tid in tag_ids:
            self.db.add(AccountToTag(accountId=account_id, tagId=tid))

    def _sync_shared_users(self, account_id: int, entries: List[SharedUserEntry]):
        self.db.query(AccountToUser).filter(AccountToUser.accountId == account_id).delete()
        for e in entries:
            self.db.add(AccountToUser(accountId=account_id, userId=e.user_id, isEdit=e.is_edit))

    def _sync_shared_groups(self, account_id: int, entries: List[SharedGroupEntry]):
        self.db.query(AccountToUserGroup).filter(AccountToUserGroup.accountId == account_id).delete()
        for e in entries:
            self.db.add(AccountToUserGroup(accountId=account_id, userGroupId=e.group_id, isEdit=e.is_edit))

    def _to_response(self, account: Account, user_id: int, group_ids: Optional[Set[int]] = None) -> ServiceResult:
        group_ids = group_ids if group_ids is not None else self._get_user_group_ids(user_id)
        return ServiceResult({
            'id': account.id,
            'user_id': account.userId,
            'user_group_id': account.userGroupId,
            'is_owner': account.userId == user_id,
            'can_edit': self._can_edit_account(account, user_id, group_ids),
            'title': account.name,
            'login': account.login,
            'url': account.url,
            'notes': account.notes,
            'category_id': account.categoryId,
            'client_id': account.clientId,
            'is_public': not (account.isPrivate or False),
            'is_private_group': bool(account.isPrivateGroup or False),
            'is_favorite': self._is_favorited(account.id, user_id),
            'other_user_edit': bool(account.otherUserEdit or False),
            'other_user_group_edit': bool(account.otherUserGroupEdit or False),
            'tags': self._get_tags(account),
            'shared_users': self._get_shared_users(account),
            'shared_groups': self._get_shared_groups(account),
            'count_view': account.countView or 0,
            'count_decrypt': account.countDecrypt or 0,
            'pass_date_change': account.passDateChange,
            'password': account.pass_,
            'created_at': account.dateAdd,
            'updated_at': account.dateEdit,
        })

    def _serialize_hook_payload(self, value):
        if isinstance(value, dict):
            return {k: self._serialize_hook_payload(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._serialize_hook_payload(v) for v in value]
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8", errors="ignore")
        if hasattr(value, "model_dump"):
            return value.model_dump()
        return value

    def _emit_hook(self, hook_name: str, **payload):
        try:
            PluginService(self.db).call_plugin_hook(hook_name, **self._serialize_hook_payload(payload))
        except Exception:
            pass

    # ── Queries ───────────────────────────────────────────────────────────

    def _list_filters(
        self,
        user_id: int,
        group_ids: Set[int],
        q: Optional[str] = None,
        category_id: Optional[int] = None,
        client_id: Optional[int] = None,
        tag_id: Optional[int] = None,
    ) -> list:
        """Access filter plus the optional list/search filters, PHP-style.

        Mirrors PHP AccountSearchFilter: free text matches name, login,
        notes and url; category/client/tag narrow by id.
        """
        filters = [self._access_filter(user_id, group_ids)]
        if q:
            term = f'%{q}%'
            filters.append(
                (Account.name.like(term))
                | (Account.login.like(term))
                | (Account.notes.like(term))
                | (Account.url.like(term))
            )
        if category_id is not None:
            filters.append(Account.categoryId == category_id)
        if client_id is not None:
            filters.append(Account.clientId == client_id)
        if tag_id is not None:
            filters.append(
                Account.id.in_(
                    self.db.query(AccountToTag.accountId).filter(AccountToTag.tagId == tag_id)
                )
            )
        return filters

    def get_accounts(
        self,
        user_id: int,
        skip: int = 0,
        limit: int = 100,
        q: Optional[str] = None,
        category_id: Optional[int] = None,
        client_id: Optional[int] = None,
        tag_id: Optional[int] = None,
    ) -> List[dict]:
        group_ids = self._get_user_group_ids(user_id)
        accounts = (
            self.db.query(Account)
            .filter(*self._list_filters(user_id, group_ids, q, category_id, client_id, tag_id))
            .order_by(Account.dateAdd.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )
        return [self._to_response(a, user_id, group_ids) for a in accounts]

    def count_accounts(
        self,
        user_id: int,
        q: Optional[str] = None,
        category_id: Optional[int] = None,
        client_id: Optional[int] = None,
        tag_id: Optional[int] = None,
    ) -> int:
        group_ids = self._get_user_group_ids(user_id)
        return (
            self.db.query(Account.id)
            .filter(*self._list_filters(user_id, group_ids, q, category_id, client_id, tag_id))
            .count()
        )

    def can_access_account(self, account_id: int, user_id: int) -> bool:
        """Non-mutating object ACL check for account-owned child resources."""
        group_ids = self._get_user_group_ids(user_id)
        return self.db.query(Account).filter(
            Account.id == account_id,
            self._access_filter(user_id, group_ids),
        ).first() is not None

    def can_edit_account(self, account_id: int, user_id: int) -> bool:
        """Non-mutating PHP ACL edit check for account-owned child resources."""
        group_ids = self._get_user_group_ids(user_id)
        account = self.db.query(Account).filter(
            Account.id == account_id,
            self._access_filter(user_id, group_ids),
        ).first()
        return bool(account and self._can_edit_account(account, user_id, group_ids))

    def get_account(self, account_id: int, user_id: Optional[int] = None) -> Optional[dict]:
        query = self.db.query(Account).filter(Account.id == account_id)
        if user_id is not None:
            group_ids = self._get_user_group_ids(user_id)
            # PHP applies the private filter only to searches; object-level
            # ACL (compileAccountAccess) lets admins open any account by id.
            if not self._is_admin(user_id):
                query = query.filter(self._access_filter(user_id, group_ids))
                if not self.db.query(Account).filter(Account.id == account_id, Account.userId == user_id).first():
                    account = self.db.query(Account).filter(Account.id == account_id).first()
                    if account and account.isPrivate:
                        return None
        else:
            group_ids = None
        account = query.first()
        if not account:
            return None
        account.countView = (account.countView or 0) + 1
        self.db.commit()
        self.db.refresh(account)
        return self._to_response(account, user_id or account.userId, group_ids)

    def search_accounts(self, user_id: int, query: str) -> List[dict]:
        group_ids = self._get_user_group_ids(user_id)
        accounts = (
            self.db.query(Account)
            .filter(*self._list_filters(user_id, group_ids, q=query))
            .all()
        )
        return [self._to_response(a, user_id, group_ids) for a in accounts]

    # ── Mutations ─────────────────────────────────────────────────────────

    def create_account(self, data: AccountCreate, user_id: int, master_pass: Optional[str] = None) -> dict:
        plaintext = maybe_decrypt(data.password)
        user = self.db.query(User).filter(User.id == user_id).first()
        user_group_id = user.userGroupId if user else 1

        if master_pass and plaintext:
            pass_hex, key_hex = encrypt_account_pass(plaintext, master_pass)
            enc_pass_bytes = pass_hex.encode()
            enc_key_bytes = key_hex.encode()
        else:
            enc_raw = self.encryption.encrypt(plaintext)
            enc_pass_bytes = enc_raw.encode() if isinstance(enc_raw, str) else enc_raw
            enc_key_bytes = b''

        account = Account(
            name=data.title,
            notes=data.notes,
            login=data.login,
            pass_=enc_pass_bytes,
            key=enc_key_bytes,
            url=data.url,
            categoryId=data.category_id,
            clientId=data.client_id,
            userId=user_id,
            userEditId=user_id,
            userGroupId=user_group_id,
            isPrivate=not data.is_public,
            isPrivateGroup=data.is_private_group,
            otherUserEdit=data.other_user_edit,
            otherUserGroupEdit=data.other_user_group_edit,
            passDateChange=data.pass_date_change,
        )
        self.db.add(account)
        self.db.flush()
        if data.tag_ids:
            self._sync_tags(account.id, data.tag_ids)
        if data.shared_users:
            self._sync_shared_users(account.id, data.shared_users)
        if data.shared_groups:
            self._sync_shared_groups(account.id, data.shared_groups)
        self.db.commit()
        self.db.refresh(account)
        result = self._to_response(account, user_id, {user_group_id})
        self._emit_hook("on_account_created", payload=result, actor_user_id=user_id)
        return result

    def update_account(
        self, account_id: int, data: AccountUpdate, user_id: int, master_pass: Optional[str] = None
    ) -> Optional[dict]:
        group_ids = self._get_user_group_ids(user_id)
        account = self.db.query(Account).filter(Account.id == account_id).first()
        if not account:
            return None
        if not self._can_edit_account(account, user_id, group_ids):
            return None

        # sysPass PHP saves the complete pre-update account state in the same
        # transaction, so password and metadata changes can be restored.
        HistoryService(self.db).stage_snapshot(account, is_modify=True)

        if data.title is not None:
            account.name = data.title
        if data.login is not None:
            account.login = data.login
        if data.url is not None:
            account.url = data.url
        if data.notes is not None:
            account.notes = data.notes
        if data.category_id is not None:
            account.categoryId = data.category_id
        if data.client_id is not None:
            account.clientId = data.client_id
        if data.is_public is not None:
            account.isPrivate = not data.is_public
        if data.is_private_group is not None:
            account.isPrivateGroup = data.is_private_group
        if data.other_user_edit is not None:
            account.otherUserEdit = data.other_user_edit
        if data.other_user_group_edit is not None:
            account.otherUserGroupEdit = data.other_user_group_edit
        if data.pass_date_change is not None:
            account.passDateChange = data.pass_date_change
        if data.is_favorite is not None:
            existing_favorite = self.db.query(AccountToFavorite).filter(
                AccountToFavorite.accountId == account_id,
                AccountToFavorite.userId == user_id,
            ).first()
            if data.is_favorite and not existing_favorite:
                self.db.add(AccountToFavorite(accountId=account_id, userId=user_id))
            elif not data.is_favorite and existing_favorite:
                self.db.delete(existing_favorite)
        if data.password:
            plaintext = maybe_decrypt(data.password)
            if master_pass and plaintext:
                pass_hex, key_hex = encrypt_account_pass(plaintext, master_pass)
                account.pass_ = pass_hex.encode()
                account.key = key_hex.encode()
            else:
                enc = self.encryption.encrypt(plaintext)
                account.pass_ = enc.encode() if isinstance(enc, str) else enc
            account.passDate = int(datetime.now().timestamp())
        account.userEditId = user_id
        if data.tag_ids is not None:
            self._sync_tags(account_id, data.tag_ids)
        if data.shared_users is not None:
            self._sync_shared_users(account_id, data.shared_users)
        if data.shared_groups is not None:
            self._sync_shared_groups(account_id, data.shared_groups)

        self.db.commit()
        self.db.refresh(account)
        result = self._to_response(account, user_id, group_ids)
        self._emit_hook("on_account_updated", payload=result, actor_user_id=user_id)
        return result

    def delete_account(self, account_id: int, user_id: int) -> bool:
        account = self.db.query(Account).filter(Account.id == account_id, Account.userId == user_id).first()
        if not account:
            return False
        payload = self._to_response(account, user_id, self._get_user_group_ids(user_id))
        HistoryService(self.db).stage_snapshot(account, is_deleted=True)
        self.db.delete(account)
        self.db.commit()
        self._emit_hook("on_account_deleted", payload=payload, actor_user_id=user_id)
        return True

    def _decrypt_account_pass(self, account: Account, master_pass: Optional[str]) -> Optional[str]:
        """
        Dispatch to defuse decryption for PHP-created accounts, or to the
        Python EncryptionService for accounts created by this backend.
        PHP accounts have a key column that starts with the defuse PKEY ASCII prefix.
        """
        pass_raw = account.pass_ if isinstance(account.pass_, bytes) else account.pass_.encode()
        key_raw  = account.key   if isinstance(account.key,   bytes) else (account.key or b'').encode()
        key_ascii = key_raw.decode('ascii', errors='ignore')
        # defuse KeyProtectedByPassword header \xDE\xF1\x00\x00 encodes to "def10000"
        if key_ascii.startswith('def10000') and master_pass:
            try:
                from app.core.defuse_compat import decrypt_account_pass
                return decrypt_account_pass(pass_raw.decode('ascii'), key_ascii, master_pass)
            except Exception:
                pass
        return self.encryption.decrypt(pass_raw.decode())

    def get_decrypted_password(self, account_id: int, user_id: Optional[int] = None,
                               master_pass: Optional[str] = None) -> Optional[str]:
        query = self.db.query(Account).filter(Account.id == account_id)
        if user_id is not None:
            group_ids = self._get_user_group_ids(user_id)
            query = query.filter(self._access_filter(user_id, group_ids))
        account = query.first()
        if not account or not account.pass_:
            return None
        account.countDecrypt = (account.countDecrypt or 0) + 1
        self.db.commit()
        password = self._decrypt_account_pass(account, master_pass)
        self._emit_hook(
            "on_password_decrypted",
            actor_user_id=user_id,
            account_id=account_id,
            account_title=account.name,
        )
        return password

    def toggle_favorite(self, account_id: int, user_id: int) -> bool:
        group_ids = self._get_user_group_ids(user_id)
        account = self.db.query(Account).filter(Account.id == account_id).filter(
            self._access_filter(user_id, group_ids)
        ).first()
        if not account:
            raise ValueError("Account not found")
        existing = self.db.query(AccountToFavorite).filter(
            AccountToFavorite.accountId == account_id,
            AccountToFavorite.userId == user_id,
        ).first()
        if existing:
            self.db.delete(existing)
            self.db.commit()
            return False
        self.db.add(AccountToFavorite(accountId=account_id, userId=user_id))
        self.db.commit()
        return True

    def copy_account(self, account_id: int, user_id: int,
                     master_pass: Optional[str] = None) -> Optional[dict]:
        group_ids = self._get_user_group_ids(user_id)
        source = self.db.query(Account).filter(Account.id == account_id).filter(
            self._access_filter(user_id, group_ids)
        ).first()
        if not source:
            return None

        plaintext = None
        if source.pass_:
            plaintext = self._decrypt_account_pass(source, master_pass)

        user = self.db.query(User).filter(User.id == user_id).first()
        copy = Account(
            name=f'{source.name} (copy)',
            notes=source.notes,
            login=source.login,
            url=source.url,
            key=b'',
            categoryId=source.categoryId,
            clientId=source.clientId,
            userId=user_id,
            userEditId=user_id,
            userGroupId=user.userGroupId if user else 1,
            isPrivate=source.isPrivate,
            isPrivateGroup=source.isPrivateGroup,
            otherUserEdit=source.otherUserEdit,
            otherUserGroupEdit=source.otherUserGroupEdit,
            passDateChange=source.passDateChange,
        )
        if plaintext:
            enc = self.encryption.encrypt(plaintext)
            copy.pass_ = enc.encode() if isinstance(enc, str) else enc

        self.db.add(copy)
        self.db.flush()

        for at in source.tags:
            self.db.add(AccountToTag(accountId=copy.id, tagId=at.tagId))

        self.db.commit()
        self.db.refresh(copy)
        result = self._to_response(copy, user_id, self._get_user_group_ids(user_id))
        self._emit_hook("on_account_copied", payload=result, source_account_id=account_id, actor_user_id=user_id)
        return result

    # ── ACL helpers ───────────────────────────────────────────────────────

    def set_user_access(self, account_id: int, user_id: int, target_user_id: int, is_edit: bool) -> bool:
        account = self.db.query(Account).filter(
            Account.id == account_id, Account.userId == user_id
        ).first()
        if not account:
            return False
        existing = self.db.query(AccountToUser).filter(
            AccountToUser.accountId == account_id,
            AccountToUser.userId == target_user_id,
        ).first()
        if existing:
            existing.isEdit = is_edit
        else:
            self.db.add(AccountToUser(accountId=account_id, userId=target_user_id, isEdit=is_edit))
        self.db.commit()
        return True

    def remove_user_access(self, account_id: int, user_id: int, target_user_id: int) -> bool:
        account = self.db.query(Account).filter(
            Account.id == account_id, Account.userId == user_id
        ).first()
        if not account:
            return False
        row = self.db.query(AccountToUser).filter(
            AccountToUser.accountId == account_id,
            AccountToUser.userId == target_user_id,
        ).first()
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    def set_group_access(self, account_id: int, user_id: int, group_id: int, is_edit: bool) -> bool:
        account = self.db.query(Account).filter(
            Account.id == account_id, Account.userId == user_id
        ).first()
        if not account:
            return False
        existing = self.db.query(AccountToUserGroup).filter(
            AccountToUserGroup.accountId == account_id,
            AccountToUserGroup.userGroupId == group_id,
        ).first()
        if existing:
            existing.isEdit = is_edit
        else:
            self.db.add(AccountToUserGroup(accountId=account_id, userGroupId=group_id, isEdit=is_edit))
        self.db.commit()
        return True

    def remove_group_access(self, account_id: int, user_id: int, group_id: int) -> bool:
        account = self.db.query(Account).filter(
            Account.id == account_id, Account.userId == user_id
        ).first()
        if not account:
            return False
        row = self.db.query(AccountToUserGroup).filter(
            AccountToUserGroup.accountId == account_id,
            AccountToUserGroup.userGroupId == group_id,
        ).first()
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True
