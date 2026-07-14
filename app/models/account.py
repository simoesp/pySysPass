"""
sysPass PHP-Compatible Database Models
Matches the exact table/column names, indexes, FKs and constraints
from the live MySQL schema.
"""
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, Integer,
    SmallInteger, String, Text, UniqueConstraint, event, func, select, text,
)
from sqlalchemy.orm import foreign, relationship
from sqlalchemy.dialects import mysql

from app.db.base import (
    Base,
    FlexibleBinary,
    mysql_integer,
    mysql_mediumint,
    mysql_smallint,
    mysql_tinyint,
)


def _utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Identity / access tables
# ---------------------------------------------------------------------------

class UserGroup(Base):
    __tablename__ = 'UserGroup'
    # DB: no UNIQUE on name, no extra indexes beyond PK

    id          = Column(mysql_smallint(), primary_key=True, autoincrement=True, nullable=True)
    name        = Column(String(50), nullable=False)
    description = Column(String(255), nullable=True)

    # -- Python-only helpers -------------------------------------------------
    @property
    def is_user_admin(self):        return False
    @property
    def isUserAdmin(self):          return getattr(self, "_isUserAdmin", False)
    @isUserAdmin.setter
    def isUserAdmin(self, value):   self._isUserAdmin = bool(value)
    @property
    def is_user_enabled(self):      return True
    @property
    def isUserEnabled(self):        return getattr(self, "_isUserEnabled", True)
    @isUserEnabled.setter
    def isUserEnabled(self, value): self._isUserEnabled = bool(value)
    @property
    def is_user_force_pwd_change(self): return False
    @property
    def isUserForcePwdChange(self): return getattr(self, "_isUserForcePwdChange", False)
    @isUserForcePwdChange.setter
    def isUserForcePwdChange(self, value): self._isUserForcePwdChange = bool(value)
    @property
    def date_create(self):          return None
    @property
    def date_update(self):          return None
    @property
    def dateCreate(self):           return None
    @property
    def dateUpdate(self):           return None

    # -- Relationships -------------------------------------------------------
    users               = relationship('User', back_populates='userGroup')
    accounts            = relationship('Account', back_populates='userGroup')
    itemPresets         = relationship('ItemPreset', back_populates='userGroup')
    accountToUserGroups = relationship('AccountToUserGroup', back_populates='userGroup')
    userToUserGroups    = relationship('UserToUserGroup', back_populates='userGroup')


class UserProfile(Base):
    __tablename__ = 'UserProfile'

    id      = Column(mysql_smallint(), primary_key=True, autoincrement=True, nullable=True)
    name    = Column(String(45), nullable=False)
    profile = Column(FlexibleBinary, nullable=False)   # blob NOT NULL

    # -- Python-only helpers -------------------------------------------------
    @property
    def user_id(self):   return None
    @property
    def created_at(self): return None
    @property
    def updated_at(self): return None

    # -- Relationships -------------------------------------------------------
    assignedUsers = relationship('User', back_populates='userProfile',
                                 foreign_keys='User.userProfileId')
    itemPresets   = relationship('ItemPreset', back_populates='userProfile')


class User(Base):
    __tablename__ = 'User'
    __table_args__ = (
        # UNIQUE KEY uk_User_01 (login, ssoLogin)
        UniqueConstraint('login', 'ssoLogin', name='uk_User_01'),
        # KEY idx_User_01 (pass)
        Index('idx_User_01', 'pass'),
        Index('fk_User_userGroupId', 'userGroupId'),
        Index('fk_User_userProfileId', 'userProfileId'),
    )

    id              = Column(mysql_smallint(), primary_key=True, autoincrement=True, nullable=True)
    name            = Column(String(80), nullable=True)
    userGroupId     = Column(mysql_smallint(), ForeignKey('UserGroup.id', name='fk_User_userGroupId'), nullable=False)
    username        = Column('login', String(50), nullable=False)
    ssoLogin        = Column(String(100), nullable=True)
    password        = Column('pass', FlexibleBinary(500, mysql_type=mysql.VARBINARY(500)), nullable=False)
    mPass           = Column(FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=True)
    mKey            = Column(FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=True)
    email           = Column(String(80), nullable=True)
    notes           = Column(Text, nullable=True)
    loginCount      = Column(mysql_integer(), default=0, server_default=text("0"), nullable=False)
    userProfileId   = Column(mysql_smallint(), ForeignKey('UserProfile.id', name='fk_User_userProfileId'), nullable=True)
    lastLogin       = Column(DateTime, nullable=True)
    lastUpdate      = Column(DateTime, nullable=True)
    lastUpdateMPass = Column(mysql_integer(width=11), default=0, server_default=text("0"), nullable=False)
    isAdminApp      = Column(Boolean, default=False, server_default=text("0"))
    isAdminAcc      = Column(Boolean, default=False, server_default=text("0"))
    isLdap          = Column(Boolean, default=False, server_default=text("0"))
    isDisabled      = Column(Boolean, default=False, server_default=text("0"))
    hashSalt        = Column(FlexibleBinary(255, mysql_type=mysql.VARBINARY(255)), nullable=True)
    isMigrate       = Column(Boolean, default=False, server_default=text("0"))
    isChangePass    = Column(Boolean, default=False, server_default=text("0"))
    isChangedPass   = Column(Boolean, default=False, server_default=text("0"))
    preferences     = Column(FlexibleBinary, nullable=True)

    # -- Python-only helpers -------------------------------------------------
    @property
    def is_admin(self):    return self.isAdminApp or self.isAdminAcc

    @property
    def isUserAdmin(self): return self.isAdminApp or self.isAdminAcc
    @isUserAdmin.setter
    def isUserAdmin(self, value):
        self.isAdminApp = value
        self.isAdminAcc = value

    @property
    def isUserEnabled(self): return not self.isDisabled
    @isUserEnabled.setter
    def isUserEnabled(self, value): self.isDisabled = not value

    @property
    def twoFactorAuth(self): return False
    @twoFactorAuth.setter
    def twoFactorAuth(self, value): pass

    @property
    def twoFactorSecret(self): return None
    @twoFactorSecret.setter
    def twoFactorSecret(self, value): pass

    @property
    def dateCreate(self):       return None
    @property
    def user_profile_id(self):  return self.userProfileId
    @property
    def two_factor_enabled(self): return False
    @property
    def created_at(self):       return None
    @property
    def is_active(self):        return not self.isDisabled

    # -- Relationships -------------------------------------------------------
    userGroup        = relationship('UserGroup', back_populates='users')
    userProfile      = relationship('UserProfile', back_populates='assignedUsers',
                                    foreign_keys=[userProfileId])
    accounts         = relationship('Account', back_populates='user',
                                    foreign_keys='Account.userId')
    accountsEdited   = relationship('Account', back_populates='userEdit',
                                    foreign_keys='Account.userEditId')
    authTokens       = relationship('AuthToken', back_populates='user')
    notifications    = relationship('Notification', back_populates='user')
    userToUserGroups = relationship('UserToUserGroup', back_populates='user')


@event.listens_for(User, 'before_insert')
def assign_user_id(mapper, connection, target):
    if target.id is None:
        max_id = connection.scalar(select(func.max(User.id)))
        target.id = (max_id or 0) + 1


@event.listens_for(UserGroup, 'before_insert')
def assign_user_group_id(mapper, connection, target):
    if target.id is None:
        max_id = connection.scalar(select(func.max(UserGroup.id)))
        target.id = (max_id or 0) + 1


# ---------------------------------------------------------------------------
# Reference / lookup tables
# ---------------------------------------------------------------------------

class Category(Base):
    __tablename__ = 'Category'
    __table_args__ = (UniqueConstraint('hash', name='uk_Category_01'),)

    id          = Column(mysql_mediumint(), primary_key=True, autoincrement=True)
    name        = Column(String(50), nullable=False)
    description = Column(String(255), nullable=True)
    hash        = Column(FlexibleBinary(40, mysql_type=mysql.VARBINARY(40)), nullable=False)

    # -- Python-only helpers -------------------------------------------------
    @property
    def icon(self):       return getattr(self, "_icon", "folder")
    @icon.setter
    def icon(self, value): self._icon = value
    @property
    def dateCreate(self): return None
    @property
    def dateUpdate(self): return None

    accounts = relationship('Account', back_populates='category')


class Client(Base):
    __tablename__ = 'Client'
    __table_args__ = (
        # KEY uk_Client_01 (hash)  — regular index (not UNIQUE in DB)
        Index('uk_Client_01', 'hash'),
    )

    id          = Column(mysql_mediumint(), primary_key=True, autoincrement=True)
    name        = Column(String(100), nullable=False)
    hash        = Column(FlexibleBinary(40, mysql_type=mysql.VARBINARY(40)), nullable=False)
    description = Column(String(255), nullable=True)
    isGlobal    = Column(Boolean, default=False, server_default=text("0"))

    # -- Python-only helpers -------------------------------------------------
    @property
    def contact(self): return getattr(self, "_contact", None)
    @contact.setter
    def contact(self, value): self._contact = value
    @property
    def notes(self):   return self.description
    @notes.setter
    def notes(self, value): self.description = value
    @property
    def dateCreate(self): return None
    @property
    def dateUpdate(self): return None

    accounts = relationship('Account', back_populates='client')


# ---------------------------------------------------------------------------
# Core account table
# ---------------------------------------------------------------------------

class Account(Base):
    __tablename__ = 'Account'
    __table_args__ = (
        Index('idx_Account_01', 'categoryId'),
        Index('idx_Account_02', 'userGroupId', 'userId'),
        Index('idx_Account_03', 'clientId'),
        Index('idx_Account_04', 'parentId'),
        Index('fk_Account_userId', 'userId'),
        Index('fk_Account_userEditId', 'userEditId'),
    )

    id               = Column(mysql_mediumint(), primary_key=True, autoincrement=True)
    userGroupId      = Column(mysql_smallint(), ForeignKey('UserGroup.id', name='fk_Account_userGroupId'), nullable=False)
    userId           = Column(mysql_smallint(), ForeignKey('User.id', name='fk_Account_userId'), nullable=False)
    userEditId       = Column(mysql_smallint(), ForeignKey('User.id', name='fk_Account_userEditId'), nullable=False)
    clientId         = Column(mysql_mediumint(), ForeignKey('Client.id', name='fk_Account_clientId'), nullable=True)
    name             = Column(String(100),    nullable=False)
    categoryId       = Column(mysql_mediumint(), ForeignKey('Category.id', name='fk_Account_categoryId'), nullable=True)
    login            = Column(String(50),     nullable=True)
    url              = Column(String(255),    nullable=True)
    pass_            = Column('pass', FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=False)
    key              = Column(FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=False)
    notes            = Column(Text,           nullable=True)
    countView        = Column(mysql_integer(), default=0, server_default=text("0"), nullable=False)
    countDecrypt     = Column(mysql_integer(), default=0, server_default=text("0"), nullable=False)
    dateAdd          = Column(DateTime,       default=_utc_now_naive, nullable=False)
    dateEdit         = Column(DateTime,       onupdate=_utc_now_naive, nullable=True)
    otherUserGroupEdit = Column(Boolean,      default=False, server_default=text("0"))
    otherUserEdit    = Column(Boolean,        default=False, server_default=text("0"))
    isPrivate        = Column(Boolean,        default=False, server_default=text("0"))
    isPrivateGroup   = Column(Boolean,        default=False, server_default=text("0"))
    passDate         = Column(mysql_integer(width=11), nullable=True)
    passDateChange   = Column(mysql_integer(width=11), nullable=True)
    parentId         = Column(mysql_mediumint(), nullable=True)   # self-ref, no FK in DB

    # -- Python-only helpers -------------------------------------------------
    @property
    def user_id(self):      return self.userId
    @property
    def category_id(self):  return self.categoryId
    @property
    def client_id(self):    return self.clientId
    @property
    def is_public(self):    return not self.isPrivate
    @is_public.setter
    def is_public(self, value): self.isPrivate = not value

    @property
    def is_favorite(self):  return getattr(self, '_is_favorite', False)
    @is_favorite.setter
    def is_favorite(self, value): self._is_favorite = value

    @property
    def created_at(self):  return self.dateAdd
    @property
    def updated_at(self):  return self.dateEdit
    @property
    def title(self):       return self.name
    @title.setter
    def title(self, value): self.name = value
    @property
    def description(self): return self.notes
    @description.setter
    def description(self, value): self.notes = value
    @property
    def password(self):    return self.pass_
    @password.setter
    def password(self, value): self.pass_ = value

    # -- Relationships -------------------------------------------------------
    userGroup         = relationship('UserGroup', back_populates='accounts')
    user              = relationship('User', back_populates='accounts',
                                     foreign_keys=[userId])
    userEdit          = relationship('User', back_populates='accountsEdited',
                                     foreign_keys=[userEditId])
    client            = relationship('Client', back_populates='accounts')
    category          = relationship('Category', back_populates='accounts')
    history           = relationship('AccountHistory', back_populates='account',
                                     primaryjoin=lambda: Account.id == foreign(AccountHistory.accountId),
                                     passive_deletes=True)
    files             = relationship('AccountFile', back_populates='account',
                                     passive_deletes=True)
    favorites         = relationship('AccountToFavorite', back_populates='account',
                                     passive_deletes=True)
    tags              = relationship('AccountToTag', back_populates='account',
                                     passive_deletes=True)
    sharedUsers       = relationship('AccountToUser', back_populates='account',
                                     passive_deletes=True)
    sharedUserGroups  = relationship('AccountToUserGroup', back_populates='account',
                                     passive_deletes=True)
    publicLinks       = relationship('PublicLink', back_populates='account',
                                     primaryjoin=lambda: Account.id == foreign(PublicLink.accountId),
                                     passive_deletes=True)


# ---------------------------------------------------------------------------
# Account history (no FK on accountId in live DB — kept for ORM navigation)
# ---------------------------------------------------------------------------

class AccountHistory(Base):
    __tablename__ = 'AccountHistory'
    __table_args__ = (
        Index('idx_AccountHistory_01', 'accountId'),
        Index('idx_AccountHistory_02', 'parentId'),
        Index('fk_AccountHistory_userGroupId', 'userGroupId'),
        Index('fk_AccountHistory_userId', 'userId'),
        Index('fk_AccountHistory_userEditId', 'userEditId'),
        Index('fk_AccountHistory_clientId', 'clientId'),
        Index('fk_AccountHistory_categoryId', 'categoryId'),
    )

    id               = Column(mysql_integer(width=11, unsigned=False), primary_key=True, autoincrement=True)
    accountId        = Column(mysql_mediumint(), nullable=False)
    userGroupId      = Column(mysql_smallint(), ForeignKey('UserGroup.id', name='fk_AccountHistory_userGroupId'), nullable=False)
    userId           = Column(mysql_smallint(), ForeignKey('User.id', name='fk_AccountHistory_userId'), nullable=False)
    userEditId       = Column(mysql_smallint(), ForeignKey('User.id', name='fk_AccountHistory_userEditId'), nullable=False)
    clientId         = Column(mysql_mediumint(), ForeignKey('Client.id', name='fk_AccountHistory_clientId'), nullable=True)
    name             = Column(String(255),  nullable=False)
    categoryId       = Column(mysql_mediumint(), ForeignKey('Category.id', name='fk_AccountHistory_categoryId'), nullable=True)
    login            = Column(String(50),   nullable=True)
    url              = Column(String(255),  nullable=True)
    pass_            = Column('pass', FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=False)
    key              = Column(FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=False)
    notes            = Column(Text,         nullable=False)
    countView        = Column(mysql_integer(), default=0, server_default=text("0"), nullable=False)
    countDecrypt     = Column(mysql_integer(), default=0, server_default=text("0"), nullable=False)
    dateAdd          = Column(DateTime,     default=_utc_now_naive, nullable=False)
    dateEdit         = Column(DateTime,     nullable=True)
    isModify         = Column(Boolean,      default=False, server_default=text("0"))
    isDeleted        = Column(Boolean,      default=False, server_default=text("0"))
    mPassHash        = Column(FlexibleBinary(255, mysql_type=mysql.VARBINARY(255)), nullable=False)
    otherUserEdit    = Column(Boolean,      default=False, server_default=text("0"))
    otherUserGroupEdit = Column(Boolean,    default=False, server_default=text("0"))
    passDate         = Column(mysql_integer(), nullable=True)
    passDateChange   = Column(mysql_integer(), nullable=True)
    parentId         = Column(mysql_mediumint(), nullable=True)
    isPrivate        = Column(Boolean,      default=False, server_default=text("0"))
    isPrivateGroup   = Column(Boolean,      default=False, server_default=text("0"))

    # -- Python-only helpers -------------------------------------------------
    @property
    def account_id(self): return self.accountId
    @property
    def user_id(self):    return self.userId
    @property
    def date_add(self):   return self.dateEdit or self.dateAdd
    @property
    def action(self):
        if self.isDeleted:
            return 'delete'
        if self.isModify:
            return 'update'
        return 'snapshot'
    @property
    def old_value(self): return None
    @property
    def new_value(self): return None

    account = relationship(
        'Account',
        back_populates='history',
        primaryjoin=lambda: Account.id == foreign(AccountHistory.accountId),
    )


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

class Tag(Base):
    __tablename__ = 'Tag'
    __table_args__ = (
        UniqueConstraint('hash', name='uk_Tag_01'),
        Index('idx_Tag_01', 'name'),
    )

    id   = Column(mysql_integer(), primary_key=True, autoincrement=True)
    name = Column(String(45),    nullable=False)
    hash = Column(FlexibleBinary(40, mysql_type=mysql.VARBINARY(40)), nullable=False)

    # -- Python-only helpers -------------------------------------------------
    @property
    def color(self):    return getattr(self, "_color", "#000000")
    @color.setter
    def color(self, value): self._color = value
    @property
    def user_id(self):  return None
    @property
    def userId(self): return getattr(self, "_user_id", None)
    @userId.setter
    def userId(self, value): self._user_id = value
    created_at = None

    accounts = relationship('AccountToTag', back_populates='tag')


# ---------------------------------------------------------------------------
# Association / join tables
# ---------------------------------------------------------------------------

class AccountToTag(Base):
    __tablename__ = 'AccountToTag'
    __table_args__ = (
        Index('fk_AccountToTag_accountId', 'accountId'),
        Index('fk_AccountToTag_tagId', 'tagId'),
    )

    accountId = Column(mysql_mediumint(), ForeignKey('Account.id',
                       name='fk_AccountToTag_accountId', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    tagId     = Column(mysql_integer(), ForeignKey('Tag.id',
                       name='fk_AccountToTag_tagId', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)

    account = relationship('Account', back_populates='tags')
    tag     = relationship('Tag', back_populates='accounts')


class AccountToFavorite(Base):
    __tablename__ = 'AccountToFavorite'
    __table_args__ = (
        Index('idx_AccountToFavorite_01', 'accountId', 'userId'),
        Index('fk_AccountToFavorite_userId', 'userId'),
    )

    accountId = Column(mysql_mediumint(), ForeignKey('Account.id',
                       name='fk_AccountToFavorite_accountId', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    userId    = Column(mysql_smallint(), ForeignKey('User.id',
                       name='fk_AccountToFavorite_userId', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)

    account = relationship('Account', back_populates='favorites')


class AccountToUser(Base):
    __tablename__ = 'AccountToUser'
    __table_args__ = (
        Index('idx_AccountToUser_01', 'accountId'),
        Index('fk_AccountToUser_userId', 'userId'),
    )

    accountId = Column(mysql_mediumint(), ForeignKey('Account.id',
                       name='fk_AccountToUser_accountId', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    userId    = Column(mysql_smallint(), ForeignKey('User.id',
                       name='fk_AccountToUser_userId', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    isEdit    = Column(mysql_tinyint(), default=0, server_default=text("0"))

    @property
    def date_add(self):
        return None

    account = relationship('Account', back_populates='sharedUsers')


class AccountToUserGroup(Base):
    __tablename__ = 'AccountToUserGroup'
    __table_args__ = (
        Index('idx_AccountToUserGroup_01', 'accountId'),
        Index('fk_AccountToUserGroup_userGroupId', 'userGroupId'),
    )

    accountId    = Column(mysql_mediumint(), ForeignKey('Account.id',
                          name='fk_AccountToUserGroup_accountId', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    userGroupId  = Column(mysql_smallint(), ForeignKey('UserGroup.id',
                          name='fk_AccountToUserGroup_userGroupId', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    isEdit       = Column(mysql_tinyint(), default=0, server_default=text("0"))

    @property
    def date_add(self):
        return None

    account   = relationship('Account', back_populates='sharedUserGroups')
    userGroup = relationship('UserGroup', back_populates='accountToUserGroups')


class UserToUserGroup(Base):
    __tablename__ = 'UserToUserGroup'
    __table_args__ = (
        UniqueConstraint('userId', 'userGroupId', name='uk_UserToUserGroup_01'),
        Index('idx_UserToUserGroup_01', 'userId'),
        Index('fk_UserToGroup_userGroupId', 'userGroupId'),
    )

    userId      = Column(mysql_smallint(), ForeignKey('User.id', name='fk_UserToGroup_userId',
                         ondelete='CASCADE', onupdate='CASCADE'), nullable=False)
    userGroupId = Column(mysql_smallint(), ForeignKey('UserGroup.id', name='fk_UserToGroup_userGroupId',
                         ondelete='CASCADE', onupdate='CASCADE'), nullable=False)
    __mapper_args__ = {"primary_key": [userId, userGroupId]}

    # -- Python-only helpers -------------------------------------------------
    def __init__(self, **kwargs):
        # Legacy PHP schema does not include isManager on UserToUserGroup.
        kwargs.pop('isManager', None)
        super().__init__(**kwargs)

    @property
    def isManager(self): return False
    @isManager.setter
    def isManager(self, value): pass

    user      = relationship('User', back_populates='userToUserGroups')
    userGroup = relationship('UserGroup', back_populates='userToUserGroups')


# ---------------------------------------------------------------------------
# API tokens
# ---------------------------------------------------------------------------

class AuthToken(Base):
    __tablename__ = 'AuthToken'
    __table_args__ = (
        UniqueConstraint('token', 'actionId', name='uk_AuthToken_01'),
        Index('idx_AuthToken_01', 'userId', 'actionId', 'token'),
        Index('fk_AuthToken_actionId', 'actionId'),
    )

    id        = Column(mysql_integer(width=11, unsigned=False), primary_key=True, autoincrement=True)
    userId    = Column(mysql_smallint(), ForeignKey('User.id', name='fk_AuthToken_userId',
                       ondelete='CASCADE', onupdate='CASCADE'), nullable=False)
    token     = Column(FlexibleBinary(255, mysql_type=mysql.VARBINARY(255)), nullable=False)
    actionId  = Column(mysql_smallint(), nullable=False)   # no FK in DB
    createdBy = Column(mysql_smallint(), nullable=False)
    startDate = Column(mysql_integer(), nullable=False)
    vault     = Column(FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=True)
    hash      = Column(FlexibleBinary(500, mysql_type=mysql.VARBINARY(500)), nullable=True)

    user = relationship('User', back_populates='authTokens')


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

class Notification(Base):
    __tablename__ = 'Notification'
    __table_args__ = (
        Index('idx_Notification_01', 'userId', 'checked', 'date'),
        Index('idx_Notification_02', 'component', 'date', 'checked', 'userId'),
        Index('fk_Notification_userId', 'userId'),
    )

    id          = Column(mysql_integer(), primary_key=True, autoincrement=True)
    type        = Column(String(100), nullable=True)
    component   = Column(String(100), nullable=False)
    description = Column(Text,        nullable=False)
    date        = Column(mysql_integer(), nullable=False)
    checked     = Column(Boolean,     default=False, server_default=text("0"))
    userId      = Column(mysql_smallint(), ForeignKey('User.id', name='fk_Notification_userId'), nullable=True)
    sticky      = Column(Boolean,     default=False, server_default=text("0"))
    onlyAdmin   = Column(Boolean,     default=False, server_default=text("0"))

    # -- Python-only helpers -------------------------------------------------
    @property
    def message(self): return self.description
    @message.setter
    def message(self, value): self.description = value
    @property
    def user_id(self):  return self.userId
    @property
    def is_read(self):  return self.checked
    @property
    def isRead(self): return self.checked
    @isRead.setter
    def isRead(self, value): self.checked = bool(value)
    @property
    def date_add(self): return self.date

    user = relationship('User', back_populates='notifications')


# ---------------------------------------------------------------------------
# Public / shared links
# ---------------------------------------------------------------------------

class PublicLink(Base):
    __tablename__ = 'PublicLink'
    __table_args__ = (
        UniqueConstraint('hash',   name='uk_PublicLink_01'),
        UniqueConstraint('itemId', name='uk_PublicLink_02'),
        Index('fk_PublicLink_userId', 'userId'),
    )

    id              = Column(mysql_integer(), primary_key=True, autoincrement=True)
    accountId       = Column('itemId', mysql_integer(), nullable=False)
    hash            = Column(FlexibleBinary(100, mysql_type=mysql.VARBINARY(100)), nullable=False)
    data            = Column(FlexibleBinary(mysql_type=mysql.MEDIUMBLOB()), nullable=True)
    userId          = Column(mysql_smallint(), ForeignKey('User.id', name='fk_PublicLink_userId'), nullable=False)
    typeId          = Column(mysql_integer(), nullable=False)
    notify          = Column(Boolean,      default=False, server_default=text("0"))
    dateAdd         = Column(mysql_integer(), nullable=False)
    dateExpire      = Column(mysql_integer(), nullable=False)
    dateUpdate      = Column(mysql_integer(), default=0, server_default=text("0"), nullable=True)
    countViews      = Column(mysql_smallint(), default=0, server_default=text("0"))
    totalCountViews = Column(mysql_mediumint(), default=0, server_default=text("0"))
    maxCountViews   = Column(mysql_smallint(), default=0, server_default=text("0"), nullable=False)
    useinfo         = Column(FlexibleBinary,  nullable=True)

    # -- Python-only helpers -------------------------------------------------
    @property
    def account_id(self): return self.accountId
    @property
    def date_add(self):   return self.dateAdd
    @property
    def expire(self):
        if self.dateAdd is None or self.dateExpire is None:
            return None
        return max(int(self.dateExpire) - int(self.dateAdd), 0)
    @expire.setter
    def expire(self, value): self.dateExpire = value
    @property
    def password(self):   return self.data
    @password.setter
    def password(self, value): self.data = value
    @property
    def has_password(self): return self.data is not None

    account = relationship(
        'Account',
        back_populates='publicLinks',
        primaryjoin=lambda: Account.id == foreign(PublicLink.accountId),
    )


# ---------------------------------------------------------------------------
# Item presets
# ---------------------------------------------------------------------------

class ItemPreset(Base):
    __tablename__ = 'ItemPreset'
    __table_args__ = (
        UniqueConstraint('hash', name='uk_ItemPreset_01'),
    )

    id            = Column(Integer,      primary_key=True, autoincrement=True)
    type          = Column(String(25),   nullable=False)
    userId        = Column(mysql_smallint(), ForeignKey('User.id', name='fk_ItemPreset_userId',
                           ondelete='CASCADE', onupdate='CASCADE'), nullable=True)
    userGroupId   = Column(mysql_smallint(), ForeignKey('UserGroup.id', name='fk_ItemPreset_userGroupId',
                           ondelete='CASCADE', onupdate='CASCADE'), nullable=True)
    userProfileId = Column(mysql_smallint(), ForeignKey('UserProfile.id', name='fk_ItemPreset_userProfileId',
                           ondelete='CASCADE', onupdate='CASCADE'), nullable=True)
    fixed         = Column(mysql_tinyint(), default=0, server_default=text("0"), nullable=False)
    priority      = Column(mysql_tinyint(width=3), default=0, server_default=text("0"), nullable=False)
    data          = Column(FlexibleBinary,  nullable=True)
    hash          = Column(FlexibleBinary(40, mysql_type=mysql.VARBINARY(40)), nullable=False)

    userGroup   = relationship('UserGroup',   back_populates='itemPresets')
    userProfile = relationship('UserProfile', back_populates='itemPresets')


# ---------------------------------------------------------------------------
# Account files
# ---------------------------------------------------------------------------

class AccountFile(Base):
    __tablename__ = 'AccountFile'
    __table_args__ = (
        Index('idx_AccountFile_01', 'accountId'),
    )

    id        = Column(mysql_integer(width=11, unsigned=False), primary_key=True, autoincrement=True)
    accountId = Column(mysql_mediumint(width=5), ForeignKey('Account.id', name='fk_AccountFile_accountId',
                       ondelete='CASCADE', onupdate='CASCADE'), nullable=False)
    name      = Column(String(100), nullable=False)
    type      = Column(String(100), nullable=False)
    size      = Column(mysql_integer(width=11, unsigned=False), nullable=False)
    content   = Column(FlexibleBinary(mysql_type=mysql.MEDIUMBLOB()), nullable=False)
    extension = Column(String(10),  nullable=False)
    thumb     = Column(FlexibleBinary(mysql_type=mysql.MEDIUMBLOB()), nullable=True)

    # -- Python-only helpers -------------------------------------------------
    @property
    def account_id(self): return self.accountId
    @property
    def date_add(self):   return None

    account = relationship('Account', back_populates='files')


# ---------------------------------------------------------------------------
# Security & recovery
# ---------------------------------------------------------------------------

class UserPassRecover(Base):
    __tablename__ = 'UserPassRecover'
    __table_args__ = (
        Index('idx_UserPassRecover_01', 'userId', 'date'),
    )

    id     = Column(mysql_integer(), primary_key=True, autoincrement=True)
    userId = Column(mysql_smallint(), ForeignKey('User.id', name='fk_UserPassRecover_userId',
                   ondelete='CASCADE', onupdate='CASCADE'), nullable=False)
    hash   = Column(FlexibleBinary(255, mysql_type=mysql.VARBINARY(255)), nullable=False)
    date   = Column(mysql_integer(), nullable=False)
    used   = Column(Boolean,      default=False, server_default=text("0"))


class EventLog(Base):
    __tablename__ = 'EventLog'

    id          = Column(mysql_integer(), primary_key=True, autoincrement=True)
    date        = Column(mysql_integer(), nullable=False)
    login       = Column(String(25), nullable=True)
    userId      = Column(mysql_smallint(), nullable=True)     # no FK in DB
    ipAddress   = Column(String(45), nullable=False)
    action      = Column(String(50), nullable=False)
    description = Column(Text,       nullable=True)
    level       = Column(String(20), nullable=False)


class Track(Base):
    """Login-attempt tracking (brute-force protection)."""
    __tablename__ = 'Track'
    __table_args__ = (
        Index('idx_Track_01', 'userId'),
        Index('idx_Track_02', 'time', 'ipv4', 'ipv6', 'source'),
    )

    id         = Column(mysql_integer(), primary_key=True, autoincrement=True)
    userId     = Column(mysql_smallint(), nullable=True)   # no FK CONSTRAINT in DB
    source     = Column(String(100),  nullable=False)
    time       = Column(mysql_integer(), nullable=False)
    timeUnlock = Column(mysql_integer(), nullable=True)
    ipv4       = Column(FlexibleBinary(4, mysql_type=mysql.BINARY(4)), nullable=True)
    ipv6       = Column(FlexibleBinary(16, mysql_type=mysql.BINARY(16)), nullable=True)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config(Base):
    __tablename__ = 'Config'

    parameter = Column(String(50),   primary_key=True)
    value     = Column(String(4000), nullable=True)


# ---------------------------------------------------------------------------
# Plugin system
# ---------------------------------------------------------------------------

class Plugin(Base):
    __tablename__ = 'Plugin'
    __table_args__ = (
        UniqueConstraint('name', name='uk_Plugin_01'),
    )

    id           = Column(mysql_integer(), primary_key=True, autoincrement=True)
    name         = Column(String(100), nullable=False)
    data         = Column(FlexibleBinary(mysql_type=mysql.MEDIUMBLOB()), nullable=True)
    enabled      = Column(Boolean,   default=False, server_default=text("0"), nullable=False)
    available    = Column(Boolean,   default=False, server_default=text("0"))
    versionLevel = Column(String(15), nullable=True)

    pluginData = relationship('PluginData', back_populates='plugin',
                              foreign_keys='PluginData.name',
                              primaryjoin='Plugin.name == PluginData.name')


class PluginData(Base):
    __tablename__ = 'PluginData'

    name   = Column(String(100), ForeignKey('Plugin.name', name='fk_PluginData_name',
                   ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    itemId = Column(Integer,     primary_key=True)
    data   = Column(FlexibleBinary, nullable=False)
    key    = Column(FlexibleBinary(2000, mysql_type=mysql.VARBINARY(2000)), nullable=False)

    plugin = relationship('Plugin', back_populates='pluginData', foreign_keys=[name])


# ---------------------------------------------------------------------------
# SQL views
# ---------------------------------------------------------------------------

class AccountDataView(Base):
    """Read-only mapping for the legacy account_data_v view."""
    __tablename__ = 'account_data_v'
    __table_args__ = {"info": {"is_view": True}}

    id                 = Column(Integer, primary_key=True)
    name               = Column(String(100), nullable=True)
    categoryId         = Column(Integer, nullable=True)
    userId             = Column(SmallInteger, nullable=True)
    clientId           = Column(Integer, nullable=True)
    userGroupId        = Column(SmallInteger, nullable=True)
    userEditId         = Column(SmallInteger, nullable=True)
    login              = Column(String(50), nullable=True)
    url                = Column(String(255), nullable=True)
    notes              = Column(Text, nullable=True)
    countView          = Column(Integer, nullable=True)
    countDecrypt       = Column(Integer, nullable=True)
    dateAdd            = Column(DateTime, nullable=True)
    dateEdit           = Column(DateTime, nullable=True)
    # MySQL's CONV() in the view turns these into strings.
    otherUserEdit      = Column(String(10), nullable=True)
    otherUserGroupEdit = Column(String(10), nullable=True)
    isPrivate          = Column(String(10), nullable=True)
    isPrivateGroup     = Column(String(10), nullable=True)
    passDate           = Column(Integer, nullable=True)
    passDateChange     = Column(Integer, nullable=True)
    parentId           = Column(Integer, nullable=True)
    categoryName       = Column(String(50), nullable=True)
    clientName         = Column(String(100), nullable=True)
    userGroupName      = Column(String(50), nullable=True)
    userName           = Column(String(80), nullable=True)
    userLogin          = Column(String(50), nullable=True)
    userEditName       = Column(String(80), nullable=True)
    userEditLogin      = Column(String(50), nullable=True)
    publicLinkHash     = Column(FlexibleBinary(100), nullable=True)


class AccountSearchView(Base):
    """Read-only mapping for the legacy account_search_v view."""
    __tablename__ = 'account_search_v'
    __table_args__ = {"info": {"is_view": True}}

    id                        = Column(Integer, primary_key=True)
    clientId                  = Column(Integer, nullable=True)
    categoryId                = Column(Integer, nullable=True)
    name                      = Column(String(100), nullable=True)
    login                     = Column(String(50), nullable=True)
    url                       = Column(String(255), nullable=True)
    notes                     = Column(Text, nullable=True)
    userId                    = Column(SmallInteger, nullable=True)
    userGroupId               = Column(SmallInteger, nullable=True)
    otherUserEdit             = Column(Boolean, nullable=True)
    otherUserGroupEdit        = Column(Boolean, nullable=True)
    isPrivate                 = Column(Boolean, nullable=True)
    isPrivateGroup            = Column(Boolean, nullable=True)
    passDate                  = Column(Integer, nullable=True)
    passDateChange            = Column(Integer, nullable=True)
    parentId                  = Column(Integer, nullable=True)
    countView                 = Column(Integer, nullable=True)
    dateEdit                  = Column(DateTime, nullable=True)
    userName                  = Column(String(80), nullable=True)
    userLogin                 = Column(String(50), nullable=True)
    userGroupName             = Column(String(50), nullable=True)
    categoryName              = Column(String(50), nullable=True)
    clientName                = Column(String(100), nullable=True)
    num_files                 = Column(Integer, nullable=True)
    publicLinkHash            = Column(FlexibleBinary(100), nullable=True)
    publicLinkDateExpire      = Column(Integer, nullable=True)
    publicLinkTotalCountViews = Column(Integer, nullable=True)
