"""
sysPass PHP ↔ Python column name reference.

The canonical SQLAlchemy models live in:
  app/models/account.py    — all core tables
  app/models/custom_field.py — CustomFieldType / CustomFieldDefinition / CustomFieldData

PHP column name → Python model attribute
───────────────────────────────────────────────────────────────────────────────
Account / AccountHistory
  pass         → pass_          (renamed: 'pass' is a Python keyword)
  dateAdd      → dateAdd        / alias: created_at
  dateEdit     → dateEdit       / alias: updated_at
  isPrivate    → isPrivate      / inverse alias: is_public

User
  login        → username       (Column alias)
  pass         → password       (Column alias)
  mPass        → mPass          (master password, AES-CTR encrypted)
  mKey         → mKey           (master key)
  hashSalt     → hashSalt       (bcrypt salt / legacy)
  isAdminApp   → isAdminApp     / composite alias: isUserAdmin / is_admin
  isAdminAcc   → isAdminAcc
  isDisabled   → isDisabled     / inverse alias: isUserEnabled / is_active

PublicLink
  itemId       → accountId      (Column alias via Column('itemId', ...))

UserProfile
  profile      → profile        (blob: PHP-serialized ProfileData object)
                                 decoded by user_profile_service._decode_permissions()

───────────────────────────────────────────────────────────────────────────────
Schema notes (live DB vs. model)
───────────────────────────────────────────────────────────────────────────────
UserGroup.name      — NOT unique in DB (no UNIQUE KEY); model removed unique=True
UserProfile.profile — blob NOT NULL in DB; model is nullable=False
User                — UNIQUE KEY uk_User_01 (login, ssoLogin) composite;
                      model uses UniqueConstraint instead of unique=True on login
AccountHistory.accountId — KEY only, no FK CONSTRAINT in DB;
                      FK kept in model for ORM navigation only
Track.userId        — no FK CONSTRAINT in DB; no ForeignKey in model
ItemPreset.hash     — varbinary(40) in DB; model uses LargeBinary(40)
AuthToken           — UNIQUE KEY uk_AuthToken_01 (token, actionId) added
PublicLink          — UNIQUE KEY uk_PublicLink_02 (itemId) added
Client.hash         — regular KEY (not UNIQUE) in DB; model uses Index only
All ON DELETE CASCADE — matched with ON UPDATE CASCADE where DB specifies both

───────────────────────────────────────────────────────────────────────────────
Tables modeled
───────────────────────────────────────────────────────────────────────────────
account.py:
  UserGroup, UserProfile, User,
  Category, Client,
  Account, AccountHistory,
  Tag, AccountToTag, AccountToFavorite, AccountToUser, AccountToUserGroup,
  UserToUserGroup,
  AuthToken, Notification, PublicLink, ItemPreset, AccountFile,
  UserPassRecover, EventLog, Track,
  Config, Plugin, PluginData

custom_field.py:
  CustomFieldType, CustomFieldDef (→ CustomFieldDefinition),
  CustomFieldValue (→ CustomFieldData)

Views (modeled as read-only ORM tables):
  account_data_v, account_search_v
"""
