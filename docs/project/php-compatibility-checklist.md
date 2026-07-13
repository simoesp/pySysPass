# sysPass PHP Compatibility Checklist

This project aims to be fully compatible with the original sysPass PHP
application. That means matching not only features, but also schema behavior,
legacy data handling, encryption semantics, and operational expectations.

## Compatibility Standard

Compatibility should be treated as successful only when:

- A database created by sysPass PHP can be opened by `pySysPass` without manual data fixes.
- Passwords, master-password data, user profiles, shares, links, logs, and attachments created by PHP remain readable and semantically unchanged.
- Exports and imports preserve the same meaning as the PHP version.
- Python-only API or schema extensions do not require changes to a PHP-owned database.

## Current Guardrails In This Repo

- PHP schema mapping: `app/models/account.py`, `app/models/php_compatibility.py`
- PHP-compatible encryption helpers: `app/core/defuse_compat.py`
- Legacy runtime config loading: `app/core/syspass_runtime_config.py`
- PHP profile parsing: `app/services/user_profile_service.py`
- XML import/export support: `app/services/import_export_service.py`

## Remaining Parity Checklist

### 1. Database Schema Parity

- ✅ Table names, column names, and nullability are checked automatically against
  the upstream PHP schema snapshot by `tests/compatibility/test_schema_parity.py`;
  existing exceptions are explicit and no new drift can be introduced silently.
- ✅ Vendored schema files are checked against `../phpSysPass/schemas/` when the
  upstream checkout is available beside this repository.
- ✅ Scalar defaults are checked against the upstream schema with no exceptions.
- ✅ Every mapped column now emits the PHP-compatible MySQL type, display width,
  unsigned flag, binary width, and blob class while retaining SQLite-compatible
  generic types; the audited type-drift baseline is empty.
- ✅ Primary, unique, and ordinary index definitions and names match PHP; the
  audited index-drift baseline is empty.
- ✅ Foreign-key names, columns, targets, and update/delete actions match PHP;
  the audited FK-drift baseline is empty.
- ✅ The ORM-only `AccountHistory.accountId` and `PublicLink.itemId` foreign keys
  were replaced by explicit relationship joins without changing PHP metadata.
- ✅ `UserToUserGroup` retains ORM identity through mapper configuration without
  inventing a primary key absent from the PHP table.
- ✅ `AUTO_INCREMENT` behavior is checked against SQLAlchemy metadata.
- ✅ Alembic revision `001` delegates to the canonical PHP schema snapshot
  instead of maintaining a divergent hand-written table definition.
- ✅ Compatibility tests prevent the initial migration from reintroducing
  hand-written `op.create_table` definitions and verify full table coverage.
- ✅ Alembic downgrade drops tables in reverse dependency order and is tested
  against every foreign-key reference in the canonical schema.
- ✅ Every physical SQLAlchemy table emits `ENGINE=InnoDB`, `CHARSET=utf8`, and
  `COLLATE utf8_unicode_ci`, matching the canonical PHP schema; mapped views are
  explicitly excluded from physical table options.
- Compare `account_data_v` and `account_search_v` definitions with upstream PHP.
- Create both PHP views during bootstrap/migration; test fixtures now exclude
  mapped views from `create_all` so they cannot silently become ordinary tables.
- Remove or isolate Python-only behavior that implies extra persisted fields not present in PHP tables.
- Replace the explicit compatibility exception for Python-only
  `AccountHistory.action`, `oldValue`, and `newValue` fields with non-persisted
  or PHP-compatible behavior.
- Remove the explicit nullability exceptions after account creation and test
  fixtures always supply the PHP-required user profile, hash, client, and
  category values.

### 2. Encryption And Secret Handling

- ✅ The offline sysPass 3.2.11 fixture verifies PHP-created login/master bcrypt
  hashes, decrypts PHP-created `User.mPass`/`User.mKey`, and decrypts a password
  written by PHP's `account/saveCreate` endpoint from `Account.pass`/`Account.key`.
- Add the reverse round trip: verify Python-produced encrypted values with PHP.
- Confirm temporary master password and password-reset flows do not diverge from PHP semantics where shared data is involved.

### 3. Auth, Permissions, And Profiles

- ✅ The real 815-byte PHP-serialized profile fixture parses all 30 permission
  flags without requiring a PHP runtime.
- ✅ JWTs and server dependencies preserve PHP's distinct `isAdminApp` and
  `isAdminAcc` scopes; account administrators no longer inherit application
  configuration privileges from a composite admin flag.
- ✅ Account and sharing routes enforce PHP's separate view, create, edit,
  password, delete, private-account, and permission-management capabilities.
- ✅ A live PHP-authored ACL corpus (100 bulk accounts, 10 non-admin users,
  five teams, and four profiles) was exercised through both PHP's web search
  and the pySysPass ACL. The comparison exposed and fixed a secondary-group
  share leak: `AccountToUserGroup` shares now apply to the primary group unless
  PHP's `accountFullGroupAccess` option is enabled, while secondary main-group
  visibility remains intact. All ten users now match PHP's recorded account
  IDs, with no missing or extra rows.
- ✅ The minimized offline ACL fixture records the PHP-visible IDs and only the
  ACL-relevant rows for all 100 accounts and ten users. CI reconstructs the
  corpus without MySQL or secret payloads and checks both the secure default
  and PHP's optional full-group-access behavior.
- Confirm user-group membership behavior matches PHP tables exactly.
- Compare admin, account-admin, disabled-user, and forced-password-change behavior with upstream sysPass flows.

### 4. Account And Sharing Behavior

- ✅ Main account-group members receive edit access as PHP's
  `AccountAclService` specifies. Explicit group shares retain their own
  `isEdit` decision and apply to secondary memberships only when
  `accountFullGroupAccess` is enabled; legacy `otherUser*` metadata does not
  override those decisions.
- ✅ A PHP-authored custom-field corpus covers 100 accounts with eight field
  types and 800 values. Custom-field value routes now inherit the parent
  account's profile and object ACL instead of exposing arbitrary item IDs to
  any authenticated user; category, client, user, and group values require the
  corresponding management capability.
- Validate account CRUD, history, favorites, tags, files, public links, and sharing against PHP-created records.
- Apply the same profile-plus-resource ACL composition to account history,
  files, and public links; these routes still use narrower owner-only checks.
- Match PHP account-admin global account visibility while retaining its private
  and private-group filters.
- Verify PHP application-layer behavior when deleting an account with a public
  link. `PublicLink.itemId` intentionally has no FK cascade, so Python must not
  leave an orphaned encrypted link servable unless PHP does the same.
- Extend the PHP-authored ACL fixture with mutation checks for creating,
  changing, and revoking user and group shares in both applications.
- Confirm counters and audit side effects match PHP expectations where the same tables are reused.

### 5. Import/Export Parity

- ✅ A real password-protected sysPass PHP 3.2.11 export was parsed by
  pySysPass. All 107 accounts and their ID-based category, client, and tag
  references were recovered, and an account password encrypted by PHP was
  decrypted successfully after the outer export layer was removed.
- ✅ Clean-database restores create PHP-compatible SHA-1 `hash` values for new
  categories, clients, and tags; the regression test removes every exported
  lookup row before import so this required creation path cannot be bypassed.
- ✅ Python now emits the native `Root`/`Meta`/section layout, preserves native
  account `pass`/`key` ciphertext, and uses PHP-compatible Defuse encryption for
  protected exports. PHP's own DOM/Defuse runtime verified a Python export's
  SHA-1/HMAC integrity fields and decrypted all four sections.
- Importing a complete Python-generated export through the PHP UI remains an
  open mutation test; run it against an isolated database before calling the
  reverse application-level round trip complete.
- Add fixture-based checks for KeePass and CSV mappings where compatibility claims are made.

### 6. Runtime Configuration Compatibility

- Verify JSON runtime config, legacy `config.xml`, and cache fallbacks resolve values the same way PHP expects.
- Add tests for mixed environments where both modern JSON config and legacy PHP config artifacts exist.

### 7. Operational Compatibility

- ✅ A disposable virgin MySQL 8 instance was validated through canonical
  bootstrap (including idempotence), Alembic upgrade/downgrade, and direct
  SQLAlchemy metadata creation; all 27 physical tables used InnoDB and the PHP
  `utf8`/`utf8_unicode_ci` settings (reported by MySQL 8 as `utf8mb3_unicode_ci`).
- ✅ A live sysPass PHP 3.2.11 initialization was opened read-only through the
  pySysPass ORM. Its 27 physical tables matched the canonical schema
  semantically, PHP created both expected views, and the ORM loaded the native
  admin row, `$2y$` password hash, Defuse `mPass`/`mKey` payloads, and runtime
  configuration without data fixes.
- Add upgrade-path tests for partially initialized or migrated databases.
- Confirm reverse-proxy, LDAP, notifications, and backup flows do not require Python-only database changes.

### 8. Compatibility CI

- ✅ A dedicated `php-compatibility` quality job runs schema parity checks.
- ✅ Ordinary unit tests and focused parity tests are reported as separate jobs.
- ✅ PHP-authored encryption and serialized-profile fixtures run in the existing
  compatibility test job without a live PHP or MySQL service.
- Add fixture-based group permissions and import/export checks to the
  compatibility job.
- Fail CI on schema drift and compatibility regressions.

## Immediate Priorities

1. Keep the database/API surface aligned with PHP-owned schema.
2. Add PHP-authored sharing fixtures and export samples to the test suite.
3. Build a parity matrix covering schema, encryption, permissions, and import/export.
