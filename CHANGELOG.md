# Changelog

All notable changes to pySysPass are documented here. Versions follow
[Semantic Versioning](https://semver.org/). Dates are ISO 8601.

## [Unreleased]

Production-readiness hardening (draft PR #66). Not yet released; several
changes alter behaviour for existing deployments, listed under **Upgrade notes**.
Evidence for each item: `docs/project/production-readiness-review-2026-10-23.md`.

### Upgrade notes
- The backend image runs as UID 10001. Volumes written by earlier (root) images
  need a one-time `chown -R 10001:10001` (see `docs/installation.md`); until
  then `/health/ready` reports `data directory not writable`.
- Sessions now expire after `session_timeout` of inactivity (default 300 s)
  instead of 24 hours. Tokens issued by earlier releases are rejected once;
  users sign in again.
- Account passwords, imports and public links can only be written with an
  unlocked vault (`428 MASTER_PASSWORD_REQUIRED` otherwise); API tokens can no
  longer create accounts or change their passwords.
- New public links cannot have an access password (sysPass PHP has none) and
  require `publinks_enabled`. Existing links keep working.
- Accounts require `client_id` and `category_id`. CSV/XML import rows without
  both are skipped. In-use clients and categories cannot be deleted (409).
- After a master password change made in sysPass PHP, users must re-enter the
  master password at their next sign-in, as in PHP.
- 2FA is stored in the sysPass Authenticator plugin's format, under the vault
  master password; changing 2FA settings requires an unlocked vault. Users
  enrolled by earlier pySysPass releases keep working, but PHP cannot read
  their rows; have them disable and re-enable 2FA. Saving the 2FA mode once
  moves it out of `Plugin.data`.
- Production startup fails without explicit, non-sample `SECRET_KEY` and
  `ENCRYPTION_KEY`; `DEBUG` defaults to false.
- `GET /api/v1/tags/{id}` now requires authentication.
- Item presets use sysPass PHP types (`account.permission`, `account.private`,
  `account.password`, `session.timeout`) and are now enforced. Managing them
  requires the `mgm_items_preset` permission, and every preset needs a user,
  group or profile scope. Presets saved by earlier releases are shown as legacy
  and ignored until saved again.

### Added
- `/health/ready` readiness checks (configuration, database, schema, storage).
- `python -m app.rotate_master_password`: offline, transactional master
  password change with a pre-change backup and PHP semantics.
- `python -m app.restore_backup` offline restore with rollback attempts.
- `POST /api/v1/auth/logout` and `POST /api/v1/auth/refresh`.
- `GET /api/v1/security/operations` (admins): failure counters and scheduler state.
- CI: canonical MySQL API/import/readiness tests, a PHP job that decodes every
  pySysPass credential write, image hardening checks, dependency lock check,
  75% coverage floor.

### Changed
- Credentials are always written as native sysPass Defuse ciphertext; public
  links as native PHP Vaults; 2FA enrollments as PHP Authenticator plugin data.
- Force HTTPS, maintenance mode and attachment limits are enforced server-side.
- Logout, password changes (from either application) and 2FA changes revoke sessions.
- Backups fail closed; runtime JSON config writes are locked and atomic.
- Container builds use an allowlist, a hash-pinned `requirements.lock` and
  digest-pinned base images; test tools moved to `requirements-dev.txt`.

### Fixed
- Client IP spoofing through forwarded headers; SPA routes losing security headers.
- Password reset not setting PHP migration flags.
- Reads of native ciphertext without a vault key raising 500.
- `masterPwd` hashing for keys longer than 72 characters (now matches PHP).

## [2.2.2] — 2026-10-23

Routine dependency and security updates. No API or database changes.

### Changed
- Backend: `fastapi` 0.141.1 → 0.143.2, `uvicorn` 0.52.4 → 0.54.0, `pydantic`
  2.13.5 → 2.14.1, `pydantic-settings` 2.15.0 → 2.16.0, `sqlalchemy` 2.0.52 →
  2.1.4, `alembic` 1.19.1 → 1.20.0, `pymysql` 1.2.0 → 1.2.3, `cryptography`
  50.0.1 → 50.0.2, `PyJWT` 2.13.0 → 2.15.1, `python-dotenv` 1.2.3 → 1.2.4.
- Frontend: `quasar` 2.31.0 → 2.35.1, `@quasar/extras` 2.0.4 → 2.1.0, `vue`
  3.5.42 → 3.5.44, `vue-router` 5.3.1 → 5.4.0, `pinia` 4.0.3 → 4.1.0, `vite`
  8.2.2 → 8.3.5, `vitest` 5.0.0 → 5.0.5, `@vitejs/plugin-vue` 6.0.8 → 6.0.10,
  `@pinia/testing` 2.0.1 → 2.0.2, `@vue/test-utils` 2.5.0 → 2.5.1, `eslint`
  10.10.0 → 10.12.0, `eslint-plugin-vue` 10.11.0 → 10.11.1, `globals` 17.12.0 →
  17.13.0, `jsdom` 30.0.1 → 30.1.3, `sass` 1.104.0 → 1.105.2.

### Security
- Frontend transitive dependencies updated to clear `npm audit` advisories:
  `brace-expansion` 5.0.9 → 5.0.12, `follow-redirects` 1.16.0 → 1.16.1,
  `undici` 8.10.0 → 8.12.3, `postcss-selector-parser` 7.1.4 → 7.1.7,
  `source-map-js` 1.2.1 → 1.2.2.

## [2.2.1] — 2026-09-13

Routine dependency updates. No API or database changes.

### Changed
- Backend: `pydantic` 2.13.4 → 2.13.5.
- Frontend: `quasar` 2.27.0 → 2.31.0, `vitest` 4.1.11 → 5.0.0, `vue-router`
  5.3.0 → 5.3.1, `eslint` 10.9.1 → 10.10.0, `eslint-plugin-vue` 10.10.0 →
  10.11.0, `globals` 17.11.0 → 17.12.0, `sass` 1.103.1 → 1.104.0.

## [2.2.0] — 2026-09-13

Closes live authorization gaps against PHP session/profile/ACL rules and adds
native PHP public-link compatibility. No database schema changes beyond
migration `002` (view repair only).

### Added
- Public-link access now **natively reads PHP-created Vault links**: a
  bounded, data-only PHP-serialize reader decrypts the `SP\Core\Crypt\Vault`
  stored in `PublicLink.data` with Defuse and returns the frozen
  `AccountExtData` snapshot (password, category/client names included),
  matching PHP `AccountController::viewLinkAction`. Verified against a
  PHP-authored synthetic fixture (21 tests); see
  `docs/project/php-public-link-reader.md`.
- Alembic migration `002_restore_php_account_views` repairs missing PHP
  account views on existing databases without touching existing PHP objects;
  bootstrap now creates the canonical views for fresh installs.
- CI: frontend lint job and a Docker build validation job; installs now use
  the committed frontend lockfile.

### Fixed
- JWT sessions no longer retain access after a user is disabled or demoted:
  requests reload live user state instead of trusting stale token claims.
- File and public-link routes now enforce PHP profile permissions and
  account ACLs, including URL-to-resource ownership checks that were
  previously skipped.
- Public-link reads atomically enforce PHP's `countViews < maxCountViews`
  and expiry gates, closing a race that let concurrent requests exceed a
  link's configured view limit.

### Changed
- Existing zero-view-limit public links are now treated as exhausted, per
  PHP's rules; they must be recreated with a positive configured view limit.
  No stored links are rewritten.

### Notes
- Full public-link write interoperability (native Vault creation, live PHP
  UI round trips) remains open; no encrypted payloads are migrated.
- See `docs/project/authorization-gap-fixes.md` for the full authorization
  gap analysis and validation record.

## [2.1.0] — 2026-07-20

Security and CI hardening. No API or database changes.

### Added
- CI **security scan** job: `bandit` (Python SAST), `pip-audit` and
  `npm audit` (vulnerable-dependency gates), and `gitleaks` (secrets scan
  with a `.gitleaks.toml` allowlist for known sample/test data).
- CI **MySQL 8 integration** job that bootstraps the full PHP-compatible
  schema against a real MySQL service and asserts the tables are created —
  automating a check that was previously manual.
- `.github/dependabot.yml` for weekly grouped pip/npm/actions updates.

### Changed
- Replaced `python-jose` with `PyJWT` for JWTs (HS256 unchanged). This drops
  the abandoned `python-jose` and its transitive `ecdsa`, resolving
  PYSEC-2026-1325 (an ECDSA timing side-channel the app never triggered,
  with no upstream fix) — `pip-audit` is now clean.
- Legacy `config.xml` parsing uses `defusedxml` (XXE hardening).
- Annotated the PHP-compatibility SHA-1 item hashes with
  `usedforsecurity=False` (output unchanged).

## [2.0.0] — 2026-07-18

Promotes 2.0.0-rc.2 to final with no code changes — CI, CodeQL, and
`npm audit` all clean, no open security alerts. See the rc entries below
for the full feature set.

## [2.0.0-rc.2] — 2026-07-18

### Fixed
- Removed the unused `@quasar/quasar-app-extension-testing-unit-vitest` dev
  dependency, eliminating a vulnerable transitive `happy-dom` (3 Dependabot
  alerts including a critical VM-context-escape RCE). `npm audit` is clean.
- Per-account audit no longer double-logs edits/deletes: mutations are
  recorded once by the global audit middleware (now tagged with the
  `[acc:<id>]` marker), and the account routes log only the reads
  (view / view-password) the middleware doesn't cover.

## [2.0.0-rc.1] — 2026-07-18

First tagged release. Adds authentication, authorization, and auditing
capabilities on top of the sysPass PHP-compatible core, with no changes to
the upstream database schema (new state lives in existing tables, the
`Plugin`/`PluginData` rows, or the JSON runtime config).

### Breaking changes
- `POST /api/v1/users` now **requires** `user_group_id`; there is no implicit
  default group (the old fallback silently placed users in group 1 / Admins).
- `GET /api/v1/auth-tokens` no longer returns token secrets; the plaintext is
  shown only on create/regenerate.
- Login now enforces two-factor authentication for enrolled users and rejects
  disabled users.
- LDAP provisioning and import refuse to create users until a default group is
  configured.

### Added
- **LDAP/Active Directory login**: tried before database auth (PHP AuthProvider
  order), provisions/syncs the local user, real group-membership filtering
  (AD nested-group chain, group-entry member lists, `memberOf` fallback), a
  connection-test button, and a directory user-import UI with selective import.
- **Two-factor authentication**: global tri-state policy (disabled/enabled/
  enforced) in Settings → Security, guided enrollment in My Profile (QR code +
  backup codes), and TOTP/backup-code enforcement at login. State stored in
  `PluginData` (the PHP Authenticator plugin's location), encrypted at rest.
- **API token authentication**: sysPass API tokens authenticate REST calls,
  scoped to routes by their PHP `actionId`.
- **Per-account audit trail**: an Audit tab showing who opened an account,
  viewed its password, edited, or deleted it (owner/main-group/admin only),
  recorded in `EventLog`.
- **Pagination**: server-side for accounts (with filters) and users (with
  search and sort); per-section settings routes; user group assignment and a
  Local/LDAP source column in the Users page.
- **Mail**: "Send test email" button and endpoint.
- **CI**: GitHub Actions running ruff, pytest, and vitest; frontend test suite
  (store, axios, theme, encryption, login challenge flow, 2FA enrollment).

### Fixed
- Account ACLs aligned with PHP `compileAccountAccess`/`getFilterHistory`:
  explicit user shares short-circuit group-derived edit rights, the
  `acc_global_search` profile permission is honored, and account-history
  visibility is filtered per snapshot.
- Two-factor state is now persisted (was discarded by no-op model setters).
- `EmailService` honors all three security modes (tls/ssl/none); plain SMTP
  was previously impossible.
- Security hardening: LDAP rejects empty-password (unauthenticated) binds, and
  a non-ASCII API token returns 401 instead of 500.

### Notes
- The per-account audit trail is forward-looking: only accesses recorded after
  this release appear.
- PHP database compatibility is preserved; see
  `docs/project/php-compatibility-checklist.md`.
