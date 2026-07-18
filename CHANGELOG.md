# Changelog

All notable changes to pySysPass are documented here. Versions follow
[Semantic Versioning](https://semver.org/). Dates are ISO 8601.

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
