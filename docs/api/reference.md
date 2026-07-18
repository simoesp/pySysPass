# API Reference

This document describes the current `pySysPass` HTTP API as implemented by the FastAPI backend. It is intentionally more practical than a raw endpoint list and focuses on how to actually call the API.

## Base URLs

- API root: `http://localhost:8000/`
- Versioned API base: `http://localhost:8000/api/v1`
- Swagger UI: `http://localhost:8000/docs`
- OpenAPI schema: `http://localhost:8000/openapi.json`

## How the API Is Organized

### Public endpoints

- `GET /`
- `GET /health`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- Password-reset endpoints
- `GET /api/v1/security/public-key`
- `GET /api/v1/public-links/{hash}/access`

### JWT-protected endpoints

Most business endpoints require:

```http
Authorization: Bearer <access_token>
```

### Higher-privilege endpoints

Some routes require more than a valid JWT:

- `require_admin`
- `require_permission(...)`

Examples:

- plugin management is admin-only
- backup/import/export/settings routes usually require profile permissions
- audit log routes require the `evl` permission

### Important implementation note

The account-sharing routes currently have weaker auth enforcement than most of the rest of the API. This document reflects the code as it exists today, not an idealized security model.

## Authentication Model

### Register

`POST /api/v1/auth/register`

JSON body:

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "name": "Alice Example",
  "password": "correct horse battery staple",
  "is_admin": false,
  "is_active": true,
  "user_profile_id": 1,
  "user_group_id": 2
}
```

`user_group_id` (the primary group) is required on create — there is no
implicit default group. Secondary memberships are managed via the
user-group member routes.

Listing: `GET /api/v1/users` accepts optional `skip`, `limit`
(1–500; omitted = all), `q` (matches username, name, email), and
`sort_by` (`id`, `username`, `email`, `user_profile_id`,
`user_group_id`) with `descending`; unknown sort keys fall back to `id`.
`GET /api/v1/users/count` returns `{ "count": n }` for the same filter.
Both require `mgm_users`.

Successful response:

```json
{
  "id": 12,
  "username": "alice",
  "email": "alice@example.com",
  "name": "Alice Example",
  "is_admin": false,
  "is_active": true,
  "is_ldap": false,
  "user_profile_id": 1,
  "user_group_id": 2,
  "two_factor_enabled": false,
  "created_at": "2026-06-30T12:34:56",
  "permissions": null
}
```

`is_ldap` reports the user's origin: `true` for accounts provisioned or
synced from the directory, `false` for internal accounts. The Users page
shows it as the Source column.

### Login

`POST /api/v1/auth/login`

This endpoint does **not** accept JSON. It uses `OAuth2PasswordRequestForm`, so send `application/x-www-form-urlencoded`.

Required form fields:

- `username`
- `password`

Optional form fields used by the current implementation:

- `mpass`
- `oldpass`

The backend attempts to decrypt `password`, `mpass`, and `oldpass` if the client sent RSA-wrapped values.

Minimal example:

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=alice' \
  --data-urlencode 'password=my-password'
```

Successful response:

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer"
}
```

Possible special error flows:

- `401 Incorrect username or password`
- `429` when login attempts are locked by IP
- `428 MASTER_PASSWORD_REQUIRED`
- `428 OLD_PASSWORD_REQUIRED`
- `401 MASTER_PASSWORD_INVALID`
- `401 OLD_PASSWORD_INVALID`
- `400 CREDENTIAL_DECRYPT_FAILED`

### Current user

`GET /api/v1/auth/me`

Returns user identity plus resolved profile permissions.

## Encryption and Credential Handling

### Public key

`GET /api/v1/security/public-key`

Returns the RSA public key used by browser clients to encrypt passwords before submission.

Example response:

```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

### Stored account passwords

Account passwords are not returned in the normal account payload. They are retrieved separately through:

- `GET /api/v1/accounts/{account_id}/password`

Response:

```json
{
  "password": "decrypted-secret"
}
```

## Common Response Patterns

### Success

- `200 OK` for normal reads and most operations
- `201 Created` for create operations
- `204 No Content` for delete operations that return no body

### Common error codes

- `400` invalid request shape, invalid file type, invalid base64, decrypt failure
- `401` invalid token or bad credentials
- `403` missing admin or profile permission
- `404` object not found
- `410` expired public link
- `422` validation failure
- `428` extra secret required for vault/encryption flows
- `429` rate-limited login

## Calling Conventions

### Query parameters

Common list routes use simple query params such as:

- `skip`
- `limit`
- `q`
- `locked_only`
- `level`
- `login`

### JSON bodies

Most create and update operations use JSON request bodies.

### Form bodies

Used by:

- `POST /api/v1/auth/login`
- import routes that accept uploaded files

### File uploads

There are two different patterns in this API:

- import/export uses multipart file upload
- account file attachments use JSON with base64-encoded content

That distinction matters.

## Core Resource Examples

### Accounts

#### Create account

`POST /api/v1/accounts`

Example request:

```json
{
  "title": "Production PostgreSQL",
  "login": "dbadmin",
  "password": "RSA:<encrypted-or-plaintext>",
  "url": "https://db.example.internal",
  "notes": "Primary production database",
  "category_id": 2,
  "client_id": 4,
  "is_public": false,
  "is_private_group": false,
  "other_user_edit": false,
  "other_user_group_edit": false,
  "pass_date_change": 1719705600,
  "tag_ids": [1, 5],
  "shared_users": [
    { "user_id": 7, "is_edit": true }
  ],
  "shared_groups": [
    { "group_id": 3, "is_edit": false }
  ]
}
```

Example response shape:

```json
{
  "id": 101,
  "user_id": 12,
  "user_group_id": 1,
  "is_owner": true,
  "can_edit": true,
  "title": "Production PostgreSQL",
  "login": "dbadmin",
  "url": "https://db.example.internal",
  "notes": "Primary production database",
  "category_id": 2,
  "client_id": 4,
  "is_public": false,
  "is_private_group": false,
  "is_favorite": false,
  "other_user_edit": false,
  "other_user_group_edit": false,
  "tags": [],
  "shared_users": [],
  "shared_groups": [],
  "count_view": 0,
  "count_decrypt": 0,
  "pass_date_change": 1719705600,
  "created_at": "2026-06-30T12:00:00",
  "updated_at": null
}
```

#### List accounts

`GET /api/v1/accounts?skip=0&limit=100`

Optional filters: `q` (matches name, login, notes, url), `category_id`,
`client_id`, `tag_id`.

Notes:

- list is scoped to the authenticated user context
- `skip >= 0`, `1 <= limit <= 500`
- response is an array of `AccountResponse`

#### Count accounts

`GET /api/v1/accounts/count`

Accepts the same optional filters as the list endpoint and returns the
total matching the authenticated user's accessible set:

```json
{ "count": 42 }
```

Used by the frontend for server-side pagination.

#### Search accounts

`GET /api/v1/accounts/search?q=postgres`

The current implementation searches within the user’s accessible account set.

#### Toggle favourite

`POST /api/v1/accounts/{account_id}/favorite`

Response:

```json
{
  "is_favorite": true
}
```

#### Clone account

`POST /api/v1/accounts/{account_id}/copy`

Creates a new account row with a re-encrypted password.

### ACL assignment endpoints

These are separate from the account-sharing module and are JWT-protected:

- `PUT /api/v1/accounts/{account_id}/users/{target_user_id}`
- `DELETE /api/v1/accounts/{account_id}/users/{target_user_id}`
- `PUT /api/v1/accounts/{account_id}/groups/{group_id}`
- `DELETE /api/v1/accounts/{account_id}/groups/{group_id}`

For the `PUT` variants, `is_edit` is sent as JSON body with embedded form:

```json
{
  "is_edit": true
}
```

## Account Sharing Endpoints

These live under `/api/v1/accounts/.../share/...`.

Current auth enforcement:

| Method | Path | Current Enforcement |
| --- | --- | --- |
| `POST` | `/api/v1/accounts/{account_id}/share/users` | Optional JWT |
| `DELETE` | `/api/v1/accounts/{account_id}/share/users/{user_id}` | None enforced |
| `GET` | `/api/v1/accounts/{account_id}/share/users` | None enforced |
| `PUT` | `/api/v1/accounts/{account_id}/share/users/{user_id}/permission` | None enforced |
| `GET` | `/api/v1/accounts/users/{user_id}/shared-accounts` | None enforced |
| `POST` | `/api/v1/accounts/{account_id}/share/groups` | None enforced |
| `DELETE` | `/api/v1/accounts/{account_id}/share/groups/{user_group_id}` | None enforced |
| `GET` | `/api/v1/accounts/{account_id}/share/groups` | None enforced |
| `PUT` | `/api/v1/accounts/{account_id}/share/groups/{user_group_id}/permission` | None enforced |
| `GET` | `/api/v1/accounts/user-groups/{user_group_id}/accounts` | None enforced |
| `POST` | `/api/v1/accounts/{account_id}/share/users/bulk` | Optional JWT |
| `POST` | `/api/v1/accounts/{account_id}/share/groups/bulk` | None enforced |
| `DELETE` | `/api/v1/accounts/{account_id}/share/all` | None enforced |

Examples:

Share with one user:

```bash
curl -X POST http://localhost:8000/api/v1/accounts/101/share/users?user_id=7\&is_edit=true
```

Bulk share with users:

```json
[7, 8, 9]
```

Bulk share with groups:

```json
[2, 3]
```

## Files API

### Important behavior

Account file attachment upload is **JSON + base64**, not multipart.

#### Upload a file

`POST /api/v1/accounts/{account_id}/files`

Example request:

```json
{
  "name": "runbook.pdf",
  "type": "application/pdf",
  "size": 58213,
  "extension": "pdf",
  "content": "JVBERi0xLjcKJc..."
}
```

Successful response:

```json
{
  "id": 55,
  "account_id": 101,
  "name": "runbook.pdf",
  "type": "application/pdf",
  "size": 58213,
  "extension": "pdf",
  "date_add": "2026-06-30T13:10:00",
  "message": "File uploaded successfully"
}
```

Other file routes:

- `GET /api/v1/accounts/{account_id}/files`
- `GET /api/v1/accounts/{account_id}/files/{file_id}`
- `GET /api/v1/accounts/{account_id}/files/{file_id}/metadata`
- `DELETE /api/v1/accounts/{account_id}/files/{file_id}`
- `GET /api/v1/accounts/{account_id}/files/count`

Notes:

- file download returns raw binary content
- these routes currently verify access by ownership check on `Account.userId`

## Public Links API

Account-scoped management routes also exist alongside the ones below:
`GET`/`DELETE /api/v1/accounts/{account_id}/public-links/{link_id}`.

### Create a public link

`POST /api/v1/accounts/{account_id}/public-links`

Example request:

```json
{
  "account_id": 101,
  "expire": 3600,
  "password": "optional-link-password"
}
```

Example response:

```json
{
  "id": 9,
  "account_id": 101,
  "hash": "3d1b0f4f...",
  "expire": 3600,
  "has_password": true,
  "date_add": "2026-06-30T13:15:00"
}
```

### Access a public link

`GET /api/v1/public-links/{link_hash}/access`

Optional query parameter:

- `password`

Example response:

```json
{
  "account_id": 101,
  "account_title": "Production PostgreSQL",
  "login": "dbadmin",
  "url": "https://db.example.internal",
  "notes": "Primary production database",
  "category_id": 2,
  "client_id": 4
}
```

Possible failures:

- `404 Invalid or expired link`
- `410 Link has expired`

## Installation API

Use the installation routes only on a brand-new deployment before any normal users exist.

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/api/v1/auth/install/status` | None |
| `POST` | `/api/v1/auth/install` | None |

`GET /api/v1/auth/install/status` response:

```json
{
  "installed": false,
  "user_count": 0,
  "has_master_password": false
}
```

`POST /api/v1/auth/install` request:

```json
{
  "username": "admin",
  "password": "admin-password",
  "email": "admin@example.test",
  "name": "Initial Administrator",
  "generate_master_password": true
}
```

Alternatively, provide a specific master password and disable generation:

```json
{
  "username": "admin",
  "password": "admin-password",
  "master_password": "vault-master-password",
  "generate_master_password": false
}
```

Generated-master-password response:

```json
{
  "user_id": 1,
  "username": "admin",
  "master_password_generated": true,
  "master_password": "generated-once-by-the-api",
  "message": "Save the master password in a secure place. It is required to recover vault access."
}
```

Notes:

- The installer can only run once per deployment.
- If the caller supplies `master_password`, the response does not echo it back.
- The web installer keeps a generated master password visible until the administrator confirms it has been saved, then continues to login. A supplied master password reloads the application at login to refresh installation state.
- The web installer provides a secure password generator and live strength feedback for the administrator login password and a manually supplied master password.
- The old public `/api/v1/auth/register` route is retired and returns `410`.

## Settings API

### Settings sections

The settings module is split into:

- `general`
- `mail`
- `ldap`
- `accounts`
- `wiki`
- `info`
- `encryption`

Representative routes:

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/api/v1/settings` | JWT + `config_general` |
| `GET` | `/api/v1/settings/general` | JWT + `config_general` |
| `PUT` | `/api/v1/settings/general` | JWT + `config_general` |
| `GET`/`PUT` | `/api/v1/settings/mail` | JWT + `config_general` |
| `POST` | `/api/v1/settings/mail/test` | JWT + `config_general` |
| `GET`/`PUT` | `/api/v1/settings/ldap` | JWT + `config_general` |
| `GET`/`PUT` | `/api/v1/settings/accounts` | JWT + `config_general` |
| `GET`/`PUT` | `/api/v1/settings/wiki` | JWT + `config_general` |
| `GET` | `/api/v1/settings/info` | JWT + `config_general` |
| `GET` | `/api/v1/settings/encryption` | JWT + `config_encryption` |
| `GET` | `/api/v1/settings/encryption/temp-master` | JWT + `config_encryption` |
| `POST` | `/api/v1/settings/encryption/temp-master` | JWT + `config_encryption` |
| `POST` | `/api/v1/settings/encryption/rekey` | Admin |

Example `general` payload:

```json
{
  "sitelang": "en_US",
  "sitetheme": "blue",
  "session_timeout": 300,
  "app_url": "https://vault.example.com",
  "https_enabled": true,
  "debug": false,
  "maintenance": false,
  "check_updates": false,
  "check_notices": false,
  "log_enabled": true,
  "syslog_enabled": false,
  "syslog_remote_enabled": false,
  "syslog_server": null,
  "syslog_port": 514,
  "proxy_enabled": false,
  "proxy_server": null,
  "proxy_port": 8080,
  "proxy_user": null
}
```

### Temporary master password

Create request:

```json
{
  "max_time": 3600,
  "send_email": false,
  "group_id": null
}
```

This route also requires the JWT to contain `master_pass`; otherwise it returns `428 MASTER_PASSWORD_REQUIRED`.

## Import and Export API

### Import routes

- `POST /api/v1/import-export/import/csv`
- `POST /api/v1/import-export/import/xml`
- `POST /api/v1/import-export/import/keepass`

These use `multipart/form-data`.

CSV import fields:

- `file`
- `delimiter`
- `user_id`

XML/KeePass import fields:

- `file`
- `user_id`

Example:

```bash
curl -X POST http://localhost:8000/api/v1/import-export/import/csv \
  -H "Authorization: Bearer <jwt>" \
  -F "file=@accounts.csv" \
  -F "delimiter=," \
  -F "user_id=12"
```

Typical response shape:

```json
{
  "format": "csv",
  "stats": {
    "created": 10,
    "updated": 0,
    "skipped": 1
  },
  "errors": []
}
```

### Export routes

- `GET /api/v1/import-export/export/csv`
- `GET /api/v1/import-export/export/xml`
- `POST /api/v1/import-export/export/xml/protected`
- `GET /api/v1/import-export/export/keepass` — KeePass 2 XML
- `POST /api/v1/import-export/export/keepass/kdbx` — binary `.kdbx` database

Optional query parameter:

- `account_ids=1,2,3`

Current implementation returns generated content inline as JSON:

```json
{
  "format": "csv",
  "content": "title,login,url,...",
  "filename": "syspass_export.csv"
}
```

The XML routes emit the native sysPass `Root`/`Meta`/section structure. Native
Defuse account ciphertext is preserved. Use the protected `POST` route with
form fields `export_password`, optional `master_password`, and optional
comma-separated `account_ids` to encrypt the four XML sections exactly as a PHP
sysPass export does. `master_password` is required only when selected accounts
still use the Python AES fallback and must be converted to native Defuse
ciphertext.

For `POST /api/v1/import-export/import/xml`, password-protected PHP exports use
the `export_password` form field. `import_master_password` is the source vault
master password; when supplied, credentials are decrypted and re-encrypted with
`current_master_password` (or the source master password when the current value
is omitted). If the source and target share a master password, omit both master
password fields to preserve the native ciphertext unchanged.

## Backup API

Routes:

- `GET /api/v1/backup/`
- `POST /api/v1/backup/create`
- `GET /api/v1/backup/{filename}/download`
- `POST /api/v1/backup/{filename}/restore`
- `DELETE /api/v1/backup/{filename}`

Required auth:

- JWT + `config_backup`

`POST /create` supports:

- `include_db=true|false`

## LDAP API

Routes:

- `POST /api/v1/ldap/test-connection`
- `GET /api/v1/ldap/users` — directory preview (used by the Settings →
  LDAP import dialog)
- `POST /api/v1/ldap/import` — body may include `default_group_id` and
  `usernames` (selective import); fails with 400 when no default group is
  configured or supplied. Imported users are marked `is_ldap`, receive
  the configured default group/profile, and keep an unusable local
  password until they log in via the directory.

Current required auth:

- JWT + `config_general`

Example test-connection body:

```json
{
  "ldap_uri": "ldap://ldap.example.com",
  "base_dn": "dc=example,dc=com",
  "bind_dn": "cn=admin,dc=example,dc=com",
  "bind_password": "secret",
  "use_tls": false
}
```

Example import body:

```json
{
  "user_filter": "(objectClass=person)",
  "default_group_id": 1
}
```

## Plugins API

All plugin routes are admin-only:

- `GET /api/v1/plugins`
- `POST /api/v1/plugins/sync`
- `GET /api/v1/plugins/hooks`
- `GET /api/v1/plugins/{plugin_name}`
- `POST /api/v1/plugins/{plugin_name}/enable`
- `POST /api/v1/plugins/{plugin_name}/disable`
- `PUT /api/v1/plugins/{plugin_name}/config`

Config update body:

```json
{
  "config": {
    "enabled": true,
    "endpoint": "https://plugin.internal"
  }
}
```

## Audit and Track Endpoints

Permission required:

- JWT + `evl`

Routes:

- `GET /api/v1/audit-log`
- `GET /api/v1/audit-log/count`
- `DELETE /api/v1/audit-log`
- `GET /api/v1/tracks`
- `GET /api/v1/tracks/count`
- `POST /api/v1/tracks/{track_id}/unlock`
- `DELETE /api/v1/tracks/{track_id}`
- `DELETE /api/v1/tracks`

Useful query parameters:

- audit log: `skip`, `limit`, `level`, `login`
- tracks: `skip`, `limit`, `locked_only`

## Endpoint Catalog

### Authentication

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/password-reset/request`
- `GET /api/v1/auth/password-reset/verify/{token}`
- `POST /api/v1/auth/password-reset/confirm`

### Two-factor

Two-factor authentication is a built-in feature (not a plugin). The
global policy is a tri-state mode, configured in Settings → Security
(`config_general` permission):

- `disabled` — feature off; no enrollment, no login challenge
- `enabled` — users may enroll; enrolled users must enter a code at login
- `enforced` — like enabled, and non-enrolled users are prompted to enroll

Policy routes:

- `GET /api/v1/settings/two-factor` → `{ "mode": "enabled" }`
- `PUT /api/v1/settings/two-factor` — body `{ "mode": "enforced" }`

Storage detail: state persists in the upstream `Plugin`/`PluginData`
tables under the reserved name `Authenticator` (kept from the sysPass PHP
plugin for data continuity, with secrets encrypted at rest). The plugins
API hides this reserved row and refuses to manage it.

User routes:

- `GET /api/v1/2fa/status` → `{ "mode", "enrolled", "setup_required" }`
- `POST /api/v1/2fa/setup` — body `{ "password": "..." }`; verifies the
  password, stores a pending secret, returns `secret` and
  `provisioning_uri` for the QR code (2FA not active yet)
- `POST /api/v1/2fa/enable` — body `{ "code": "<totp>" }`; confirms the
  pending secret and returns one-time backup codes
- `POST /api/v1/2fa/disable` — body `{ "password": "..." }`
- `POST /api/v1/2fa/verify` — body `{ "code": "<totp>" }`
- `POST /api/v1/2fa/backup-code` — body `{ "code": "..." }`; consumes one
  backup code

Login enforcement: when the mode is not `disabled` and the user is
enrolled, `POST /auth/login` answers `428` with code
`TWO_FACTOR_REQUIRED` until the form is resubmitted with an `otp` field
(TOTP or backup code); invalid codes return `401` `TWO_FACTOR_INVALID`
and count toward brute-force tracking. Enrollment and disabling live in
the My Profile page; `two_factor_enabled` in user responses reflects the
stored state.

### Accounts

- `GET /api/v1/accounts`
- `GET /api/v1/accounts/search`
- `POST /api/v1/accounts`
- `GET /api/v1/accounts/{account_id}`
- `PUT /api/v1/accounts/{account_id}`
- `DELETE /api/v1/accounts/{account_id}`
- `GET /api/v1/accounts/{account_id}/password`
- `POST /api/v1/accounts/{account_id}/favorite`
- `POST /api/v1/accounts/{account_id}/copy`
- `PUT /api/v1/accounts/{account_id}/users/{target_user_id}`
- `DELETE /api/v1/accounts/{account_id}/users/{target_user_id}`
- `PUT /api/v1/accounts/{account_id}/groups/{group_id}`
- `DELETE /api/v1/accounts/{account_id}/groups/{group_id}`

### Organization

- `GET|POST /api/v1/categories`
- `GET|PUT|DELETE /api/v1/categories/{category_id}`
- `GET|POST /api/v1/clients`
- `GET|PUT|DELETE /api/v1/clients/{client_id}`
- `GET|POST /api/v1/tags`
- `GET|PUT|DELETE /api/v1/tags/{tag_id}`
- `GET /api/v1/tags/{tag_id}/accounts`
- `POST /api/v1/accounts/{account_id}/tags/{tag_id}`
- `DELETE /api/v1/accounts/{account_id}/tags/{tag_id}`
- `GET /api/v1/accounts/{account_id}/tags`

### Users and groups

- `GET|POST /api/v1/users`
- `GET|PUT|DELETE /api/v1/users/{user_id}`
- `POST /api/v1/users/{user_id}/password`
- `GET|POST /api/v1/user-profiles`
- `GET|PUT|DELETE /api/v1/user-profiles/{profile_id}`
- `GET|POST /api/v1/user-groups`
- `GET|PUT|DELETE /api/v1/user-groups/{group_id}`
- `GET /api/v1/user-groups/{group_id}/members`
- `POST /api/v1/user-groups/{group_id}/members/{user_id}`
- `DELETE /api/v1/user-groups/{group_id}/members/{user_id}`
- `GET /api/v1/users/{user_id}/groups`

## Notifications API

All routes require a JWT; users see their own notifications.

- `GET /api/v1/notifications` — list for the current user
- `GET /api/v1/notifications/unread-count` — `{ "count": n }`, polled by the UI
- `GET /api/v1/notifications/{notification_id}`
- `GET /api/v1/notifications/type/{notification_type}`
- `POST /api/v1/notifications` — body: `{ "type": "...", "message": "...", "user_id": 1 }`
- `POST /api/v1/notifications/{notification_id}/read`
- `POST /api/v1/notifications/read-all`
- `DELETE /api/v1/notifications/{notification_id}`
- `DELETE /api/v1/notifications` — clear all for the current user

Response fields: `id`, `user_id`, `type`, `message`, `is_read`, `date_add`
(unix timestamp).

## Custom Fields API

Reading is JWT-only; managing types/definitions requires
`mgm_custom_fields`.

Types and definitions:

- `GET|POST /api/v1/custom-fields/types`
- `PUT|DELETE /api/v1/custom-fields/types/{type_id}`
- `GET|POST /api/v1/custom-fields/definitions`
- `PUT|DELETE /api/v1/custom-fields/definitions/{def_id}`
- `GET /api/v1/custom-fields/modules` — module ids values can attach to

Values:

- `GET /api/v1/custom-fields/values/account/{account_id}`
- `GET /api/v1/custom-fields/values/{module_id}/{item_id}`
- `POST /api/v1/custom-fields/values`
- `DELETE /api/v1/custom-fields/values/account/{def_id}/{account_id}`
- `DELETE /api/v1/custom-fields/values/{def_id}/{module_id}/{item_id}`

Encrypted definitions store their values encrypted at rest, matching the
PHP behaviour.

## Item Presets API

JWT required; mutations are admin-only. Presets provide per-user/group
defaults (permissions, private flags, session timeouts) resolved by
specificity, as in sysPass PHP.

- `GET /api/v1/item-presets` — optional `?preset_type=` filter
- `GET /api/v1/item-presets/types`
- `GET /api/v1/item-presets/{preset_id}`
- `GET /api/v1/item-presets/context/{preset_type}` — the preset that
  applies to the calling user (most specific match wins)
- `POST /api/v1/item-presets`
- `PUT /api/v1/item-presets/{preset_id}`
- `DELETE /api/v1/item-presets/{preset_id}`

## Auth Tokens API

JWT required for management. Manages sysPass API tokens (the PHP
`AuthToken` table).

- `GET /api/v1/auth-tokens` — listings return `token: null`; the secret is
  never included in a list response
- `GET /api/v1/auth-tokens/actions` — valid action ids
- `POST /api/v1/auth-tokens` — body: `{ "user_id": 1, "action_id": 1 }`;
  the plain token is only returned on create/regenerate
- `POST /api/v1/auth-tokens/{token_id}/regenerate`
- `DELETE /api/v1/auth-tokens/{token_id}`

### Using API tokens

Tokens authenticate REST calls directly, in place of a JWT:

```
Authorization: Bearer <64-char token>
```

Each token is scoped by its `action_id` to the matching routes — e.g.
Account Search (3) may call the account list/search/count endpoints,
Account Add (5) may `POST /accounts`, Category Search (102) may read
categories, and so on. Calls outside the token's scope return 403. The
token acts as its owning user: profile permissions and account ACLs
still apply, and tokens of disabled users are rejected. Tokens carry no
master-password vault, so PHP-encrypted account passwords cannot be
decrypted through them.

```bash
curl -H "Authorization: Bearer $TOKEN" https://host/api/v1/accounts
```

## History Endpoints

- `GET /api/v1/accounts/{account_id}/history` — account snapshots
- `GET /api/v1/accounts/{account_id}/history/view-count`
- `GET /api/v1/accounts/{account_id}/history/decrypt-count`
- `GET /api/v1/users/{user_id}/history` — user-scoped action history

## Health

`GET /health` (no `/api/v1` prefix, unauthenticated) returns
`{ "status": "healthy" }`; used by the compose healthchecks.

## Recommended Usage

- Use this document for the calling conventions and examples.
- Use `/docs` for exact live schemas and model details.
- When behavior here and live code disagree, trust the code and update the docs.
