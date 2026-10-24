# Production readiness review — 2026-10-23

**Verdict: not ready for production password storage.** The application builds and has useful regression coverage, but deployment, recovery, session security, and PHP write compatibility have release-blocking gaps. Keep the README production warning.

Reviewed revision: `ccfa503`. This was an assessment; no application code, schema, encrypted values, or deployment configuration was changed. Tests used isolated SQLite fixtures and a disposable MySQL 8 container, not an existing sysPass database.

## GitHub tracking

All 16 findings have open issues with evidence and completion criteria. Milestones have no assumed due dates or assignees. Complete all four milestones and the release gate before reconsidering the production warning.

| Milestone | Findings |
| --- | --- |
| [Production readiness: security and sessions](https://github.com/simoesp/pySysPass/milestone/1) | [R1 / #50](https://github.com/simoesp/pySysPass/issues/50), [R7 / #51](https://github.com/simoesp/pySysPass/issues/51), [R9 / #52](https://github.com/simoesp/pySysPass/issues/52), [R10 / #53](https://github.com/simoesp/pySysPass/issues/53), [R12 / #54](https://github.com/simoesp/pySysPass/issues/54) |
| [Production readiness: PHP compatibility and encryption](https://github.com/simoesp/pySysPass/milestone/2) | [R4 / #55](https://github.com/simoesp/pySysPass/issues/55), [R5 / #56](https://github.com/simoesp/pySysPass/issues/56), [R6 / #57](https://github.com/simoesp/pySysPass/issues/57), [R8 / #58](https://github.com/simoesp/pySysPass/issues/58) |
| [Production readiness: backup and recovery](https://github.com/simoesp/pySysPass/milestone/3) | [R2 / #59](https://github.com/simoesp/pySysPass/issues/59), [R3 / #60](https://github.com/simoesp/pySysPass/issues/60), [R11 / #61](https://github.com/simoesp/pySysPass/issues/61) |
| [Production readiness: operations and release validation](https://github.com/simoesp/pySysPass/milestone/4) | [R13 / #62](https://github.com/simoesp/pySysPass/issues/62), [R14 / #63](https://github.com/simoesp/pySysPass/issues/63), [R15 / #64](https://github.com/simoesp/pySysPass/issues/64), [R16 / #65](https://github.com/simoesp/pySysPass/issues/65) |

GitHub issues are the live work tracker; the findings below preserve the review evidence at `ccfa503`.

## Validation performed

### Implementation follow-up

The first implementation batch is on `fix/production-readiness-foundations`:

- R1 / #50: normalized client addresses, explicit proxy trust, private backend
  ports, and nginx replacement of caller-supplied forwarded addresses.
- R10 / #53: fail-fast production key validation using effective environment or
  `.env` values; production defaults to non-debug mode.
- R12 / #54: security headers inherited by SPA and asset responses, verified
  against the built frontend container and added as a CI check.
- R6 / #57: shared password-replacement logic sets PHP migration flags; recovery
  tests start with PHP-authored master-password ciphertext.
- R8 / #58: immediate mitigation disables unsafe online rotation and removes its
  UI form. Complete rotation functionality is still outstanding.

Validation for this batch: 305 backend tests passed on the host and in the
Python 3.11 image, with the same two external-fixture skips. After adding the
explicit spoofed-header lockout regression, all 11 security tests passed.
Frontend tests passed (22), lint had no errors (523 existing warnings), both
images built, all three Compose files parsed, and nginx header checks passed
for `/`, `/index.html`, `/login`, and a built asset. Ruff and Bandit passed.
Graphify's AST update completed; SQL extraction remains unavailable because
`tree_sitter_sql` is not installed, and document semantics were not regenerated.

This is a partial implementation, not production approval. The findings below
remain the original review evidence; all other milestone work remains open.

### Original review results

| Check | Result |
| --- | --- |
| Graphify architecture query | Completed; followed with direct source inspection |
| Ruff, CI scope | Passed |
| Backend suite, isolated Python 3.12 environment | 293 passed, 2 skipped; 70.73% statement coverage |
| Backend suite, built Python 3.11 image | 293 passed, 2 skipped, 3 deprecation warnings |
| Frontend tests | 6 files / 22 tests passed |
| Frontend lint | No errors; 524 warnings |
| Frontend production build | Passed; large-chunk warning |
| Backend and frontend Docker builds | Both passed |
| Bandit, medium/high severity | No findings |
| pip-audit against requirements | No known vulnerabilities reported |
| npm audit against lockfile | No known vulnerabilities reported |
| Gitleaks with repository allowlist | No leaks reported across 69 local commits |
| Canonical schema on MySQL 8 | Bootstrap passed: 27 tables and 2 queryable views; second bootstrap made no changes |
| MySQL account creation probe | Failed on API-accepted missing client: `Column 'clientId' cannot be null` |
| Built nginx response probes | SPA routes lacked CSP, frame protection, and nosniff headers |
| Built backend recovery probe | No mysql/mysqldump binaries; restore into mounted data directory failed |

The first host test run failed because `pykeepass` was absent from the host environment. Installing the declared `pykeepass==4.2.0` in an isolated environment resolved it; this was not counted as an application defect. The two skipped tests require the absent sibling PHP checkout: schema snapshot freshness and an external KeePass fixture. Existing committed PHP crypto, ACL, and public-link fixtures ran.

Scanners passing means no findings from those tools and their configured scope, not that the application is secure. Container OS vulnerability scanning and a full browser acceptance suite were not performed.

## Release blockers

### R1 — High: client-IP spoofing defeats login lockout attribution

Evidence: `app/api/v1/auth.py:27`, `app/main.py:64`, `app/main.py:109`, `podman-compose.external.yml:25`, `portainer-stack.yml:42`.

Login and audit code trust caller-supplied `X-Real-IP` / `X-Forwarded-For`, and middleware trusts every proxy. All supplied stacks publish the backend port. A direct client can select its apparent IP, rotate it to evade IP-based login locks, and falsify audit attribution. An isolated request from `198.51.100.1` with `X-Real-IP: 192.0.2.99` was attributed to `192.0.2.99`.

Make the backend private, trust only the actual proxy network, and consume the normalized client address instead of raw headers. Verify that both direct and proxied spoofed headers cannot change the lockout identity.

### R2 — High: backup creation can succeed without the database

Evidence: `Dockerfile:6`, `app/services/backup_service.py:62`, `app/services/backup_service.py:151`, `app/api/v1/backup.py:42`.

The built backend has neither `mysqldump` nor `mysql`. Requested database backup failure becomes `db_included: false` while archive creation still succeeds. The isolated no-client/no-data probe returned a 22-byte empty ZIP. Database restore is also unavailable in this image.

Install compatible database clients and fail a requested database backup if it cannot be produced. Require a consistent snapshot strategy, archive validation, secure off-host retention, and an actual restore rehearsal. The current dump command has no explicit `--single-transaction` strategy for concurrent InnoDB writes.

### R3 — High: restore fails with the supplied persistent-data layout

Evidence: `app/services/backup_service.py:244`, especially lines 261–273; `podman-compose.external.yml:23`.

Restore renames `./data` to a rollback directory under `./backups`. In the provided deployment, `data` is a mounted volume. A probe in the built image with mounted `/app/data` failed with `Errno 16: Device or resource busy`. A different-filesystem rename may also fail. The database restore precedes this step, so a full restore can leave the database changed but files unrestored.

Stage and restore within the supported volume layout, preflight prerequisites before changing either database or files, and define coordinated rollback. Test recovery with the exact deployment mounts and real database payloads.

### R4 — High: accepted account data violates the PHP schema

Evidence: `app/schemas/account.py:35`, `app/services/account_service.py:445`, `tests/compatibility/test_schema_parity.py:30`.

The request model permits omitted client/category IDs and the service writes `None`. The canonical MySQL schema rejects that data. This was reproduced against a freshly bootstrapped MySQL 8 database: minimal account creation raised error 1048 for `clientId`. SQLite tests allow this because ORM nullability differs from PHP; explicit parity exceptions preserve that difference.

Validate required PHP relationships at the API boundary and supply valid reference rows in fixtures/imports. Do not loosen the PHP schema. Test CRUD and imports against canonical MySQL, including missing and invalid reference IDs; return validation errors instead of database errors.

### R5 — High: new writes still use Python-only ciphertext formats

Evidence: `app/services/import_export_service.py:47`, CSV import around line 156, KeePass import around line 422, `app/services/account_service.py:450`, `app/api/deps.py:87`, `app/services/public_link_service.py:18`.

CSV/KeePass imports and account writes without a vault master password use the local AES fallback and an empty `Account.key`, rather than native Defuse credentials. API-token authentication deliberately supplies no master password, while action 5/6 permits account creation/editing. The native PHP reader cannot be assumed to understand those newly persisted values. Public-link creation also remains in the documented legacy Python format.

This conflicts with the project's hard requirement for PHP-compatible persisted semantics. Require native-compatible writes or reject unsupported operations. Retain legacy readers without silently rewriting existing data. Gate release on Python-to-PHP round trips for account credentials, imports, links, and plugin data; matching table names alone does not establish format compatibility.

### R6 — High: password reset skips vault migration

Evidence: `app/services/password_reset_service.py:106`, `app/services/user_service.py:98`, compared with `app/services/user_service.py:130` and `app/api/v1/auth.py:246`.

Reset replaces the login hash without setting the existing PHP migration flags or rewrapping master-password material. The generic user-update password path has the same omission. A reset probe left `isChangedPass` false; login with the new password plus the correct old password returned `MASTER_PASSWORD_REQUIRED` instead of migrating the vault. Users without the shared master password can lose their normal recovery path.

Use the existing PHP-compatible password-change/migration flow consistently. Cover self-service reset, administrator edits, and old-password recovery with PHP-authored user ciphertext. Do not add Python-only user columns.

### R7 — High: reset/logout do not revoke sessions; timeout is ignored

Evidence: `app/services/auth_service.py:124`, `app/api/v1/auth.py:281`, `app/api/deps.py:108`, `frontend/src/stores/index.js:28`, `app/services/config_service.py:80`.

Tokens last 24 hours. Authorization checks current user existence/enabled state and roles, but has no password-change or session-revocation check. A JWT minted before password reset still received HTTP 200 from `/auth/me` afterward. Logout only removes the local token; a copied bearer remains usable. The exposed `session_timeout` setting is not consumed by authentication.

Implement revocation and the configured timeout using a PHP-compatible design or external ephemeral session state. Define behavior for password reset, password change, logout, key changes, and 2FA enrollment. Continue rechecking current permissions as the code already does.

### R8 — High: encryption rekey breaks active runtime access

Evidence: `app/api/v1/config_settings.py:256`, `app/api/v1/config_settings.py:319`, `app/core/security.py:45`.

Rekey rewrites legacy account/history ciphertext and stores a new key in `Config`, but runtime encryption continues using `settings.ENCRYPTION_KEY`. A successful one-account rekey probe immediately made the account unreadable through `get_encryption_service()`; the supplied new key could decrypt it. The route also does not rotate other consumers such as 2FA vaults and legacy public-link passwords. Native Defuse records are passed through the fallback decryptor, causing the operation to fail rather than providing native rotation.

Disable this operation until it has a complete, format-aware, recoverable rotation design with coordinated runtime activation and all dependent secrets covered. Maintenance mode currently provides no write exclusion (R9). Do not migrate PHP ciphertext as part of an unrelated fix.

### R9 — High: security controls shown in settings are not enforced

Evidence: `frontend/src/views/SettingsPage.vue:62`, `app/services/config_service.py:80`, `app/api/v1/files.py:31`, `app/schemas/file.py:5`.

Source tracing found storage/UI wiring but no runtime enforcement for Force HTTPS, maintenance mode, file enablement, configured file size, or allowed extensions. Upload accepts caller-declared size and unbounded base64 content. The session-timeout problem is covered by R7. The UI even advises enabling maintenance mode before rekey, although requests remain writable.

Implement and test these controls or remove misleading controls until supported. Enforce decoded upload size and configured restrictions server-side, with transport-level limits as an additional boundary. Configure actual TLS termination before exposing the application; RSA wrapping is not a substitute for HTTPS.

### R10 — High: production can start with unstable or empty keys

Evidence: `app/core/config.py:42`, `app/core/config.py:81`, `portainer-stack.yml:34`.

Absent keys are generated per process; non-debug validation only warns. Empty environment values are likewise not rejected. Missing keys can therefore yield incompatible workers, invalid sessions after restart, or loss of access to data encrypted under a previous transient key. The external compose template requires nonempty variables, but the application and Portainer template do not provide equivalent enforcement.

Fail startup on missing, empty, or known sample production keys. Validate runtime configuration before reporting readiness. Document secret backup and recovery. Avoid treating an environment-presence warning as validation of effective settings, including `.env` values.

### R11 — High: runtime state and backups are not consistently durable

Evidence: `portainer-stack.yml:27`, `portainer-stack.yml:41`, `app/api/v1/backup.py:17`, both compose volume lists.

Portainer mounts only MySQL storage; backend runtime JSON and RSA data live in the container layer. Recreating the backend loses locally updated mail/LDAP/runtime configuration and RSA state. Neither application compose stack persists `/app/backups`, so locally created backup archives disappear on container replacement. The external compose stack correctly persists `/app/data`, but does not solve backup persistence.

Provide persistent volumes for required runtime state and backup staging, plus independently managed off-host backups. Rehearse container replacement and bare-environment recovery, including externally supplied encryption keys and password salt.

## Additional production requirements

### R12 — Medium: SPA security headers disappear in nginx

Evidence: `frontend/nginx.conf:29` and `frontend/nginx.conf:33`.

Location-specific `add_header Cache-Control` overrides inheritance of server-level headers. Requests to `/`, `/index.html`, and `/login` in the built image returned HTTP 200 and `Cache-Control: no-store`, but no CSP, X-Frame-Options, or X-Content-Type-Options. This is consistent with the [nginx header inheritance rules](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header).

Apply the full header set at the effective locations and assert response headers in container tests. The pinned nginx 1.27 configuration cannot use newer inheritance directives without a version change. Tokens in localStorage make retaining XSS defenses especially important; this finding does not itself establish an exploitable XSS.

### R13 — Medium: health checks do not establish readiness

Evidence: `app/main.py:191` and all stack health checks.

`/health` always returns healthy. A probe with no configured database returned 200. With automatic initialization disabled, the service can appear ready while database-backed requests fail.

Separate liveness from readiness. Check database connectivity, supported schema, required secrets/configuration, and essential storage with bounded timeouts. Return a non-success readiness response when prerequisites fail.

### R14 — Medium: build context can include secrets; runtime is root

Evidence: `Dockerfile:17`, `.dockerignore`, `Dockerfile:23`.

`COPY . .` includes files not excluded by `.dockerignore`, which omits `.env*`, `data/`, `backups/`, and runtime configuration. Those paths can contain credentials and private keys on a deployed checkout. This is a conditional packaging risk; the review did not establish an actual leaked image. The built backend runs as UID 0 and retains build tools and test dependencies.

Use an explicit application allowlist/build context, exclude local secrets and runtime state, and run under an unprivileged account. Pin the resolved Python dependency set and image digests for reproducible releases; current lower bounds and floating tags can change the deployed artifact without a source change.

### R15 — Medium: runtime config writes are not atomic

Evidence: `app/core/runtime_json_config.py:116`, `app/core/runtime_json_config.py:137`, `app/services/config_service.py:32`.

Each setting update reads and overwrites the entire JSON document; bulk updates repeat this operation. There is no atomic replacement or cross-process lock. Concurrent workers can lose updates or observe a truncated document, and interrupted writes can prevent future config reads. Mail/LDAP credentials also rely on ambient filesystem permissions.

Use a locked read-modify-write transaction, atomic file replacement, explicit restrictive permissions, and a recoverable validation failure. Test concurrent writers and interrupted writes without changing PHP config semantics.

### R16 — Medium: operational and verification coverage is incomplete

Evidence: `app/main.py:149`, `app/services/password_reset_service.py:84`, `app/services/task_service.py:210`, `.github/workflows/ci.yml`.

Audit failures and reset-email failures can be silently discarded. The global scheduler starts without registered jobs or a database session; its existence does not establish automated backups or expiry notifications. Synchronous database, bcrypt, file/archive, and subprocess work runs inside many async routes, including login and backup, so the default single worker can stall other requests during slow operations. No load or failure-budget result was established.

CI has useful lint, security, frontend, and schema-bootstrap gates, but no full MySQL CRUD/auth/import suite, container recovery test, browser acceptance suite, or coverage threshold. Local statement coverage was 70.73%; password-reset service coverage was 30%, consisting of imports and definitions rather than the recovery flow. The two external-fixture skips mean complete upstream parity was not verified. The compatibility checklist also contains stale text about Python-only history columns although the current column exception map is empty.

Add observable failures and alerting, explicit background-job ownership, suitable execution boundaries for blocking work, and release tests for the findings above. Pin PHP fixtures and test reverse round trips. Update documentation from verified evidence, not historical completion claims.

## Release gate

1. Resolve R1–R11 with focused regression tests and no PHP schema extensions.
2. Verify the hardened stack under TLS, including effective headers, private backend access, stable keys, readiness failure, and durable state after replacement.
3. Run canonical-MySQL CRUD/auth/import/export tests and PHP bidirectional fixtures. Eliminate unexplained compatibility skips.
4. Complete backup/restore and key-recovery rehearsals using mounted volumes, realistic data, and an isolated replacement environment; record recovery time and acceptable data loss.
5. Exercise critical browser flows and representative concurrent load, including slow database/email/backup operations. Establish alerting and rollback procedures.

The review covered source, configuration, local tests, dependency/secret scans, image builds, selected runtime probes, and canonical schema bootstrap. It did not certify an external deployment, conduct a live penetration test, test real SMTP/LDAP services, or establish capacity and disaster-recovery objectives. No production database was accessed.

## Recovery implementation follow-up

Draft PR #66 now addresses R2, R3, and R11: requested dumps fail closed,
archives publish only after validation, dump/import clients ship in the backend,
and all supplied stacks persist runtime state and archives. Web restore is blocked;
the offline command stages files on the destination filesystem, preserves mounted
directory roots, and attempts database/file rollback with retained recovery material
when rollback fails. See [the recovery procedure](../backup-recovery.md), including
migration of existing Portainer files and nontransactional SQL limitations.

Validation: 313 backend tests passed, two external PHP fixture tests skipped;
frontend production build passed. An actual MySQL 8 canonical-schema dump/import
restored a changed Category row and a runtime file on a Docker named volume while
preserving the mount root. CI now repeats this rehearsal. This small fixture does
not establish production recovery time, application-wide PHP parity, or large-data
recovery guarantees. Issues remain open until review and merge.

The security gate has an exact historical-fingerprint exception for a synthetic
key in a test; full-history scanning remains enabled. GitHub reported dependency
alerts whose affected ranges exclude the versions in the current frontend lockfile;
the alerts were not dismissed. The earlier dependency audit found no advisories.

R15 follow-up: runtime JSON key updates now use a POSIX file lock across the full
read/modify/write, a same-directory temporary file with mode 0600, fsync, and atomic
replacement. Bulk runtime settings use one transaction. Tests cover 12 concurrent
processes, replacement failure, malformed input preservation, unknown document
sections, and retention of the existing PHP password salt. The supplied Linux
containers support these semantics; shared storage must support POSIX locking and
atomic rename. This does not coordinate external writers that ignore the lock.

R4 / #55 follow-up: account create requires `client_id` and `category_id`, matching
upstream PHP `AccountForm::checkCommon()` and the canonical `NOT NULL` foreign keys.
Missing, zero, or unknown client/category/tag/user/group IDs and values longer than
the PHP columns (name 100, login 50, URL 255 characters; notes 65,535 UTF-8 bytes)
return 422 before any write. Updates validate the same way and leave the account and
its history unchanged. The ORM now declares these columns `NOT NULL`, removing four
nullability parity exceptions, so SQLite tests enforce the PHP rule too. Deleting a
client or category still referenced by an account or history row returns 409 instead
of silently nulling references. CSV and XML imports reject rows without both a client
and a category; KeePass imports use PHP's `KeePass` client and parent-group category,
including entries in the root group. Each import row runs in a savepoint, so one
database error no longer aborts the rest of the import. The account form marks both
fields as required.

Validation: 328 backend tests passed, 6 skipped (the two external PHP fixtures plus
four MySQL tests that need a server). The four MySQL tests passed against a disposable
MySQL 8.0.46 database bootstrapped from `schemas/dbstructure.sql`; against the
previous code they reproduced error 1048 (`clientId` cannot be null) as HTTP 500.
CI's MySQL job now runs them. Frontend tests (22) and build passed; lint has no
errors (523 existing warnings). Ruff and Bandit passed. Remaining limitations: CRUD
coverage on MySQL is limited to the account-reference paths above, not the full API;
the remaining `User`/`UserGroup`/`UserProfile` nullability exceptions are unchanged.

R13 / #62 follow-up: liveness and readiness are separate. `/health` and `/health/live`
still answer 200 while the process serves requests. `/health/ready` returns 503
unless the effective production configuration validates, the runtime JSON config
parses, the database answers `SELECT 1`, every canonical table and both account views
exist, and the data, runtime-config, and backup directories are writable. Each check
has a 3-second timeout and runs in a dedicated four-thread pool, so a hung dependency
fails the probe instead of blocking request threads. Responses contain only check
names and generic reasons. All three stacks' backend health checks now use
`/health/ready` (12-second container timeout), so dependents wait for real readiness.

Validation: 337 backend tests passed, 8 skipped (the two external PHP fixtures plus
six MySQL tests that need a server). The six MySQL tests passed on disposable MySQL
8.0.46: an empty database, a bootstrapped one, a dropped view, and a refused
connection. Ruff and Bandit passed; the three Compose files parsed. Limitations: the
schema check confirms canonical tables and views exist; it does not compare column
definitions, migration revision, or encrypted data. A hung database connection may
hold a pool thread until the driver's own connect timeout.

R14 / #63 follow-up: the backend build context is an allowlist (`.dockerignore` denies
everything, then re-includes application code, schemas, Alembic files, the lock, and
`config/cors-origins.json`), and the Dockerfile copies the same explicit paths. The
image installs the hash-pinned `requirements.lock` (48 packages, Python 3.11, universal
markers) with `--require-hashes`. Test tools moved to `requirements-dev.txt`. Compiler
and header packages were removed. The service runs as UID/GID 10001 with read-only
code; only `/app/data` and `/app/backups` are writable. Backend, frontend, MySQL, and
graphify base images are pinned by multi-arch digest; Dependabot now proposes digest
updates. CI tests the locked set, checks that the lock satisfies `requirements.txt`,
audits it with pip-audit, and asserts the image is non-root and free of tests, pytest,
gcc, and runtime config.

Validation: with probe secrets placed in `.env.probe-secret`, `app/.env`,
`data/rsa_private.pem`, and `backups/old.zip`, none reached the built image. Inside the
image: `id -u` is 10001, pytest and gcc are absent, `/app/app` is not writable, and
`mysqldump` is present. The backend suite passed inside the image on Python 3.11 as
UID 10001 (337 passed, 8 skipped), and on the host. Live probes: with an unreachable
database and auto-initialization disabled, `/health` returned 200 and `/health/ready`
returned 503 (`database unreachable`); with MySQL 8.0.46 and a fresh named volume,
readiness returned 200; with a root-owned volume left by an older image, readiness
returned 503 (`data directory not writable`) until the documented one-time `chown`, then
200. The recovery rehearsal passed as UID 10001 on a named volume. The pinned frontend
image passed the SPA header check. pip-audit found no known vulnerabilities in the lock.
Ruff and Bandit passed; all three Compose files parsed.

Upgrade impact: existing volumes created by root images need the one-time ownership
change in `docs/installation.md`; until then readiness fails closed. Limitations: the
frontend nginx master still starts as root; Dependabot does not regenerate
`requirements.lock` (CI fails until it is refreshed); `Dockerfile.security` was not
updated and is not a deployment artifact; no container OS vulnerability scan was run.

R7 / #51 follow-up: session tokens now carry a token ID, issue time, original login
time, and `sfp`, an HMAC of the user's current `User.pass`. Authentication rejects a
token whose fingerprint no longer matches, so a self-service reset, an administrator
change, or a password changed by sysPass PHP ends existing sessions. `POST /auth/logout`
revokes the presented token. Revocations live in `data/sessions.json` (locked, atomic,
mode 0600, pruned at expiry; deployment state, no PHP schema change). Tokens expire
after the configured `session_timeout` (default 300 s, clamped to 60–86,400 s) instead
of 24 hours. `POST /auth/refresh` renews one window and revokes the old token; the SPA
calls it only after user input, so polling does not keep idle sessions alive. No session
outlives 24 hours from login. Enabling or disabling 2FA revokes the user's other sessions;
own-password changes and 2FA changes return a replacement token for the acting
browser. Tokens issued before this change lack these claims and are rejected. A
`SECRET_KEY` change invalidates all sessions; per-request permission rechecks are
unchanged.

Validation: 13 new session tests cover timeout configuration and clamping, expired and
legacy tokens, logout of one of two sessions, refresh rotation and vault retention, the
24-hour cap, reset/admin/PHP-side password changes, self-service rotation, 2FA enable
and disable, API-token refusal, cross-instance revocation, pruning, file mode, and
corrupt-state recovery. Backend suite: 350 passed, 8 skipped (two external PHP fixtures;
six MySQL tests, which passed separately on MySQL 8.0.46). Frontend: 24 tests passed,
build passed, lint 0 errors (523 existing warnings). Ruff and Bandit passed.
Limitations: PHP's per-user `SessionTimeout` item presets are not applied; revocation is
shared only by backends that share `/app/data`; an ENCRYPTION_KEY change leaves sessions
valid without a readable vault key. Separate observation for follow-up: the session
token embeds the user's master password encrypted with unauthenticated AES-CTR under
`ENCRYPTION_KEY`, and browsers keep the token in `localStorage`, so token theft plus
key disclosure exposes the master password.

R9 / #52 follow-up: the controls on the settings page are now enforced server-side.
Settings are read through the same runtime-JSON/`Config` precedence, cached for two
seconds per process; saving settings clears the local cache.

- Force HTTPS: plain-HTTP requests other than `/health*` get a 308 to HTTPS. The check
  runs after trusted-proxy normalization, so a trusted proxy's `X-Forwarded-Proto` is
  honoured and a direct caller's is not. It can be enabled only from an HTTPS request,
  so an HTTP-only deployment cannot lock itself out. TLS must still terminate at a
  proxy; RSA field wrapping is not transport security.
- Maintenance mode: non-admin sign-in (after credential checks), JWT and API-token
  requests, public links, password reset, and registration return 503. Application
  administrators stay admitted, unlike PHP's lock holder.
- Attachments: `files_enabled` gates upload and listing; the decoded upload must not
  exceed `files_allowed_size` × 1000 bytes (1–16,384 KB, PHP's ceiling); oversized
  base64 is refused before decoding; invalid base64 returns 400; the extension comes
  from the file name (upper-cased, as in PHP) and must be in `files_allowed_exts` when
  that list is set. Caller-declared size and extension are ignored. File names follow
  PHP's 100-character column.
- Transport: nginx allows 24 MB API bodies (the previous 1 MB default rejected uploads
  near the default limit) and the backend refuses larger `Content-Length` with 413.
- `GET /tags/{id}` required no authentication; it now requires a session like the other
  tag routes.

Validation: 13 new tests cover each control, including spoofed and trusted
`X-Forwarded-Proto`, middleware order, and the HTTPS enable guard. Backend: 363 passed,
8 skipped. Frontend: 24 tests and build passed; lint 0 errors (526 warnings, 3 new ones
of the existing attribute-style classes in `SettingsPage.vue`). The rebuilt nginx image
returned 413 for a 25 MiB API body, forwarded a 2 MiB body, and passed the header check.
Ruff and Bandit passed. Limitations: other workers see setting changes within two
seconds; extension checks do not inspect content (PHP checks MIME); maintenance does
not stop external PHP writers; configuring real TLS remains a deployment task.

R5 / #56 follow-up: pySysPass no longer writes Python-only credential formats.
Account create, password change, and copy, plus CSV/KeePass/XML imports, encrypt with
Defuse under the vault master password, as PHP `Crypt::encrypt()` does. Without an
unlocked vault (API tokens, or sessions whose vault could not be opened) these writes,
password reads, and imports return `428 MASTER_PASSWORD_REQUIRED` instead of falling
back. Native rows are never handed to the legacy decryptor; previously such a read
raised a 500. A supplied XML target master must match `masterPwd`. Public links are
created natively: a PHP-serialized `Vault` over the `AccountExtData` snapshot that
`getDataForLink()` yields, keyed by `PublicLinkKey`, with PHP's 30-byte hex hash and
`publinks_max_time` lifetime. Creation honours `publinks_enabled` like the PHP UI.
Access passwords on new links are rejected because PHP has no such field. Legacy
Python rows and links remain readable and are not rewritten. Failed decryptions no
longer increment `countDecrypt`.

Validation: re-serializing the PHP-authored fixture reproduced both the outer Vault and
the inner AccountExtData bytes exactly. In `php:8.2-cli` with upstream sysPass
`9d0e169` and Defuse v2.4.0, PHP's `Crypt::decrypt`, `Vault::getData`, `PublicLinkKey`,
and `Util::unserialize` decoded all seven Python credential writes (API create, update,
copy, whitespace password, CSV, KeePass, XML) and a Python-created link with exact
field values. As a negative control, the same PHP code rejected the previous Python
formats (`BadFormatException`; link data not a Vault). This round trip is now the CI job
"PHP reads Python writes". Backend: 370 passed, 9 skipped (two external fixtures; six
MySQL and one PHP test that need their runtimes, all passing separately). Frontend tests
and build passed. Ruff and Bandit passed. Remaining: built-in 2FA state still uses a
Python format in the PHP `Authenticator` plugin row; the round trip uses PHP's class
library, not the PHP web UI; PHP API-token vaults (`AuthToken.vault`) are not read, so
token callers cannot write credentials; link refresh is not implemented.

R8 / #58 follow-up: online rekey stays disabled. The vault master password now changes
offline through `python -m app.rotate_master_password`, which follows PHP
`MasterPassService::changeMasterPassword()`: it rotates `Account.pass/key`,
`AccountHistory` rows whose `mPassHash` matches `masterPwd`, and encrypted
`CustomFieldData`, then sets `masterPwd` (PHP `Hash::hashKey`) and `lastupdatempass`.
It requires maintenance mode, as PHP does, and an explicit `--confirm-stopped`. It proves
every value decrypts with the current master before writing; any failure aborts, where
PHP would skip the row. It takes a fail-closed full backup, rewrites in one transaction,
verifies with the new master before commit, retires temporary master passwords, and ends
all pySysPass sessions. Legacy pySysPass AES rows are converted only with
`--include-legacy`.

The work exposed and fixed a live PHP-compatibility bug: sign-in ignored
`lastupdatempass` and never checked the unlocked master against `masterPwd`. After a
master change made in PHP, pySysPass would have kept unlocking users' stale master copies
and encrypting new data with the old master. Sign-in now follows PHP `loadUserMPass()`
and asks for the master password again. `masterPwd` hashing now matches PHP
`Hash::hashKey()` for keys longer than 72 characters (Python bcrypt previously raised).

Validation: 11 rotation tests start from the PHP-authored 3.2.11 vault. They cover full
rotation, skipped old-master history, the custom field, preconditions, maintenance,
undecryptable-value abort, legacy conversion, write-failure rollback, PHP MPASS_CHANGED
login behaviour, long-key hash parity, and the CLI with session revocation. Upstream PHP
(9d0e169, Defuse 2.4.0) decrypted the Python-rotated account and history row with the new
80-character multibyte master and accepted its hash, while rejecting the old master. On
MySQL 8.0.46 a failure injected mid-rotation left all rows readable with the old master.
A full rehearsal in the non-root backend image against MySQL (25 accounts) refused a wrong
master with no backup or writes, then wrote a backup, rotated and verified all 25, and
revoked every session. Restoring the reported backup brought back the old-master vault.
Limitations: there is no online or zero-downtime rotation; `ENCRYPTION_KEY` rotation
(legacy rows, 2FA state, session claims) is still unsupported; PHP's per-run task progress
UI and "hash only" option are not offered; the rehearsal used a small dataset, so
large-vault duration is unmeasured.

R16 / #65 partial follow-up: audit-write and reset-mail failures are logged at ERROR and
counted per worker; `GET /api/v1/security/operations` (admins) reports the counts and the
scheduler state. The empty scheduler thread no longer starts, and the docs say plainly
that backups and expiry notices are not automated. Sign-in is now a threadpool route, and
audit writes run in the threadpool. (Correction: the original concurrency test used
`TestClient`, which gives each thread its own event loop, so it could not detect blocking.
It was replaced in the third follow-up below.) CI enforces a 75% coverage floor; measured coverage is 76%
(was 70.73%), and the password-reset service is at 81% (was 30%). New CI gates added on
this branch: MySQL API/import/readiness tests, the PHP reverse round trip, image
hardening, and the lock check. The SPA header check now retries connection resets during
nginx start-up (a CI flake seen on 02a198c).

Still open for #65: no load or failure-budget test; no browser acceptance suite; no
full-API MySQL suite; many async routes still do synchronous database work; alerting
depends on external log monitoring; the two external PHP fixture skips remain.

R5 / #56 second follow-up (2FA state): pySysPass now writes the sysPass Authenticator
plugin's own format, one `PluginData` row per enrolled user holding
`serialize(AuthenticatorData)` encrypted under the vault master password, instead of a
Python JSON/AES document. Sign-in checks 2FA after the vault is unlocked, as PHP's
`login.finish` hook does. 2FA changes need an unlocked vault (`428` otherwise). Pending
enrollment secrets are kept in `data/` rather than the PHP table. Secrets and recovery
codes use PHP's formats. The 2FA policy moved from `Plugin.data` (which PHP's plugin
upgrade unserializes) to runtime JSON, and created `Plugin` rows record PHP's
`versionLevel`.

Validation: with upstream sysPass `9d0e169`, Defuse 2.4.0, and plugin-Authenticator
`b304661` in `php:8.2-cli`, PHP decoded a pySysPass enrollment, including a consumed
recovery code, and `Google2FA::verify_key` accepted a current TOTP from it. A PHP-authored
`AuthenticatorData` fixture (`tests/fixtures/php_authenticator_plugindata.json`,
generator in `scripts/`) decodes in Python, re-serializes to identical bytes, and works for
sign-in with TOTP and a single-use recovery code. The byte test caught a real type
mismatch: PHP stores `twofaEnabled` as an int. CI's PHP job now covers the plugin.
Remaining: legacy pySysPass 2FA rows are read but not converted; PHP's expiry warnings are
not shown; the round trips use PHP class libraries rather than the PHP web UI.

R16 / #65 second follow-up (full MySQL suite): every backend test can now run on MySQL 8
against a disposable database bootstrapped from `schemas/dbstructure.sql`, rather than ORM
metadata on SQLite. `tests/conftest.py` switches on `PYSYSPASS_SUITE_MYSQL_URL` and resets
the tables between tests. A new CI job runs the full suite this way, together with the
dedicated MySQL tests. The first run found 51 tests whose data the canonical schema rejects:
users without the PHP-required name, profile, or salt; groups, users, and custom-field types
that did not exist; and a test that set a user's profile to NULL. The application's own
creation paths already set these values. With the test data fixed, the ORM now declares
`User.name`, `User.userProfileId`, and `User.hashSalt` `NOT NULL` like PHP, removing three
more nullability exceptions.

Validation: 390 passed, 12 skipped on MySQL 8.0.46 (6 min 53 s) and on SQLite. The skips
are the 2 external PHP fixtures plus 10 tests that need the PHP runtime or a dedicated
MySQL URL; both run in CI. This is full-suite coverage on MySQL, not new endpoint coverage:
routes without tests are still untested on either database.

R16 / #65 third follow-up (event-loop blocking): 181 API handlers were `async def` but
never awaited anything, so their synchronous database, bcrypt, Defuse, and file work ran
on the event loop and stalled every other request. They are now plain `def` routes,
which FastAPI runs in its threadpool. The three upload imports stay `async` to read the
file, but run parsing, per-row encryption, and writes in the threadpool. A static test
fails if an `async` route without an `await` is reintroduced.

Validation: two tests serve the app with a real uvicorn server, sharing one event loop,
and time a `/ping` while a 1.5-second sign-in or category listing is in flight. With the
fix, `/ping` answers in under a second. With the route temporarily reverted to
`async def`, both tests fail, so they detect blocking. Backend suites passed on SQLite and
MySQL. Remaining: threadpool size (anyio default, 40 threads) bounds concurrent blocking
requests per worker, and no load test has measured capacity.

R8 / #58 and R5 / #56 follow-up (ENCRYPTION_KEY rotation and legacy formats):
`python -m app.encryption_key` reports (`check`), converts (`migrate`), and finalizes
(`end-sessions`) an `ENCRYPTION_KEY` change. `migrate` requires maintenance mode,
`--confirm-stopped`, the master password (checked against `masterPwd`), and a successful
backup. In one transaction it rewrites legacy account and history passwords as Defuse
ciphertext under the master, with the current `mPassHash`, and legacy 2FA documents as
native `AuthenticatorData`. Unconfirmed legacy setups are dropped, since PHP would have no
row. It verifies each value before commit. Legacy public links are never converted:
they showed metadata only, while native links reveal the password. They block migration
until `--drop-legacy-links`. After migration nothing persisted depends on `ENCRYPTION_KEY`;
it protects only session claims and pending 2FA setups, which `end-sessions` retires.

Validation: 5 tests cover the inventory, refusing to convert links, conversion, wrong
master or key with no writes, and the CLI. Upstream PHP decoded a migrated account and 2FA
row. A rehearsal in the backend image against MySQL 8 seeded 20 legacy accounts and a
legacy 2FA row under key A: `check` reported 21; `migrate` took a backup and converted
all 21; `check` then reported 0; after switching to key B and `end-sessions`, all 20
accounts and the 2FA secret were readable. Remaining: rotation is offline; SECRET_KEY
rotation is only `end-sessions` plus the new value.

R16 / #65 fourth follow-up (load test): `scripts/load_test.py` drove a production-like
stack (nginx → backend → MySQL 8, `DEBUG=false`) with a mixed authenticated workload; see
`docs/project/load-test-2026-10-24.md`. The first run exposed an N+1 query pattern:
account lists and search issued about five queries per account, so listing took 3.3 s
(p50) at 10 users and throughput was 5.1 req/s. Listing now eager-loads tags and shares
and caches users, groups, and favourites per request: 10 queries regardless of page size,
pinned by a test that fails on the old code. The same run then reached 49.3 req/s with list
p50 148 ms. At 30 users with a mid-run backup, one worker held 46.5 req/s with p95 near
1 s; four workers (`WEB_CONCURRENCY`) reached 133.6 req/s with p95 300–520 ms. All runs
had zero errors, and the backup took about 2.6 s during load. Limits: one host, datasets
under 1,000 accounts, no remote-database latency, no slow SMTP/LDAP, no soak test.

R16 / #65 fifth follow-up (browser acceptance): `e2e/` holds a Playwright suite (pinned
`@playwright/test` 1.64.0, own lockfile, audited in CI) that drives the built frontend
through nginx against MySQL 8 and the production backend image (`scripts/e2e-stack.sh`).
It covers sign-in, creating an account through the dialog (category and client
selection), revealing the password through the clipboard, and signing out. After sign-out
the copied bearer token is rejected by the API (401). It also checks failed sign-in,
redirects from protected routes, and the CSP/frame headers on SPA routes. All 3 tests
passed locally in Chromium (8 s); the new CI job runs them and keeps traces on failure.
Remaining: 2FA enrollment, settings, imports, and the admin pages have no browser
coverage, and only Chromium is tested.

R5 / #56 follow-up (PHP web UI): sysPass PHP itself, not only its class library, now
reads pySysPass writes. `scripts/php-interop-stack.sh` installs the official
`syspass/syspass:3.2.11` image (digest-pinned) with the PHP installer on MySQL 8 (native
password auth, which PHP 7.3 requires). pySysPass then joins that PHP-created database
with the PHP password salt and no bootstrap; readiness reported the canonical schema as
ready. In `e2e/php-interop/`, pySysPass signs in as the PHP-created admin, which unlocks
the PHP-authored `mPass`/`mKey`, and writes an account and a native public link through
its API. PHP's `viewLink` page then rendered the snapshot with the password, client and
category, and incremented `countViews` and the account's view and decrypt counters. PHP's
own sign-in, search, and `account/viewPass` dialog decrypted and showed the password. The
test passed locally and runs in a new CI job. A second test exports an account as password-protected XML
through pySysPass and deletes it there. It then imports the file through PHP's own Import
screen and confirms that PHP's view-password dialog decrypts the imported copy. A third test installs the pinned sysPass
Authenticator plugin into the PHP container, registered with Composer's autoloader as a
real plugin install would. It enrolls the PHP admin through pySysPass: PHP's sign-in then
redirected to the plugin's 2FA step, rejected a wrong code, and accepted a current TOTP
and a pySysPass recovery code. The suite passed three consecutive runs locally and runs
in CI.

R5 / #56 and R9 / #52 follow-up (item presets): pySysPass stored presets in a format
PHP ignores and never applied them, while its API documentation claimed admin-only
writes and PHP resolution. The write routes accepted any signed-in user: the
`require_admin` helper in `item_presets.py` was a no-op. Now:

- Rows use PHP's types, PHP-serialized `SP\DataModel\ItemPreset\*` objects, and PHP's
  hash. A PHP-authored fixture covering all four types round-trips byte for byte with
  matching hashes. In CI, PHP's `ItemPresetData::hydrate()` and getters read
  pySysPass-written presets.
- Lookup matches PHP `getByFilter()`: user, primary or secondary group, or profile, with
  the highest priority plus scope bonus winning. A scope is required.
- Fixed presets are enforced like PHP. A `session.timeout` preset sets the session
  lifetime when the client address is in its network. `account.private` sets the privacy
  flags. `account.permission` adds default shares, excluding the editor and their group.
  `account.password` rejects passwords that miss the policy (422) and sets the expiry when
  `account_expire_enabled`.
- Management requires `mgm_items_preset`. The context endpoint returns only the caller's
  own preset.

Legacy pySysPass rows are listed as legacy and never applied until resaved. Password
`score` and `use_image` are kept for PHP but not enforced. Validation: 9 preset tests
plus a PHP round trip; 407 backend tests passed; MySQL subset and both browser suites
passed. This round also fixed a CI startup race: the stack scripts waited for MySQL over
its socket, which its first-run init server accepts before restarting. They now wait
over TCP and keep the backend container for logs.
