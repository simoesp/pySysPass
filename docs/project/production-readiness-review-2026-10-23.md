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
