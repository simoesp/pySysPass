# ADR-0016 — Database Schema Ownership and Migration Governance

## Status

**Status:** Active

## Context

pySysPass shares a database with sysPass PHP. The schema is a compatibility contract (ADR-0002), yet multiple mechanisms (bootstrap, Alembic, schema guard, `python_init.sql`) attempt to manage it. This ADR reconciles these mechanisms against the verified implementation.

**Investigation sources:**
- `schemas/dbstructure.sql` — 18 PHP tables + 2 PHP views (single bootstrap source)
- `schemas/python_init.sql` — **unused** (zero code references; legacy)
- `app/db/bootstrap.py` — bootstrap DDL (CREATE TABLE IF NOT EXISTS from dbstructure.sql), serialization via `GET_LOCK`/`fcntl`, `database_requires_bootstrap()`
- `app/db/base.py` — schema guard (`before_cursor_execute` event), `GuardedSession`, `apply_php_mysql_table_options()`
- `alembic/env.py` — reads `settings.DATABASE_URL`, metadata guard pattern, **not called at startup**
- `alembic/versions/001_initial_syspass_schema.py` — calls `_load_schema_statements()` from bootstrap (same source)
- `alembic/versions/002_restore_php_account_views.py` — recreates PHP views with `CREATE OR REPLACE`
- `alembic/versions/003_emergency_credentials.py` — Python extension table
- `alembic/versions/004_audit_logging.py` — Python extension tables (4 tables)
- `alembic/versions/005_service_accounts.py` — Python extension tables (3 tables)
- `app/main.py` — startup calls `bootstrap_database_on_startup()` only; **no Alembic upgrade**
- `app/core/config.py` — `AUTO_INIT_DB_ON_STARTUP` (default true), `SQLALCHEMY_SCHEMA_GUARD` (default true)
- `app/services/readiness_service.py` — `check_schema()` verifies table existence only

**PHP migration schema files** (`schemas/3*.sql`): 12 files representing PHP schema version upgrades (e.g., `30018010101.sql` adds `ItemPreset`/`Plugin`/`PluginData` with FKs). **Not referenced by any Python code.**

---

## Decision

### 1. Current Implementation (Verified)

#### 1.1 Schema Sources

| File | Referenced By | Purpose |
|------|---------------|---------|
| `schemas/dbstructure.sql` | `bootstrap.py:27`, `alembic/001` | **Canonical** PHP table definitions (18 tables + 2 views + 1 Config seed) |
| `schemas/python_init.sql` | **Nothing** (dead code) | Legacy duplicate; should be removed or documented as deprecated |
| `schemas/3*.sql` (12 files) | **Nothing** in Python code | PHP migration increments; informational only |

#### 1.2 Migration Path (Actual)

```
Application Startup (main.py:94)
    │
    ├── validate_production_settings()     ← env/config validation
    ├── bootstrap_database_on_startup()    ← CREATE TABLE IF NOT EXISTS (guarded by GET_LOCK)
    │   ├── AUTO_INIT_DB_ON_STARTUP check  ← skip if false
    │   ├── database_requires_bootstrap()  ← table EXISTENCE check (not shape/compatibility)
    │   └── execute_schema_statements()    ← raw_connection() (bypasses schema guard)
    │
    └── (manual) alembic upgrade head      ← NOT called at startup
        ├── 001 → same bootstrap SQL
        ├── 002 → CREATE OR REPLACE views
        ├── 003 → emergency_credentials
        ├── 004 → audit_events, audit_archives, audit_retention_policies, audit_access_logs
        └── 005 → service_accounts, service_auth_tokens, service_vault_contexts
```

#### 1.3 Bootstrap vs Alembic Coordination

| Aspect | Bootstrap | Alembic |
|--------|-----------|---------|
| Trigger | Automatic on startup (if `AUTO_INIT_DB_ON_STARTUP=true`) | Manual (`alembic upgrade head`) |
| Source | `schemas/dbstructure.sql` | `001` reuses bootstrap; `003-005` are Python-owned |
| Lock | `GET_LOCK('pysyspass_bootstrap', 300)` or `fcntl` | None (relies on sequential manual execution) |
| Idempotency | `CREATE TABLE IF NOT EXISTS` | Alembic tracks version; `001` has no IF NOT EXISTS guard within `op.execute()` |
| Schema Guard | Bypassed (uses `raw_connection()`) | Bypassed (uses its own engine from `alembic.ini`) |
| Rollback | N/A | `alembic downgrade -1` (per-migration `downgrade()`) |

**Verified finding:** Alembic is NOT invoked by application startup or any Makefile/CI target. It is a manual operator action.

---

### 2. Approved Migration Architecture

#### 2.1 Schema Ownership Boundaries

| Owner | Scope | Modification Authority | Compatibility Contract |
|-------|-------|----------------------|----------------------|
| **PHP (shared)** | 18 base tables + 2 views + `Config` seed data | PHP upgrades; pySysPass bootstrap mirrors definitions | pySysPass MUST NOT rename/drop/retype PHP columns |
| **Python (extension)** | `emergency_credentials`, `audit_*`, `service_*` tables | Alembic versioned migrations | PHP MAY ignore; no FK from PHP tables to Python tables |
| **Shared** | `Config` table | Both read/write; Python does not change schema shape | Column set must remain PHP-superset |

#### 2.2 Migration Flow (Target)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Migration Execution                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  1. INSTALL (new database)                                           │
│     └── bootstrap_database_on_startup()                              │
│         (CREATE TABLE IF NOT EXISTS from dbstructure.sql)            │
│         + alembic upgrade head (stamp + Python extensions)           │
│                                                                       │
│  2. UPGRADE (existing database)                                       │
│     ├── alembic current          ← detect version                    │
│     ├── backup verification      ← mandatory (see §6)               │
│     ├── alembic upgrade head     ← Python extension migrations       │
│     └── stamp shared schema      ← if PHP schema updated out-of-band │
│                                                                       │
│  3. STARTUP (running application)                                    │
│     ├── validate_production_settings()                               │
│     ├── database_requires_bootstrap() ← table existence only         │
│     ├── (proposed) validate_alembic_version() ← extension check     │
│     └── schema guard active (blocks runtime DDL)                     │
│                                                                       │
│  4. DOWNGRADE / ROLLBACK                                             │
│     ├── alembic downgrade -1     ← extension tables only             │
│     ├── application rollback     ← container image swap              │
│     └── shared schema rollback   ← NOT supported (restore backup)   │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

#### 2.3 Approved Responsibilities

| Responsibility | Component | Status |
|----------------|-----------|--------|
| PHP base schema creation (new DB) | `bootstrap_database_on_startup()` | Verified ✓ |
| PHP base schema upgrade (existing PHP DB) | Manual PHP upgrade + pySysPass bootstrap IF NOT EXISTS | Verified ✓ |
| Python extension table creation | `alembic upgrade head` (versions 003–005) | Verified ✓ |
| Python extension schema upgrade | `alembic upgrade head` (future versions) | Proposed |
| Alembic version check at startup | `validate_alembic_version()` | **Proposed (not implemented)** |
| Schema shape validation | Column existence + FK integrity check | **Proposed (not implemented)** |
| PHP migration SQL application | **Not implemented** (12 `.sql` files unused) | Gap |
| Schema guard | `before_cursor_execute` event blocks DDL | Verified ✓ |
| Migration lock | `GET_LOCK('pysyspass_bootstrap')` for bootstrap only | Partially verified |
| Alembic migration lock | None | **Gap (see §4)** |

---

### 3. Current Implementation Deviations

| Deviation | Severity | Evidence | Required Action |
|-----------|----------|----------|-----------------|
| **`python_init.sql` is dead code** | Low | Zero references in Python codebase | Remove or deprecate |
| **PHP `3*.sql` migration files unused** | Medium | No code reads these files | Document as reference-only; future: auto-apply when schema version behind |
| **No Alembic version check at startup** | **High** | `main.py:94` only calls bootstrap, not Alembic | Add readiness check: `alembic_version` table exists + current >= minimum required |
| **No schema shape validation** | **High** | `database_requires_bootstrap()` checks table existence only, not column types or FKs | Add readiness validation comparing detected schema against `Base.metadata` |
| **Alembic 001 idempotency risk** | Medium | `op.execute(statement)` with `CREATE TABLE` (no IF NOT EXISTS) on already-populated DB | Already mitigated: bootstrap applies first; if Alembic applied first, `001` would fail on existing tables |
| **No migration coordination lock** | Medium | Alembic has no distributed lock; concurrent `alembic upgrade` possible | Implement: MySQL advisory lock in Alembic env.py or operational procedure |
| **Bootstrap bypasses schema guard** | Low (by design) | `execute_schema_statements()` uses `raw_connection()` | Correct: guard protects runtime, not initialization |
| **`databaseVersion` in Config not validated** | Low | Read for display only; never checked against code requirements | Add version detection to readiness |
| **`SQLALCHEMY_SCHEMA_GUARD` bypassed by Alembic** | Low (by design) | Alembic uses its own engine from `alembic.ini` | Correct: migrations need DDL |
| **`AUTO_INIT_DB_ON_STARTUP=true` is default** | Medium | Silently mutates schema on production startup | Should require explicit opt-in for production; validate-only mode proposed |

---

### 4. Proposed Migration Locking Strategy

| Operation | Lock | Scope | Status |
|-----------|------|-------|--------|
| Bootstrap (initial schema) | `GET_LOCK('pysyspass_bootstrap', 300)` | MySQL server-wide | Verified ✓ |
| Alembic migration | `GET_LOCK('pysyspass_alembic', 600)` | MySQL server-wide | **Proposed** (add to env.py) |
| Schema guard (runtime) | N/A (event-based block) | Per-process | Verified ✓ |
| Multi-replica Alembic | Operational runbook: one migration at a time | Process discipline | **Proposed** |

**Gap:** Alembic has no built-in distributed lock. For MySQL deployments, `before_execute` hook in `alembic/env.py` should acquire `GET_LOCK('pysyspass_alembic', 600)`.

---

### 5. Readiness and Validation Requirements

| Check | Current | Required | Status |
|-------|---------|----------|--------|
| Database connectivity | `SELECT 1` | Same | ✓ |
| PHP tables exist | `inspect().has_table()` (18 tables) | Same | ✓ |
| PHP views exist | `VIEW_TABLES.issubset()` | Same | ✓ |
| Alembic version >= minimum | Not checked | Required (extension tables must exist) | ✗ |
| Column shape validation | Not checked | Verify critical columns (e.g., `Account.pass` varbinary(2000)) | ✗ |
| `alembic_version` table exists | Not checked | Required for production deployments | ✗ |
| `Config.databaseVersion` >= supported | Not checked | Required for PHP DB adoption | ✗ |

**Proposed readiness extension:**

```python
def check_schema_version(engine: Engine) -> None:
    """Verify extension schema meets minimum version."""
    if engine is None:
        raise CheckFailedError("database not configured")
    inspector = inspect(engine)
    # Extension tables required for functionality
    if "emergency_credentials" not in set(inspector.get_table_names()):
        raise CheckFailedError("Python extension schema not applied (alembic upgrade needed)")
```

---

### 6. Backup Prerequisites (ADR-0013 Reconciliation)

| Migration Type | Backup Required | Verification |
|----------------|----------------|--------------|
| Initial bootstrap (empty DB) | No | N/A (nothing to lose) |
| Alembic upgrade (additive: CREATE TABLE) | Recommended | Verify before destructive ops |
| Alembic upgrade (ALTER TABLE on shared schema) | **Mandatory** | Restorable, encrypted, integrity-verified |
| Alembic downgrade (DROP TABLE) | **Mandatory** | Restorable, encrypted, integrity-verified |
| PHP schema adoption (existing PHP DB) | **Mandatory** | Pre-adoption PHP dump verified |
| Encryption key rotation | **Mandatory** | Old key + backup both available |

Backup must be verified as restorable before relying on it for migration recovery (ADR-0013: integrity + authenticity checks).

---

### 7. Upgrade and Rollback Semantics

| Operation | Scope | Support | Method |
|-----------|-------|---------|--------|
| **Application upgrade** | Container image | ✓ | New image tag, `docker compose up` |
| **Extension schema upgrade** | Alembic | ✓ | `alembic upgrade head` before image swap |
| **Extension schema rollback** | Alembic | ✓ | `alembic downgrade -1` (drops extension tables) |
| **Application rollback** | Container image | ✓ | Previous image tag |
| **Shared schema rollback** | PHP base tables | **Not supported** | Restore database from backup |
| **PHP schema adoption** | Import PHP DB | ✓ | Bootstrap sees existing tables, applies IF NOT EXISTS |
| **PHP rollback (pySysPass → PHP)** | Remove extensions | ⚠️ | Drop Python extension tables; alembic_version table; PHP ignores them |

---

### 8. Schema Guard Contract

```
┌───────────────────────────────────────────────────────────────┐
│                    Schema Guard Behavior                        │
├───────────────────────────────────────────────────────────────┤
│                                                                 │
│  GuardedSession (runtime):                                      │
│    └── before_cursor_execute event                              │
│        └── SCHEMA_STATEMENT_RE matches CREATE/ALTER/DROP/...   │
│            └── SchemaMutationError raised                       │
│                                                                 │
│  Bootstrap (startup, guarded by AUTO_INIT_DB_ON_STARTUP):      │
│    └── execute_schema_statements() via raw_connection()         │
│        └── NOT blocked by guard (by design)                     │
│                                                                 │
│  Alembic (manual):                                              │
│    └── Own engine from alembic.ini                              │
│        └── NOT blocked by guard (different engine)              │
│                                                                 │
│  Contract:                                                     │
│    - Runtime NEVER mutates schema                              │
│    - Bootstrap applies base PHP tables only                    │
│    - Alembic owns extension tables                             │
│    - Neither modifies columns/types of PHP tables              │
│                                                                 │
└───────────────────────────────────────────────────────────────┘
```

---

### 9. Python Extension Schema Inventory

| Table | Alembic Version | Owner | PHP Compatibility | Migration |
|-------|----------------|-------|-------------------|-----------|
| `emergency_credentials` | 003 | Python | PHP ignores; no FK from PHP | Create/Drop safe |
| `audit_events` | 004 | Python | PHP ignores; reads `EventLog` | Create/Drop safe |
| `audit_archives` | 004 | Python | PHP ignores | Create/Drop safe |
| `audit_retention_policies` | 004 | Python | PHP ignores | Create/Drop safe |
| `audit_access_logs` | 004 | Python | PHP ignores | Create/Drop safe |
| `service_accounts` | 005 | Python | PHP ignores | Create/Drop safe |
| `service_auth_tokens` | 005 | Python | PHP ignores | Create/Drop safe |
| `service_vault_contexts` | 005 | Python | PHP ignores | Create/Drop safe |

All extension tables use singular English identifiers (glossary compliant) and `utf8mb4_unicode_ci` collation.

---

### 10. PHP Base Schema Inventory

| Table | Role | Python May Read | Python May Write | Python May DDL |
|-------|------|-----------------|------------------|----------------|
| `User` | Identity | ✓ | ✓ (profile updates) | ✗ |
| `UserGroup` | Access control | ✓ | ✓ | ✗ |
| `UserProfile` | Authorization | ✓ | ✗ (PHP-owned semantics) | ✗ |
| `Account` | Credentials | ✓ | ✓ | ✗ |
| `AccountHistory` | Audit trail | ✓ | ✓ (append) | ✗ |
| `AccountToTag` | Tag association | ✓ | ✓ | ✗ |
| `AccountToFavorite` | User favorites | ✓ | ✓ | ✗ |
| `AccountToUser` | Sharing | ✓ | ✓ | ✗ |
| `AccountToUserGroup` | Group sharing | ✓ | ✓ | ✗ |
| `Category` | Classification | ✓ | ✓ | ✗ |
| `Client` | Organization | ✓ | ✓ | ✗ |
| `Tag` | Classification | ✓ | ✓ | ✗ |
| `Config` | Settings | ✓ | ✓ | ✗ |
| `AuthToken` | Token history | ✓ | ✓ (append) | ✗ |
| `Notification` | User notices | ✓ | ✓ | ✗ |
| `PublicLink` | Shared access | ✓ | ✓ | ✗ |
| `ItemPreset` | UI state | ✓ | ✓ | ✗ |
| `AccountFile` | Attachments | ✓ | ✓ | ✗ |
| `UserPassRecover` | Recovery | ✓ | ✓ | ✗ |
| `EventLog` | Legacy audit | ✓ | ✓ (append) | ✗ |
| `Track` | Request tracking | ✓ | ✓ (append) | ✗ |
| `Plugin` | PHP plugins | ✓ | ⚠️ (read-mostly) | ✗ |
| `PluginData` | Plugin state | ✓ | ⚠️ (read-mostly) | ✗ |
| `CustomFieldType` | Extensions | ✓ | ✓ | ✗ |
| `CustomFieldDefinition` | Extensions | ✓ | ✓ | ✗ |
| `CustomFieldData` | Extensions | ✓ | ✓ | ✗ |
| `UserToUserGroup` | Membership | ✓ | ✓ | ✗ |
| `account_data_v` | View (PHP) | ✓ | ✗ | ✗ |
| `account_search_v` | View (PHP) | ✓ | ✗ | ✗ |

**Note:** `CustomField*`, `Plugin*`, `ItemPreset` tables exist in the PHP schema (`dbstructure.sql`) — they are PHP-owned despite Python use. Python cannot change their shape.

---

### 11. OpenShift and UBI Compatibility (ADR-0015 Reconciliation)

This ADR supersedes ADR-0015's "fixed UID" decision regarding OpenShift.

**Revised position:**
- Target native OpenShift restricted SCC compatibility (arbitrary UID, read-only rootfs, non-root).
- UBI Python base image (`registry.access.redhat.com/ubi9/python-311`) runs arbitrary UID by default.
- Writable paths (`/app/data`, `/app/backups`) must use `group-add` permissions (group 0) so any UID in root group can write.
- Custom SCCs and privileged init containers are deployment workarounds, not the intended architecture.
- Fixed UID 10001 remains Docker/Podman default (`.env.example`), but image must not depend on it.

---

### 12. Session Storage (ADR-0009 / ADR-0015 Reconciliation)

This section corrects ADR-0015's file-based session approval.

**Verified current state:** `session_service.py` stores sessions in `/app/data/sessions.json`. File-based storage is a transitional implementation, not an approved production default.

**Approved architecture (ADR-0009):**
- Sessions stored in database (`sessions` table, MySQL/MariaDB)
- No additional infrastructure mandatory for production
- Redis optional for HA (never required)
- Fail-closed: if session store unavailable, reject requests

**Migration requirement:** Moving from file to database-backed sessions requires a data migration (active sessions must survive the transition or force re-authentication).

---

### 13. Outstanding Questions (Requiring Approval)

| Question | Context | Recommendation |
|----------|---------|----------------|
| Should `AUTO_INIT_DB_ON_STARTUP` default to `false` in production? | Current default `true` allows silent schema creation on any startup | Yes — startup should validate, not mutate; production compose should set `false` |
| Should Alembic migrations be auto-applied on startup? | Currently manual; HA replicas might start with different schema versions | No for production (separate Job); Yes for development only |
| Minimum extension schema version for startup | App crashes at runtime if extension tables missing | Should fail readiness immediately with clear error message |
| Should `python_init.sql` be deleted? | Dead file, 305 lines, zero references | Yes — `dbstructure.sql` is canonical |
| `schemas/3*.sql` PHP migration files purpose | Reference-only; no code reads them | Keep as documentation; add README explaining status |

---

### 14. Threat Model Updates

| Threat ID | Description | Mitigation | Status |
|-----------|-------------|------------|--------|
| **T-MIG-01** | Concurrent migration without lock corrupts schema | Alembic advisory lock (proposed) | Gap |
| **T-MIG-02** | Silent schema mutation at startup with unexpected schema | `AUTO_INIT_DB_ON_STARTUP=true` default | Gap |
| **T-MIG-03** | Application starts against incomplete schema (extension tables missing) | No Alembic version check at startup | Gap |
| **T-MIG-04** | PHP schema upgrade (manual `.sql` application) not reflected in bootstrap definition | `dbstructure.sql` may lag behind applied `.sql` increments | Gap |
| **T-MIG-05** | Alembic downgrade drops extension data without backup verification | No pre-downgrade backup gate | Gap |

---

### 15. Glossary Entries (Added)

| Term | Definition |
|------|------------|
| **Alembic Version** | The revision identifier stored in `alembic_version` table indicating which migrations have been applied. |
| **Bootstrap Schema** | The PHP base table definitions applied by `CREATE TABLE IF NOT EXISTS` on first startup. |
| **Extension Schema** | Python-native tables added by Alembic migrations (003–005+). PHP ignores these. |
| **Migration Lock** | `GET_LOCK('pysyspass_alembic')` serializing Alembic across processes (proposed). |
| **Schema Superset** | The property that pySysPass tables must be a superset of what PHP expects (no removals). |

---

### 16. Consequences

**Positive:**
- Clear ownership boundaries between PHP and Python schema
- Documented migration path and gap analysis
- Readiness check gap identified (high priority)
- Bootstrap + guard architecture validated as sound
- Dead code identified (`python_init.sql`, PHP `.sql` files)
- Alembic locking gap identified

**Negative:**
- Alembic is currently manual — HA deployments may start with incomplete extension schema
- No automated PHP schema version upgrade path (`.sql` files unused)
- Schema guard protects runtime but not startup — `AUTO_INIT_DB_ON_STARTUP=true` default is a production risk
- No distributed migration lock for Alembic

---

### 17. Verification

| Check | Method | Status |
|-------|--------|--------|
| Bootstrap creates PHP schema | Fresh DB → verify all 18 tables + 2 views | Verified ✓ |
| Schema guard blocks runtime DDL | Attempt `CREATE TABLE` in guarded session → `SchemaMutationError` | Verified ✓ |
| Bootstrap uses GET_LOCK (MySQL) | Concurrent startup → only one applies schema | Verified ✓ |
| Alembic not invoked at startup | Grep `main.py` → no alembic call | Verified ✓ |
| Extension tables created by Alembic | `alembic upgrade head` → tables exist | Verified ✓ |
| Alembic 001 idempotent after bootstrap | Bootstrap then Alembic 001 → `CREATE TABLE` on existing → potential failure | **Needs fix** (IF NOT EXISTS or skip) |
| `python_init.sql` referenced | `grep -rn "python_init"` → zero hits | Verified (dead code) ✓ |
| Config.databaseVersion validated at startup | Readiness checks do not check this | Verified (not checked) ✓ |
| Alembic has distributed lock | env.py has no GET_LOCK | Verified (no lock) ✓ |
| Extension tables use utf8mb4 | Check Alembic migrations → `utf8mb4_unicode_ci` | Verified ✓ |

---

## Related ADRs

| ADR | Relationship |
|-----|-------------|
| ADR-0002 | PHP compatibility contract (parent) — this ADR operationalizes its schema rules |
| ADR-0008 | Key hierarchy — migration must preserve encrypted columns |
| ADR-0009 | Session architecture — file-to-DB session migration requires Alembic change |
| ADR-0013 | Backup/DR — mandatory backup before destructive migrations |
| ADR-0015 | Deployment — corrects fixed UID position, session storage status |

---

## Related Kanban Tasks

| Task | Description |
|------|-------------|
| IMPL-004 | Emergency credentials table (Alembic 003) — extension migration |
| IMPL-010 | Service vault contexts (Alembic 005) — extension migration |
| IMPL-011 | Audit logging framework (Alembic 004) — extension migration |
| IMPL-015 | Alembic migration locking (GET_LOCK in env.py) — **new** |
| IMPL-016 | Startup Alembic version validation — **new** |
| IMPL-017 | Database-backed session storage (ADR-0009) — **new** |
| IMPL-018 | Remove `python_init.sql` and document PHP `.sql` files — **new** |
| TEST-011 | Alembic lock serialization test — **new** |
| TEST-012 | Extension schema version detection test — **new** |
| TEST-013 | Schema guard blocks runtime DDL test — **new** |
| TEST-014 | Alembic idempotency after bootstrap test — **new** |
| TEST-015 | PHP rollback compatibility test (drop extensions, PHP reads base) — **new** |