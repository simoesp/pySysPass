# ADR-0015 — Deployment Architecture and Infrastructure Requirements

## Status

**Status:** Active

## Context

pySysPass must support both straightforward self-hosted deployments and enterprise infrastructure. This ADR investigates the current deployment implementation and establishes requirements based on verified evidence, distinguishing supported configurations from proposed future support.

**Investigation sources:**
- `Dockerfile`, `frontend/Dockerfile`, `podman-compose.yml`, `podman-compose.external.yml`, `portainer-stack.yml`
- `docs/installation.md`, `docs/backup-recovery.md`
- `app/main.py` (health endpoints), `app/services/readiness_service.py`
- `app/db/bootstrap.py` (multi-worker bootstrap locking)
- `app/services/session_service.py` (session storage)
- `app/services/auth_service.py` (vault context in JWT)
- `app/services/task_service.py` (background tasks)
- `app/services/backup_service.py` (backup operations)

---

## Decision

### 1. Supported Deployment Profiles

| Profile | Status | Description |
|---------|--------|-------------|
| **Development** | Supported and verified | Local Python/Node.js or container stack with `DEBUG=true`, ephemeral secrets |
| **Standalone self-hosted** | Supported and verified | Single-host Docker Compose / Podman stack with internal MySQL |
| **Production Docker Compose** | Supported and verified | `podman-compose.yml` with explicit secrets, `DEBUG=false`, external reverse proxy |
| **External database** | Supported and verified | `podman-compose.external.yml` against existing MySQL/MariaDB (PHP-owned schema) |
| **Portainer stack** | Supported and verified | `portainer-stack.yml` for Portainer UI deployments |
| **Kubernetes** | Proposed | No manifests exist; requires session storage, vault context, migration coordination |
| **OpenShift** | Proposed | Requires arbitrary UID, rootless, read-only rootfs, SCC — not verified |
| **High availability** | Proposed | Requires shared session storage, distributed vault contexts, DB migration locking — not verified |
| **Disaster recovery** | Partially supported | Backup/restore via API and offline CLI; no automated DR orchestration |

---

### 2. Container Architecture

#### 2.1 Container Images

| Component | Base Image | User | UID/GID | Writable Paths | Read-Only Paths |
|-----------|------------|------|---------|----------------|-----------------|
| Backend | `python:3.11-slim` (Debian) | `syspass` | 10001:10001 | `/app/data`, `/app/backups` | `/app` (code) |
| Frontend | `nginx:alpine` (unprivileged) | `nginx` | 101:101 | `/var/cache/nginx`, `/var/run`, `/tmp` | `/etc/nginx`, `/usr/share/nginx/html` |
| Database | `mysql:8` or `mariadb:10.11` | `mysql`/`mariadb` | 999:999 / 999:999 | `/var/lib/mysql` | — |

**Verified:** Both images run as non-root users. Backend code is root-owned and read-only to the `syspass` user. Only `/app/data` and `/app/backups` are writable.

#### 2.2 Rootless and Arbitrary UID Compatibility

- **Rootless Podman:** Verified working. Volumes require correct ownership on host (`chown -R 10001:10001`) or `--userns`/`:U` mapping.
- **Arbitrary UID (OpenShift):** The current image uses fixed UID 10001, which **conflicts** with standard restricted OpenShift SCC (`runAsUser: RunAsAny` assigns random UID).
- **Target:** Native compatibility with restricted OpenShift policies without requiring custom SCCs or privileged init containers.
- **Required changes:** Group-based permissions (world/group-writable volumes), non-fixed UID in image, or use of `USER` directive that allows override via PodSpec `securityContext`.
- **Acceptable default:** Fixed UID 10001 may remain the default for conventional Docker/Podman deployments, but the container must not fundamentally depend on that exact UID.

**Arbitrary UID Path:** The Red Hat UBI Python image (`ubi9/python-311`) runs with an arbitrary UID by default and supports group-writable volumes. A pySysPass image built on UBI would support OpenShift without custom SCCs.

**Read-only root filesystem:** Backend code directory is effectively read-only. Writable directories (`/app/data`, `/app/backups`) must be mounted as volumes. The container can run with `--read-only` if these volumes are mounted.

**SELinux:** Requires UBI-compatible labels or `:Z` volume mount options. Not yet tested.

**Non-privileged ports:** Container currently exposes 8000 (>1024). Frontend nginx uses 8080 (>1024). No privileged port binding required.

#### 2.3 Security Hardening

| Capability | Status | Notes |
|------------|--------|-------|
| Non-root execution | Verified | UID 10001 (backend), UID 101 (frontend) |
| Rootless containers | Verified | Podman rootless works |
| Read-only rootfs | Partially supported | Requires volume mounts for writable dirs |
| Linux capability minimization | Not configured | Default Docker/Podman capabilities; no explicit drop |
| SELinux | Not tested | No SELinux policies or labels provided |
| Seccomp profiles | Not configured | Default runtime profiles only |
| Privileged containers | Not required | No privileged mode needed |
| Host networking | Not required | Bridge/overlay networks used |

---

### 3. Application Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                    REVERSE PROXY (External)                     │
│              Nginx / HAProxy / Traefik / Ingress                │
└────────────────────────────────┬────────────────────────────────┘
                                 │ HTTPS (TLS termination)
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                  FRONTEND CONTAINER (nginx)                     │
│  - Serves static Vue 3 SPA                                      │
│  - Proxies /api/* to backend (private network)                  │
│  - Injects TRUSTED_PROXY_HOSTS for X-Forwarded headers          │
│  - Listens on 8080 (container)                                  │
└────────────────────────────────┬────────────────────────────────┘
                                 │ HTTP (internal)
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              BACKEND CONTAINER(S) — FastAPI + Uvicorn           │
│  - WEB_CONCURRENCY workers (default 1)                          │
│  - Each worker runs startup bootstrap (serialized via MySQL     │
│    GET_LOCK or fcntl file lock)                                 │
│  - Shared /app/data (sessions.json, runtime-config.json,        │
│    RSA transport key)                                           │
│  - Shared /app/backups (backup archives)                        │
│  - Background scheduler (runs in ONE worker)                    │
│  - JWT tokens with encrypted vault claim (master password)      │
└────────────────────────────────┬────────────────────────────────┘
                                 │ MySQL protocol
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DATABASE (MySQL/MariaDB)                     │
│  - PHP-compatible schema (sysPass tables)                       │
│  - Python-native extension tables (additive only)               │
│  - External or internal (compose)                               │
└─────────────────────────────────────────────────────────────────┘
```

#### 3.1 Process Model

- **Backend:** Uvicorn with `WEB_CONCURRENCY` workers (env var, default 1). Each worker is a separate process.
- **Frontend:** Nginx master + worker processes (static file serving + proxy).
- **Database:** MySQL/MariaDB server process(es).

#### 3.2 Background Tasks

- **Task scheduler:** Runs in the first worker that acquires the scheduler lock (file-based in `/app/data/scheduler.lock`).
- **Jobs:** Password expiry notices (not implemented), automated backups (not scheduled by default).
- **Coordination:** Single-writer lock prevents duplicate execution across workers/replicas.
- **Current limitation:** No distributed scheduler; multiple container replicas would each run their own scheduler unless disabled.

#### 3.3 Session Storage

**Current Implementation:** File-based JSON at `/app/data/sessions.json` (see `app/services/session_service.py`).

**Known Issues with File-Based Storage:**
- ❌ No file locking (concurrent access unsafe)
- ❌ No atomic updates (partial writes possible)
- ❌ No crash recovery (corruption possible)
- ❌ No multi-worker support (separate copies diverge)
- ❌ No multi-replica support (separate volumes have inconsistent state)
- ⚠️ Container restarts lose state

**Approved Target (ADR-0009 §5):**
- **Single instance:** In-memory OK (development)
- **Multi-worker, single host:** Database-backed sessions (use existing MySQL/MariaDB)
- **Multi-replica, HA:** Database-backed sessions (shared authoritative state)
- **Optional:** Redis backend for sub-second latency (never mandatory)

**Storage Backends:**

| Backend | Use Case | Concurrency | Atomicity | HA-Safe | Mandatory |
|---------|----------|-------------|-----------|---------|-----------|
| In-memory | Development | Single process | No | No | No |
| Database | Production | Full | Yes | Yes | No (recommended) |
| Redis | HA / performance | Full | Yes | Yes | No (optional) |
| File-based | Transitional | Limited | Partial | No | No |

**Database Backend Requirements (per ADR-0009):**
- `Session` table with: `session_id`, `user_id`, `authenticated_until`, `vault_until`, `revoked`, `revoked_until`, `ip_address`, `user_agent`, `created_at`
- Revocation stored server-side (not in JWT)
- Immediate effect across workers and replicas (shared database)
- Fail-closed: if session backend unavailable, reject all requests (no fallback to stateless JWT)

**Current Status:** File-based implementation. Requires migration to database-backed sessions before ADR-0009 target is met and before HA can be claimed.

#### 3.4 Vault Context Distribution

**Current Implementation:** Master password encrypted in JWT claim (`mpass` field, AES-256-GCM under key derived from `ENCRYPTION_KEY` + user ID).

**Approved Target Architecture (ADR-0008, ADR-0009):**
- JWTs contain only identity and session identifier — **no cryptographic material**
- Short-lived access tokens (15 min default)
- Authoritative server-side session state (database-backed, not file-based)
- Server-side vault contexts — independently managed, per-session, time-limited
- Vault contexts stored in application memory or AES-GCM encrypted if persisted
- **No master password in client-held tokens**

**HA Implication:** `ENCRYPTION_KEY` must be identical across replicas (token validation and vault context encryption). Service vault contexts (ADR-0010) require independent key hierarchy per service identity.

**Migration Status:** JWT-embedded `mpass` is transitional. Target removes it. Requires session storage implementation (ADR-0009 §5) before vault claims can be removed.

#### 3.5 Persistent Files

| Path | Purpose | Writable | Persistent | Shared (HA) | Backup |
|------|---------|----------|------------|-------------|--------|
| `/app/data/runtime-config.json` | Application settings (UI) | Yes | Yes | Yes | Yes |
| `/app/data/sessions.json` | Session revocation state | Yes | Yes | **Required** | No (ephemeral) |
| `/app/data/transport.key` | RSA key for credential transport | Yes | Yes | Yes | Yes |
| `/app/data/*.json` | Other runtime JSON configs | Yes | Yes | Yes | Yes |
| `/app/backups/*.zip` | Backup archives | Yes | Yes | No (per-instance) | N/A (is backup) |
| `/var/lib/mysql` | Database | Yes (mysqld) | Yes | N/A (single DB) | Via mysqldump |
| `/app` (code) | Application code | No | Image | N/A | No |

---

### 4. Database Infrastructure

#### 4.1 Supported Versions

| Database | Version | Status | Notes |
|----------|---------|--------|-------|
| MySQL | 8.0+ | Supported and verified | Compose uses `mysql:8` |
| MariaDB | 10.11+ | Supported and verified | Compatible with MySQL 8 protocol |
| External MySQL/MariaDB | 8.0+/10.11+ | Supported and verified | Via `podman-compose.external.yml` |

#### 4.2 Connection Configuration

- **TLS:** Supported via SQLAlchemy URL query parameters (`ssl_ca`, `ssl_cert`, `ssl_key`, `ssl_verify_cert`, `ssl_verify_identity`). Not configured in compose files.
- **Connection pooling:** SQLAlchemy `QueuePool` (default pool_size=5, max_overflow=10). Configurable via `DATABASE_URL` query parameters.
- **Credential rotation:** Not automated. Requires `DATABASE_URL` update and container restart.
- **Least-privilege accounts:** Not enforced by application. Compose uses root for bootstrap; application should use dedicated account with `SELECT, INSERT, UPDATE, DELETE, EXECUTE` on schema.

#### 4.3 Schema Management

- **Bootstrap-on-startup:** `AUTO_INIT_DB_ON_STARTUP=true` (default) creates full PHP-compatible schema on empty database.
- **Migration locking:** `GET_LOCK('pysyspass_bootstrap', 300)` serializes bootstrap across workers and containers (MySQL). Fallback: `fcntl` file lock for SQLite.
- **Schema guard:** `SQLALCHEMY_SCHEMA_GUARD=true` prevents unintended mutations (blocks `CREATE TABLE`, `ALTER TABLE` at runtime).
- **Alembic:** Available for Python-native extension migrations (not used for PHP schema).
- **PHP schema ownership:** The core sysPass tables are PHP-owned. Python only adds additive extension tables.

#### 4.4 Character Sets and Collations

- **Database:** `utf8mb4` / `utf8mb4_unicode_ci` (MySQL 8 default).
- **Tables:** Created with `CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`.
- **Connection:** `charset=utf8mb4` in SQLAlchemy URL.

---

### 5. Networking

#### 5.1 Reverse Proxy Integration

| Proxy | Status | Configuration |
|-------|--------|---------------|
| Nginx (frontend container) | Supported and verified | Built into frontend image; proxies `/api/*` to backend |
| External Nginx | Supported | Requires `TRUSTED_PROXY_HOSTS` with proxy IP/CIDR |
| HAProxy | Proposed | Requires `TRUSTED_PROXY_HOSTS` config |
| Traefik | Proposed | Requires `TRUSTED_PROXY_HOSTS` config |
| Kubernetes Ingress | Proposed | Requires `TRUSTED_PROXY_HOSTS` config |
| OpenShift Routes | Proposed | Requires `TRUSTED_PROXY_HOSTS` config |

#### 5.2 Trusted Proxy Configuration

- **Backend setting:** `TRUSTED_PROXY_HOSTS` (JSON array of IPs/CIDRs, e.g., `["10.20.0.10", "172.30.81.0/24"]`).
- **Default:** Empty array (no trusted proxies).
- **Security:** Nginx in frontend container replaces `X-Forwarded-For` with actual peer address. If another proxy terminates TLS in front, that proxy's address must be in `TRUSTED_PROXY_HOSTS`.
- **Header spoofing prevention:** Untrusted clients cannot spoof forwarded headers because backend validates against allowlist.

#### 5.3 Network Ports

| Service | Container Port | Protocol | Published (compose) |
|---------|----------------|----------|---------------------|
| Frontend (nginx) | 8080 | HTTP | 8080 (dev), 8081 (external) |
| Backend (uvicorn) | 8000 | HTTP | Not published (private) |
| MySQL | 3306 | MySQL | 3306 (dev only) |
| Graphify viewer | 8090 | HTTP | 8090 (dev only) |

#### 5.4 LDAP Connectivity

- Outbound LDAP/LDAPS (389/636) required when LDAP authentication enabled.
- TLS supported via `use_tls`/`use_ssl` in LDAP service configuration.
- No outbound restrictions enforced by application; network policy is infrastructure responsibility.

---

### 6. High Availability — Current Gaps

The following must be resolved before claiming HA support:

| Requirement | Current State | Needed for HA |
|-------------|---------------|---------------|
| **Stateless replicas** | Backend workers share `/app/data` | Shared volume or external session store |
| **Shared session state** | File-based (`sessions.json`) | Redis backend or shared volume with locking |
| **Distributed vault contexts** | JWT-embedded (works if `ENCRYPTION_KEY` shared) | Verified — no additional infrastructure |
| **Service vault contexts** | Not implemented | ADR-0010 implementation |
| **DB migration locking** | `GET_LOCK` for bootstrap only | Migration-level locking for Alembic |
| **Background job coordination** | Single-writer file lock per container | Distributed lock (Redis) or disable in replicas |
| **Duplicate execution prevention** | Scheduler lock file | Distributed lock |
| **Graceful shutdown** | Not implemented | SIGTERM handling, drain connections |
| **Rolling upgrades** | Not documented | Readiness checks, backward-compatible migrations |
| **Health/readiness/liveness** | `/health` (live), `/health/ready` (ready) | Verified — suitable for K8s probes |

**Redis:** May be used as optional backend for sessions/scheduler locks but **must not** become mandatory for basic deployments. Development and standalone profiles work without Redis.

---

### 7. Persistent Storage Inventory

| Storage Class | Paths | Writable | Persistent | Shared (HA) | Backup | Notes |
|---------------|-------|----------|------------|-------------|--------|-------|
| **Credential DB** | MySQL `/var/lib/mysql` | Yes (mysqld) | Yes | No (single writer) | mysqldump | Primary data |
| **Python extensions** | MySQL (same DB) | Yes (app) | Yes | No | mysqldump | Additive tables only |
| **Crypto material** | `/app/data/transport.key`, JWT keys | Yes | Yes | Yes | Yes | `ENCRYPTION_KEY`, `SECRET_KEY` in env |
| **App config** | `/app/data/runtime-config.json` | Yes | Yes | Yes | Yes | UI-managed settings |
| **Audit records** | MySQL `EventLog`, `Track` | Yes (app) | Yes | No | mysqldump | Append-only |
| **Backup archives** | `/app/backups/*.zip` | Yes | Yes | No | N/A (is backup) | Created by backup service |
| **Temp runtime** | `/tmp`, `/var/cache/nginx` | Yes | No | No | No | Disposable |
| **Session state** | `/app/data/sessions.json` | Yes | Yes | **Required** | No | Ephemeral revocation data |
| **Vault contexts** | In JWT tokens (client-side) | N/A | N/A | N/A | No | `ENCRYPTION_KEY` in env |

**Writable directories (must be volumes):**
- `/app/data`
- `/app/backups`
- `/var/lib/mysql` (database container)

**Excluded from backups:**
- `/tmp`, `/var/cache`, `/var/run` (disposable)
- `/app/data/sessions.json` (ephemeral, regenerated)

---

### 8. Operational Lifecycle

| Phase | Mechanism | Verified |
|-------|-----------|----------|
| **Installation** | `docker compose -f podman-compose.yml up -d --build` | Yes |
| **Initial setup** | First-run UI at `/` or `POST /api/v1/auth/install` | Yes |
| **Startup validation** | `validate_production_settings()` rejects unsafe config | Yes |
| **Readiness** | `GET /health/ready` (DB, schema, config, storage) | Yes |
| **Liveness** | `GET /health` (process alive) | Yes |
| **Graceful shutdown** | **Not implemented** — SIGTERM kills workers immediately | No |
| **Config changes** | UI writes `runtime-config.json`; workers converge in 2s | Yes |
| **Application upgrades** | Rebuild image, `docker compose up -d --build` | Yes (manual) |
| **Database migrations** | Bootstrap-on-startup (PHP schema); Alembic (extensions) | Partial |
| **Secret rotation** | Update env, restart containers | Manual |
| **Backup** | `POST /api/v1/backup/create` or host cron | Yes |
| **Restoration** | Offline CLI `restore_backup.py` (writers stopped) | Yes |
| **Rollback** | Previous image + database restore | Manual |
| **Disaster recovery** | Backup archives + offline restore procedure | Partial |

**Health endpoint security:** `/health` and `/health/ready` return no sensitive configuration or cryptographic material. Readiness checks expose only pass/fail status and check names.

---

### 9. Deployment Verification Matrix

| Environment | Status | Required Config | Known Limitations | Verification | Related Tasks |
|-------------|--------|-----------------|-------------------|--------------|---------------|
| **Docker Compose (dev)** | Supported and verified | `.env` with dev secrets | Debug keys, auto-init DB | CI: `podman-compose up` + health checks | — |
| **Docker Compose (prod)** | Supported and verified | Explicit `SECRET_KEY`, `ENCRYPTION_KEY`, `DATABASE_URL`, `TRUSTED_PROXY_HOSTS` | Single-host only | Manual: prod stack + external proxy | — |
| **Podman rootless** | Supported and verified | Volume ownership (10001:10001) or userns | SELinux may block | Manual: rootless Podman | — |
| **External MySQL/MariaDB** | Supported and verified | `podman-compose.external.yml`, `.env.external` with PHP `passwordSalt` | Schema guard on, no auto-init | Manual: against PHP sysPass DB | — |
| **Portainer** | Supported and verified | `portainer-stack.yml` | Same as compose prod | Manual: Portainer deploy | — |
| **Kubernetes** | Proposed | Manifests, shared session store, `ENCRYPTION_KEY` secret | No manifests; session HA not implemented | Not verified | ADR-0015 investigation |
| **OpenShift** | Proposed | SCC for UID 10001, rootless, read-only rootfs | Fixed UID 10001 conflicts with RunAsAny | Not verified | ADR-0015 investigation |
| **HA (multi-replica)** | Proposed | Shared `/app/data`, Redis for sessions/scheduler, identical secrets | Session revocation inconsistent without shared store | Not verified | ADR-0015, IMPL-010+ |
| **RHEL/UBI base** | Proposed | Rebuild on `registry.access.redhat.com/ubi9/python-311` | Not tested | Not verified | ADR-0015 investigation |

---

### 10. Architectural Tradeoffs

| Tradeoff | Decision | Rationale |
|----------|----------|-----------|
| **Simple vs. HA** | Keep simple self-hosted working without Redis/K8s | Majority of sysPass users are single-host; HA is opt-in |
| **Fixed UID vs. OpenShift RunAsAny** | Native arbitrary-UID compatibility preferred | UBI base image or group-writable volumes eliminate need for custom SCC/init containers; fixed UID 10001 remains Docker/Podman default but is not mandatory |
| **File-based sessions vs. Redis** | File-based transitional; database-backed target | Zero-infrastructure for basic deployments; existing DB used for authoritative sessions; Redis optional for HA latency |
| **Bootstrap-on-startup vs. Alembic** | Bootstrap for PHP schema; Alembic for extensions | PHP schema is external contract; Python owns extensions |
| **JWT-embedded vault vs. server-side vault** | Server-side vault (target per ADR-0009) | JWT-embedded `mpass` is transitional; target removes crypto material from tokens; server-side vault contexts require session storage first |
| **Single scheduler vs. distributed** | Single-writer file lock | Simplicity; distributed lock only needed for HA replicas |

---

### 11. Kanban Reconciliation

**Operational Kanban board (`pysyspass`): 30 tasks total**
- 6 ADR tasks (ADR-0015 through ADR-0020)
- 14 Implementation tasks (IMPL-001 through IMPL-014)
- 10 Testing tasks (TEST-001 through TEST-010)

**Previous documentation (`docs/kanban/tasks.md`) reported 31 tasks (6 ADR + 20 IMPL + 10 TEST = 36 claimed, actually 30 in board).**
- The 20 implementation tasks in the old inventory included items that were consolidated or deprecated during architectural review (e.g., separate LDAP/MFA tasks merged into IMPL-001/002/003).
- No requirements were dropped; they were re-scoped into the 14 current implementation cards with clearer acceptance criteria.

**Corrected count: 30 operational tasks.**

---

### 12. Related ADRs

- **ADR-0003** — Identity Authentication, MFA and Cryptographic Unlocking Boundaries (vault unlock order)
- **ADR-0008** — Encryption Architecture, Master Password and Cryptographic Key Lifecycle (`ENCRYPTION_KEY`, `SECRET_KEY`)
- **ADR-0009** — Session Architecture, API Token Lifecycle and Server-Side Vault Context (session storage, JWT vault claim)
- **ADR-0010** — Service Accounts, Workload Identity and Automated Credential Retrieval (service vault contexts)
- **ADR-0011** — Audit Logging and Accountability (audit records in DB)
- **ADR-0012** — Threat Model and Trust Boundaries (reverse proxy trust boundary)
- **ADR-0013** — Backup, Disaster Recovery and Cryptographic Recoverability (backup encryption, storage)
- **ADR-0014** — Emergency Authentication and Offline Recovery Access (break-glass accounts)
- **ADR-0016** — Database Migration Governance (schema ownership, migration locking)
- **ADR-0017** — Configuration and Secret Management (mounted secrets, precedence)
- **ADR-0018** — API and Integration Governance (proxy trust, API compatibility)
- **ADR-0019** — Testing and CI/CD (deployment verification)
- **ADR-0020** — Documentation Governance (ongoing lifecycle)

---

### 13. Glossary Updates

| Term | Definition |
|------|------------|
| **Bootstrap Lock** | MySQL `GET_LOCK` or `fcntl` file lock serializing schema initialization across workers/containers |
| **Schema Guard** | Runtime `SQLALCHEMY_SCHEMA_GUARD` preventing unintended DDL mutations |
| **PHP-Owned Schema** | Core sysPass tables managed by PHP migrations; Python treats as immutable |
| **Python-Native Extensions** | Additive tables created by Python (e.g., `emergency_credentials`) with Alembic migrations |
| **Trusted Proxy Hosts** | `TRUSTED_PROXY_HOSTS` allowlist validating `X-Forwarded-*` headers |
| **Vault Claim** | Encrypted master password embedded in JWT (`mpass` field) |
| **Service Vault Context** | Independent cryptographic context for service accounts (ADR-0010) |

---

### 14. Threat Model Updates (ADR-0012)

| Threat ID | Mitigation | Deployment Relevance |
|-----------|------------|----------------------|
| **T-001** Credential theft via untrusted proxy headers | `TRUSTED_PROXY_HOSTS` allowlist; nginx replaces `X-Forwarded-For` | Required for all reverse proxy deployments |
| **T-002** Session revocation bypass in HA | Shared session store (Redis) or shared volume with locking | Required for multi-replica |
| **T-003** Vault key exposure via `ENCRYPTION_KEY` rotation | Rotation disabled pending migration workflow; explicit keys required | Production startup validation |
| **T-004** Bootstrap race condition | `GET_LOCK('pysyspass_bootstrap')` / `fcntl` | Multi-worker, multi-container |
| **T-005** Backup encryption key loss | Asymmetric backup encryption (ADR-0013); key escrow procedures | Backup storage |

---

## Consequences

### Positive
- Clear distinction between verified and proposed deployment support
- Self-hosted simplicity preserved (no mandatory Redis, K8s, external secret managers)
- PHP schema compatibility maintained through bootstrap and schema guard
- Container security baseline established (non-root, read-only code, minimal writable dirs)
- Operational lifecycle documented with verification status

### Negative
- HA requires significant additional implementation (session store, scheduler coordination, graceful shutdown)
- OpenShift arbitrary UID requires image rebuild or init container
- No automated secret rotation or certificate management
- Kubernetes/OpenShift manifests do not exist

### Risks
- Claiming HA support without implementing shared session storage and distributed locks
- OpenShift deployment failing due to fixed UID without SCC/init container
- Backup encryption key rotation not implemented (ADR-0013 dependency)

---

## Verification

| Check | Method | Status |
|-------|--------|--------|
| Container non-root execution | `docker inspect` — User field | Verified |
| Rootless Podman | `podman run --rootless` | Verified |
| Readiness probe | `curl /health/ready` — checks DB, schema, config, storage | Verified |
| Liveness probe | `curl /health` — returns healthy | Verified |
| Bootstrap serialization | Concurrent container start — only one bootstraps | Verified |
| Trusted proxy validation | Request with spoofed `X-Forwarded-For` from untrusted IP — rejected | Verified |
| External DB compatibility | `podman-compose.external.yml` against PHP sysPass DB | Verified |
| Backup/restore round-trip | API create + offline CLI restore | Verified |
| Session revocation | Logout + token reuse — 401 | Verified |
| Vault claim in JWT | Decode token — `mpass` field present and decryptable | Verified |

---

## References

- `Dockerfile`, `frontend/Dockerfile`
- `podman-compose.yml`, `podman-compose.external.yml`, `portainer-stack.yml`
- `docs/installation.md`, `docs/backup-recovery.md`
- `app/main.py` (health endpoints)
- `app/services/readiness_service.py`
- `app/db/bootstrap.py` (bootstrap lock)
- `app/services/session_service.py` (session storage)
- `app/services/auth_service.py` (vault claim)
- `app/services/task_service.py` (scheduler)
- `app/services/backup_service.py` (backup operations)
- `app/core/config.py` (settings validation)