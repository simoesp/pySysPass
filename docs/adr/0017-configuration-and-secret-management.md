# ADR-0017 — Configuration and Secret Management

## Status

**Status:** Proposed

## Context

pySysPass operates in multiple deployment modes (local development, Docker Compose, external database) and must interoperate with sysPass PHP's configuration patterns. The current system manages configuration across several layers with no unified governance:

**Current Configuration Layers:**
1. **Environment variables** — Highest precedence; used for secrets (`SECRET_KEY`, `ENCRYPTION_KEY`, `DATABASE_URL`, `SYSPASS_PASSWORD_SALT`) and deployment toggles (`DEBUG`, `TRUSTED_PROXY_HOSTS`)
2. **`.env` file** — Local development defaults; loaded by `pydantic-settings`
3. **Pydantic `Settings` defaults** — Fallback values in `app/core/config.py` (e.g., auto-generated `SECRET_KEY`/`ENCRYPTION_KEY`)
4. **Runtime JSON config** — `config/runtime-config.json` for mutable application settings (mail, LDAP, general, wiki) persisted atomically with file locking
5. **Database `Config` table** — Legacy sysPass PHP settings; read as fallback when runtime JSON lacks a key
6. **PHP `config.xml` / cache** — Compatibility layer for bidirectional interoperability (ADR-0002)

**Current Secret Management:**
- `SECRET_KEY`: JWT signing, session tokens; auto-generated if missing (unsafe for production)
- `ENCRYPTION_KEY`: AES-256-CTR for pending 2FA secrets, legacy pySysPass formats; rotation via `app/encryption_key.py`
- `SYSPASS_PASSWORD_SALT`: Password hashing salt from PHP; required for interoperability
- Master password: Vault encryption key; rotation via `app/services/master_password_rotation.py` with fail-closed backup
- Temporary master password: Break-glass recovery (ADR-0014); expires after use

**Gaps and Risks:**
- No formal precedence documentation; developers guess which layer wins
- Auto-generated secrets accepted in production (validated only by `validate_production_settings`)
- No mounted secret support (Docker secrets, Kubernetes secrets, HashiCorp Vault, AWS Secrets Manager)
- Key rotation procedures exist but are not codified as policy with SLAs
- Recovery material (backup, temporary master password) scattered across ADRs (0008, 0013, 0014)
- No secret lifecycle: generation, storage, rotation, revocation, destruction
- Startup validation is best-effort; readiness probe covers configuration but not secret freshness
- External secret providers not supported; operators must inject via environment

**Requirements to Reconcile:**
1. **Mounted secrets** — First-class support for file-based secrets (`/run/secrets/...`) with optional external provider abstraction
2. **Configuration precedence** — Explicit, documented, testable precedence order across all layers
3. **Secret lifecycle** — Generation, rotation schedules, revocation, destruction, audit trail
4. **Startup validation** — Fail-fast on missing/invalid secrets; distinguish dev vs production
5. **Key rotation** — Automated rotation with overlapping validity, rollback capability, coordination
6. **Recovery material** — Consolidated break-glass procedures with time-bound access
7. **Optional external providers** — Pluggable interface for Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager

## Decision

### 0. Verified Implementation Deviations (ADR-0017 Discovery)

The following findings were verified against the codebase and represent deviations from the design in this ADR. Each is tagged with its current status.

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| **V-01** | `Settings` has no `env_prefix` — all fields use bare names (`SECRET_KEY`, `ENCRYPTION_KEY`, `DATABASE_URL`). The `PYSYSPASS_` prefix in `.env.external.example` is a **host-level only** mechanism: docker-compose maps `${PYSYSPASS_SECRET_KEY}` → `SECRET_KEY` inside the container. Operators using `.env` directly must use bare names. | Low | Documented |
| **V-02** | `secrets_dir` is **not configured** in `Settings.model_config`. Layer 1 (mounted secrets) is proposed, not implemented. Currently secrets must come via env vars (compose mapping). | Medium | Gap |
| **V-03** | Multiple secrets bypass `Settings` entirely via raw `os.environ.get()`: `AUDIT_HMAC_KEY`, `BACKUP_KEYRING_PATH`, `BACKUP_SIGNING_KEYRING`, `BACKUP_VERIFICATION_KEYRING`, `BACKUP_REQUIRE_SIGNATURE`, `BACKUP_ALLOW_UNENCRYPTED`, `SERVICE_VAULT_KEYRING_PATH`, `PYSYSPASS_CURRENT_MASTER_PASSWORD`, `PYSYSPASS_NEW_MASTER_PASSWORD`. These cannot be validated at startup, managed by the precedence layers, or mounted via `secrets_dir`. | **High** | Gap |
| **V-04** | `validate_production_settings` checks only `SECRET_KEY`, `ENCRYPTION_KEY`, `DATABASE_URL`, and `TRUSTED_PROXY_HOSTS`. It does **not** check `SYSPASS_PASSWORD_SALT` (required for PHP interop) or `SERVICE_VAULT_KEY` (required for service accounts). PHP-created databases without a salt in config are silently incompatible. | **High** | Gap |
| **V-05** | No `SECRET_KEY_PREVIOUS` or `ENCRYPTION_KEY_PREVIOUS` fields — the overlapping validity window (Layer 5 rotation) described in §5 is proposed but not implemented. Rotating `SECRET_KEY` immediately invalidates all outstanding JWTs. | Medium | Gap |
| **V-06** | `SECRET_KEY` and `ENCRYPTION_KEY` default to `_generated_secret()` (random 48-byte token) when not explicitly set. In development with `DEBUG=true`, this is fine. In production, `validate_production_settings` correctly rejects auto-generated values. This is working as designed. | — | Verified ✓ |
| **V-07** | `SYSPASS_PASSWORD_SALT` is not validated at startup — an empty value is accepted. But `defuse_compat.py` uses it to construct the PHP-compatible user encryption key `(loginPass + loginUser + passwordSalt).strip()`. A missing salt makes all PHP-created `User.mPass` values undecryptable. The runtime JSON config (`syspass_runtime_config.py`) can supply it from PHP's `config.xml` or serialized cache; this fallback is the current mechanism. | Medium | Partially mitigated |
| **V-08** | `SERVICE_VAULT_KEY` is validated at the point of use (`service_vault_crypto.py`) via fail-closed check, not at startup. If service accounts are deployed but `SERVICE_VAULT_KEY` is unset, failures are deferred to the first API call rather than caught at startup. | Medium | Gap |

**Precedence layers confirmed implemented:**

| Layer | Status | Evidence |
|-------|--------|---------|
| 1 — Mounted secrets (`/run/secrets/`) | **Not implemented** | No `secrets_dir` in `Settings.model_config` |
| 2 — Environment variables | **Implemented** ✓ | pydantic-settings, `case_sensitive=False` |
| 3 — External secret provider | **Not implemented** | No `SecretProvider` class in codebase |
| 4 — `.env` file | **Implemented** ✓ | `env_file=".env"` in `model_config` |
| 5 — Pydantic defaults | **Implemented** ✓ | Defaults in `Settings` class |
| 6 — Runtime JSON config | **Implemented** ✓ | `runtime_json_config.py` → `SECTION_KEYS` |
| 7 — Database `Config` table | **Implemented** ✓ | `config_service.py` reads PHP key/value rows |
| 8 — PHP `config.xml` / cache | **Implemented** ✓ | `syspass_runtime_config.py` XML + PHP serialized cache regex |

**Raw environment variables bypassing Settings (Layer 2 only):**

| Variable | Consumer | Purpose |
|----------|----------|---------|
| `AUDIT_HMAC_KEY` | `audit_service.py` | HMAC for audit log integrity |
| `BACKUP_KEYRING_PATH` | `backup_crypto.py` | Path to backup encryption keyring file |
| `BACKUP_SIGNING_KEYRING` | `backup_service.py` | Path to backup signing keyring |
| `BACKUP_VERIFICATION_KEYRING` | `backup_service.py` | Path to backup signature verification keyring |
| `BACKUP_REQUIRE_SIGNATURE` | `backup_crypto.py` | Enforce signature check on restore |
| `BACKUP_ALLOW_UNENCRYPTED` | `backup_crypto.py` | Allow unencrypted backup (exception) |
| `SERVICE_VAULT_KEYRING_PATH` | `service_vault_keyring.py` | Path to service vault keyring file |
| `PYSYSPASS_CURRENT_MASTER_PASSWORD` | `rotate_master_password.py` | CLI rotation input |
| `PYSYSPASS_NEW_MASTER_PASSWORD` | `rotate_master_password.py` | CLI rotation input |

### 1. Configuration Precedence (Highest → Lowest)

| Layer | Source | Scope | Mutability | Example |
|-------|--------|-------|------------|---------|
| **1** | **Mounted secret files** (`/run/secrets/<name>`) | Secrets only | Read-only at runtime | `SECRET_KEY`, `ENCRYPTION_KEY`, `DATABASE_URL` |
| **2** | **Environment variables** | All settings | Read-only at runtime | `DEBUG=false`, `TRUSTED_PROXY_HOSTS=[...]` |
| **3** | **External secret provider** (Vault, AWS, etc.) | Secrets only | Read at startup/refresh interval | Dynamic database credentials |
| **4** | **`.env` file** | All settings | Developer-controlled | Local development overrides |
| **5** | **Pydantic `Settings` defaults** | Non-secrets | Compile-time | `ALLOWED_HOSTS=["*"]`, `AUTO_INIT_DB_ON_STARTUP=true` |
| **6** | **Runtime JSON config** (`/app/data/runtime-config.json`) | Application settings | Runtime (admin UI) | Mail, LDAP, general, wiki |
| **7** | **Database `Config` table** | Legacy sysPass settings | Runtime (admin UI / PHP) | PHP-interop fallbacks |
| **8** | **PHP `config.xml` / cache** | Compatibility only | Read-only (PHP-owned) | `passwordSalt`, `configDate` |

**Rules:**
- Layer 1–3 are **deployment-time** (immutable at runtime); Layer 4 is **developer-time**; Layer 5 is **build-time**; Layers 6–8 are **runtime**.
- A setting resolved at Layer *n* **never falls back** to Layer *n+1* if explicitly set (including empty string).
- Secrets (`SECRET_KEY`, `ENCRYPTION_KEY`, `DATABASE_URL`, `SYSPASS_PASSWORD_SALT`, `masterPwd`) **must** resolve at Layer 1–3 in production.
- Runtime JSON (Layer 6) and Database Config (Layer 7) share the same key namespace; Layer 6 wins for keys it recognizes (see `SECTION_KEYS` in `runtime_json_config.py`).

### 2. Mounted Secrets & External Providers

**File-based Secrets (Docker/K8s):**
- Path convention: `/run/secrets/<setting_name>` (e.g., `/run/secrets/SECRET_KEY`)
- Settings opt-in via `SettingsConfigDict(secrets_dir="/run/secrets")` — new field `secrets_dir` in `Settings.model_config`
- On startup, `Settings` reads any file in `secrets_dir` matching a field name **before** environment variables
- File content is stripped of trailing newline; empty file = unset (falls through to env)

**External Provider Abstraction:**
```python
# app/core/secret_providers.py
from abc import ABC, abstractmethod
from typing import Optional

class SecretProvider(ABC):
    @abstractmethod
    def get_secret(self, name: str) -> Optional[str]: ...
    @abstractmethod
    def list_secrets(self, prefix: str) -> list[str]: ...
    @abstractmethod
    def health_check(self) -> bool: ...

class FileSecretProvider(SecretProvider):
    """Reads from /run/secrets/ or configured directory."""
    ...

class VaultSecretProvider(SecretProvider):
    """HashiCorp Vault KV v2; config via VAULT_ADDR, VAULT_TOKEN, VAULT_MOUNT."""
    ...

class AWSSecretsManagerProvider(SecretProvider):
    """AWS Secrets Manager; config via AWS_REGION, AWS_SECRET_PREFIX."""
    ...

# ... AzureKeyVaultProvider, GCPSecretManagerProvider
```

**Integration:**
- `Settings` accepts optional `secret_provider: SecretProvider` at construction (test-only; production uses singleton)
- Provider queried **after** mounted files, **before** environment variables (Layer 3)
- Provider errors at startup = hard failure; runtime refresh errors = log + continue with cached value
- Configuration: `SECRET_PROVIDER=vault|aws|azure|gcp|file|none` (default: `file` for `/run/secrets`)

### 3. Secret Lifecycle Policy

| Secret | Generation | Rotation Schedule | Revocation | Destruction | Audit |
|--------|------------|-------------------|------------|-------------|-------|
| `SECRET_KEY` | `openssl rand -hex 32` (32 bytes) | **90 days** (configurable) | Immediate on compromise | Overwrite file, revoke all sessions | Rotation event in `EventLog` |
| `ENCRYPTION_KEY` | `openssl rand -hex 32` | **180 days** | Immediate on compromise | `app/encryption_key.py migrate` + overwrite | Migration + rotation in `EventLog` |
| `DATABASE_URL` | External (DB admin) | Per DB policy | Immediate on compromise | N/A (external) | Connection change in `EventLog` |
| `SYSPASS_PASSWORD_SALT` | PHP install (immutable) | **Never** | N/A | N/A | N/A |
| Master password | User-chosen (argon2id) | **365 days** (recommended) | User-initiated | Re-encrypt vault (ADR-0008) | Rotation in `EventLog` + `Config.lastupdatempass` |
| Temporary master password | `secrets.token_urlsafe(32)` | **Single-use, 15 min TTL** | Auto-expiry | Auto-delete after use | Generation + use in `EventLog` |

**Rotation Procedure (SECRET_KEY / ENCRYPTION_KEY):**
1. Generate new key (`NEW_KEY`)
2. Deploy `NEW_KEY` as **secondary** (both old and new accepted)
3. Wait for all workers to reload (max `SESSION_TTL` + grace period)
4. Promote `NEW_KEY` to primary; mark old as **revoked**
5. After grace period, remove old key from configuration
6. For `ENCRYPTION_KEY`: run `app/encryption_key.py migrate` to re-encrypt dependent data

**Overlapping Validity Window:**
- `SECRET_KEY`: JWT tokens signed with current key; verification accepts current + previous key (configurable `JWT_KEY_GRACE_PERIOD`, default 24h)
- `ENCRYPTION_KEY`: Decrypt tries current key, then previous key (configurable `ENCRYPTION_KEY_GRACE_PERIOD`, default 7 days)

### 4. Startup Validation

**Fail-Fast Checks (in `validate_production_settings` + new `validate_secrets`):**

| Check | Dev Mode (`DEBUG=true`) | Production (`DEBUG=false`) |
|-------|-------------------------|----------------------------|
| `DATABASE_URL` set | Warn | **Fail** |
| `SECRET_KEY` explicit, ≥32 bytes, not sample | Warn | **Fail** |
| `ENCRYPTION_KEY` explicit, ≥32 bytes, not sample | Warn | **Fail** |
| `SYSPASS_PASSWORD_SALT` set | Warn | **Fail** |
| `TRUSTED_PROXY_HOSTS` not `["*"]` | Warn | **Fail** |
| `SECRET_KEY` not in rotation grace period expiry | Warn | **Warn** (configurable: `SECRET_KEY_MAX_AGE_DAYS`) |
| `ENCRYPTION_KEY` not in rotation grace period expiry | Warn | **Warn** (configurable: `ENCRYPTION_KEY_MAX_AGE_DAYS`) |
| Runtime JSON readable/writable | Warn | **Fail** |
| Secret provider healthy (if configured) | Warn | **Fail** |

**New Settings:**
```python
class Settings(BaseSettings):
    # ... existing ...
    SECRET_KEY_MAX_AGE_DAYS: int = 90
    ENCRYPTION_KEY_MAX_AGE_DAYS: int = 180
    JWT_KEY_GRACE_PERIOD_HOURS: int = 24
    ENCRYPTION_KEY_GRACE_PERIOD_DAYS: int = 7
    SECRET_PROVIDER: Literal["vault", "aws", "azure", "gcp", "file", "none"] = "file"
    SECRETS_DIR: str = "/run/secrets"
    VAULT_ADDR: Optional[str] = None
    VAULT_TOKEN: Optional[str] = None
    VAULT_MOUNT: str = "secret"
    VAULT_PATH_PREFIX: str = "pysyspass/"
    AWS_REGION: Optional[str] = None
    AWS_SECRET_PREFIX: str = "pysyspass/"
    # ... Azure/GCP equivalents ...
```

**Readiness Probe Enhancement:**
- Add `secrets` check: validates secret provider health, key age warnings
- Add `configuration` check: validates all production settings + secret freshness
- Probe returns `ready: false` with specific check failures (no sensitive data)

### 5. Key Rotation Implementation

**SECRET_KEY Rotation:**
1. New setting `SECRET_KEY_PREVIOUS` (optional, mounted/env)
2. `decode_token` tries current `SECRET_KEY`, then `SECRET_KEY_PREVIOUS`
3. `encode_token` always uses current `SECRET_KEY`
4. Rotation: set `SECRET_KEY_PREVIOUS=old`, `SECRET_KEY=new`; reload workers; clear `SECRET_KEY_PREVIOUS` after grace period

**ENCRYPTION_KEY Rotation:**
1. New setting `ENCRYPTION_KEY_PREVIOUS` (optional)
2. `EncryptionService.decrypt` tries current, then previous
3. `EncryptionService.encrypt` always uses current
4. Rotation: set `ENCRYPTION_KEY_PREVIOUS=old`, `ENCRYPTION_KEY=new`; reload; run `app/encryption_key.py migrate`; clear `ENCRYPTION_KEY_PREVIOUS` after grace period

**Automation:**
- `app/rotate_secrets.py` CLI: generates new keys, stages them, verifies reload, promotes
- CI/CD integration: rotation job on schedule; manual approval gate for production
- Rollback: set `SECRET_KEY=previous`, `SECRET_KEY_PREVIOUS=current`; reload

### 6. Recovery Material Consolidation

**Break-Glass Access (ADR-0014 + ADR-0017):**
| Material | Purpose | Storage | Access Control | Expiry |
|----------|---------|---------|----------------|--------|
| Temporary master password | Vault unlock without master | `Config.temporary_master_password` (encrypted) | Admin API + MFA | 15 min, single-use |
| Pre-rotation backup | Rollback failed rotation | `backups/pre_rotation_<key>_<timestamp>.sql.gz` | File system (0700) | 30 days |
| Emergency admin token | API access without master | JWT with `emergency_admin=true` claim | Generated via CLI, logged | 1 hour |
| Disaster recovery key | Full vault recovery | Shamir split (3-of-5) in `data/recovery/` | Physical + MFA | Until reassembled |

**Recovery CLI:**
```bash
# Generate recovery split (run once, store shares offline)
python -m app.recovery generate-shares --threshold 3 --shares 5 --output-dir /secure/offline

# Reassemble for disaster recovery
python -m app.recovery reassemble --shares share1.txt share2.txt share3.txt

# Emergency admin token (requires maintenance mode)
python -m app.recovery emergency-token --ttl 3600
```

### 7. External Provider Configuration

**HashiCorp Vault (KV v2):**
```yaml
# Environment
SECRET_PROVIDER=vault
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=${VAULT_TOKEN_FROM_FILE}
VAULT_MOUNT=secret
VAULT_PATH_PREFIX=pysyspass/

# Vault paths
# secret/data/pysyspass/SECRET_KEY
# secret/data/pysyspass/ENCRYPTION_KEY
# secret/data/pysyspass/DATABASE_URL
```

**AWS Secrets Manager:**
```yaml
SECRET_PROVIDER=aws
AWS_REGION=us-east-1
AWS_SECRET_PREFIX=pysyspass/
# Secret names: pysyspass/SECRET_KEY, pysyspass/ENCRYPTION_KEY, etc.
```

**Azure Key Vault:**
```yaml
SECRET_PROVIDER=azure
AZURE_KEY_VAULT_NAME=pysyspass-kv
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
```

**GCP Secret Manager:**
```yaml
SECRET_PROVIDER=gcp
GCP_PROJECT_ID=pysyspass-prod
GCP_SECRET_PREFIX=pysyspass-
```

### 8. Developer Workflow

**Local Development (`.env`):**
```bash
# .env (never committed)
SECRET_KEY=dev-secret-key-32-bytes-minimum!!
ENCRYPTION_KEY=dev-encryption-key-32-bytes!!
DATABASE_URL=mysql+pymysql://syspass:syspass@localhost:3306/syspass
SYSPASS_PASSWORD_SALT=d4f0430a25f464b8f284e1726f692f8f175937b33bf963669f8d80499231
DEBUG=true
```

**Production Deployment (Docker Secrets):**
```yaml
# docker-compose.yml
services:
  backend:
    secrets:
      - secret_key
      - encryption_key
      - database_url
      - password_salt
    environment:
      SECRET_PROVIDER: file
      DEBUG: "false"

secrets:
  secret_key:
    file: ./secrets/secret_key.txt
  encryption_key:
    file: ./secrets/encryption_key.txt
  database_url:
    file: ./secrets/database_url.txt
  password_salt:
    file: ./secrets/password_salt.txt
```

**Kubernetes (External Secrets Operator):**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: pysyspass-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: pysyspass-secrets
    creationPolicy: Owner
  data:
    - secretKey: SECRET_KEY
      remoteRef:
        key: secret/data/pysyspass/SECRET_KEY
        property: SECRET_KEY
    # ... ENCRYPTION_KEY, DATABASE_URL, SYSPASS_PASSWORD_SALT
```

### 9. Testing Requirements

| Test | Scope | Frequency |
|------|-------|-----------|
| Precedence order unit tests | All 8 layers, every setting | Every PR |
| Secret provider contract tests | File, Vault, AWS, Azure, GCP mocks | Every PR |
| Rotation integration test | Full SECRET_KEY/ENCRYPTION_KEY cycle | Nightly |
| Startup validation matrix | Dev vs prod, all failure modes | Every PR |
| Recovery procedure drill | Temporary master, emergency token, DR shares | Quarterly |
| External provider failover | Provider down at startup, mid-runtime | Nightly |

## Consequences

### Operational
- **Clear precedence**: No ambiguity on which configuration source wins
- **Secret hygiene**: Auto-generated secrets rejected in production; rotation policy enforced
- **Mounted secrets**: Native Docker/K8s support; no more env var leakage in `docker inspect`
- **External providers**: Optional; zero code change to switch provider
- **Recovery consolidated**: Single ADR for all break-glass procedures
- **Observability**: Rotation events, secret age, provider health in readiness probe

### Development
- **Local parity**: `.env` mirrors production precedence (minus mounted secrets)
- **Testability**: `Settings` accepts `secret_provider` override; all layers mockable
- **Migration path**: Existing deployments work unchanged (env vars still Layer 2)

### Compatibility
- **PHP interop preserved**: Layer 7–8 unchanged; `SYSPASS_PASSWORD_SALT` still required
- **Bidirectional config**: Runtime JSON (Layer 6) still wins over DB Config (Layer 7)
- **No breaking changes**: New layers insert above existing; defaults unchanged

### Deployment
- **New requirements**: `SECRET_KEY`/`ENCRYPTION_KEY` must be provisioned (not auto-generated)
- **Secret provisioning**: CI/CD must generate and inject secrets (Docker secrets, K8s secrets, Vault)
- **Rotation automation**: Scheduled job + approval gate; manual CLI for emergency

### Security
- **Defense in depth**: Mounted files > env vars > external provider > .env > defaults
- **Key separation**: `SECRET_KEY` (auth) vs `ENCRYPTION_KEY` (data) vs master password (vault)
- **Rotation with overlap**: Zero-downtime key rotation; grace periods prevent lockout
- **Audit trail**: Every secret operation logged to `EventLog` with operator, timestamp, reason

## Approved Decisions (Architecture Implementation Readiness Review, 2026-11-27)

### Decision 4 — `SYSPASS_PASSWORD_SALT`: CONDITIONALLY APPROVED

Production configuration must fail securely when required cryptographic
compatibility parameters are missing or invalid — but validation must be
**compatibility-aware**, not a blanket non-empty check.

#### Verified salt semantics (investigated 2026-11-27)

| Question | Verified finding | Evidence |
|----------|------------------|----------|
| Does the salt participate in password hashing, key derivation or credential decryption? | **Key derivation and credential decryption.** `make_user_key(login, user) = login_password + username + salt` (PHP `UserPassService::makeKeyForUser`) is the key that decrypts `User.mKey` → `User.mPass` → master password/vault unlock. Also feeds the import/export PBKDF2 key and the public-link hash. It is **not** used in the identity-password hash (`User.pass`). | `app/models/user.py:87-92`, `app/services/auth_service.py:112-116`, `app/services/import_export_service.py:673`, `app/services/public_link_service.py:54` |
| Is it an original PHP configuration parameter? | **Yes.** `passwordSalt` exists in the PHP `Config` key/value table (`test_migrate_php_password_changes` adds `Config(parameter="passwordSalt", ...)`), the serialized PHP cache (`s:N:"passwordSalt";s:M:"..."`) and PHP `config.xml` (`<passwordSalt>`). | `tests/compatibility/test_bidirectional_interop.py:113`, `app/core/syspass_runtime_config.py:57-81` |
| Can its expected value be established from existing installation configuration? | **Yes** — discovery chain (runtime JSON → config.xml → PHP cache → env) already implements this. `SYSPASS_PASSWORD_SALT` is only a **fallback layer** when no PHP config artifact is present. | `app/core/syspass_runtime_config.py:113-125` |
| Do missing, empty and incorrect values have distinct effects? | **Yes.** (a) *Present-but-incorrect*: master-password decryption fails (`decrypt_user_master_pass` returns `None`) → all PHP-created vault unlocks fail; deterministic, recoverable by supplying the correct salt. (b) *Empty where PHP data expects a salt*: same failure mode as incorrect for vault unlock; **public links fail closed** (`read_public_link_snapshot` returns `None` without consuming a view; `write_public_link_vault` raises). (c) *Missing from env but present in PHP config*: no effect — discovery resolves it. | `app/services/auth_service.py:116-119`, `tests/compatibility/test_php_public_link_fixture.py:130-136`, `app/core/php_public_link.py:136,239` |
| Is an empty salt valid for any supported installation? | **Possibly, for fresh pySysPass-created installs only** — Python-created users are wrapped with the same empty-salt key, so the system is internally consistent. PHP-created data in the fixture corpus always carries a non-empty salt. **Not yet demonstrated for any PHP-created dataset.** | `tests/fixtures/php_syspass_3211_crypto.json:4` |
| Do fresh installations differ from adopted PHP databases? | **Yes.** Fresh installs control their own salt; adopted PHP databases **must** match the installation's salt or vault unlock breaks. | `docs/adr/0017` Context §2 |

#### Approved validation policy (compatibility-aware)

1. **Never silently generate or substitute a salt for an existing/adopted
   installation.** (Working tree currently violates this for *fresh* installs
   only: `salt = ... or secrets.token_hex(32)` — acceptable for fresh
   installations, must never apply to adopted data.)
2. **Missing required salt** (no PHP config source, no env value, adopted PHP
   data present): **reject at startup**.
3. **Incorrect salt**: detect at first vault unlock (deterministic decryption
   failure); startup cannot verify salt correctness without user credentials —
   readiness surface should expose salt-source provenance.
4. **Explicit legacy empty salt**: permitted **only** where verified valid for
   the installation format (fresh pySysPass-created data) and documented. Not
   verified valid for any PHP-created format to date.
5. **Fresh installations**: initialize with a generated salt per the approved
   secure-configuration policy.
6. Distinguish **effective salt** (`get_password_salt()` — PHP config or env)
   from the **`SYSPASS_PASSWORD_SALT` env var** in all validation and error
   messages. Validating only the env var is wrong when PHP config supplies the
   salt.

The working-tree validation (`if not config.SYSPASS_PASSWORD_SALT: error`) is
classified as **preliminary**: it checks only the env var, not the effective
salt, and does not distinguish adopted vs fresh installations. IMPL-019 and
T-CFG-03 are updated accordingly. The issue is **not** classified as
credential corruption or universal incompatibility — the failure mode is
detectable, deterministic and recoverable.

---

### Keyring bootstrap decision — APPROVED 2026-11-27 (AIRR §3, modified Q2a)

Backup/service-vault keyring gaps (baseline `PermissionError` on
`/etc/syspass`; CI "No backup encryption key configured") are resolved by
the architecture recorded in ADR-0010: root secrets from read-only mounted
sources (never written back); mutable keyring state behind a storage
abstraction (file / DB-wrapped / read-only+redeployment). CI provisions
synthetic root keys via its secret mechanism — mandatory backup encryption
is **not** disabled to make tests pass. The raw `os.environ` secret-read
policy (V-10/T-CFG-05) remains an open owner decision.

## References

- `docs/adr/0002-bidirectional-database-interoperability-and-extension-isolation.md`: PHP config compatibility
- `docs/adr/0008-encryption-architecture-master-password-and-cryptographic-key-lifecycle.md`: Master password, encryption
- `docs/adr/0013-backup-disaster-recovery-and-cryptographic-recoverability.md`: Backup policy
- `docs/adr/0014-emergency-authentication-mode.md`: Temporary master password, break-glass
- `docs/adr/0015-deployment-architecture-and-infrastructure-requirements.md`: Deployment constraints
- `docs/adr/0016-database-schema-ownership-and-migration-governance.md`: Migration locking (coordination model)
- `app/core/config.py`: Settings, validation
- `app/core/runtime_json_config.py`: Runtime JSON config (Layer 6)
- `app/core/syspass_runtime_config.py`: PHP config fallback (Layer 7–8)
- `app/services/config_service.py`: ConfigService (Layer 6/7 unification)
- `app/services/readiness_service.py`: Startup validation
- `app/encryption_key.py`: ENCRYPTION_KEY rotation
- `app/services/master_password_rotation.py`: Master password rotation
- `app/services/temporary_master_password_service.py`: Break-glass recovery