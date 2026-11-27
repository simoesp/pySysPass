# ADR-0018 — API Versioning and Integration Compatibility

## Status

**Status:** Active (Discovery Complete)
**Date:** 2026-11-27
**Deciders:** Architecture team
**Technical Summary:** Establish explicit API versioning contract, PHP integration compatibility matrix, and service account HTTP surface for the credential vault platform.
**Outstanding TODOs:** 1 (`docs/adr/REGISTER.md` — API compatibility test execution)

---

## Context

pySysPass exposes 202 REST endpoints under `/api/v1` across 29 router modules. The API serves two distinct consumer populations:

1. **The Vue/Quasar web frontend** — session-token authenticated, same-origin, tightly coupled to the backend's release cycle.
2. **External integrations** — PHP `AuthToken`-authenticated (64-hex API tokens with action scoping), third-party scripts, and (per ADR-0010) future service-account consumers.

Three problems require an explicit contract before behavioural implementation begins:

1. **No version negotiation or deprecation mechanism.** The URI carries `/v1` but there is no `Accept` header negotiation, no `Sunset` header, and no documented policy for breaking changes.
2. **Version metadata is inconsistent.** `main.py` reports `version="2.2.2"` to FastAPI (OpenAPI metadata) while the root endpoint returns `{"version": "1.0.0"}`.
3. **Service accounts (ADR-0010) have no HTTP surface.** `ServiceAccountService`, `ServiceVaultService`, and `ServiceTokenService` are implemented in the service layer but no router is registered in `main.py`. External workloads cannot authenticate via service accounts.

### Verified API Surface Inventory

| Item | Count | Evidence |
|------|-------|---------|
| Router modules in `app/api/v1/` | 29 | File listing |
| Registered endpoints (`@router.*`) | 202 | grep count |
| FastAPI version metadata | `"2.2.2"` | `app/main.py:105` |
| Root endpoint version string | `"1.0.0"` | `app/main.py:231` |
| API token action scopes | 14 action IDs | `API_TOKEN_SCOPES` in `deps.py` |
| Auth paths | JWT, PHP AuthToken, emergency token | `get_current_user` in `deps.py` |
| Service account API routes | 0 | No router registered for service accounts |
| `Sunset` / deprecation headers | 0 | No response header middleware |
| Content-type negotiation | JSON only | All routes use `response_model` (Pydantic) |
| Rate limiting at API layer | 0 | No middleware; ADR-0015 specifies nginx-layer only (optional) |

---

## Decision

### 0. Verified Implementation Deviations (ADR-0018 Discovery)

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| **V-01** | FastAPI version `"2.2.2"` and root endpoint version `"1.0.0"` are inconsistent. OpenAPI consumers (`/openapi.json`, `/docs`) see `"2.2.2"`; integration health checks hitting `GET /` see `"1.0.0"`. | Low | Gap |
| **V-02** | Service accounts (ADR-0010) are implemented in the service layer (`service_account_service.py`, `service_vault_service.py`, `service_token_service.py`) but **no HTTP router is registered**. External workloads cannot authenticate or retrieve vault contexts. | **High** | Gap |
| **V-03** | Emergency authentication (`POST /api/v1/auth/emergency`) is implemented and registered, but `emergency_credentials` table is created by Alembic `003` — available only after a migration run, not at bootstrap. New deployments without Alembic have no emergency auth. | Medium | Gap |
| **V-04** | `API_TOKEN_SCOPES` is a static dict. Adding support for a new PHP action ID requires a code change and deployment — no configuration-driven scoping. | Low | Acceptable |
| **V-05** | All error responses use `{"detail": "..."}` except maintenance mode (`{"detail": {"code": "MAINTENANCE", "message": "..."}}`). No machine-readable error codes in the general case. | Medium | Gap |
| **V-06** | No `Sunset` (RFC 8594), `Deprecation` (draft header), or version advisory response header mechanism. Breaking API changes are communicated only via release notes. | Medium | Gap |
| **V-07** | No idempotency key support for POST endpoints. Duplicate credential creation requests (e.g., CI retry) produce duplicate accounts rather than a conflict. | Low | Gap |
| **V-08** | The `X-Forwarded-Proto` HTTPS redirect is active (`main.py:186`) but `TRUSTED_PROXY_HOSTS` must be configured; the default `["*"]` trusts all forwarded headers. Combined with `ALLOWED_HOSTS=["*"]`, any client can spoof `X-Forwarded-Proto`. | Medium | Gap (see ADR-0015 V-03) |

### 1. Versioning Strategy

**Target:** URI-based major versioning (`/api/v1`, `/api/v2`) with backward-compatible additions within a major version.

**Within a major version (e.g., v1):**
- New fields in response models are additive; consumers must ignore unknown fields.
- New endpoints may be added at any time.
- No field removals, type changes, or semantic changes without a major version bump or a deprecation period.

**Major version transitions (v1 → v2):**
- Old version enters a **deprecation period** (minimum 6 months) with `Sunset: <RFC-8594-date>` response header on all v1 routes.
- After the sunset date, v1 routes return `410 Gone` with a machine-readable body.
- Both versions may run concurrently; the version is selected purely by the URI prefix.

**API version metadata (target):**
- Source of truth: `__version__` in `app/__init__.py` (single definition).
- `GET /` returns `{"name": "pySysPass", "version": __version__, "api": {"major": 1, "minor": 0}}`.
- OpenAPI metadata uses the same `__version__`.
- Add `GET /api/v1/version` → `{"version": ..., "api_version": "v1", "schema_version": <alembic_head>}`.

**Not implemented (proposed):** `Accept: application/vnd.syspass.v1+json` content-type negotiation. URI prefix is the sole version selector for v1.

### 2. PHP AuthToken Integration Compatibility

sysPass PHP `AuthToken` records carry a numeric `actionId` that grants a fixed set of REST operations. pySysPass replicates this via `API_TOKEN_SCOPES`.

**Compatibility guarantee:** Any PHP-created `AuthToken` with a recognized `actionId` must produce the same HTTP status and response shape on the corresponding pySysPass endpoint as it would on sysPass PHP.

| actionId | PHP Permission | Python Route(s) | Implemented | Verified |
|----------|---------------|-----------------|-------------|---------|
| 3 | Account Search | `GET /api/v1/accounts`, `/search`, `/count` | ✅ | ⚠️ Partially |
| 4 | Account View Password | + `GET /accounts/{id}/password` | ✅ | ⚠️ Partially |
| 5 | Account Add | `POST /api/v1/accounts` | ✅ | ⚠️ Partially |
| 6 | Account Edit | `PUT /api/v1/accounts/{id}` | ✅ | ⚠️ Partially |
| 7 | Account Delete | `DELETE /api/v1/accounts/{id}` | ✅ | ⚠️ Partially |
| 8 | Account View | `GET /api/v1/accounts/{id}` | ✅ | ⚠️ Partially |
| 102–106 | Category CRUD | `/api/v1/categories/*` | ✅ | ❌ Not tested |
| 202–206 | Client CRUD | `/api/v1/clients/*` | ✅ | ❌ Not tested |
| 302–306 | Tag CRUD | `/api/v1/tags/*` | ✅ | ❌ Not tested |
| 802 | API Token Search | `GET /api/v1/auth-tokens` | ✅ | ❌ Not tested |
| Other PHP IDs | (future) | unmapped → 403 | N/A | N/A |

**Unmapped action IDs:** tokens with an unrecognized `actionId` return `403 Forbidden`. This is the correct fail-closed behaviour.

**AuthToken vault context:** PHP API tokens carry no master-password vault. Accessing a stored account password through the API (`GET /accounts/{id}/password`) requires the service to decrypt using the `ENCRYPTION_KEY` (server-side) rather than a user-supplied master password. This is the current implementation path; confirm before release (IMPL-024).

### 3. Service Account HTTP Surface (ADR-0010)

**Target:** Register a `/api/v1/service-accounts` router exposing:

| Endpoint | Purpose | Depends on |
|----------|---------|------------|
| `POST /api/v1/service-accounts` | Create service account (admin) | `ServiceAccountService.create_service_account` |
| `GET /api/v1/service-accounts` | List service accounts (admin) | |
| `GET /api/v1/service-accounts/{id}` | Get service account | |
| `DELETE /api/v1/service-accounts/{id}` | Disable service account | |
| `POST /api/v1/service-accounts/{id}/tokens` | Issue service token | `ServiceTokenService` |
| `POST /api/v1/service-accounts/auth` | Authenticate workload (service token → vault context) | `ServiceVaultService` |
| `GET /api/v1/service-accounts/vault/{account_id}/password` | Retrieve decrypted credential | `ServiceVaultService` |

**Authentication for service endpoints:** Workload requests present the service token via `Authorization: Bearer <service_token>`. The `get_current_user` dependency resolves the token via `ServiceTokenService` and returns a service-context payload. The service token is NOT a JWT — it is a server-random token (like PHP AuthToken) stored as a hash in `service_auth_tokens`.

### 4. Error Response Contract

**Current:** All HTTP errors return `{"detail": <string>}` (FastAPI default). Validation errors return `{"detail": [{"loc": [...], "msg": ..., "type": ...}]}` (Pydantic/FastAPI). Maintenance returns `{"detail": {"code": "MAINTENANCE", "message": ...}}`.

**Target (proposed — to be implemented in a coordinated change):**
```json
{
  "error": {
    "code": "ACCOUNT_NOT_FOUND",
    "message": "Account 42 does not exist or is not accessible",
    "request_id": "abc123"
  }
}
```
Breaking change: must be coordinated with the frontend release and `AuthToken` consumers. **Do not implement until ADR-0018 readiness review is complete.**

For now, document the current contract as-is and add a stable `X-Request-ID` response header for correlation with audit logs.

### 5. PHP Interop API Endpoints (Compatibility Surface)

PHP-compatible endpoints that PHP `AuthToken` holders or migration tooling may call:

| PHP endpoint | Python route | Status |
|-------------|-------------|--------|
| REST token authenticate | `POST /api/v1/auth/login` | ✅ Implemented |
| Account list (search) | `GET /api/v1/accounts` | ✅ Implemented |
| Account get | `GET /api/v1/accounts/{id}` | ✅ Implemented |
| Account get password | `GET /api/v1/accounts/{id}/password` | ✅ Implemented |
| Category list | `GET /api/v1/categories` | ✅ Implemented |
| Client list | `GET /api/v1/clients` | ✅ Implemented |
| Tag list | `GET /api/v1/tags` | ✅ Implemented |
| XML-RPC (legacy) | — | ❌ Not implemented |
| `public_data.php` | `GET /api/v1/public-links/{token}` | ✅ Implemented |
| Site config endpoint | `GET /api/v1/settings` | ✅ Implemented |

**XML-RPC is explicitly out of scope.** The compatibility contract (ADR-0001) covers database and credential data, not the legacy PHP XML-RPC transport. Consumers requiring XML-RPC must use a PHP gateway.

### 6. Rate Limiting and Abuse

pySysPass itself implements no application-layer rate limiting. ADR-0015 specifies nginx as the recommended deployment proxy (optional, not required for `--network=host` deployments). For production deployments behind nginx:

- Default: `limit_req zone=syspass burst=20 nodelay` per IP (10 req/s sustained).
- Credential-retrieval endpoints (`GET /accounts/{id}/password`): stricter per-token limit (1 req/s) to slow brute-force token guessing.
- Login endpoint (`POST /auth/login`): 5 req/min per IP (brute-force protection already in place at the auth-service level via `auth_time` tracking).

These are **deployment recommendations**, not enforced application invariants.

### 7. OpenAPI / Schema Generation

FastAPI auto-generates `/openapi.json` and serves `/docs` (Swagger UI) and `/redoc`. The schema is derived from Pydantic response models and is the authoritative contract for typed client generation.

**Target:** Publish `openapi.json` as a release artifact so external consumers can generate clients against a stable snapshot.

---

## Consequences

### Positive
- Single version source of truth eliminates the `"1.0.0"` / `"2.2.2"` confusion.
- Service accounts become reachable via HTTP, completing ADR-0010.
- Explicit PHP AuthToken compatibility matrix makes integration risk visible.
- `X-Request-ID` header enables cross-system traceability without a structured error contract change.

### Negative
- Service account HTTP surface requires new schemas, routes, and tests before release.
- Structured error response is a breaking change; deferred until coordinated frontend release.
- `Sunset` header support requires middleware; adding it is low effort but must be coordinated with deprecation policy.
- `API_TOKEN_SCOPES` being hardcoded means each new PHP action requires a code deploy.

### Neutral
- URI versioning is simple but less flexible than content negotiation. For a self-hosted tool with a single frontend consumer, URI versioning is appropriate.
- No application-layer rate limiting is acceptable given the expected deployment model (single-team vault).

---

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| API router registration | ✅ Implemented | 29 modules, 202 endpoints, `/api/v1` prefix |
| PHP AuthToken authentication | ✅ Implemented | `get_current_user` falls back to `_resolve_api_token` |
| Action scope enforcement | ✅ Implemented | `API_TOKEN_SCOPES` per-request check |
| Emergency auth endpoint | ✅ Implemented | `POST /api/v1/auth/emergency` |
| Service account HTTP router | ❌ Not implemented | Service layer exists; no router in `main.py` |
| `X-Request-ID` response header | ❌ Not implemented | |
| `Sunset` / deprecation header | ❌ Not implemented | |
| Version source of truth | ❌ Not implemented | Inconsistent: `"2.2.2"` vs `"1.0.0"` |
| `GET /api/v1/version` endpoint | ❌ Not implemented | |
| Structured error contract | ❌ Not implemented | Deferred |
| Idempotency key support | ❌ Not implemented | |
| OpenAPI artifact publishing | ❌ Not implemented | |

---

## Outstanding Decisions

| Decision | Status | Priority | Notes |
|----------|--------|----------|-------|
| Service account router registration and schema | Pending | High | IMPL-025 |
| Version single source of truth (`__version__`) | Pending | Medium | IMPL-026 |
| `X-Request-ID` response header | Pending | Medium | IMPL-027 |
| Structured error contract (breaking change) | Deferred | Low | Post-readiness review |
| PHP AuthToken action-ID coverage test | Pending | Medium | TEST-019 |
| Service token authentication path test | Pending | High | TEST-020 (blocks ADR-0010 completion) |

---

## Compliance and Governance

- **Data retention:** N/A to API contract.
- **Compliance mapping:** API version deprecation policy supports auditability (stable version history for API change tracking).
- **Governance:** API contract changes require an ADR update and must be reflected in `openapi.json` before release.

---

## References

- ADR-0001: Project Identity and Compatibility Contract
- ADR-0002: Bidirectional Database Interoperability (PHP `AuthToken` table)
- ADR-0009: Session Architecture, API Token Lifecycle (JWT claims contract)
- ADR-0010: Service Accounts (HTTP surface target)
- ADR-0015: Deployment Architecture (nginx rate limiting)
- ADR-0016: Schema Ownership (`emergency_credentials` table Alembic dependency)
- ADR-0017: Configuration (no per-secret API surface configuration)
- RFC 8594: The `Sunset` HTTP Header Field
- `app/main.py`: Router registration, FastAPI metadata
- `app/api/deps.py`: `API_TOKEN_SCOPES`, `get_current_user`, `_resolve_api_token`
- `app/services/service_account_service.py`, `service_vault_service.py`, `service_token_service.py`: Service-layer implementation (no HTTP surface)

---

## Annex A: Verified Implementation Gaps (Detail)

### Gap V-02: Service Account HTTP Surface

`main.py` registers 29 routers. None correspond to service accounts. The following service-layer functions exist but are unreachable via HTTP:

- `ServiceAccountService.create_service_account` (`service_account_service.py:79`)
- `ServiceVaultService` (vault context management)
- `ServiceTokenService` (token issuance, revocation)

**Impact:** ADR-0010 is implemented at the data-model and service layer (Alembic `005` creates `service_accounts`, `service_auth_tokens`, `service_vault_contexts`) but the integration is incomplete without an HTTP surface.

### Gap V-03: Emergency Auth Requires Alembic Migration

`POST /api/v1/auth/emergency` queries the `emergency_credentials` table (created by Alembic `003`). The normal bootstrap path creates the 18 PHP base tables but NOT the extension tables. A deployment that skips `alembic upgrade head` (which is the default path since bootstrap runs automatically) will have the route registered but the table absent — resulting in a `500` at runtime, not a clean `401`.

**Mitigation:** The readiness check (`GET /health/ready`) already calls `run_readiness_checks(db_base.engine)` which includes a schema validation check. Confirm that missing extension tables cause a readiness failure (IMPL-016, ADR-0016).

### Gap V-05: Error Format Inconsistency

The maintenance-mode path returns a structured `{"detail": {"code": "...", "message": "..."}}` body while all other errors return `{"detail": "plain string"}`. This inconsistency means integration clients cannot rely on a uniform error parsing strategy.

**Proposed fix:** Add a single FastAPI `exception_handler` for `HTTPException` that wraps all string details into `{"error": {"code": ..., "message": ...}}`. This is a coordinated breaking change — do not implement before readiness review.
