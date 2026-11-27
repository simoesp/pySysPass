# ADR-0019 — Testing and CI/CD Governance

## Status

**Status:** Active (Discovery Complete)
**Date:** 2026-11-27
**Deciders:** Architecture team
**Technical Summary:** Establish the authoritative testing contract, CI gate policy, and verification-matrix ownership for pySysPass. Distinguish executed test evidence from documented-but-unexecuted test scenarios.
**Outstanding TODOs:** 3 (`docs/adr/REGISTER.md`, `docs/tests/verification-matrix.md`)

---

## Context

pySysPass has a mature test infrastructure: 679 test functions across 73 test files (~16,634 lines), 12 dedicated PHP-compatibility test modules, 5 PHP fixture files, 9 CI jobs including two browser-acceptance suites and a real PHP-to-Python and Python-to-PHP crypto round-trip. The CI has a 75% coverage floor, multi-DB backends (SQLite + MySQL 8), security scanning (bandit, pip-audit, npm audit, gitleaks), and container image hardening tests.

The architecture discovery process (ADR-0015 through ADR-0018) revealed that several ADRs are documented but lack executed test evidence. This ADR establishes which tests are the authoritative gate for each architectural claim and what gaps must be closed before the Architecture Implementation Readiness Review can conclude.

### Verified Test Infrastructure Inventory

| Item | Count | Evidence |
|------|-------|---------|
| Test Python files | 73 | `find tests -name "*.py"` |
| Test functions/classes | 679 | grep count |
| Total test lines | ~16,634 | `wc -l tests/**/*.py` |
| Compatibility test modules | 12 | `tests/compatibility/` |
| PHP fixture files | 5 | `tests/fixtures/` |
| CI jobs | 9 | `.github/workflows/ci.yml` |
| Coverage floor | 75% | `--cov-fail-under=75` |
| Known xfail tests | 3 test classes (IMPL-005) | `pytest.mark.xfail` grep |
| Known skip-if-file-missing tests | 4 (IMPL-006, PHP verify) | `skipif` grep |
| Security tests | `test_production_security.py`, `test_security_regression_adr0012.py`, `test_ldap_security.py` | file listing |
| Browser E2E (own stack) | `e2e-browser` CI job | Playwright, own container stack |
| Browser PHP interop | `php-web-interop` CI job | Real sysPass 3.2.11 PHP + 2FA plugin |
| Crypto reverse round-trip | `compat-php-reverse` CI job | PHP decrypts pySysPass writes; pinned commit `9d0e169` |
| MySQL schema bootstrap test | `compat-mysql` CI job | Asserts 27 physical PHP tables + 2 views + idempotent bootstrap |

### CI Job Matrix

| Job | Trigger | DB | Scope |
|-----|---------|----|-------|
| `lint` | push/PR → main | — | ruff, PEP 8 |
| `backend-tests` | push/PR → main | SQLite in-memory | All 679 tests, coverage ≥75% |
| `backend-tests-mysql` | push/PR → main | MySQL 8.0 (pinned SHA) | All 679 tests on canonical DB (NOT NULL FKs, strict types) |
| `frontend-build` | push/PR → main | — | lint, vitest, build, container security headers |
| `security` | push/PR → main | — | bandit, pip-audit, npm audit (frontend+e2e), gitleaks (full history) |
| `e2e-browser` | push/PR → main | MySQL (stack) | Playwright browser suite, own stack |
| `php-web-interop` | push/PR → main | MySQL (stack) | Real sysPass PHP 3.2.11 UI reads pySysPass data + 2FA |
| `compat-php-reverse` | push/PR → main | MySQL (stack) | PHP decrypts pySysPass writes (crypto, ACL, public links, 2FA) |
| `compat-mysql` | push/PR → main | MySQL 8.0 | Schema bootstrap, 27-table assertion, backup recovery, image hardening |

---

## Decision

### 0. Verified Implementation Deviations (ADR-0019 Discovery)

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| **V-01** | **Branch coverage gap:** CI triggers only on `push: [main]` and `pull_request: [main]`. Work on feature branches (`fix/production-readiness-foundations`) receives no automated CI feedback. The 30+ commits on the current branch are unverified by CI. | **High** | Gap |
| **V-02** | **No Alembic migration test on a populated PHP database.** `test_initial_migration.py` exists and `test_schema_parity.py` validates the schema, but neither exercises `alembic upgrade head` against a database bootstrapped from `schemas/dbstructure.sql` with data. IMPL-015/016 (Alembic lock, readiness version check) are unverified without such a test. | **High** | Gap |
| **V-03** | **No concurrent bootstrap/replica test.** `GET_LOCK('pysyspass_bootstrap', 300)` serialises bootstrap across replicas (verified in code), but no test spawns concurrent bootstrap calls and asserts only one executes the DDL. | Medium | Gap |
| **V-04** | **IMPL-006 skipif conditions are stale.** `scripts/activate-emergency-auth.sh` and `scripts/deactivate-emergency-auth.sh` exist (confirmed in `scripts/` listing) but the tests use `skipif(not SCRIPTS["activate"].exists())`. These tests should now run. | Low | Stale skips |
| **V-05** | **Verification matrix is authorization-only.** `docs/tests/authorization-test-matrix.md` covers 69 authorization scenarios (ADR-0005/0006/0007) but there is no unified verification matrix covering deployment (ADR-0015), migration (ADR-0016), configuration (ADR-0017), and API (ADR-0018) claims. | Medium | Gap |
| **V-06** | **PHP interop tests are skipped in local development.** `PYSYSPASS_PHP_VERIFY_CMD` is set only in the `compat-php-reverse` CI job. Developers running `pytest tests/` locally silently skip these tests without a visible warning. | Low | Acceptable (documented) |
| **V-07** | **No performance/load test in CI.** `scripts/load_test.py` exists but is not gated in CI. ADR-0015 performance claims (connection pool sizing, startup time) are not verified by CI. | Medium | Gap |
| **V-08** | **No test for multi-process SECRET_KEY consistency.** ADR-0017 V-01 documents the `PYSYSPASS_` compose prefix and auto-generated `SECRET_KEY`. No test simulates multi-process startup with unset `SECRET_KEY` to confirm JWT verification fails across workers. | Low | Gap |

### 1. Quality Gate Contract

The following CI jobs are **required to pass** before a change may be merged to `main`. This list is authoritative for Architecture Implementation Readiness Review purposes.

**Blocking gates (must pass):**
- `lint` — zero ruff violations
- `backend-tests` — all tests pass, coverage ≥ 75%
- `backend-tests-mysql` — all tests pass on MySQL 8.0 (canonical)
- `frontend-build` — lint, vitest, build, security headers all pass
- `security` — no new high/critical findings
- `compat-mysql` — 27-table bootstrap assertion + idempotent bootstrap + backup recovery

**Blocking for release (must pass before tagging):**
- `e2e-browser` — Playwright acceptance suite
- `php-web-interop` — real PHP reads pySysPass data
- `compat-php-reverse` — PHP decrypts pySysPass writes

**Non-blocking (informational):**
- CodeQL analysis (available but not gated)
- `load_test.py` (run manually, not in CI)

### 2. Branch Coverage Policy

**Current:** CI triggers only on `main` pushes and PRs targeting `main`.

**Target:** All active feature branches with open PRs receive CI. Add to `.github/workflows/ci.yml`:

```yaml
on:
  push:
    branches: [main, "feature/*", "fix/*"]
  pull_request:
    branches: [main]
```

This closes V-01 without requiring a full Gitea Actions migration. The cost is CI time on feature branches, which is appropriate given the PHP interop tests require a live PHP stack.

### 3. PHP Compatibility Test Contract

The bidirectional compatibility contract (ADR-0001, ADR-0002) requires test evidence in both directions:

**Direction 1 — PHP reads Python writes (`compat-php-reverse`):**
- PHP decrypts `User.mPass` values written by pySysPass
- PHP decrypts `Account.pass` values written by pySysPass
- PHP reads public links created by pySysPass
- PHP ACL fixture matches pySysPass `effective_permissions`
- Authenticator 2FA plugin reads pySysPass enrollment data
- **Pinned to sysPass commit `9d0e169`, Defuse `f53396c` (v2.4.0), plugin `b304661`**

**Direction 2 — Python reads PHP writes (`php-web-interop`):**
- pySysPass API serves data created by real sysPass 3.2.11
- pySysPass frontend renders PHP-created accounts
- pySysPass 2FA flow works with PHP-created enrollment

**Gap:** Neither direction tests Alembic extension tables (`service_accounts`, `audit_events`, etc.) from the PHP side, because PHP has no code for those tables. This is by design (extension tables are Python-only per ADR-0016).

### 4. ADR Test Evidence Requirements

Each ADR must have at least one **named test file or test function** that exercises its core claims. ADRs without test evidence cannot be marked "Verified" in the register.

| ADR | Test evidence | Status |
|-----|--------------|--------|
| ADR-0001 (Compatibility Contract) | `test_bidirectional_interop.py`, `test_php_reverse_roundtrip.py`, `test_schema_parity.py` | ✅ Evidence exists |
| ADR-0002 (DB Interop) | `test_native_writes.py`, `test_legacy_migration.py`, compat tests | ✅ Evidence exists |
| ADR-0003 (Auth + MFA) | `test_auth_login.py`, `test_mfa_before_vault_unlock.py`, `test_two_factor.py` | ✅ Evidence exists |
| ADR-0004 (IdP binding) | `test_ldap_login.py`, `test_ldap_security.py` | ✅ Evidence exists |
| ADR-0005 (Authorization) | `test_authorization_gaps.py`, `test_account_acl.py`, `test_php_permission_acl.py` | ✅ Evidence exists |
| ADR-0006 (Ownership/Sharing) | `test_account_sharing_api.py`, authorization test matrix (documented, 69 scenarios) | ⚠️ Matrix documented, partially executed |
| ADR-0007 (Effective permissions) | `test_account_acl.py` (combination tests) | ⚠️ Partially verified |
| ADR-0008 (Encryption) | `test_backup_encryption.py`, `test_php_crypto_fixture.py`, reverse round-trip | ✅ Evidence exists |
| ADR-0009 (Sessions/API tokens) | `test_sessions.py`, `test_api_token_auth.py` | ✅ Evidence exists |
| ADR-0010 (Service accounts) | `test_service_vault_context*.py` (4 files) | ⚠️ Service-layer tests; no HTTP integration test (IMPL-025 blocks) |
| ADR-0011 (Audit logging) | `test_account_audit.py` | ⚠️ Partially covered |
| ADR-0012 (Threat model) | `test_security_regression_adr0012.py`, `test_production_security.py` | ✅ Evidence exists |
| ADR-0013 (Backup/DR) | `test_backup.py`, `test_backup_integrity_authenticity.py`, CI recovery rehearsal | ✅ Evidence exists |
| ADR-0014 (Emergency auth) | `test_emergency_auth.py` (xfail: IMPL-005 pending) | ❌ Tests exist but skipped (IMPL-005) |
| ADR-0015 (Deployment) | No dedicated test — deploy docs + CI container image tests | ❌ Gap |
| ADR-0016 (Schema/Migration) | `test_db_bootstrap.py`, `test_initial_migration.py`, `test_schema_parity.py` | ⚠️ Bootstrap tested; Alembic-on-populated-DB not tested (V-02) |
| ADR-0017 (Config/Secrets) | `test_production_security.py` (validate_production_settings), `test_runtime_json_config.py`, `test_syspass_runtime_config.py` | ✅ Evidence exists |
| ADR-0018 (API versioning) | `test_api_token_auth.py` (AuthToken scoping) | ⚠️ Partially verified; service token E2E missing (TEST-020) |

### 5. Verification Matrix Ownership

**Proposed:** Create `docs/tests/verification-matrix.md` as a single document that maps every ADR architectural claim to its test evidence. This closes V-05.

**Structure:**
```
| ADR | Claim | Test ID/File | Last Run | Status |
```

The existing `docs/tests/authorization-test-matrix.md` is a domain-specific matrix (authorization tests) and should remain as a supporting document. The unified matrix links to it.

### 6. Test Skip / Xfail Policy

- All `xfail` and `skip` annotations must reference a tracked Kanban card ID.
- Skips due to file existence must be reviewed after the referenced card is done (V-04 demonstrates drift).
- CI must surface skipped tests as a warning count in the job summary (already done: `-rs` flag in pytest).
- Maximum acceptable skip count before release: 0 critical-path skips (emergency auth, service tokens, backup restore).

### 7. Known-Skip Register

| Skip/Xfail | Reason | Blocking card | Status |
|-----------|--------|--------------|--------|
| 3 emergency auth xfail classes | `POST /api/v1/auth/emergency` not wired to service layer | IMPL-005 | Active |
| 2 emergency script skips | `activate/deactivate` script existence checks (now exist; V-04) | IMPL-006 (done) | Stale — should run |
| 3 PHP verify skip-ifs | `PYSYSPASS_PHP_VERIFY_CMD` not set locally | CI-only | Acceptable |
| 1 IMPL-010 xfail probe | Service vault seal round-trip | IMPL-010 | Active |

---

## Consequences

### Positive
- Single authoritative verification matrix eliminates ambiguity about which claims have test evidence.
- Named-gate policy makes "verified" a testable property, not a documentation claim.
- Stale skips identified (V-04) will be cleaned up, recovering 2 already-implemented test suites.
- Alembic-on-populated-DB test (IMPL-028) is the precondition for ADR-0016 verification.

### Negative
- Adding feature branch CI triggers increases CI resource consumption (PHP interop tests require a real PHP container).
- Creating and maintaining a unified verification matrix adds a documentation obligation that must not drift.

### Neutral
- Coverage floor of 75% is acceptable given the complexity of the compatibility layer. Raising it before the readiness review is not recommended (would add friction to the ADR work).

---

## Implementation Status

| Item | Status | Notes |
|------|--------|-------|
| 679-test Python suite on SQLite | ✅ Implemented and passing | CI `backend-tests` |
| 679-test Python suite on MySQL 8 | ✅ Implemented and passing | CI `backend-tests-mysql` |
| PHP forward interop (PHP reads Python) | ✅ Implemented, CI-gated at release | `php-web-interop` |
| PHP reverse interop (Python writes decryptable by PHP) | ✅ Implemented, CI-gated at release | `compat-php-reverse` |
| Security scanning (4 tools) | ✅ Implemented, blocking | `security` job |
| Coverage floor at 75% | ✅ Enforced in CI | `--cov-fail-under=75` |
| Feature branch CI | ❌ Not configured | V-01 |
| Alembic-on-populated-DB test | ❌ Not implemented | V-02, IMPL-028 |
| Concurrent bootstrap test | ❌ Not implemented | V-03, IMPL-029 |
| Unified ADR verification matrix | ❌ Not implemented | V-05, IMPL-030 |
| Load test in CI | ❌ Not gated | V-07 |

---

## Outstanding Decisions

| Decision | Status | Priority |
|----------|--------|----------|
| Enable feature branch CI | Pending (IMPL-028) | **High** |
| Alembic-on-populated-DB integration test | Pending (IMPL-028) | **High** |
| Create unified verification matrix | Pending (IMPL-030) | **High** |
| Clean up stale IMPL-006 skipifs | Pending (IMPL-031) | Low |
| Add concurrent bootstrap/replica test | Pending (IMPL-029) | Medium |
| Gate load_test.py in CI | Deferred | Low |

---

## References

- `.github/workflows/ci.yml`: All CI jobs, 315 lines
- `docs/tests/authorization-test-matrix.md`: Authorization domain matrix (69 scenarios)
- `tests/compatibility/`: 12 compatibility test modules
- `tests/fixtures/`: 5 PHP fixture files (real sysPass 3.2.11 exported data)
- ADR-0001: Project Identity and Compatibility Contract
- ADR-0016: Schema Ownership (Alembic test gap V-02)
- ADR-0015: Deployment Architecture (load test gap V-07)
