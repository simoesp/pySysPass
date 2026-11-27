# Risk Register — Consolidated Decision Matrix

**Status:** PENDING OWNER DISPOSITION (Decision 5: no blanket acceptance authorized)
**Date:** 2026-11-27 (AIRR consolidation)
**Scope:** T-DEP-01…12 (previously referenced in `docs/adr/REGISTER.md` but undefined —
defined here), T-MIG-01…05 (ADR-0016), T-CFG-01…05 (ADR-0017), T-API-01…04 (ADR-0018),
T-TEST-01…02 (ADR-0019), and Phase-1 security-critical defects.
**Rule:** a risk is *not accepted* until the owner records a disposition here.
Likelihood/Impact values below are the agent's assessment; **Recommended disposition**
requires explicit authorization.

Disposition classes:
`MBP` Mitigate before production · `MBR` Mitigate before feature release ·
`ATC` Accept temporarily w/ compensating controls + expiration ·
`AAL` Accept as explicit architectural limitation · `AVD` Avoid by changing architecture ·
`PEND` Pending decision

## Deployment risks (T-DEP — ADR-0015)

| ID | Description | Asset | Actor | Likelihood | Impact | Current controls | Residual risk | Proposed mitigation | Dependency | Verification | Recommended | Disposition |
|----|-------------|-------|-------|-----------|--------|------------------|---------------|---------------------|------------|--------------|-------------|-------------|
| T-DEP-01 | Multi-replica deployments have no shared authoritative session state (file/in-process sessions) | Sessions | Operator (scale-out) | Medium | High | Single-instance verified | Replica-local sessions break revocation | DB-backed authoritative sessions, Redis-independent | IMPL-017 (Phase 4) | TEST: multi-worker revocation | MBP | PEND |
| T-DEP-02 | JWT embeds encrypted master-password vault material; no immediate revocation of vault context | Vault contexts | External attacker with captured JWT | Medium | High | Encrypted claim, 24 h expiry, server session check | Token valid until expiry; claim size/leakage surface | Server-side vault contexts (approved Decision 1) | Phase 4 | TEST: revocation bounded ≤ configured lease | MBP | PEND |
| T-DEP-03 | `SECRET_KEY`/`ENCRYPTION_KEY` auto-generate per process when unset → JWT validation fails across workers | JWT signing / encryption keys | Misconfigured deployment | Medium | High | Production validator requires presence | Dev/staging multi-worker inconsistent | Fail-fast in any multi-worker mode; docs | IMPL-013/config | TEST: multi-worker shared-key validation | MBR | PEND |
| T-DEP-04 | Background task scheduler is single-host (file lock, local state) | Scheduled tasks | Operator (multi-replica) | Medium | Medium | Advisory file lock | Duplicate/missed tasks across replicas | DB-coordinated task claims | Phase 4+ | TEST: concurrent scheduler claim | AAL (for current single-instance profile) | PEND |
| T-DEP-05 | Secrets only via env vars (no `secrets_dir` wiring) — visible in `docker inspect`/`/proc` | All secrets | Host-level observer | Medium | Medium | Compose secret indirection | Env exposure on shared hosts | Configure `secrets_dir` mounted secrets | IMPL-022 | TEST-018 | MBR | PEND |
| T-DEP-06 | OpenShift restricted-SCC / SELinux / arbitrary-UID deployment unverified (Decision 3 target) | Deployment target | Enterprise operator | Medium | High | Non-root user in Dockerfiles | Platform claims unverifiable | UBI image + SCC test suite | Phase 7 | OpenShift CI job (restricted SCC, random UID) | MBP (for supported-target claim) | PEND |
| T-DEP-07 | `TRUSTED_PROXY_HOSTS=["*"]` default permits `X-Forwarded-For` spoofing | Audit IP fidelity, rate limiting | External attacker | High | Low | Validation when configured | Spoofed client IPs in audit | Secure-by-default empty list + docs | IMPL-013/config | TEST: untrusted proxy header ignored | MBR | PEND |
| T-DEP-08 | Session/vault backend failure behaviour unverified (must fail secure per Decision 2) | Sessions, vault | Infra failure | Low | High | None verified | Unknown: may fail open | Fail-secure contract + tests | Phase 4 | TEST: backend-down denies access | MBR | PEND |
| T-DEP-09 | No readiness gate on schema/migration version → old replicas against migrated schema | Schema/version consistency | Operator (rolling upgrade) | Medium | High | Manual upgrade runbook | Version skew during rollout | Readiness version gate | IMPL-016 | TEST-012 | MBP | PEND |
| T-DEP-10 | Backup encryption key rotation not implemented | Backup confidentiality | Long-lived operator | Low | Medium | Offline restore verified | Key longevity risk | Rotation procedure + rewrap | ADR-0013 impl | Backup recovery rehearsal | ATC (expires: next minor release) | PEND |
| T-DEP-11 | Writable paths (runtime config JSON, cache) conflict with read-only root filesystem | Config storage | Hardened deployment | Medium | Medium | Volume mounts documented | Read-only rootfs breaks runtime config writes | Relocate runtime state to declared volume paths | Phase 7 | OpenShift read-only rootfs test | MBR | PEND |
| T-DEP-12 | MySQL 8.4 LTS not in CI matrix (8.0 only) | Database compatibility | Operator choice | Medium | Medium | Version documented | 8.4 regressions undetected | Add 8.4 job to CI matrix | IMPL-028 scope | CI matrix job | MBR | PEND |

## Migration risks (T-MIG — ADR-0016; mirror into ADR-0012)

| ID | Description | Asset | Actor | Likelihood | Impact | Current controls | Residual risk | Proposed mitigation | Dependency | Verification | Recommended | Disposition |
|----|-------------|-------|-------|-----------|--------|------------------|---------------|---------------------|------------|--------------|-------------|-------------|
| T-MIG-01 | Concurrent bootstrap/Alembic mutation of shared schema (no single authority) | Schema | Replica race / operator | Medium | High | Bootstrap `GET_LOCK` only | Alembic concurrent with bootstrap corrupts schema | **Single coordinated schema-mutation lock** (Decision 6) | IMPL-015 (re-scoped) | TEST-011 (incl. bootstrap-vs-Alembic exclusion) | MBP | PEND |
| T-MIG-02 | Silent schema mutation at startup (`AUTO_INIT_DB_ON_STARTUP=true` default) | Schema | Unexpected first-boot | Medium | Medium | Idempotent bootstrap + lock | Runtime DDL on shared DB unnoticed | Validate-not-modify at startup; privilege split | IMPL-016, IMPL-014 | TEST-013 | MBP | PEND |
| T-MIG-03 | App starts against incomplete extension schema | Availability | Deploy before `alembic upgrade` | Medium | Medium | None | 500s at first use (e.g. emergency auth) | Readiness version gate | IMPL-016 | TEST-012 | MBP | PEND |
| T-MIG-04 | `dbstructure.sql` lags PHP incremental `.sql` upgrades | Schema parity | Manual PHP upgrades | Low | High | Schema-parity tests vs. canonical file | Adopted DB drift | Parity test + runbook gate | TEST suite | `test_schema_parity.py` (executed, not vs-upstream-latest) | ATC (expires: ADR-0016 Gate 2) | PEND |
| T-MIG-05 | Alembic downgrade drops extension data without backup gate | Extension data | Operator | Low | Medium | Documented procedure only | Unrecoverable downgrade | Pre-downgrade backup verification gate | ADR-0013 ops | Downgrade drill in recovery rehearsal | MBR | PEND |

## Configuration risks (T-CFG — ADR-0017)

| ID | Description | Asset | Actor | Likelihood | Impact | Current controls | Residual risk | Proposed mitigation | Dependency | Verification | Recommended | Disposition |
|----|-------------|-------|-------|-----------|--------|------------------|---------------|---------------------|------------|--------------|-------------|-------------|
| T-CFG-01 | Env-visible secrets (see T-DEP-05) | Secrets | Host observer | High | Medium | Compose files | Same as T-DEP-05 | `secrets_dir` layer | IMPL-022 | TEST-018 | MBR | PEND |
| T-CFG-02 | `SECRET_KEY` rotation invalidates all live sessions (no overlap window) | Sessions | Operational rotation | Medium | Medium | Manual rotation runbook | Forced mass logout | `SECRET_KEY_PREVIOUS` overlap | Phase 4 | TEST-017 | MBR | PEND |
| T-CFG-03 | Effective password salt missing/incorrect on adopted PHP data | Vault unlock | Misconfigured adoption | Medium | High | Runtime-config discovery; env fallback | Vault unlock fails deterministically (recoverable; **not** corruption — see ADR-0017 Decision 4) | Compatibility-aware validation (effective salt, adopted-vs-fresh) | IMPL-019 (re-scoped) | Adoption-fixture test: wrong/empty/missing salt classes | MBP | PEND |
| T-CFG-04 | `AUDIT_HMAC_KEY` raw env, no Settings/rotation | Audit integrity | Internal attacker | Medium | Low | HMAC signing present | Rotation/unenforced-config risk | Move into Settings + validation | IMPL-023 | Audit-key tests | MBR | PEND |
| T-CFG-05 | `SERVICE_VAULT_KEY` unset discovered at runtime, not startup | Service vault | Misconfiguration | Medium | Medium | Feature opt-in | Late failure | Startup validation **when service accounts enabled** (decision presented in AIRR) | IMPL-021 scope | Startup matrix | MBR | PEND |

## API/integration risks (T-API — ADR-0018)

| ID | Description | Asset | Actor | Likelihood | Impact | Current controls | Residual risk | Proposed mitigation | Dependency | Verification | Recommended | Disposition |
|----|-------------|-------|-------|-----------|--------|------------------|---------------|---------------------|------------|--------------|-------------|-------------|
| T-API-01 | PHP AuthToken guessing | Accounts | External attacker | Low | Low | 2^256 space, action scoping | Deployment rate limiting only | Keep; document rate-limit requirement | nginx config | Token tests exist | ATC (expires: Phase 5) | PEND |
| T-API-02 | Service tokens have no HTTP surface; rotation grace unenforced end-to-end | Service identity | Integration | Medium | Medium | Hashed storage | ADR-0010 incomplete externally | Register router | IMPL-025 | TEST-020 | MBR | PEND |
| T-API-03 | Emergency auth 500 (not 401) when extension table absent | Availability/clarity | Deploy gap | Medium | Low | None | Confusing failure | Readiness gate | IMPL-016 | TEST-012 | MBR | PEND |
| T-API-04 | Version metadata inconsistency (2.2.2 vs 1.0.0) | Clients | Consumers | Low | Medium | None | Wrong client compat checks | Single `__version__` source | IMPL-026 | Version endpoint test | MBR | PEND |

## Test-governance risks (T-TEST — ADR-0019)

| ID | Description | Asset | Actor | Likelihood | Impact | Current controls | Residual risk | Proposed mitigation | Dependency | Verification | Recommended | Disposition |
|----|-------------|-------|-------|-----------|--------|------------------|---------------|---------------------|------------|--------------|-------------|-------------|
| T-TEST-01 | Feature branches untested → regressions reach main | Whole product | Dev workflow | High | Medium | CI trigger widened in working tree (IMPL-028) | Not yet in CI on main | Commit + keep triggers | IMPL-028 | Observe CI run on this branch | MBP | PEND |
| T-TEST-02 | Alembic never exercised on populated PHP DB in CI | Migration path | Deploy | Medium | Low | Unit-level migration tests only | Deploy-time discovery | Alembic-on-populated-DB job | IMPL-028 | New CI job | MBP | PEND |

## Security-critical defects (Phase 1 candidates)

| ID | Description | Asset | Actor | Likelihood | Impact | Current controls | Residual risk | Proposed mitigation | Dependency | Verification | Recommended | Disposition |
|----|-------------|-------|-------|-----------|--------|------------------|---------------|---------------------|------------|--------------|-------------|-------------|
| T-EVP-05 | LDAP failure fallback semantics — confirm fail-secure (no silent local-account downgrade) | Authentication | Attacker during LDAP outage | Medium | High | Unknown — needs code verification | Possible auth downgrade | Verify + fix fallback policy | Phase 1 card | LDAP-down auth matrix test | MBP | PEND |
| T-PM-01 | Unrestricted export: mass credential export authorization/limits | All credentials | Malicious user | Medium | High | Export authorization partial | Bulk exfiltration | Export scope checks + limits + audit | Phase 1 card | Export authz tests | MBP | PEND |
| ADMIN-DISC | Unauthorized administrator credential disclosure (field-level exposure in API responses) | Credential fields | Authenticated non-admin | Medium | High | Pending exact-surface verification | Metadata/field leakage | Response field allow-list | Phase 1 card | Regression tests on affected endpoints | MBP | PEND |

## Disposition summary

- **0 risks accepted.** Every disposition above is `PEND` pending owner authorization.
- Recommended mix: 8 MBP, 10 MBR (some overlapping mitigations), 3 ATC with expirations,
  1 AAL (single-host scheduler within the documented single-instance profile).
- No risk here is closed by documentation; closure requires the named
  verification executed and recorded in `docs/tests/verification-matrix.md`.

## Owner disposition record

| Risk IDs | Disposition | Authorized by | Date | Notes |
|----------|-------------|---------------|------|-------|
| _(none yet)_ | | | | |
