# Verification Matrix

**Canonical gate artifact (ADR-0020).** Chain per row:
ADR → requirement → security invariant → threat → implementation task → test scenario →
executable test → verification result → release gate.

**Status vocabulary (independent per stage):** Documented · Implemented · Executed ·
Passed · Failed · Skipped · Blocked · N/A.
"A documented test scenario is not an executed test. Discovery completion is not
implementation verification."

**Evidence dates:** "Executed/Passed 2026-11-27" = baseline run recorded in
`docs/security/risk-register.md` companion notes / CI on `fix/production-readiness-foundations`.
CI-published evidence is marked "(CI)". Rows citing static reading only are marked
"static" and are **not** Executed.

## Gate status (AIRR Wave 1, 2026-11-27 owner ruling)

- **Gate 1 — Architectural readiness:** conditionally approved for Wave 1 scope.
- **Gate 2 — Implementation verification:** **not passed** (baseline failures open; CI scope divergence unexplained).
- **Gate 3 — Release readiness:** not passed. **No production deployment or release authorized.**

## Baseline run 2026-11-27 (authorized foundation work)

`.venv/bin/python -m pytest tests/ -q` → **28 failed, 702 passed, 35 skipped, 1 xfailed** (344.9 s).
Failed clusters are defect-documenting or environment-blocked; none were skipped or weakened:

| Cluster | Count | Classification |
|---------|-------|----------------|
| `tests/test_emergency_auth.py` (endpoint auth 12, audit trail 1, offline recovery 3, revocation-on-deactivation 1) | **17** | Failed — skipif masks removed (3504551) exposed ADR-0014 gaps end-to-end; defect-documenting, tracked by new Phase-6 card IMPL-041 |
| `tests/test_backup_encryption.py::test_restore_wrong_key_fails` | 1 | Failed — wrong-key restore acceptance defect (ADR-0013 crypto boundary) |
| `tests/test_backup_integrity_authenticity.py::test_signature_missing_from_manifest_fails` | 1 | Failed — manifest signature-omission not rejected (ADR-0013) |
| `tests/test_impl010_seal_matrix.py::test_seal_matrix` | 1 | Failed — `PermissionError` writing default keyring path (`/etc/syspass/…` not writable for test uid): environment gap, keyring bootstrap decision (GOV-002) |
| `tests/test_master_password_rotation.py` (preconditions, maintenance mode) | 2 | Failed — rotation flow defects (ADR-0008 lifecycle) |
| `tests/test_production_security.py::test_production_accepts_effective_dotenv_secrets` | 1 | Failed — dotenv/effective-config precedence defect (ADR-0017) |
| `tests/test_readiness.py` (ready-when-OK, malformed runtime config) | 2 | Failed — readiness logic defects (T-DEP-09 area) |
| `tests/test_service_vault_forward_security.py` (post-revoke reveal, internal validation) + `test_service_vault_operator_bootstrap.py` | 3 | Failed — service-vault forward-security + operator-bootstrap regressions (ADR-0010); new Phase-3 card IMPL-042 |

Cluster arithmetic reconciled (AIRR §7): 17+2+1+2+1+2+3 = **28**, matching pytest.
The previously reported "18 emergency" was an enumeration error: the
endpoint-auth class contains **12**, not 13, distinct node ids. No failure
belongs to two clusters. Authoritative unique failing-test-id inventory
(28):

<details><summary>28 unique FAILED node ids (2026-11-27 baseline, commit 7e24d9d lineage, dirty-tree run)</summary>

- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_disabled_emergency_account_rejected
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_emergency_endpoint_never_consults_ldap_or_user_table
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_emergency_login_audited_as_critical
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_emergency_token_is_short_lived
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_invalid_mfa_rejected
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_invalid_recovery_token_rejected_for_recovery_account
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_login_rejected_when_mode_inactive
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_login_succeeds_with_password_and_valid_mfa
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_missing_mfa_rejected
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_ordinary_ldap_user_rejected
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_recovery_personnel_can_present_recovery_token
- tests/test_emergency_auth.py::TestEmergencyEndpointAuthentication::test_wrong_password_rejected
- tests/test_emergency_auth.py::TestOfflineRecoveryPersonnel::test_expired_recovery_token_rejected
- tests/test_emergency_auth.py::TestOfflineRecoveryPersonnel::test_recovery_personnel_authenticated_only_while_mode_active
- tests/test_emergency_auth.py::TestOfflineRecoveryPersonnel::test_recovery_personnel_usage_audited
- tests/test_emergency_auth.py::TestSessionRevocationOnDeactivation::test_deactivation_revokes_active_emergency_sessions
- tests/test_emergency_auth.py::TestAuditTrail::test_login_event_recorded_with_required_fields
- tests/test_backup_encryption.py::test_restore_wrong_key_fails
- tests/test_backup_integrity_authenticity.py::test_signature_missing_from_manifest_fails
- tests/test_impl010_seal_matrix.py::test_seal_matrix  *(environment-specific: default keyring path not writable for test uid; re-evaluate under clean checkout + GOV-002 keyring abstraction)*
- tests/test_master_password_rotation.py::test_rotation_preconditions[wrong-master-Rotated-Master-\u79d8\u5bc6-2026-does not match]
- tests/test_master_password_rotation.py::test_rotation_requires_maintenance_mode
- tests/test_production_security.py::test_production_accepts_effective_dotenv_secrets
- tests/test_readiness.py::test_not_ready_with_malformed_runtime_configuration
- tests/test_readiness.py::test_ready_when_all_prerequisites_hold
- tests/test_service_vault_forward_security.py::test_context_service_internally_still_validates_after_revoke
- tests/test_service_vault_forward_security.py::test_revoked_context_never_reveals_the_master_again
- tests/test_service_vault_operator_bootstrap.py::test_operator_bootstrap_provisions_with_operator_audit

</details>

**Baseline provenance caveat:** the 28-failure baseline was executed in a
working tree that active workers were concurrently editing. A reproducible
clean-checkout baseline (same commit, no local edits) is being established
per AIRR §6; deltas will be recorded as newly-introduced vs
environment-specific before any Gate 2 claim.

Matrix rows below that cite these files now record Failed where the scenario is in a
failed cluster; "Passed (2026-11-27)" claims apply only to files actually observed green.

| ADR | Requirement | Invariant | Threat | Impl task | Test scenario | Executable test | Result | Gate |
|-----|-------------|-----------|--------|-----------|---------------|-----------------|--------|------|
| 0001/0002 | PHP schema parity preserved | Shared tables unchanged by Python-only semantics | T-CFG-03 | — | Compare live schema to `schemas/dbstructure.sql` | `tests/compatibility/test_schema_parity.py` | Documented, Implemented, Executed, Passed (2026-11-27 baseline) | G2 |
| 0002 | PHP→pySysPass forward interop | PHP 3.2.11 reads pySysPass-written data | T-MIG-04 | — | Forward E2E against upstream PHP | `scripts/php_interop_e2e.php` (CI job) | Implemented, Passed (CI, ADR-0019 discovery) | G3 |
| 0002 | pySysPass→PHP reverse interop | PHP decrypts pySysPass writes | T-MIG-04 | — | Reverse E2E (syspass `9d0e169`, defuse `f53396c`) | `scripts/php_reverse_interop_e2e.php` (CI job) | Implemented, Passed (CI) | G3 |
| 0002 | Defuse crypto parity | Encrypted column format identical | T-IDI-01 | — | Fixture vectors from PHP 3.2.11 | `tests/compatibility/test_php_crypto_fixture.py` | Implemented, Executed, Passed (2026-11-27) | G2 |
| 0005/0007 | ACL semantics parity | Effective permission resolution matches PHP | T-EVP-04 | — | PHP ACL fixture | `tests/compatibility/test_php_acl_fixture.py`, `tests/test_php_permission_acl.py` | Implemented, Executed, Passed (2026-11-27) | G2 |
| 0008 | Password salt participates in user key (PHP `makeKeyForUser`) | No silent salt substitution on adopted data | T-CFG-03 | IMPL-019 (re-scoped) | Wrong/empty/missing salt classes on adopted fixture | `tests/compatibility/test_php_crypto_fixture.py` + new adoption matrix | Documented (ADR-0017 Decision 4); adoption matrix **Not implemented** | G2 |
| 0008 | Master password ≠ identity password | Distinct secrets | T-IDI-02 | — | Login succeeds, vault unlock uses mPass | `tests/test_master_password_not_identity.py` | Implemented, Executed, Passed (2026-11-27) | G2 |
| 0009 | Server-side authoritative sessions (target) | No vault material in client JWTs | T-DEP-02 | Phase 4 | Server session revocation ≤ lease bound | **Not implemented** (current: `tests/test_auth_login.py` covers present-behavior) | Documented; target tests **Not implemented** | G2 |
| 0009 | Session revocation | Logout kills token reuse | T-DEP-01 | — | Logout → replay same token | `tests/test_auth_login.py` (revocation cases) | Implemented, Executed, Passed (2026-11-27) | G2 |
| 0010 | Service vault contexts server-side encrypted | AEAD + domain separation, key id only persisted | T-IDI-08, T-API-02 | IMPL-025, IMPL-021 | Seal matrix per service AAD | `tests/test_impl010_seal_matrix.py` | Implemented (working tree), Executed (2026-11-27 baseline), **Failed (PermissionError: default keyring path unwritable — environment bootstrap gap, see T-CFG-05 decision)** | G2 |
| 0010 | Service token end-to-end auth | HTTP surface resolves service tokens | T-API-02 | IMPL-025 | Token issued → authenticated request | **Not implemented** (no HTTP router) | Documented, Blocked on IMPL-025 | G2 |
| 0011 | Audit HMAC integrity | Entries verify against HMAC key | T-CFG-04, T-REP-* | IMPL-023 | Tamper detection on audit row | `tests/test_account_audit.py` | Implemented (partial: audit fields), verify-key matrix **Not implemented** | G2 |
| 0013 | Backup/restore round-trip | Restored DB cryptographically identical | T-IDI-07 | — | Create backup → offline restore → decrypt account | `scripts/test_backup_recovery.py` (CI: MySQL bootstrap+recovery job) | Implemented, Passed (CI) | G3 |
| 0013 | Backup encryption parity | Backup crypto interoperable | T-IDI-07 | — | Encrypted backup vectors | `tests/test_backup_encryption.py`, `tests/test_backup_integrity_authenticity.py` | Implemented, Executed (2026-11-27), **Failed (2: restore-with-wrong-key accepted; manifest signature omission not rejected)** — parity vectors passed | G2 |
| 0014 | Emergency auth (break-glass) | Extension-table absence → 401-class, not 500 | T-API-03 | IMPL-041 (new, Phase 6) | POST /auth/emergency full ADR-0014 matrix | `tests/test_emergency_auth.py` (+ stale skipifs IMPL-031) | Implemented; Executed (2026-11-27), **Failed (17 node ids — corrected 2026-11-27: endpoint auth enumerates 12)** | G2 |
| 0015 | Non-root container execution | No root runtime | T-DEP-06 | Phase 7 | Image User field + whoami | `Dockerfile` + container smoke (deployment suite) | Implemented (Debian image), Executed (manual, pre-AIRR); **UBI/OpenShift variants Not implemented** | G3 |
| 0015 | Readiness/liveness probes | Ready only when DB+schema+storage OK | T-DEP-09 | IMPL-016 | Ready endpoint under schema skew | `tests/test_readiness.py`, `tests/test_mysql_readiness.py` | Implemented (no version gate yet), Executed (2026-11-27), **Failed (2: ready-when-all-OK, malformed runtime config)**; version-gate scenario **Not implemented** | G2 |
| 0015 | Bootstrap serialization | Single bootstrapper under concurrency | T-MIG-01 | IMPL-029 | N concurrent bootstrap calls (MySQL `GET_LOCK`) | **Not implemented** (multi-replica concurrency test) | Documented | G2 |
| 0015 | Trusted proxy validation | Untrusted XFF ignored | T-DEP-07 | IMPL-013/config | Spoofed XFF from untrusted source | `tests/test_production_security.py` (static config cases) | Documented; request-level test **Not implemented** | G2 |
| 0016 | Alembic owns Python-native extensions only | No runtime DDL at startup | T-MIG-02 | IMPL-016, schema guard | Runtime DDL attempt rejected | **Not implemented** (TEST-013) | Documented | G2 |
| 0016 | Alembic on populated PHP DB | Upgrade preserves runtime data | T-MIG-01, T-TEST-02 | IMPL-015 (re-scoped, coordinated authority), IMPL-028 | Bootstrap from `dbstructure.sql` + fixtures → `alembic upgrade head` → data intact | `tests/test_alembic_upgrade_php_bootstrap.py` (uncommitted; needs Phase-2 cluster) | Documented, Implemented (working tree), Executed (2026-11-27 baseline), Passed (2026-11-27); **not CI-committed yet** | G2 |
| 0016 | Coordinated schema-mutation lock | Bootstrap ∩ Alembic never concurrent | T-MIG-01 | IMPL-015 (re-scoped per Decision 6) | Mutual-exclusion race; timeout≠duration | **Not implemented** (TEST-011 extended) | Documented (Decision 6, 2026-11-27) | G2 |
| 0016 | Interrupted migration recovery | Documented + drilled recovery | T-MIG-03, T-MIG-05 | ADR-0016 §recovery | Kill mid-migration → recover | **Not implemented** (downgrade drill) | Documented | G2 |
| 0017 | Production fail-fast config validation | Weak/placeholder production secrets rejected | T-CFG-01 | IMPL-013 | Placeholder/short env values in prod mode | `tests/test_production_security.py` | Implemented, Executed (2026-11-27), **Failed (1: effective dotenv secrets rejected)** — remainder of file passed | G2 |
| 0017 | Mounted secrets layer (`secrets_dir`) | Secrets readable from files | T-DEP-05 | IMPL-022 | Secrets dir injection equivalence | **Not implemented** (TEST-018) | Documented | G2 |
| 0017 | Effective-salt provenance | Validation uses effective salt, not env var only | T-CFG-03 | IMPL-019 (re-scoped) | config.xml-supplied salt with empty env passes validation | **Not implemented** | Documented (Decision 4) | G2 |
| 0018 | URI versioning `/api/v1` | Breaking change ⇒ `/api/v2` | T-API-04 | IMPL-026 | OpenAPI surface snapshot | Frontend `api:types` + contract check (CI) | Implemented, Passed (CI) | G2 |
| 0018 | PHP AuthToken action scoping | Unmapped action id ⇒ 403 fail-closed | T-API-01 | — | Per-action-id access matrix | `tests/test_api_token_auth.py` | Implemented, Executed, Passed (2026-11-27) | G2 |
| 0018 | X-Request-ID correlation | Every response carries correlation id | T-REP-* | IMPL-027 | Header presence/uniqueness | **Not implemented** | Documented | G2 |
| 0019 | Feature-branch CI | Every branch gets CI signal | T-TEST-01 | IMPL-028 | Trigger config + observed run | `.github/workflows/ci.yml` triggers (working tree) | Implemented (working tree), **Executed (CI): pending push of this commit** | G2 |
| 0019 | Coverage floor 75% | Named gate | T-TEST-* | — | pytest-cov gate | CI coverage job | Implemented, Passed (CI) | G3 |
| 0019 | Authorization matrix | Every AT row executable | T-EVP-* | — | `scripts/authz_matrix.py` + `docs/tests/authorization-test-matrix.md` | `tests/test_authorization_gaps.py` et al. | Implemented, Executed, Passed (2026-11-27) | G2 |
| 0020 | Docs ↔ reality | No ADR claims verified status without a Passed row here | — | IMPL-030 | This file exists & rows cite executables | review gate (process) | Implemented (this file) | G1 |
| Phase-1 | LDAP fail-secure on backend outage | No local-account downgrade | T-EVP-05 | Phase 1 defect card | LDAP down + valid/invalid local creds | `tests/test_ldap_login.py`, `tests/test_ldap_security.py` | Implemented (current-behavior), Executed, Passed (2026-11-27); **fail-secure semantics under verification** | G2 |
| Phase-1 | Export authorization | No unrestricted bulk export | T-PM-01 | Phase 1 defect card | Non-admin bulk export attempt | `tests/test_import_export.py` (authz subset) | Partial; unrestricted-export scenario **Failed/defect — pending Phase-1 confirmation** | G2 |
| Phase-1 | Admin credential field disclosure | Non-privileged responses omit secrets | T-PM-01, T-IDI-05 | Phase 1 defect card | Response field allow-list probes | **Not implemented** | Documented | G2 |

## Gate legend

- **G1** Architectural Readiness (may start) — this matrix + cards with acceptance criteria.
- **G2** Implementation Verification — every in-scope row Executed+Passed.
- **G3** Release Readiness — G2 + risk dispositions recorded + supported-platform rows Passed.

## Executive rules

1. A row may not advance to Executed without a named executable test that ran.
2. Defect-documenting tests may be Failed at first; classification required, no
   assertion-weakening to force green.
3. `docs/adr/REGISTER.md` verification column cites this file; both move together
   (Atomic Update Rule).
