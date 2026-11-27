# Wave 1 Reconciliation Manifest (GOV-003, AIRR §5)

Date: 2026-11-27. Canonical repo/ref: `origin/fix/production-readiness-foundations` @ `5e2923c`.
Evidence branches (preserved, **not** merged): `gov-003/snapshot` @ `228d612`
(64 files, +14,920 — includes `d7641d2` impl-035 atop `7e24d9d`) and local
`fix/production-readiness-foundations` @ `b2f481b` (per-card merge cluster +
one bulk WIP commit; **not pushed**). No uploads to external file services.

Remote-state incident: the earlier push of `7e24d9d` to `origin/fix` was
superseded/reset back to `5e2923c` (cause under review by GOV-003);
`7e24d9d` content survives via this branch (cherry-picked as `aeeedc8`) and
the snapshot lineage. Force-pushes to canonical branches are prohibited
going forward without owner authorization.

| Cluster | Source | Originating task | Worker | ADRs | Intended change | Status | Overlaps | Security | Required tests | Disposition |
|---------|--------|------------------|--------|------|-----------------|--------|----------|----------|----------------|-------------|
| Coordinated schema-mutation lock | `origin/impl-035/coordinated-schema-mutation-lock` @ `d7641d2` (11 files, +850) | IMPL-035 | kanban worker (night profile) | ADR-0016/0002/0013 | Single `pysyspass_schema_mutation` lock shared by bootstrap+Alembic; 600 s acquisition timeout | Unverified | `alembic/env.py`, bootstrap module (also touched by IMPL-015/016 line) | DDL serialization; aborted-migration recovery | lock serialization + populated-DB migration tests (TEST-011/012) | **Authorized but unverified** → independent review (in progress), PR |
| Main-tree capture blob | `228d612` (64 files) | GOV-003 | orchestrator worker | mixed | Preservation snapshot of concurrent worker outputs (migrations 003–006, emergency models, audit, service-account router, `verify_salt.py`, harness files) | Unreviewed | service-account router vs IMPL-025; ADR filenames | several behavioural | per-cluster | **Requires review** → split into logical clusters; per-cluster PRs; nothing merges as one blob |
| Per-card merge cluster (IMPL-012/016/017/018/030/032/033) | local `b2f481b` parents | named cards | kanban workers | per-card | direct-to-branch merges on local canonical line | Not pushed | verification-matrix (this PR touches same file) | IMPL-017 session store needs Decision-1/2 conformance review | per-card suites | **Authorized but unverified** → re-propose as PRs after reconciliation; ADR-file rename churn to be resolved here first |
| Bulk WIP commit | `b2f481b` "integration artifacts staged" | GOV-003 | kanban worker | mixed | staging of 77-path bucket | Not pushed | snapshot overlap | unclassified | — | **Unattributed/superseded** by snapshot evidence; may be dropped |
| Owner-decision docs + 28-id baseline | this PR | GOV-001/002 | orchestrator | 0010/0017/0019 | AIRR §1–§7 rulings recorded; baseline accounting corrected | CI pending | REGISTER/matrix | doc-only | — | **Authorized and verified** (doc cluster PR) |

ADR filename drift: `0010`/`0017` canonical filenames on `5e2923c` are
`...automated-credential-retrieval.md` / `...configuration-and-secret-management.md`
(AGENTS.md titles). Worker-lineage renames are reverted; further renames need
REGISTER.md + reference updates.

Cluster splits mandated by owner (AIRR §5): migrations 003–006; emergency-auth
models; audit changes; service-account HTTP router — **four distinct PRs**,
each with secret scanning and generated-artifact review before merge.
