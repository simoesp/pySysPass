# ADR-0020 — Documentation Governance

## Status

**Status:** Active (Discovery Complete)
**Date:** 2026-11-27
**Deciders:** Architecture team
**Technical Summary:** Establish canonical documentation locations, ADR lifecycle, glossary ownership, verification matrix ownership, and traceability obligations. The final ADR in the discovery sequence, synthesising governance requirements from all predecessor ADRs.
**Outstanding TODOs:** 2 (`docs/tests/verification-matrix.md`, `docs/adr/0000-template.md`)

---

## Context

pySysPass has 51 markdown documents across a structured `docs/` tree plus root files. The ADR discovery process (ADR-0015 through ADR-0019) revealed several governance issues that must be addressed before the Architecture Implementation Readiness Review:

### Verified Documentation Inventory

| Location | Count | Role | Source of truth? |
|----------|-------|------|-----------------|
| `docs/adr/` | 20 files (0001–0019 + template) | Architectural decisions | ✅ Canonical |
| `docs/adr/REGISTER.md` | 1 file, 354 lines | ADR status, dependencies, outstanding decisions | ✅ Canonical for status |
| `docs/adr/archive/` | 3 superseded drafts | Historical ADR drafts | ⚠️ Not supersession-tracked |
| `docs/GLOSSARY.md` | 1 file, 339 lines | Canonical domain terminology | ✅ Canonical (single location) |
| `AGENTS.md` | 94 lines, repo root | Agent/tooling instructions, code style, ADR rules | ✅ Canonical for coding rules |
| `docs/README.md` | Documentation map | Reader entry point | ✅ Canonical map |
| `docs/project/` | 6 files | Project status, compat checklist, load test report | ⚠️ Mixed temporal currency |
| `docs/security/` | 2 files | Security policy, scanning workflow | ✅ Canonical |
| `docs/audit/` | 9 files | Audit domain documentation | ✅ Canonical for audit |
| `docs/tests/` | 1 file (authorization matrix) | Domain-specific test matrix | ✅ Canonical (authorization only) |
| `docs/tests/verification-matrix.md` | Does not exist yet | Unified ADR claim ↔ test evidence | ❌ Gap (ADR-0019 V-05) |
| `docs/kanban/tasks.md` | 321 lines | Operational card descriptions | ❌ Not authoritative (DB is) |
| `docs/api/reference.md` | API endpoint catalog | ✅ Canonical for API docs |
| `README.md` | Root project README | Project entry point | ✅ Canonical for user-facing overview |

### Discovered Governance Issues

| ID | Finding | Severity |
|----|---------|----------|
| **V-01** | **ADR template (0000-template.md) is stale.** The template has 4 sections (Context, Decision, Consequences, References) but ADR-0015 through ADR-0019 all have a "Verified Implementation Deviations" section, a "Implementation Status" section, and an "Outstanding Decisions" section that the template does not prescribe. | Medium |
| **V-02** | **`docs/kanban/tasks.md` is a duplicate of the Kanban DB content.** The operational card body duplicates what is in the Kanban SQLite database. The file is not automatically updated when the DB changes; it will drift. | Medium |
| **V-03** | **`docs/project/production-readiness-review-2026-10-23.md` predates the current discovery cycle.** It was written 5 weeks ago and does not reflect any findings from ADR-0015 through ADR-0019. Its conclusions may be misleading. | Low |
| **V-04** | **Archive files have no supersession metadata.** `docs/adr/archive/0010-revised.md` and `0010-revised-reconciled.md` contain older ADR-0010 drafts but are not explicitly linked as superseded from the active ADR-0010. | Low |
| **V-05** | **No unified ADR verification matrix.** Only `authorization-test-matrix.md` exists. ADR-0019 mapped test evidence to all ADRs but there is no living document that tracks which ADR claims have been verified by which tests. | Medium |
| **V-06** | **`docs/README.md` is incomplete.** It lists Getting Started, Security, and Development sections but omits: ADR directory, runbooks, audit docs, the glossary, and the tests directory. | Low |

---

## Decision

### 1. Canonical Location Registry

Each document type has exactly one authoritative location. A change to the authoritative location is a change to the system of record; any other copies are downstream consumers that must be kept in sync or marked as derived.

| Document type | Canonical location | Derived/consumers |
|---------------|-------------------|-------------------|
| Architectural decision | `docs/adr/NNNN-*.md` | REGISTER.md status summary |
| ADR implementation status | `docs/adr/REGISTER.md` | Kanban card body (summary only) |
| Domain terminology | `docs/GLOSSARY.md` | ADR term references |
| Threat model | `docs/adr/0012-*.md` | ADR threat cross-references |
| Verification matrix | `docs/tests/verification-matrix.md` (to be created) | ADR-0019 test evidence table |
| Authorization test matrix | `docs/tests/authorization-test-matrix.md` | Verification matrix links to it |
| API endpoint reference | `docs/api/reference.md` | OpenAPI auto-generated docs |
| PHP compatibility status | `docs/project/php-compatibility-checklist.md` | REGISTER.md compatibility column |
| Security policy | `docs/security/policy.md` | ADR-0012 threat model |
| Operational runbooks | `docs/runbooks/` | Referenced from ADRs |
| Agent coding rules | `AGENTS.md` (root) | Referenced from CI, developer setup |
| Project status/overview | `README.md` (root) | Not duplicated |
| Kanban operational state | Kanban SQLite DB (`kanban.db`) | `docs/kanban/tasks.md` is a convenience view |

### 2. ADR Status Lifecycle

```
Proposed → Active → Completed
                  → Superseded (by: NNNN)
                  → Deprecated (reason: ...)
```

**Proposed:** Draft. Status is provisional; may change without supersession.
**Active:** Decision is authoritative. Implementation may be partial. All predecessor ADRs must be reconciled.
**Completed:** Decision is fully implemented and verified. A "Completed" ADR has no outstanding Kanban cards and all claims have test evidence.
**Superseded:** Replaced by a specific later ADR. `Status: Superseded by ADR-NNNN`. The active ADR has a `Supersedes: ADR-NNNN` line. Superseded ADRs move to `docs/adr/archive/`.
**Deprecated:** No longer applicable; no replacement. Reason stated.

**Prohibition:** An ADR cannot be marked Completed if any claim lacks test evidence. See ADR-0019 §4.

### 3. ADR Template Extension

`0000-template.md` is updated to include the sections that ADR-0015–0019 have evolved:

- `## Verified Implementation Deviations` — after `## Decision`, before `## Consequences`. Table format: `| # | Finding | Severity | Status |`
- `## Implementation Status` — after `## Consequences`. Table format: `| Item | Status | Notes |`
- `## Outstanding Decisions` — after `## Implementation Status`. Table format: `| Decision | Status | Priority |`

The existing 4 sections remain required.

### 4. Kanban Source of Truth

The Kanban SQLite database (`/home/hermes/.hermes/kanban/boards/pysyspass/kanban.db`) is the sole authoritative source for task state. `docs/kanban/tasks.md` is a convenience snapshot for humans browsing the repository.

**Rule:** `docs/kanban/tasks.md` must be annotated with "Last synced: YYYY-MM-DD" at the top and "Not authoritative — Kanban DB is the source of truth" below. Task state changes are made in the DB, not the file.

### 5. Verification Matrix Requirements

`docs/tests/verification-matrix.md` (to be created per ADR-0019 IMPL-030) must contain one row per ADR architectural claim:

```
| ADR | Claim | Test file/function | CI job | Last verified | Status |
```

Status values: `Verified` (test ran in CI), `Documented` (test written but not CI-gated), `Gap` (no test exists).

A claim marked `Gap` in the verification matrix blocks its ADR from being marked `Completed`.

### 6. Archive Supersession Convention

Superseded ADRs in `docs/adr/archive/` must have a header line:

```markdown
> Superseded by: ADR-NNNN — <title>. Kept for provenance.
```

The active ADR must list `Supersedes: ADR-NNNN (archive/...)` in its front matter or first section.

### 7. Documentation Consistency Obligation

When an ADR's implementation status changes, the following must be updated atomically in the same commit:

1. The ADR document itself (Status, Implementation Status table, Outstanding Decisions)
2. `docs/adr/REGISTER.md` (summary table + detail section)
3. The Kanban DB (task status update)
4. `docs/tests/verification-matrix.md` (if the status change affects test evidence)

**Prohibition:** Do not update one without the others. Partial updates create the drift that V-03 (stale readiness review) demonstrates.

### 8. docs/README.md Completeness

`docs/README.md` must link to every subdirectory in `docs/`. Add a section for:

- Architecture Decisions: links to `adr/REGISTER.md` as entry point
- Domain Glossary: link to `GLOSSARY.md`
- Threat Model: link to `adr/0012-*.md`
- Audit: link to `audit/` directory
- Runbooks: link to `runbooks/`
- Tests and verification: link to `tests/`

### 9. Historical Documents

Documents with a date in the filename (e.g. `production-readiness-review-2026-10-23.md`, `load-test-2026-10-24.md`) are historical records. They must carry a "Historical: written YYYY-MM-DD; may not reflect current state" banner. They are never updated in place; a new document supersedes them.

### 10. AGENTS.md Obligations

`AGENTS.md` at the repository root is the authoritative coding agent instruction file. It must include:

1. Link to `docs/adr/REGISTER.md` before any architectural change
2. Link to `docs/GLOSSARY.md` for canonical terminology
3. Link to `docs/adr/0012-*.md` for security impact assessment
4. `sysPass compatibility` rules (existing)
5. `graphify update .` after code changes (existing)
6. Code style / ruff rules (existing)

`AGENTS.md` must NOT duplicate content from ADRs — it links to them.

---

## Consequences

### Positive
- Single authoritative locations eliminate "which document is correct" ambiguity.
- ADR template now prescribes the deviation-tracking sections that the discovery process invented.
- Verification matrix becomes the readiness gate: an ADR cannot be marked Completed without test evidence rows.
- `docs/kanban/tasks.md` is demoted from source-of-truth to convenience view, eliminating the drift vector.

### Negative
- Creating `docs/tests/verification-matrix.md` with initial content for all 19 ADRs is a one-time effort (IMPL-030, estimated as one task).
- Historical documents need banner annotations (low effort, high volume).

### Neutral
- `docs/adr/archive/` is correctly populated; no new moves needed in this cycle.
- The ADR 0020 itself becomes the governance document; it is referenced by `AGENTS.md` to enforce documentation compliance on future changes.

---

## Implementation Status

| Item | Status | Notes |
|------|--------|-------|
| 20 ADRs follow template structure | ✅ Verified | 0001–0019 + 0000 template |
| Single canonical glossary | ✅ Verified | `docs/GLOSSARY.md` only (339 lines, ~90 terms) |
| Single canonical ADR register | ✅ Verified | `docs/adr/REGISTER.md` (354 lines) |
| ADR cross-references | ✅ Verified | All new ADRs (0015–0019) reference predecessors |
| Threat model in single location | ✅ Verified | `docs/adr/0012-*.md` |
| AGENTS.md links to ADRs | ✅ Verified | AGENTS.md references REGISTER.md |
| ADR template has deviation section | ❌ Not updated | V-01, IMPL-032 |
| Unified verification matrix | ❌ Not created | V-05, IMPL-030 (tracked in ADR-0019) |
| `docs/kanban/tasks.md` annotated | ❌ Not annotated | V-02, IMPL-032 |
| Historical document banners | ❌ Not added | V-03, IMPL-033 |
| `docs/README.md` completeness | ❌ Incomplete | V-06, IMPL-032 |
| Archive supersession headers | ❌ Not added | V-04, IMPL-033 |

---

## Outstanding Decisions

| Decision | Status | Priority |
|----------|--------|----------|
| Update `0000-template.md` with deviation/status/decision sections | Pending (IMPL-032) | Medium |
| Create `docs/tests/verification-matrix.md` | Pending (IMPL-030, ADR-0019) | **High** |
| Annotate `docs/kanban/tasks.md` as non-authoritative | Pending (IMPL-032) | Low |
| Add historical banners to dated project documents | Pending (IMPL-033) | Low |
| Complete `docs/README.md` navigation | Pending (IMPL-032) | Low |
| Add supersession headers to archive files | Pending (IMPL-033) | Low |

---

## References

- ADR-0019: Testing and CI/CD Governance (verification matrix requirement)
- ADR-0015–0019: Discovery deviation sections (template evolution)
- `AGENTS.md`: Repository coding agent instruction file
- `docs/adr/README.md`: ADR directory entry point
- `docs/adr/0000-template.md`: ADR template (to be updated)
- `docs/adr/REGISTER.md`: ADR status register
- `docs/GLOSSARY.md`: Canonical domain glossary
