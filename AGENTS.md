## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, invoke the `skill` tool with `skill: "graphify"` before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

## Code style

All Python code must follow PEP 8 conventions.

Rules:
- Use 4 spaces per indentation level; never tabs.
- Keep lines within 79 characters (72 for docstrings/comments), unless the surrounding code consistently uses a longer project limit.
- Naming: `snake_case` for functions, methods, and variables; `PascalCase` for classes; `UPPER_SNAKE_CASE` for constants; a leading underscore for internal names.
- Imports at the top of the file, one per line, grouped in order: standard library, third-party, local — with a blank line between groups.
- Two blank lines around top-level functions and classes; one blank line between methods.
- Use spaces around operators and after commas; no whitespace immediately inside parentheses/brackets.
- Compare to `None` with `is` / `is not`; use `isinstance()` instead of type comparisons.
- When editing existing files, match the established style of the surrounding code rather than reformatting unrelated lines.

## sysPass PHP compatibility

This project must remain fully compatible with the original sysPass PHP version.

Rules:
- Treat sysPass PHP compatibility as a hard requirement, not a best-effort goal.
- Do not add Python-only database columns, tables, defaults, constraints, or persisted semantics unless they also exist in the upstream PHP schema.
- Before changing models, migrations, import/export, auth, permissions, encryption, or runtime config, verify behavior against the schema files in `schemas/` and the compatibility helpers in:
  - `app/models/account.py`
  - `app/models/php_compatibility.py`
  - `app/core/defuse_compat.py`
  - `app/core/syspass_runtime_config.py`
  - `app/services/user_profile_service.py`
  - `app/services/import_export_service.py`
- Prefer compatibility-preserving shims over schema changes when PHP data lacks a Python concept.
- Do not expose API fields or routes that imply persisted PHP data the upstream schema does not store.
- When fixing bugs, prefer the behavior that matches sysPass PHP over introducing a cleaner Python-only design.
- For any compatibility-sensitive change, add or update tests covering PHP-created data or upstream schema expectations.
- If a change may break PHP-created databases, XML exports, encrypted values, user profiles, shares, or config parsing, stop and call out the compatibility risk explicitly.
- Keep docs honest: do not claim “fully compatible” unless schema, behavior, and legacy data parity are verified.

Compatibility validation checklist:
- Database schema parity: columns, types, nullability, indexes, FKs, defaults.
- Encryption parity: `User.mPass`, `User.mKey`, `Account.pass`, `Account.key`.
- Config/runtime parity: JSON config plus legacy `config.xml` and cache fallbacks.
- Import/export parity: sysPass XML in both directions.
- Permissions/profile parity: PHP profile data and group/share semantics.

After compatibility-sensitive code changes:
- Run the relevant pytest coverage.
- Run `graphify update .`.
- Update `docs/project/php-compatibility-checklist.md` if the compatibility posture changed.
