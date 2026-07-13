#!/usr/bin/env python3
"""Filter reviewed CodeQL false positives by stable SARIF fingerprints."""

from __future__ import annotations

import json
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: filter-codeql-sarif.py RAW OUTPUT ALLOWLIST", file=sys.stderr)
        return 2

    raw_path, output_path, allowlist_path = map(Path, sys.argv[1:])
    sarif = json.loads(raw_path.read_text(encoding="utf-8"))
    allowlist_data = json.loads(allowlist_path.read_text(encoding="utf-8"))
    allowed = {
        (entry["rule_id"], entry["primary_location_line_hash"])
        for entry in allowlist_data["allowlist"]
    }
    matched: set[tuple[str, str]] = set()

    suppressed = 0
    for run in sarif.get("runs", []):
        retained = []
        for result in run.get("results", []):
            fingerprint = result.get("partialFingerprints", {}).get(
                "primaryLocationLineHash"
            )
            if (result.get("ruleId"), fingerprint) in allowed:
                suppressed += 1
                matched.add((result["ruleId"], fingerprint))
            else:
                retained.append(result)
        run["results"] = retained

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"CodeQL reviewed compatibility findings suppressed: {suppressed}")
    if missing := allowed - matched:
        print(
            f"CodeQL allowlist entries not present in this scan: {len(missing)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
