#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEQL_VERSION="${CODEQL_VERSION:-2.25.5}"
DEFAULT_VERSION="2.25.5"
DEFAULT_LINUX64_SHA256="24717f939f1bef659f893ff4a9c99ba8c056fbaca9640f877c4dc74cf96486d7"
CACHE_ROOT="${CODEQL_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/pysyspass-codeql}"
BUNDLE_DIR="$CACHE_ROOT/codeql-$CODEQL_VERSION"
WORK_DIR="${CODEQL_WORK_DIR:-$ROOT_DIR/.codeql}"
DATABASE_DIR="$WORK_DIR/python-database"
RESULTS_FILE="${CODEQL_RESULTS_FILE:-$WORK_DIR/python-results.sarif}"
RAW_RESULTS_FILE="$WORK_DIR/python-results.raw.sarif"
ALLOWLIST_FILE="$ROOT_DIR/config/codeql-allowlist.json"
RELEASE_URL="https://github.com/github/codeql-action/releases/download/codeql-bundle-v$CODEQL_VERSION"

usage() {
    cat <<'EOF'
Usage: scripts/codeql-local.sh [install|analyze|clean|version]

  install  Download and verify the pinned CodeQL bundle in the user cache.
  analyze  Create a fresh Python database and write a SARIF report (default).
  clean    Remove this repository's local database and SARIF report.
  version  Print the CodeQL CLI version in use.

Environment overrides:
  CODEQL_BIN, CODEQL_VERSION, CODEQL_BUNDLE_SHA256, CODEQL_CACHE_DIR,
  CODEQL_WORK_DIR, CODEQL_RESULTS_FILE, CODEQL_THREADS, CODEQL_RAM_MB
EOF
}

platform_archive() {
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64|Linux-amd64)
            printf '%s\n' "codeql-bundle-linux64.tar.gz"
            ;;
        *)
            echo "Unsupported platform: $(uname -s) $(uname -m)" >&2
            echo "Set CODEQL_BIN to an existing CodeQL CLI binary." >&2
            return 1
            ;;
    esac
}

resolve_codeql() {
    if [[ -n "${CODEQL_BIN:-}" ]]; then
        [[ -x "$CODEQL_BIN" ]] || {
            echo "CODEQL_BIN is not executable: $CODEQL_BIN" >&2
            return 1
        }
        printf '%s\n' "$CODEQL_BIN"
        return
    fi
    if command -v codeql >/dev/null 2>&1; then
        command -v codeql
        return
    fi
    if [[ -x "$BUNDLE_DIR/codeql/codeql" ]]; then
        printf '%s\n' "$BUNDLE_DIR/codeql/codeql"
        return
    fi
    return 1
}

install_bundle() {
    if resolve_codeql >/dev/null 2>&1; then
        echo "CodeQL CLI is already available: $(resolve_codeql)"
        return
    fi

    for tool in curl sha256sum tar; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "Required tool is missing: $tool" >&2
            return 1
        }
    done

    local archive expected_sha tmp_dir archive_path
    archive="$(platform_archive)"
    expected_sha="${CODEQL_BUNDLE_SHA256:-}"
    if [[ -z "$expected_sha" && "$CODEQL_VERSION" == "$DEFAULT_VERSION" ]]; then
        expected_sha="$DEFAULT_LINUX64_SHA256"
    fi
    if [[ -z "$expected_sha" ]]; then
        echo "CODEQL_BUNDLE_SHA256 is required when overriding CODEQL_VERSION." >&2
        return 1
    fi

    mkdir -p "$CACHE_ROOT"
    tmp_dir="$(mktemp -d "$CACHE_ROOT/install.XXXXXX")"
    archive_path="$tmp_dir/$archive"

    echo "Downloading CodeQL bundle v$CODEQL_VERSION..."
    curl --fail --location --proto '=https' --tlsv1.2 \
        "$RELEASE_URL/$archive" --output "$archive_path"
    printf '%s  %s\n' "$expected_sha" "$archive_path" | sha256sum --check --status || {
        echo "CodeQL bundle checksum verification failed." >&2
        return 1
    }

    mkdir -p "$BUNDLE_DIR"
    tar -xzf "$archive_path" -C "$BUNDLE_DIR"
    [[ -x "$BUNDLE_DIR/codeql/codeql" ]] || {
        echo "Downloaded bundle did not contain the CodeQL CLI." >&2
        return 1
    }
    rm -rf "$tmp_dir"
    echo "Installed CodeQL CLI at $BUNDLE_DIR/codeql/codeql"
}

summarize_sarif() {
    python3 - "$RESULTS_FILE" <<'PY'
import json
import sys
from collections import Counter

with open(sys.argv[1], encoding="utf-8") as handle:
    sarif = json.load(handle)
results = [result for run in sarif.get("runs", []) for result in run.get("results", [])]
levels = Counter(result.get("level", "warning") for result in results)
summary = ", ".join(f"{name}={count}" for name, count in sorted(levels.items())) or "none"
print(f"CodeQL findings: {len(results)} ({summary})")
for rule_id, count in Counter(result.get("ruleId", "unknown") for result in results).most_common():
    print(f"  {count:3}  {rule_id}")
PY
}

analyze() {
    local codeql
    if ! codeql="$(resolve_codeql)"; then
        install_bundle
        codeql="$(resolve_codeql)"
    fi

    command -v python3 >/dev/null 2>&1 || {
        echo "python3 is required to summarize the SARIF report." >&2
        return 1
    }

    mkdir -p "$WORK_DIR"
    rm -rf "$DATABASE_DIR"
    "$codeql" database create "$DATABASE_DIR" \
        --language=python \
        --source-root="$ROOT_DIR" \
        --threads="${CODEQL_THREADS:-0}"
    "$codeql" database analyze "$DATABASE_DIR" \
        codeql/python-queries:codeql-suites/python-security-and-quality.qls \
        --format=sarif-latest \
        --output="$RAW_RESULTS_FILE" \
        --threads="${CODEQL_THREADS:-0}" \
        ${CODEQL_RAM_MB:+--ram="$CODEQL_RAM_MB"}

    python3 "$ROOT_DIR/scripts/filter-codeql-sarif.py" \
        "$RAW_RESULTS_FILE" "$RESULTS_FILE" "$ALLOWLIST_FILE"
    summarize_sarif
    echo "SARIF report: $RESULTS_FILE"
}

case "${1:-analyze}" in
    install)
        install_bundle
        ;;
    analyze)
        analyze
        ;;
    clean)
        rm -rf "$WORK_DIR"
        echo "Removed $WORK_DIR"
        ;;
    version)
        if ! codeql_bin="$(resolve_codeql)"; then
            install_bundle
            codeql_bin="$(resolve_codeql)"
        fi
        "$codeql_bin" version
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
