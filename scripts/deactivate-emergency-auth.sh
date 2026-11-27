#!/usr/bin/env bash
# Emergency Authentication Mode Deactivation Script
# Usage: sudo /srv/pySysPass/scripts/deactivate-emergency-auth.sh
# Thin wrapper that calls the main activation script with deactivate command

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_SCRIPT="${SCRIPT_DIR}/activate-emergency-auth.sh"

if [[ ! -f "$MAIN_SCRIPT" ]]; then
    echo "Error: Main script not found at $MAIN_SCRIPT" >&2
    exit 1
fi

exec "$MAIN_SCRIPT" deactivate "$@"