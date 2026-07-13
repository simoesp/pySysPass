#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SOURCE_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_ROOT="$SOURCE_ROOT/../pySysPass2"
SOURCE_REF=HEAD
DRY_RUN=0
COMMIT=0
PUSH=0

SYNC_PATHS=(
  .dockerignore
  .env.external.example
  .gitignore
  Dockerfile
  Dockerfile.security
  Makefile
  alembic
  alembic.ini
  app
  config
  frontend
  init_db.py
  podman-compose.external.yml
  podman-compose.yml
  portainer-stack.yml
  requirements.txt
  schemas
  scripts
  tests
)

usage() {
  cat <<'EOF'
Usage: scripts/sync-code-mirror.sh [options]

Copy code from a committed pySysPass snapshot into the pySysPass2 working tree.
Git history, documentation, repository-specific CI, and untracked target files
are not copied or removed.

Options:
  --target PATH     Mirror checkout (default: ../pySysPass2)
  --source-ref REF  Committed source ref to copy (default: HEAD)
  --dry-run         Show the files that would change without writing them
  --commit          Commit mirror changes after synchronization
  --push            Commit and push the mirror's current branch
  -h, --help        Show this help

Examples:
  scripts/sync-code-mirror.sh --dry-run
  scripts/sync-code-mirror.sh
  scripts/sync-code-mirror.sh --commit
  scripts/sync-code-mirror.sh --push
EOF
}

while (($#)); do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || { echo "--target requires a path" >&2; exit 2; }
      TARGET_ROOT=$2
      shift 2
      ;;
    --source-ref)
      [[ $# -ge 2 ]] || { echo "--source-ref requires a ref" >&2; exit 2; }
      SOURCE_REF=$2
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --commit)
      COMMIT=1
      shift
      ;;
    --push)
      COMMIT=1
      PUSH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
command -v rsync >/dev/null || { echo "rsync is required" >&2; exit 1; }

TARGET_ROOT=$(cd -- "$TARGET_ROOT" 2>/dev/null && pwd) || {
  echo "Target checkout does not exist: $TARGET_ROOT" >&2
  exit 1
}

git -C "$SOURCE_ROOT" rev-parse --is-inside-work-tree >/dev/null
git -C "$TARGET_ROOT" rev-parse --is-inside-work-tree >/dev/null

SOURCE_COMMIT=$(git -C "$SOURCE_ROOT" rev-parse --verify "$SOURCE_REF^{commit}")
if [[ -n $(git -C "$TARGET_ROOT" status --porcelain) ]]; then
  echo "Refusing to overwrite a dirty target checkout: $TARGET_ROOT" >&2
  git -C "$TARGET_ROOT" status --short >&2
  exit 1
fi

SNAPSHOT=$(mktemp -d)
trap 'rm -rf -- "$SNAPSHOT"' EXIT
git -C "$SOURCE_ROOT" archive "$SOURCE_COMMIT" -- "${SYNC_PATHS[@]}" | tar -x -C "$SNAPSHOT"

# Compare file content instead of archive timestamps. Preserve only the
# executable bit from Git rather than rewriting target ownership or modes.
RSYNC_ARGS=(-rlE --checksum --itemize-changes)
if ((DRY_RUN)); then
  RSYNC_ARGS+=(--dry-run)
fi

for path in "${SYNC_PATHS[@]}"; do
  if [[ -d "$SNAPSHOT/$path" ]]; then
    rsync "${RSYNC_ARGS[@]}" -- "$SNAPSHOT/$path/" "$TARGET_ROOT/$path/"
  elif [[ -f "$SNAPSHOT/$path" ]]; then
    rsync "${RSYNC_ARGS[@]}" -- "$SNAPSHOT/$path" "$TARGET_ROOT/$path"
  fi
done

# Remove only files tracked by the target that were removed from the source
# snapshot. Target-specific untracked files and build caches remain untouched.
while IFS= read -r -d '' tracked; do
  if [[ ! -e "$SNAPSHOT/$tracked" ]]; then
    echo "delete $tracked"
    if ((!DRY_RUN)); then
      rm -f -- "$TARGET_ROOT/$tracked"
    fi
  fi
done < <(git -C "$TARGET_ROOT" ls-files -z -- "${SYNC_PATHS[@]}")

if ((DRY_RUN)); then
  echo "Dry run complete; source commit: $SOURCE_COMMIT"
  exit 0
fi

echo "Synchronized code from $SOURCE_COMMIT"
git -C "$TARGET_ROOT" status --short

if ((COMMIT)); then
  git -C "$TARGET_ROOT" add -- "${SYNC_PATHS[@]}"
  if git -C "$TARGET_ROOT" diff --cached --quiet; then
    echo "Mirror already matches the selected code snapshot; nothing to commit."
  else
    git -C "$TARGET_ROOT" commit \
      -m "Sync current application code snapshot" \
      -m "Synchronize code from pySysPass commit $SOURCE_COMMIT without importing Git history or repository-specific documentation."
  fi
fi

if ((PUSH)); then
  BRANCH=$(git -C "$TARGET_ROOT" symbolic-ref --quiet --short HEAD) || {
    echo "Cannot push from a detached target HEAD" >&2
    exit 1
  }
  git -C "$TARGET_ROOT" push origin "$BRANCH"
fi
