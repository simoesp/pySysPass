"""Fail when requirements.lock no longer satisfies requirements.txt.

requirements.txt declares supported ranges (Dependabot edits it);
requirements.lock is the hash-pinned set the container installs. Regenerate
the lock after changing requirements.txt:

    uv pip compile requirements.txt --generate-hashes --python-version 3.11 --universal -o requirements.lock
"""
import re
import sys
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def _requirements(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            yield Requirement(line)


def _locked_versions(path: Path) -> dict:
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)==([^\s;\\]+)", line)
        if match:
            pins[canonicalize_name(match.group(1).split("[")[0])] = match.group(2)
    return pins


def main() -> int:
    pins = _locked_versions(ROOT / "requirements.lock")
    errors = []
    for requirement in _requirements(ROOT / "requirements.txt"):
        version = pins.get(canonicalize_name(requirement.name))
        if version is None:
            errors.append(f"{requirement.name} is not pinned in requirements.lock")
        elif not requirement.specifier.contains(version, prereleases=True):
            errors.append(f"{requirement.name}=={version} does not satisfy '{requirement}'")
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print(f"requirements.lock satisfies requirements.txt ({len(pins)} pinned packages)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
