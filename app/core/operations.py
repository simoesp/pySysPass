"""Process-local operational failure counters (R16 / #65).

Failures that must not break a request (audit writes, reset e-mail) used to be
swallowed silently. They are now logged at ERROR level, which is what log-based
alerting should match, and counted here so administrators can see them through
GET /api/v1/security/operations. Counters reset when the process restarts and
are per worker.
"""
from collections import Counter
from datetime import UTC, datetime
import threading

_lock = threading.Lock()
_failures: Counter = Counter()
_last: dict[str, str] = {}


def record_failure(kind: str) -> None:
    with _lock:
        _failures[kind] += 1
        _last[kind] = datetime.now(UTC).isoformat()


def failure_snapshot() -> dict:
    with _lock:
        return {kind: {"count": count, "last": _last.get(kind)} for kind, count in _failures.items()}


def reset_failures() -> None:
    with _lock:
        _failures.clear()
        _last.clear()
