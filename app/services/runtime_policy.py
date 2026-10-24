"""Server-side enforcement of security settings shown in the UI (R9 / #52).

Values come from the same sources as the settings page (runtime JSON, then
the PHP ``Config`` table). Reads are cached briefly per process so each
request does not reparse configuration; saving settings clears this
process's cache and other workers converge within ``CACHE_SECONDS``.
"""
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import FrozenSet, Optional

logger = logging.getLogger(__name__)

CACHE_SECONDS = 2.0
# sysPass PHP ConfigAccountController caps files_allowed_size at 16384 KB and
# compares bytes against size * 1000.
MAX_FILE_SIZE_KB = 16384
DEFAULT_FILE_SIZE_KB = 1024


@dataclass(frozen=True)
class RuntimePolicy:
    https_required: bool = False
    maintenance: bool = False
    files_enabled: bool = True
    files_allowed_size_kb: int = DEFAULT_FILE_SIZE_KB
    files_allowed_exts: FrozenSet[str] = field(default_factory=frozenset)
    # None: no MIME rule configured. Empty: PHP refuses every upload.
    files_allowed_mime: Optional[FrozenSet[str]] = None
    account_pass_to_image: bool = False
    publinks_image_enabled: bool = False

    @property
    def max_file_bytes(self) -> int:
        return self.files_allowed_size_kb * 1000


_lock = threading.Lock()
_cached: Optional[tuple] = None


def _parse_extensions(raw: Optional[str]) -> FrozenSet[str]:
    if not raw:
        return frozenset()
    return frozenset(
        part.strip().lstrip(".").upper()
        for part in raw.replace(";", ",").replace(" ", ",").split(",")
        if part.strip().lstrip(".")
    )


def _allowed_mime(raw: Optional[str]) -> Optional[FrozenSet[str]]:
    # An empty pySysPass value means "not set"; only PHP's config.xml can say
    # "no MIME type is allowed".
    if raw is not None and raw.strip():
        return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())
    from app.core.syspass_runtime_config import load_syspass_xml_list

    items = load_syspass_xml_list("filesAllowedMime")
    return None if items is None else frozenset(item.lower() for item in items)


def _flag(config, key: str, php_key: str) -> bool:
    # Unset in pySysPass: use the shared sysPass PHP config.xml value.
    value = config.get(key)
    if value is None:
        from app.core.syspass_runtime_config import load_syspass_runtime_config

        value = load_syspass_runtime_config().get(php_key)
    return (value or "").strip().lower() in ("true", "1", "yes")


def _load(db) -> RuntimePolicy:
    from app.services.config_service import ConfigService

    config = ConfigService(db)
    size = config._int_val("files_allowed_size", DEFAULT_FILE_SIZE_KB) or DEFAULT_FILE_SIZE_KB
    return RuntimePolicy(
        https_required=config._bool_val("https_enabled"),
        maintenance=config._bool_val("maintenance"),
        files_enabled=config._bool_val("files_enabled", True),
        files_allowed_size_kb=max(1, min(int(size), MAX_FILE_SIZE_KB)),
        files_allowed_exts=_parse_extensions(config.get("files_allowed_exts")),
        files_allowed_mime=_allowed_mime(config.get("files_allowed_mime")),
        account_pass_to_image=_flag(config, "account_pass_to_image", "accountPassToImage"),
        publinks_image_enabled=_flag(config, "publinks_image_enabled", "publinksImageEnabled"),
    )


def get_policy(db=None) -> RuntimePolicy:
    """Return the effective policy; opens a short session when ``db`` is None."""
    global _cached
    now = time.monotonic()
    with _lock:
        if _cached and now - _cached[0] < CACHE_SECONDS:
            return _cached[1]
    try:
        if db is not None:
            policy = _load(db)
        else:
            from app.db import base as db_base

            if db_base.engine is None:
                return RuntimePolicy()
            session = db_base.SessionLocal()
            try:
                policy = _load(session)
            finally:
                session.close()
    except Exception:
        logger.exception("Could not load runtime policy; keeping the previous one")
        with _lock:
            return _cached[1] if _cached else RuntimePolicy()
    with _lock:
        _cached = (now, policy)
    return policy


def invalidate_policy_cache() -> None:
    global _cached
    with _lock:
        _cached = None
