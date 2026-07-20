from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional
# defusedxml hardens against XXE/billion-laughs when parsing the legacy
# PHP config.xml (which may not be fully trusted).
from defusedxml import ElementTree

from app.core.config import settings
from app.core.runtime_json_config import load_runtime_json_config


_CACHE_PASSWORD_SALT_RE = re.compile(r'passwordSalt";s:\d+:"([^"]+)"')
_CACHE_CONFIG_DATE_RE = re.compile(r'configDate";i:(\d+)')


def _candidate_paths() -> tuple[list[Path], list[Path]]:
    xml_candidates = [
        getattr(settings, "SYSPASS_CONFIG_XML_PATH", None),
        Path("app/config/config.xml"),
        Path("/app/php-config/config.xml"),
        Path("/var/www/html/app/config/config.xml"),
        Path("/app/tests/res/config/config.xml"),
    ]
    cache_candidates = [
        getattr(settings, "SYSPASS_CONFIG_CACHE_PATH", None),
        Path("app/cache/config.cache"),
        Path("/app/php-cache/config.cache"),
        Path("/var/www/html/app/cache/config.cache"),
    ]
    return (
        [Path(p) for p in xml_candidates if p],
        [Path(p) for p in cache_candidates if p],
    )


def _read_xml_config(path: Path) -> dict[str, str]:
    root = ElementTree.parse(path).getroot()
    values: dict[str, str] = {}
    for child in root:
        if child.tag and child.text is not None:
            values[child.tag] = child.text
    return values


def _read_cache_config(path: Path) -> dict[str, str]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    values: dict[str, str] = {}
    salt_match = _CACHE_PASSWORD_SALT_RE.search(raw)
    if salt_match:
        values["passwordSalt"] = salt_match.group(1)
    config_date_match = _CACHE_CONFIG_DATE_RE.search(raw)
    if config_date_match:
        values["configDate"] = config_date_match.group(1)
    return values


@lru_cache(maxsize=1)
def load_syspass_runtime_config() -> dict[str, str]:
    try:
        runtime_json = load_runtime_json_config()
        compatibility = runtime_json.get("compatibility", {})
        if compatibility:
            return {k: str(v) for k, v in compatibility.items() if v is not None}
    except Exception:
        pass

    xml_candidates, cache_candidates = _candidate_paths()

    for path in xml_candidates:
        if path.exists():
            try:
                values = _read_xml_config(path)
                if values:
                    return values
            except Exception:
                continue

    for path in cache_candidates:
        if path.exists():
            try:
                values = _read_cache_config(path)
                if values:
                    return values
            except Exception:
                continue

    values: dict[str, str] = {}
    if settings.SYSPASS_PASSWORD_SALT:
        values["passwordSalt"] = settings.SYSPASS_PASSWORD_SALT
    return values


def get_password_salt() -> str:
    return load_syspass_runtime_config().get("passwordSalt", settings.SYSPASS_PASSWORD_SALT or "")


def get_config_date() -> Optional[int]:
    value = load_syspass_runtime_config().get("configDate")
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def clear_runtime_config_cache() -> None:
    load_syspass_runtime_config.cache_clear()
