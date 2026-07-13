from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from app.core.config import settings


SECTION_KEYS: dict[str, tuple[str, str]] = {
    "sitelang": ("general", "sitelang"),
    "sitetheme": ("general", "sitetheme"),
    "session_timeout": ("general", "session_timeout"),
    "app_url": ("general", "app_url"),
    "https_enabled": ("general", "https_enabled"),
    "debug": ("general", "debug"),
    "maintenance": ("general", "maintenance"),
    "check_updates": ("general", "check_updates"),
    "check_notices": ("general", "check_notices"),
    "log_enabled": ("general", "log_enabled"),
    "syslog_enabled": ("general", "syslog_enabled"),
    "syslog_remote_enabled": ("general", "syslog_remote_enabled"),
    "syslog_server": ("general", "syslog_server"),
    "syslog_port": ("general", "syslog_port"),
    "proxy_enabled": ("general", "proxy_enabled"),
    "proxy_server": ("general", "proxy_server"),
    "proxy_port": ("general", "proxy_port"),
    "proxy_user": ("general", "proxy_user"),
    "mail_enabled": ("mail", "mail_enabled"),
    "mail_server": ("mail", "mail_server"),
    "mail_port": ("mail", "mail_port"),
    "mail_user": ("mail", "mail_user"),
    "mail_pass": ("mail", "mail_pass"),
    "mail_security": ("mail", "mail_security"),
    "mail_from": ("mail", "mail_from"),
    "mail_requests_enabled": ("mail", "mail_requests_enabled"),
    "mail_auth_enabled": ("mail", "mail_auth_enabled"),
    "mail_recipients": ("mail", "mail_recipients"),
    "ldap_enabled": ("ldap", "ldap_enabled"),
    "ldap_server": ("ldap", "ldap_server"),
    "ldap_base": ("ldap", "ldap_base"),
    "ldap_group": ("ldap", "ldap_group"),
    "ldap_binduser": ("ldap", "ldap_binduser"),
    "ldap_bindpass": ("ldap", "ldap_bindpass"),
    "ldap_server_type": ("ldap", "ldap_server_type"),
    "ldap_tls_enabled": ("ldap", "ldap_tls_enabled"),
    "ldap_defaultgroup": ("ldap", "ldap_defaultgroup"),
    "ldap_defaultprofile": ("ldap", "ldap_defaultprofile"),
    "account_count": ("accounts", "account_count"),
    "account_link": ("accounts", "account_link"),
    "account_pass_to_image": ("accounts", "account_pass_to_image"),
    "account_full_group_access": ("accounts", "account_full_group_access"),
    "account_expire_enabled": ("accounts", "account_expire_enabled"),
    "account_expire_time": ("accounts", "account_expire_time"),
    "global_search": ("accounts", "global_search"),
    "results_as_cards": ("accounts", "results_as_cards"),
    "demo_enabled": ("accounts", "demo_enabled"),
    "files_enabled": ("accounts", "files_enabled"),
    "files_allowed_size": ("accounts", "files_allowed_size"),
    "files_allowed_exts": ("accounts", "files_allowed_exts"),
    "publinks_enabled": ("accounts", "publinks_enabled"),
    "publinks_image_enabled": ("accounts", "publinks_image_enabled"),
    "publinks_max_time": ("accounts", "publinks_max_time"),
    "publinks_max_views": ("accounts", "publinks_max_views"),
    "wiki_enabled": ("wiki", "wiki_enabled"),
    "wiki_pageurl": ("wiki", "wiki_pageurl"),
    "wiki_searchurl": ("wiki", "wiki_searchurl"),
    "wiki_filter": ("wiki", "wiki_filter"),
    "dokuwiki_enabled": ("wiki", "dokuwiki_enabled"),
    "dokuwiki_url": ("wiki", "dokuwiki_url"),
    "dokuwiki_url_base": ("wiki", "dokuwiki_url_base"),
    "dokuwiki_user": ("wiki", "dokuwiki_user"),
    "dokuwiki_pass": ("wiki", "dokuwiki_pass"),
    "dokuwiki_namespace": ("wiki", "dokuwiki_namespace"),
    "configVersion": ("system", "configVersion"),
    "databaseVersion": ("system", "databaseVersion"),
    "dbHost": ("system", "dbHost"),
    "dbName": ("system", "dbName"),
    "configDate": ("system", "configDate"),
    "passwordSalt": ("compatibility", "passwordSalt"),
}

DEFAULT_DOCUMENT = {
    "general": {},
    "mail": {},
    "ldap": {},
    "accounts": {},
    "wiki": {},
    "system": {},
    "compatibility": {},
}


def _config_path() -> Path:
    return Path(settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH)


def _ensure_sections(document: dict) -> dict:
    for section in DEFAULT_DOCUMENT:
        if section not in document or not isinstance(document[section], dict):
            document[section] = {}
    return document


def load_runtime_json_config() -> dict:
    path = _config_path()
    if not path.exists():
        return _ensure_sections({})

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid runtime JSON config: {path}")
    return _ensure_sections(data)


def save_runtime_json_config(document: dict) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_ensure_sections(document), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def get_runtime_config_value(parameter: str) -> Optional[str]:
    location = SECTION_KEYS.get(parameter)
    if not location:
        return None

    section, key = location
    value = load_runtime_json_config().get(section, {}).get(key)
    if value is None:
        return None
    return str(value)


def set_runtime_config_value(parameter: str, value: Optional[str]) -> bool:
    location = SECTION_KEYS.get(parameter)
    if not location:
        return False

    section, key = location
    document = load_runtime_json_config()
    bucket = document.setdefault(section, {})
    if value is None:
        bucket.pop(key, None)
    else:
        bucket[key] = value
    save_runtime_json_config(document)
    return True
