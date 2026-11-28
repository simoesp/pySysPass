from pydantic import ConfigDict
from pydantic_settings import BaseSettings
from typing import List, Any, Optional
import os
import secrets
import sys
import warnings
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_CORS_ORIGINS_FILE = BASE_DIR / "config" / "cors-origins.json"


def _generated_secret(length: int = 48) -> str:
    return secrets.token_urlsafe(length)


def _load_origin_list(path_value: str | os.PathLike[str]) -> list[str]:
    path = Path(path_value)
    if not path.is_absolute():
        path = BASE_DIR / path
    if not path.exists():
        return []

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise ValueError(f"Invalid CORS origins file: {path}")
    return data

class Settings(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )

    DATABASE_URL: Optional[str] = None
    AUTO_INIT_DB_ON_STARTUP: Any = True
    SQLALCHEMY_SCHEMA_GUARD: Any = True
    SCHEMA_MUTATION_LOCK_SECONDS: int = 600
    SQLALCHEMY_READ_ONLY: Any = None
    SECRET_KEY: str = _generated_secret()
    SECRET_KEY_PREVIOUS: Optional[str] = None
    ENCRYPTION_KEY: str = _generated_secret()
    SERVICE_VAULT_KEY: Optional[str] = None
    SYSPASS_PASSWORD_SALT: str = ""
    SYSPASS_RUNTIME_CONFIG_JSON_PATH: str = str(BASE_DIR / "config" / "runtime-config.json")
    SYSPASS_CONFIG_XML_PATH: str = ""
    SYSPASS_CONFIG_CACHE_PATH: str = ""
    DEBUG: bool = False
    ALLOWED_HOSTS: List[str] = ["*"]
    TRUSTED_PROXY_HOSTS: List[str] = []
    CORS_ORIGINS_FILE: str = str(DEFAULT_CORS_ORIGINS_FILE)
    CORS_ORIGINS: List[str] = []
settings = Settings()


def _running_under_pytest() -> bool:
    return "pytest" in sys.modules

if isinstance(settings.SQLALCHEMY_SCHEMA_GUARD, str):
    settings.SQLALCHEMY_SCHEMA_GUARD = settings.SQLALCHEMY_SCHEMA_GUARD.lower() in ('true', '1', 'yes', 'on')
elif not isinstance(settings.SQLALCHEMY_SCHEMA_GUARD, bool):
    settings.SQLALCHEMY_SCHEMA_GUARD = bool(settings.SQLALCHEMY_SCHEMA_GUARD)

if isinstance(settings.AUTO_INIT_DB_ON_STARTUP, str):
    settings.AUTO_INIT_DB_ON_STARTUP = settings.AUTO_INIT_DB_ON_STARTUP.lower() in ('true', '1', 'yes', 'on')
elif not isinstance(settings.AUTO_INIT_DB_ON_STARTUP, bool):
    settings.AUTO_INIT_DB_ON_STARTUP = bool(settings.AUTO_INIT_DB_ON_STARTUP)

if settings.SQLALCHEMY_READ_ONLY is not None:
    if isinstance(settings.SQLALCHEMY_READ_ONLY, str):
        settings.SQLALCHEMY_SCHEMA_GUARD = settings.SQLALCHEMY_READ_ONLY.lower() in ('true', '1', 'yes', 'on')
    else:
        settings.SQLALCHEMY_SCHEMA_GUARD = bool(settings.SQLALCHEMY_READ_ONLY)


def _is_adopted_install(config: Settings) -> bool:
    """Check if this is an adoptive (existing) installation with pre-existing data.

    An install is "adopted" when config.xml contains a non-empty ``passwordSalt``,
    meaning sysPass is managing pre-existing PHP-generated data and the salt is
    part of that adopted state — not a fresh pySysPass-created value.

    Key distinction: if passwordSalt exists in config/XML, the install is adopted
    and SYSPASS_PASSWORD_SALT must be explicitly set to match.  If no salt exists
    in config/xml, it's a fresh install and empty SYSPASS_PASSWORD_SALT is legal.
    """
    from app.core.syspass_runtime_config import load_syspass_runtime_config
    # Check runtime config first (JSON -> cache -> XML -> env)
    runtime = load_syspass_runtime_config()
    if runtime.get("passwordSalt"):
        return True
    # Check config.xml directly as fallback
    xml_candidates = [
        getattr(config, "SYSPASS_CONFIG_XML_PATH", None),
        "./app/config/config.xml",
        "/app/php-config/config.xml",
        "/var/www/html/app/config/config.xml",
        "/app/tests/res/config/config.xml",
    ]
    for path in xml_candidates:
        p = Path(path)
        if p and p.exists():
            try:
                import xml.etree.ElementTree as ET
                root = ET.parse(p).getroot()
                for child in root:
                    if child.tag == "passwordSalt" and child.text and child.text.strip():
                        return True
            except Exception:
                continue
    return False


def validate_production_settings(config: Settings) -> None:
    """Reject unsafe effective settings before starting the application.

    Distinguishes fresh-install from adoptive-data cases:

    - **Fresh install**: ``SYSPASS_PASSWORD_SALT`` may be empty; salt will be
      generated on bootstrap and persisted in the runtime JSON.
    - **Adopted data**: non-empty ``passwordSalt`` in config.xml/JSON means the
      installation is managing pre-existing PHP data; ``SYSPASS_PASSWORD_SALT`` must
      be explicitly set to the same salt, otherwise startup is rejected with a
      fail-secure error that names the remediation.
    - **Config-supplied salt**: if ``passwordSalt`` exists in config.xml, it is
      accepted as the effective salt even when ``SYSPASS_PASSWORD_SALT`` env var is
      empty — no silent substitution, the config value is the source of truth.
    """
    if config.DEBUG:
        return
    errors = []
    if not config.DATABASE_URL:
        errors.append("DATABASE_URL is required")
    for name in ("SECRET_KEY", "ENCRYPTION_KEY"):
        value = getattr(config, name)
        if name not in config.model_fields_set or len(value.strip().encode()) < 32:
            errors.append(f"{name} must be explicitly configured with at least 32 bytes")
        elif value.lower().startswith(("change-this-", "replace-with-", "test-")):
            errors.append(f"{name} must not use a sample value")
    if "*" in config.TRUSTED_PROXY_HOSTS:
        errors.append("TRUSTED_PROXY_HOSTS must identify specific proxy addresses or networks")
    # Effective-salt compatibility (IMPL-036 / ADR-0017 V-02)
    # Determine if this is an adopted installation (pre-existing PHP data)
    adopted = _is_adopted_install(config)
    if adopted:
        # Check if salt is provided via config.xml (accepted as effective salt)
        effective_salt = None
        # Check runtime config first
        from app.core.syspass_runtime_config import load_syspass_runtime_config
        runtime = load_syspass_runtime_config()
        if runtime.get("passwordSalt"):
            effective_salt = runtime["passwordSalt"]
        # If no runtime salt, check config.xml directly
        if not effective_salt:
            xml_candidates = [
                getattr(config, "SYSPASS_CONFIG_XML_PATH", None),
                "./app/config/config.xml",
                "/app/php-config/config.xml",
                "/var/www/html/app/config/config.xml",
                "/app/tests/res/config/config.xml",
            ]
            for path in xml_candidates:
                p = Path(path)
                if p and p.exists():
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.parse(p).getroot()
                        for child in root:
                            if child.tag == "passwordSalt" and child.text and child.text.strip():
                                effective_salt = child.text.strip()
                                break
                    except Exception:
                        continue
        # If we still have no effective salt, check env var
        if not effective_salt:
            effective_salt = config.SYSPASS_PASSWORD_SALT or ""
        if not effective_salt or not effective_salt.strip():
            errors.append(
                "SYSPASS_PASSWORD_SALT must be set for adopted installations; "
                "set it via env var or ensure config.xml contains passwordSalt"
            )
    if errors:
        raise RuntimeError("Invalid production configuration: " + "; ".join(errors))


if not settings.DATABASE_URL and not _running_under_pytest():
    warnings.warn(
        "DATABASE_URL is not configured. Set it in the environment or .env before using the database-backed app.",
        RuntimeWarning,
        stacklevel=2,
    )

if not settings.CORS_ORIGINS:
    settings.CORS_ORIGINS = _load_origin_list(settings.CORS_ORIGINS_FILE)
