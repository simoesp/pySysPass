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
    SQLALCHEMY_READ_ONLY: Any = None
    SECRET_KEY: str = _generated_secret()
    ENCRYPTION_KEY: str = _generated_secret()
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


def validate_production_settings(config: Settings) -> None:
    """Reject unsafe effective settings before starting the application."""
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
