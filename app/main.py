from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from app.core.config import settings, validate_production_settings
from app.core.runtime_json_config import load_runtime_json_config
from app.db.bootstrap import bootstrap_database_on_startup
from app.db import base as db_base
from app.db.base import SchemaMutationError
from app.api.v1 import (
    accounts, auth, categories, clients, users, two_factor, tags, history,
    files, public_links, notifications, user_groups, user_profiles, security,
    config_settings, custom_fields, account_sharing, import_export, auth_tokens,
    security_logs, password_reset, ldap, item_presets, backup, plugins, audit,
)
from app.services.readiness_service import run_readiness_checks
from app.services.runtime_policy import get_policy
from app.services.task_service import task_service
from app.services.emergency_auth import emergency_endpoint_enabled
from app.core.operations import record_failure
from contextlib import asynccontextmanager
import logging
import re


# ── Audit log middleware ───────────────────────────────────────────────────────
# Maps (METHOD, path-pattern) → human-readable action name written to EventLog.
# Only mutating methods on successful (2xx) responses are logged.
_AUDIT_ROUTES: list[tuple[str, re.Pattern, str, str]] = [
    # method, pattern, action, level
    ("POST",   re.compile(r"^/api/v1/accounts$"),                "account.create",       "INFO"),
    ("PUT",    re.compile(r"^/api/v1/accounts/\d+$"),            "account.edit",         "INFO"),
    ("DELETE", re.compile(r"^/api/v1/accounts/\d+$"),            "account.delete",       "WARN"),
    ("POST",   re.compile(r"^/api/v1/accounts/\d+/copy$"),       "account.clone",        "INFO"),
    ("POST",   re.compile(r"^/api/v1/users$"),                   "user.create",          "INFO"),
    ("PUT",    re.compile(r"^/api/v1/users/\d+$"),               "user.edit",            "INFO"),
    ("DELETE", re.compile(r"^/api/v1/users/\d+$"),               "user.delete",          "WARN"),
    ("POST",   re.compile(r"^/api/v1/categories$"),              "category.create",      "INFO"),
    ("PUT",    re.compile(r"^/api/v1/categories/\d+$"),          "category.edit",        "INFO"),
    ("DELETE", re.compile(r"^/api/v1/categories/\d+$"),          "category.delete",      "WARN"),
    ("POST",   re.compile(r"^/api/v1/clients$"),                 "client.create",        "INFO"),
    ("PUT",    re.compile(r"^/api/v1/clients/\d+$"),             "client.edit",          "INFO"),
    ("DELETE", re.compile(r"^/api/v1/clients/\d+$"),             "client.delete",        "WARN"),
    ("POST",   re.compile(r"^/api/v1/user-groups$"),             "usergroup.create",     "INFO"),
    ("PUT",    re.compile(r"^/api/v1/user-groups/\d+$"),         "usergroup.edit",       "INFO"),
    ("DELETE", re.compile(r"^/api/v1/user-groups/\d+$"),         "usergroup.delete",     "WARN"),
    ("POST",   re.compile(r"^/api/v1/custom-fields/definitions$"), "customfield.create", "INFO"),
    ("DELETE", re.compile(r"^/api/v1/custom-fields/definitions/\d+$"), "customfield.delete", "WARN"),
    ("PUT",    re.compile(r"^/api/v1/settings/"),                "settings.change",      "WARN"),
    ("POST",   re.compile(r"^/api/v1/settings/encryption/temp-master$"), "tempmaster.generate", "WARN"),
    ("POST",   re.compile(r"^/api/v1/backup/create$"),           "backup.create",        "INFO"),
    ("POST",   re.compile(r"^/api/v1/backup/.+/restore$"),       "backup.restore",       "WARN"),
    ("DELETE", re.compile(r"^/api/v1/backup/"),                  "backup.delete",        "WARN"),
    ("POST",   re.compile(r"^/api/v1/plugins/sync$"),            "plugin.sync",          "INFO"),
    ("POST",   re.compile(r"^/api/v1/plugins/.+/enable$"),       "plugin.enable",        "WARN"),
    ("POST",   re.compile(r"^/api/v1/plugins/.+/disable$"),      "plugin.disable",       "WARN"),
    ("PUT",    re.compile(r"^/api/v1/plugins/.+/config$"),       "plugin.config.update", "WARN"),
    ("POST",   re.compile(r"^/api/v1/import"),                   "import.run",           "WARN"),
    ("DELETE", re.compile(r"^/api/v1/audit-log$"),              "auditlog.clear",       "WARN"),
]


logger = logging.getLogger(__name__)


def _resolve_audit(method: str, path: str):
    for m, pattern, action, level in _AUDIT_ROUTES:
        if method == m and pattern.match(path):
            return action, level
    return None, None


def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "0.0.0.0"  # nosec B104


def _get_user_from_request(request: Request):
    """Extract user_id + username from JWT without raising — best-effort."""
    try:
        auth_hdr = request.headers.get("Authorization", "")
        if not auth_hdr.startswith("Bearer "):
            return None, None
        from app.services.auth_service import decode_token
        payload = decode_token(auth_hdr[7:])
        if payload:
            return payload.get("user_id"), payload.get("username")
    except Exception:
        pass
    return None, None


@asynccontextmanager
async def lifespan(application: FastAPI):
    validate_production_settings(settings)
    bootstrap_database_on_startup()
    _audit_emergency_gate_config()
    # IMPL-036: Generate salt on fresh install bootstrap; adopted installs
    # must already have SYSPASS_PASSWORD_SALT set (validated above).
    if not _is_adopted_install(settings):
        from app.core.syspass_runtime_config import save_runtime_json_config, load_runtime_json_config
        import secrets
        runtime = load_runtime_json_config()
        runtime.setdefault("compatibility", {})
        runtime["compatibility"]["passwordSalt"] = secrets.token_hex(32)
        save_runtime_json_config(runtime)
        logger.warning(
            "Fresh pySysPass install: generated and persisted passwordSalt to runtime JSON."
        )
    # No jobs are registered by default: backups and expiry notices are not
    # automated (docs/installation.md). Do not run an empty scheduler thread.
    if task_service.tasks:
        task_service.start_scheduler()
    yield
    task_service.stop_scheduler()

app = FastAPI(
    title="sysPass Python",
    description="Password Manager - Python Edition",
    version="2.2.2",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _write_audit_event(action, level, description, user_id, username, ip) -> None:
    from app.db.base import SessionLocal
    from app.services.security_log_service import EventLogService

    db = SessionLocal()
    try:
        EventLogService(db).log_event(
            action=action,
            description=description,
            user_id=user_id,
            login=username or "",
            ip=ip,
            level=level,
        )
    finally:
        db.close()


def _audit_emergency_gate_config() -> None:
    """Audit-log the emergency-endpoint exposure gate at startup (ADR-0014).

    Records whether EMERGENCY_AUTH_ENABLED exposed POST /api/v1/auth/emergency
    in this process: CRITICAL when the break-glass route is registered, INFO
    when the default-deny configuration kept it unregistered. An audit-write
    failure never breaks startup.
    """
    enabled = emergency_endpoint_enabled()
    description = (
        f"Startup exposure gate EMERGENCY_AUTH_ENABLED={'true' if enabled else 'false'}: "
        f"POST /api/v1/auth/emergency {'registered' if enabled else 'not registered (default-deny)'}"
    )
    logger.log(logging.CRITICAL if enabled else logging.INFO, "%s", description)
    try:
        _write_audit_event(
            "auth.emergency.config",
            "CRITICAL" if enabled else "INFO",
            description,
            0,
            "system",
            "127.0.0.1",
        )
    except Exception:
        logger.exception("Failed to audit-log emergency exposure gate config at startup")


@app.middleware("http")
async def audit_log_middleware(request: Request, call_next):
    response = await call_next(request)
    action, level = _resolve_audit(request.method, request.url.path)
    if action and 200 <= response.status_code < 300:
        try:
            user_id, username = _get_user_from_request(request)
            ip = _get_ip(request)
            description = f"{request.method} {request.url.path}"
            # Tag account mutations with the per-account audit marker so the
            # account Audit tab (AccountAuditService) can find them.
            acc_match = re.match(r"^/api/v1/accounts/(\d+)", request.url.path)
            if acc_match:
                description += f" [acc:{acc_match.group(1)}]"
            # Synchronous DB work runs in the threadpool, not on the event loop.
            await run_in_threadpool(_write_audit_event, action, level, description, user_id, username, ip)
        except Exception:
            # Never let audit logging break a request, but never hide it either.
            logger.exception("Audit event write failed for %s %s", request.method, request.url.path)
            record_failure("audit_log_write")
    return response

MAX_REQUEST_BODY_BYTES = 24 * 1024 * 1024  # matches nginx client_max_body_size


@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    """Refuse oversized bodies before parsing them (transport-level bound)."""
    length = request.headers.get("content-length")
    if length is not None:
        try:
            too_large = int(length) > MAX_REQUEST_BODY_BYTES
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        if too_large:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    return await call_next(request)


@app.middleware("http")
async def force_https_middleware(request: Request, call_next):
    """sysPass PHP HttpUtil::checkHttps(): redirect plain HTTP when enabled.

    Registered before ProxyHeadersMiddleware, so it runs after a trusted
    proxy's X-Forwarded-Proto has set the request scheme. Health probes stay
    reachable on the private network.
    """
    if request.url.scheme != "https" and not request.url.path.startswith("/health"):
        if (await run_in_threadpool(get_policy)).https_required:
            return RedirectResponse(str(request.url.replace(scheme="https")), status_code=308)
    return await call_next(request)


# Install last so proxy normalization happens before audit attribution.
# Uvicorn must use --no-proxy-headers to avoid a second trust policy.
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=settings.TRUSTED_PROXY_HOSTS)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
# ADR-0014 exposure gate (impl-041): the break-glass endpoint is registered
# ONLY when EMERGENCY_AUTH_ENABLED is explicitly set at startup. Default
# (absent/false): the route is not registered at all and
# POST /api/v1/auth/emergency answers 404. When the flag is set, the route is
# mounted and the /var/run/syspass activation flag file still gates each login.
if emergency_endpoint_enabled():
    app.include_router(auth.emergency_router, prefix="/api/v1/auth", tags=["Authentication"])
    logger.critical(
        "EMERGENCY_AUTH_ENABLED is set: POST /api/v1/auth/emergency registered "
        "(ADR-0014 break-glass route exposed; per-login activation flag still required)"
    )
else:
    logger.info(
        "EMERGENCY_AUTH_ENABLED not set: POST /api/v1/auth/emergency NOT registered "
        "(default-deny per ADR-0014; set EMERGENCY_AUTH_ENABLED=true at startup to expose)"
    )
app.include_router(accounts.router, prefix="/api/v1", tags=["Accounts"])
app.include_router(categories.router, prefix="/api/v1", tags=["Categories"])
app.include_router(clients.router, prefix="/api/v1", tags=["Clients"])
app.include_router(users.router, prefix="/api/v1", tags=["Users"])
app.include_router(two_factor.router, prefix="/api/v1", tags=["Two-Factor Authentication"])
app.include_router(tags.router, prefix="/api/v1", tags=["Tags"])
app.include_router(history.router, prefix="/api/v1", tags=["History"])
app.include_router(files.router, prefix="/api/v1", tags=["Files"])
app.include_router(public_links.router, prefix="/api/v1", tags=["Public Links"])
app.include_router(notifications.router, prefix="/api/v1", tags=["Notifications"])
app.include_router(user_groups.router, prefix="/api/v1", tags=["User Groups"])
app.include_router(user_profiles.router, prefix="/api/v1", tags=["User Profiles"])
app.include_router(security.router, prefix="/api/v1", tags=["Security"])
app.include_router(config_settings.router, prefix="/api/v1", tags=["Settings"])
app.include_router(custom_fields.router, prefix="/api/v1", tags=["Custom Fields"])
app.include_router(account_sharing.router, prefix="/api/v1", tags=["Account Sharing"])
app.include_router(import_export.router, prefix="/api/v1", tags=["Import/Export"])
app.include_router(auth_tokens.router, prefix="/api/v1", tags=["API Authorizations"])
app.include_router(security_logs.router, prefix="/api/v1", tags=["Security & Audit"])
app.include_router(audit.router, prefix="/api/v1", tags=["Audit Logging"])
app.include_router(password_reset.router, prefix="/api/v1/auth", tags=["Password Reset"])
app.include_router(ldap.router, prefix="/api/v1", tags=["LDAP"])
app.include_router(item_presets.router, prefix="/api/v1", tags=["Item Presets"])
app.include_router(backup.router, prefix="/api/v1", tags=["Backup"])
app.include_router(plugins.router, prefix="/api/v1", tags=["Plugins"])

@app.exception_handler(SchemaMutationError)
async def schema_mutation_exception_handler(request: Request, exc: SchemaMutationError):
    return JSONResponse(
        status_code=403,
        content={"detail": str(exc)},
    )

@app.get("/")
async def root():
    return {"message": "sysPass Python API", "version": "1.0.0"}

@app.get("/health")
@app.get("/health/live")
async def health():
    """Liveness: the process is serving requests. Says nothing about readiness."""
    return {"status": "healthy"}


@app.get("/health/ready")
async def readiness():
    """Readiness: configuration, database, canonical schema, and storage."""
    result = await run_readiness_checks(db_base.engine)
    # Expose get_password_salt() provenance for IMPL-036 / ADR-0017 V-02
    from app.core.syspass_runtime_config import load_syspass_runtime_config
    runtime = load_syspass_runtime_config()
    salt = runtime.get("passwordSalt") or settings.SYSPASS_PASSWORD_SALT or ""
    # Determine provenance following the same priority: JSON -> XML -> cache -> env
    provenance = "none"
    if salt:
        # Check runtime JSON compatibility first
        try:
            rj = load_runtime_json_config()
            if rj.get("compatibility", {}).get("passwordSalt") == salt:
                provenance = "runtime-config.json"
            else:
                provenance = "config.xml"
        except Exception:
            provenance = "config.xml"
    salt_info = {"salt": salt, "provenance": provenance} if salt or salt == "" else {"salt": "", "provenance": "none"}
    result["salt_provenance"] = salt_info
    return JSONResponse(
        status_code=200 if result["ready"] else 503,
        content={"status": "ready" if result["ready"] else "not_ready", "checks": result["checks"]},
    )
