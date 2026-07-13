from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from app.core.config import settings
from app.db.bootstrap import bootstrap_database_on_startup
from app.db.base import SchemaMutationError
from app.api.v1 import (
    accounts, auth, categories, clients, users, two_factor, tags, history,
    files, public_links, notifications, user_groups, user_profiles, security,
    config_settings, custom_fields, account_sharing, import_export, auth_tokens,
    security_logs, password_reset, ldap, item_presets, backup, plugins,
)
from app.services.task_service import task_service
from contextlib import asynccontextmanager
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


def _resolve_audit(method: str, path: str):
    for m, pattern, action, level in _AUDIT_ROUTES:
        if method == m and pattern.match(path):
            return action, level
    return None, None


def _get_ip(request: Request) -> str:
    # X-Real-IP is set by nginx to $remote_addr (single, reliable value).
    # X-Forwarded-For is used as fallback for other proxies.
    # After ProxyHeadersMiddleware, request.client.host already reflects the
    # forwarded IP, but we read headers directly to be explicit.
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


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
    bootstrap_database_on_startup()
    task_service.start_scheduler()
    yield
    task_service.stop_scheduler()

app = FastAPI(
    title="sysPass Python",
    description="Password Manager - Python Edition",
    version="1.0.0",
    lifespan=lifespan,
)

# Trust X-Forwarded-For / X-Real-IP from the nginx reverse proxy.
# trusted_hosts="*" is safe here because the upstream proxy is in the same
# private Docker network — no untrusted clients can reach the backend directly.
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def audit_log_middleware(request: Request, call_next):
    response = await call_next(request)
    action, level = _resolve_audit(request.method, request.url.path)
    if action and 200 <= response.status_code < 300:
        try:
            from app.db.base import SessionLocal
            from app.services.security_log_service import EventLogService
            user_id, username = _get_user_from_request(request)
            ip = _get_ip(request)
            db = SessionLocal()
            try:
                EventLogService(db).log_event(
                    action=action,
                    description=f"{request.method} {request.url.path}",
                    user_id=user_id,
                    login=username or "",
                    ip=ip,
                    level=level,
                )
            finally:
                db.close()
        except Exception:
            pass  # never let audit logging break a request
    return response

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
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
async def health():
    return {"status": "healthy"}
