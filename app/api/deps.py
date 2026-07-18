"""Centralized FastAPI dependencies for auth and role checks."""
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.services.auth_service import decode_token

security = HTTPBearer()

# PHP AuthToken actionId → REST routes the token may call. Route templates
# are matched against the resolved FastAPI route, so path params are safe.
# Profile permissions and object ACLs of the token's user still apply.
API_TOKEN_SCOPES: dict[int, set[tuple[str, str]]] = {
    3: {  # Account Search
        ("GET", "/api/v1/accounts"),
        ("GET", "/api/v1/accounts/search"),
        ("GET", "/api/v1/accounts/count"),
    },
    8: {  # Account View (includes search)
        ("GET", "/api/v1/accounts"),
        ("GET", "/api/v1/accounts/search"),
        ("GET", "/api/v1/accounts/count"),
        ("GET", "/api/v1/accounts/{account_id}"),
    },
    4: {  # Account View Password
        ("GET", "/api/v1/accounts"),
        ("GET", "/api/v1/accounts/search"),
        ("GET", "/api/v1/accounts/count"),
        ("GET", "/api/v1/accounts/{account_id}"),
        ("GET", "/api/v1/accounts/{account_id}/password"),
    },
    5: {("POST", "/api/v1/accounts")},                     # Account Add
    6: {("PUT", "/api/v1/accounts/{account_id}")},         # Account Edit
    7: {("DELETE", "/api/v1/accounts/{account_id}")},      # Account Delete
    102: {("GET", "/api/v1/categories"), ("GET", "/api/v1/categories/{category_id}")},
    103: {("POST", "/api/v1/categories")},
    104: {("PUT", "/api/v1/categories/{category_id}")},
    106: {("DELETE", "/api/v1/categories/{category_id}")},
    202: {("GET", "/api/v1/clients"), ("GET", "/api/v1/clients/{client_id}")},
    203: {("POST", "/api/v1/clients")},
    204: {("PUT", "/api/v1/clients/{client_id}")},
    205: {("DELETE", "/api/v1/clients/{client_id}")},
    206: {("GET", "/api/v1/clients"), ("GET", "/api/v1/clients/{client_id}")},
    302: {("GET", "/api/v1/tags"), ("GET", "/api/v1/tags/{tag_id}")},
    304: {("POST", "/api/v1/tags")},
    305: {("PUT", "/api/v1/tags/{tag_id}")},
    306: {("DELETE", "/api/v1/tags/{tag_id}")},
    802: {("GET", "/api/v1/auth-tokens")},                 # API Token Search
}


def _resolve_api_token(db: Session, token_value: str, request: Request) -> dict:
    """Authenticate a sysPass API token and enforce its action scope."""
    from app.models.account import AuthToken, User

    row = db.query(AuthToken).filter(
        AuthToken.token.in_([token_value, token_value.encode("ascii")])
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    route = request.scope.get("route")
    template = getattr(route, "path", request.url.path)
    # FastAPI >= 0.139 resolves nested router paths without the mount
    # prefix; accept the template with and without /api/v1.
    candidates = {template, request.url.path}
    if not template.startswith("/api/"):
        candidates.add("/api/v1" + template)
    allowed = API_TOKEN_SCOPES.get(row.actionId, set())
    if not any((request.method, path) in allowed for path in candidates):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This API token is not authorized for this action",
        )

    user = db.query(User).filter(User.id == row.userId).first()
    if user is None or not user.isUserEnabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    return {
        "id": user.id,
        "username": user.username,
        # API tokens carry no vault here, so PHP-encrypted account passwords
        # cannot be decrypted through them.
        "master_pass": None,
        "is_admin": bool(user.isAdminApp),
        "is_admin_app": bool(user.isAdminApp),
        "is_admin_acc": bool(user.isAdminAcc),
        "auth_method": "api_token",
    }


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> dict:
    payload = decode_token(credentials.credentials)
    if not payload:
        # Not a JWT — try it as a sysPass API token (Authorization: Bearer <token>).
        return _resolve_api_token(db, credentials.credentials, request)
    legacy_admin = bool(payload.get("is_admin", False))
    is_admin_app = bool(payload.get("is_admin_app", legacy_admin))
    is_admin_acc = bool(payload.get("is_admin_acc", legacy_admin))
    return {
        "id": payload.get("user_id"),
        "username": payload.get("username"),
        "master_pass": payload.get("master_pass"),
        # is_admin remains the application-wide scope for existing callers.
        "is_admin": is_admin_app,
        "is_admin_app": is_admin_app,
        "is_admin_acc": is_admin_acc,
    }


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if not current_user.get("is_admin_app"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


def _profile_permissions(db: Session, user_id: int) -> dict[str, bool]:
    from app.models.account import User
    from app.services.user_profile_service import UserProfileService

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.userProfileId:
        return {}
    profile = UserProfileService(db).get_user_profile(user.userProfileId)
    return profile["permissions"].model_dump() if profile else {}


def has_permissions(
    current_user: dict,
    db: Session,
    keys: tuple[str, ...],
    *,
    require_all: bool = False,
    account_admin: bool = False,
) -> bool:
    """Apply PHP's profile gate before an object-level ACL decision."""
    if current_user.get("is_admin_app"):
        return True
    if account_admin and current_user.get("is_admin_acc"):
        return True
    permissions = _profile_permissions(db, current_user["id"])
    checks = (bool(permissions.get(key, False)) for key in keys)
    return all(checks) if require_all else any(checks)


def enforce_permissions(
    current_user: dict,
    db: Session,
    *keys: str,
    require_all: bool = False,
    account_admin: bool = False,
) -> dict:
    if has_permissions(
        current_user,
        db,
        tuple(keys),
        require_all=require_all,
        account_admin=account_admin,
    ):
        return current_user
    mode = " and ".join(keys) if require_all else " or ".join(keys)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Your profile does not grant '{mode}' permission",
    )


def require_any_permission(*keys: str, account_admin: bool = False):
    def _dep(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict:
        return enforce_permissions(
            current_user, db, *keys, account_admin=account_admin
        )

    _dep.__name__ = f"require_any_permission_{'_or_'.join(keys)}"
    return _dep


def require_all_permissions(*keys: str, account_admin: bool = False):
    def _dep(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict:
        return enforce_permissions(
            current_user,
            db,
            *keys,
            require_all=True,
            account_admin=account_admin,
        )

    _dep.__name__ = f"require_all_permissions_{'_and_'.join(keys)}"
    return _dep


def require_permission(key: str):
    """Return a FastAPI dependency that passes admins through and otherwise checks
    that the caller's profile grants the named ProfilePermissions flag."""
    def _dep(
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict:
        return enforce_permissions(current_user, db, key)
    # Give FastAPI a stable identity so it can deduplicate the dependency.
    _dep.__name__ = f"require_permission_{key}"
    return _dep
