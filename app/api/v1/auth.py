from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
import secrets
from app.db.base import get_db
from app.schemas.install import InstallRequest, InstallResponse, InstallStatusResponse
from app.schemas.user import UserCreate, UserResponse, Token
from app.services.auth_service import (
    get_password_hash, verify_password, create_access_token,
    decrypt_user_master_pass, get_master_password_hash_row,
    finalize_user_master_pass, migrate_user_master_pass,
    verify_master_password_hash, store_user_master_pass,
)
from app.services.user_profile_service import UserProfileService
from app.services.user_service import UserService
from app.services.security_log_service import TrackService, EventLogService
from app.services.ldap_service import authenticate_ldap_login
from app.models.account import Config, User, UserGroup
from app.core.security import get_encryption_service
from app.core.rsa_service import maybe_decrypt
from app.services.temporary_master_password_service import TemporaryMasterPasswordService


def _client_ip(request: Request) -> str:
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

router = APIRouter()
security = HTTPBearer()


def _installation_state(db: Session) -> tuple[int, bool]:
    user_count = db.query(User).count()
    has_master_password = get_master_password_hash_row(db) is not None
    return user_count, has_master_password


def _ensure_default_user_group(db: Session) -> UserGroup:
    group = db.query(UserGroup).filter(UserGroup.id == 1).first()
    if group:
        return group

    group = UserGroup(id=1, name="Master", description="Master user group with full privileges")
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def _decode_secret(value: str | None, field_name: str) -> str | None:
    if not value:
        return None
    try:
        return maybe_decrypt(value)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "CREDENTIAL_DECRYPT_FAILED",
                "message": f"Could not decrypt {field_name}. Refresh the page and try again.",
            },
        ) from exc


@router.get("/install/status", response_model=InstallStatusResponse)
async def install_status(db: Session = Depends(get_db)):
    user_count, has_master_password = _installation_state(db)
    return InstallStatusResponse(
        installed=user_count > 0 and has_master_password,
        user_count=user_count,
        has_master_password=has_master_password,
    )


@router.post("/install", response_model=InstallResponse, status_code=status.HTTP_201_CREATED)
async def install(body: InstallRequest, db: Session = Depends(get_db)):
    user_count, has_master_password = _installation_state(db)
    if user_count > 0 or has_master_password:
        raise HTTPException(status_code=409, detail="sysPass is already installed")

    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if body.email and db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    _ensure_default_user_group(db)
    default_profile = UserProfileService(db).ensure_default_profile()

    login_password = body.password
    master_password = body.master_password or secrets.token_urlsafe(24)
    hashed_password = get_password_hash(login_password).encode("utf-8")

    db_user = User(
        id=UserService(db).next_user_id(),
        name=body.name or body.username,
        username=body.username,
        email=body.email,
        password=hashed_password,
        isUserAdmin=True,
        isUserEnabled=True,
        userGroupId=1,
        userProfileId=default_profile.id,
        hashSalt=secrets.token_bytes(32),
    )
    store_user_master_pass(db_user, login_password, master_password)
    db.add(db_user)
    db.add(Config(parameter="masterPwd", value=get_password_hash(master_password)))
    db.commit()
    db.refresh(db_user)

    return InstallResponse(
        user_id=db_user.id,
        username=db_user.username,
        master_password_generated=body.master_password is None,
        master_password=master_password if body.master_password is None else None,
        message=(
            "Save the generated master password in a secure place before continuing."
            if body.master_password is None
            else "Installation completed successfully. Redirecting to login."
        ),
    )

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    raise HTTPException(
        status_code=410,
        detail="Public registration has been replaced by /api/v1/auth/install for first-time setup and administrator-managed user creation afterwards.",
    )

@router.post("/login", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip = _client_ip(request)
    track = TrackService(db)
    elog = EventLogService(db)

    if track.is_locked(ip):
        elog.log_event("auth.login.blocked", f"Login blocked for IP {ip} (brute-force lock)",
        login=form_data.username, ip=ip, level="ERROR")
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")

    user = db.query(User).filter(User.username == form_data.username).first()
    plain_password = _decode_secret(form_data.password, "password")
    # PHP AuthProvider tries LDAP before database auth when it is enabled;
    # on LDAP success the local row is provisioned/synced (isLdap).
    ldap_user = authenticate_ldap_login(db, form_data.username, plain_password)
    if ldap_user is not None:
        user = ldap_user
    if ldap_user is None and (not user or not verify_password(plain_password, user.password)):
        track.record_attempt(ip, source="login", user_id=user.id if user else None)
        locked = track.maybe_lock(ip)
        elog.log_event(
            "auth.login.fail",
            f"Failed login for '{form_data.username}' from {ip}" + (" — IP now locked" if locked else ""),
            user_id=user.id if user else None,
            login=form_data.username, ip=ip, level="WARN",
        )
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    login_form = await request.form()
    supplied_master_pass = _decode_secret(login_form.get("mpass"), "master password")
    old_password = _decode_secret(login_form.get("oldpass"), "previous password")
    master_pass = decrypt_user_master_pass(user, plain_password)

    if master_pass is None:
        if supplied_master_pass:
            master_hash_row = get_master_password_hash_row(db)
            hashed_master_password = master_hash_row.value if master_hash_row else None
            resolved_master_pass = supplied_master_pass
            if hashed_master_password and not verify_master_password_hash(supplied_master_pass, hashed_master_password):
                resolved_master_pass = TemporaryMasterPasswordService(db).resolve_master_password(supplied_master_pass)
                if resolved_master_pass is None:
                    raise HTTPException(
                        status_code=401,
                        detail={
                            "code": "MASTER_PASSWORD_INVALID",
                            "message": "Wrong master password",
                        },
                    )
            elif not hashed_master_password:
                if master_hash_row:
                    master_hash_row.value = get_password_hash(supplied_master_pass)
                else:
                    db.add(Config(parameter="masterPwd", value=get_password_hash(supplied_master_pass)))
            finalize_user_master_pass(user, plain_password, resolved_master_pass)
            master_pass = resolved_master_pass
            db.commit()

        if master_pass is None and user.isChangedPass:
            if not old_password:
                raise HTTPException(
                    status_code=428,
                    detail={
                        "code": "OLD_PASSWORD_REQUIRED",
                        "message": "Your previous password is needed to unlock and migrate your vault",
                    },
                )

            master_pass = migrate_user_master_pass(db, user, old_password, plain_password)
            if master_pass is None:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "code": "OLD_PASSWORD_INVALID",
                        "message": "Wrong previous password",
                    },
                )
            db.commit()

        if master_pass is None:
            raise HTTPException(
                status_code=428,
                detail={
                    "code": "MASTER_PASSWORD_REQUIRED",
                    "message": "Master password required to unlock your vault",
                },
            )

    access_token = create_access_token(
        data={"user_id": user.id, "username": user.username},
        expires_delta=timedelta(hours=24),
        master_pass=master_pass,
        is_admin_app=bool(user.isAdminApp),
        is_admin_acc=bool(user.isAdminAcc),
    )
    elog.log_event("auth.login.success", f"User '{user.username}' logged in from {ip}",
                   user_id=user.id, login=user.username, ip=ip, level="INFO")
    return {"access_token": access_token, "token_type": "bearer"}  # nosec B105

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    credentials: HTTPBearer = Depends(security),
    db: Session = Depends(get_db)
):
    from app.services.auth_service import decode_token
    from app.services.user_profile_service import UserProfileService
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    permissions = None
    if user.userProfileId:
        profile_data = UserProfileService(db).get_user_profile(user.userProfileId)
        if profile_data:
            permissions = profile_data["permissions"]

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        is_admin=user.isUserAdmin,
        user_profile_id=user.userProfileId,
        two_factor_enabled=user.twoFactorAuth,
        is_active=user.isUserEnabled,
        created_at=user.dateCreate,
        permissions=permissions,
    )
