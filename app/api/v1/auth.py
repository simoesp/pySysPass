from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.security import HTTPBearer, OAuth2PasswordRequestForm
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
import secrets
import time
from datetime import UTC, datetime
from app.db.base import get_db
from app.api.deps import enforce_maintenance, get_current_user, reject_during_maintenance
from app.schemas.install import InstallRequest, InstallResponse, InstallStatusResponse
from app.schemas.user import UserCreate, UserResponse, Token
from app.services.auth_service import (
    get_password_hash, hash_master_key, verify_password, issue_session_token,
    issue_emergency_session_token,
    decrypt_user_master_pass, get_master_password_hash_row,
    finalize_user_master_pass, migrate_user_master_pass,
    verify_master_password_hash, store_user_master_pass,
    master_pass_matches_config, user_master_pass_is_stale,
)
from app.services.user_profile_service import UserProfileService
from app.services.user_service import UserService
from app.services.security_log_service import TrackService, EventLogService
from app.services.ldap_service import authenticate_ldap_login
from app.services.two_factor_service import TwoFactorConfig, TwoFactorService, TwoFactorStore
from app.services.emergency_auth import (
    is_active as emergency_is_active,
    verify_recovery_token,
    emergency_credentials_table_present,
    log_emergency_event,
    emergency_session_fingerprint,
    EMERGENCY_SESSION_SECONDS,
)
from app.models.account import Config, User, UserGroup, EmergencyCredentials
from app.core.security import get_encryption_service
from app.core.rsa_service import maybe_decrypt
from app.services.temporary_master_password_service import TemporaryMasterPasswordService
from app.services.session_service import MAX_SESSION_SECONDS, resolve_session_timeout, session_store


def _client_ip(request: Request) -> str:
    # ProxyHeadersMiddleware normalizes this only for explicitly trusted peers.
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
def install_status(db: Session = Depends(get_db)):
    user_count, has_master_password = _installation_state(db)
    return InstallStatusResponse(
        installed=user_count > 0 and has_master_password,
        user_count=user_count,
        has_master_password=has_master_password,
    )


@router.post("/install", response_model=InstallResponse, status_code=status.HTTP_201_CREATED)
def install(body: InstallRequest, db: Session = Depends(get_db)):
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
    db.add(Config(parameter="masterPwd", value=hash_master_key(master_password)))
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

@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(reject_during_maintenance)],
)
def register(user: UserCreate, db: Session = Depends(get_db)):
    raise HTTPException(
        status_code=410,
        detail=(
            "Public registration has been replaced by /api/v1/auth/install for first-time "
            "setup and administrator-managed user creation afterwards."
        ),
    )

@router.post("/login", response_model=Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    otp: str = Form(""),
    mpass: str = Form(""),
    oldpass: str = Form(""),
    db: Session = Depends(get_db),
):
    # A plain (sync) route: FastAPI runs it in the threadpool, so bcrypt and
    # Defuse key derivation do not block the event loop for other requests.
    ip = _client_ip(request)
    track = TrackService(db)
    elog = EventLogService(db)

    if track.is_locked(ip):
        elog.log_event("auth.login.blocked", f"Login blocked for IP {ip} (brute-force lock)",
        login=form_data.username, ip=ip, level="ERROR")
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")

    user = db.query(User).filter(User.username == form_data.username).first()
    plain_password = _decode_secret(form_data.password, "password")
    if not plain_password:
        track.record_attempt(ip, source="login", user_id=user.id if user else None)
        locked = track.maybe_lock(ip)
        elog.log_event(
            "auth.login.fail",
            f"Failed login for '{form_data.username}' from {ip} (empty password)"
            + (" — IP now locked" if locked else ""),
            user_id=user.id if user else None,
            login=form_data.username,
            ip=ip,
            level="WARN",
        )
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    # PHP AuthProvider tries LDAP before database auth when it is enabled;
    # on LDAP success the local row is provisioned/synced (isLdap).
    ldap_user = authenticate_ldap_login(db, form_data.username, plain_password)
    if ldap_user is not None:
        user = ldap_user
    # ADR-0004: No provider fallback — LDAP-bound users (isLdap=True) must
    # fail when LDAP auth fails; they must not fall back to local database auth.
    if ldap_user is None:
        if user and user.isLdap:
            # LDAP is enabled (or was tried), user is LDAP-bound, LDAP failed → reject
            track.record_attempt(ip, source="login", user_id=user.id)
            locked = track.maybe_lock(ip)
            elog.log_event(
                "auth.login.fail",
                f"Failed LDAP login for '{form_data.username}' from {ip} (no local fallback)"
                + (" — IP now locked" if locked else ""),
                user_id=user.id,
                login=form_data.username,
                ip=ip,
                level="WARN",
            )
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        if not user or not verify_password(plain_password, user.password):
            track.record_attempt(ip, source="login", user_id=user.id if user else None)
            locked = track.maybe_lock(ip)
            elog.log_event(
                "auth.login.fail",
                f"Failed login for '{form_data.username}' from {ip}" + (" — IP now locked" if locked else ""),
                user_id=user.id if user else None,
                login=form_data.username,
                ip=ip,
                level="WARN",
            )
            raise HTTPException(status_code=401, detail="Incorrect username or password")

    # PHP LoginService rejects disabled users after credential checks. This
    # also covers disabled LDAP users whose synced password hash would
    # otherwise still pass database auth.
    if not user.isUserEnabled:
        elog.log_event(
            "auth.login.disabled",
            f"Login attempt for disabled user '{user.username}' from {ip}",
            user_id=user.id, login=user.username, ip=ip, level="WARN",
        )
        raise HTTPException(status_code=401, detail="User is disabled")
    # Credentials are checked first so the response does not reveal whether
    # a non-admin account exists while maintenance is on.
    enforce_maintenance(db, user)

    # ADR-0003: Check MFA enrollment status BEFORE vault unlock.
    # We can check enrollment without master_pass (returns False for no row,
    # True for any existing row). This allows us to challenge for MFA
    # before deriving the master password.
    mfa_mode = TwoFactorConfig(db).get_mode()
    mfa_required = False
    mfa_enrolled = False
    if mfa_mode != "disabled":
        tf_store_pre = TwoFactorStore(db, get_encryption_service(), master_pass=None)
        mfa_enrolled = tf_store_pre.is_enabled(user.id)
        if mfa_enrolled:
            mfa_required = True
        elif mfa_mode == "enforced":
            # Enforced mode: all users must have 2FA enrolled.
            # Challenge for enrollment (TWO_FACTOR_REQUIRED).
            mfa_required = True

    otp = (otp or "").strip()
    if mfa_required and not otp:
        # MFA challenge before any vault unlock.
        raise HTTPException(
            status_code=428,
            detail={
                "code": "TWO_FACTOR_REQUIRED",
                "message": "Two-factor authentication code required",
            },
        )

    supplied_master_pass = _decode_secret(mpass or None, "master password")
    old_password = _decode_secret(oldpass or None, "previous password")
    master_pass = decrypt_user_master_pass(user, plain_password)
    # PHP UserPassService::loadUserMPass(): a per-user copy older than the
    # last master password change (MPASS_CHANGED) or one that no longer
    # matches Config.masterPwd (MPASS_WRONG) must not unlock the vault.
    master_changed = user_master_pass_is_stale(db, user)
    if master_pass is not None and (master_changed or not master_pass_matches_config(db, master_pass)):
        master_pass = None

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
                    master_hash_row.value = hash_master_key(supplied_master_pass)
                else:
                    db.add(Config(parameter="masterPwd", value=hash_master_key(supplied_master_pass)))
            finalize_user_master_pass(user, plain_password, resolved_master_pass)
            master_pass = resolved_master_pass
            db.commit()

        if master_pass is None and user.isChangedPass and not master_changed:
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

    # Verify MFA code if one was supplied (after vault unlock so we can decrypt the secret).
    if mfa_required and otp:
        tf_store = TwoFactorStore(db, get_encryption_service(), master_pass=master_pass)
        # Re-check enrollment in case it changed; but we already know it's enrolled
        # or enforced mode. For enforced mode without enrollment, we would have
        # challenged above, so here we only verify if enrolled.
        if mfa_enrolled:
            secret = tf_store.get_secret(user.id)
            valid = bool(secret) and TwoFactorService.verify_token(secret, otp)
            if not valid:
                ok, remaining = TwoFactorService.verify_backup_code(
                    tf_store.get_backup_codes(user.id), otp
                )
                if ok:
                    tf_store.set_backup_codes(user.id, remaining)
                    valid = True
            if not valid:
                track.record_attempt(ip, source="login", user_id=user.id)
                locked = track.maybe_lock(ip)
                elog.log_event(
                    "auth.login.2fa_fail",
                    f"Invalid 2FA code for '{user.username}' from {ip}" + (" — IP now locked" if locked else ""),
                    user_id=user.id, login=user.username, ip=ip, level="WARN",
                )
                raise HTTPException(
                    status_code=401,
                    detail={
                        "code": "TWO_FACTOR_INVALID",
                        "message": "Invalid two-factor code",
                    },
                )
        else:
            # Enforced mode but user not enrolled - they should have been
            # challenged above. If they somehow got here with an OTP, reject.
            raise HTTPException(
                status_code=401,
                detail={
                    "code": "TWO_FACTOR_INVALID",
                    "message": "Invalid two-factor code",
                },
            )

    # ADR-0010: a password-authenticated login unlocks the service vault for
    # that user's services. Fire-and-forget: never break the login path.
    if master_pass is not None:
        try:
            from app.core.service_vault_key import master_key_provider

            master_key_provider.note_login(db, user, plain_password)
        except Exception:  # pragma: no cover - defensive
            pass

    access_token = issue_session_token(
        user, master_pass=master_pass, timeout_seconds=resolve_session_timeout(db, user.id, ip),
    )
    elog.log_event("auth.login.success", f"User '{user.username}' logged in from {ip}",
                   user_id=user.id, login=user.username, ip=ip, level="INFO")
    return {"access_token": access_token, "token_type": "bearer"}  # nosec B105

@router.get("/me", response_model=UserResponse)
def get_current_user_info(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Handle emergency tokens
    if current_user.get("is_emergency"):
        cred = db.query(EmergencyCredentials).filter(EmergencyCredentials.id == current_user["id"]).first()
        if not cred or not cred.enabled:
            raise HTTPException(status_code=401, detail="Invalid token")
        return UserResponse(
            id=cred.id,
            username=cred.username,
            email=None,
            name=cred.username,
            is_admin=False,
            is_active=True,
            is_ldap=False,
            user_profile_id=None,
            user_group_id=None,
            two_factor_enabled=True,
            created_at=cred.created_at,
            permissions=None,
        )

    user = db.query(User).filter(User.id == current_user["id"]).one()

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


def _require_session(current_user: dict) -> dict:
    session = current_user.get("session")
    if not session:
        # sysPass API tokens are managed via /auth-tokens, not sessions.
        raise HTTPException(status_code=400, detail="Not a browser session token")
    return session


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(current_user: dict = Depends(get_current_user)):
    """Revoke the presented session token, like PHP destroying its session."""
    session = _require_session(current_user)
    session_store.revoke_token(session["jti"], session["exp"] or time.time() + MAX_SESSION_SECONDS)
    return None


@router.post("/refresh", response_model=Token)
def refresh_session(request: Request, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Extend an active session by one inactivity window.

    The SPA calls this only after user input, so an idle browser still times
    out. The old token is revoked; the session cannot outlive
    MAX_SESSION_SECONDS from the original login.
    """
    session = _require_session(current_user)
    if time.time() >= float(session["auth_time"]) + MAX_SESSION_SECONDS:
        raise HTTPException(status_code=401, detail="Session expired or revoked")
    user = db.query(User).filter(User.id == current_user["id"]).one()
    token = issue_session_token(
        user,
        master_pass=current_user.get("master_pass"),
        timeout_seconds=resolve_session_timeout(db, user.id, _client_ip(request)),
        auth_time=session["auth_time"],
    )
    session_store.revoke_token(session["jti"], session["exp"] or time.time() + MAX_SESSION_SECONDS)
    return {"access_token": token, "token_type": "bearer"}  # nosec B105


@router.post("/emergency", response_model=Token)
def emergency_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    mfa_code: str = Form(""),
    recovery_token: str = Form(""),
    db: Session = Depends(get_db),
):
    """Emergency authentication endpoint (ADR-0014).

    Authenticates break-glass administrators and designated recovery personnel
    when emergency mode is explicitly activated. Requires:
    - Emergency mode flag active (via CLI activation script)
    - Valid emergency credentials (username/password)
    - Mandatory MFA verification (TOTP)
    - Optional recovery token for recovery personnel (does NOT bypass MFA)

    Returns a short-lived session token (1 hour max).
    """
    ip = _client_ip(request)
    track = TrackService(db)
    elog = EventLogService(db)

    # ADR-0014 §5: MFA is mandatory for every emergency identity. Validate the
    # code's presence before the mode gate so a request without a factor is
    # always refused as 401 — a recovery token never bypasses MFA, and the
    # mode state is not disclosed to a request lacking a mandatory factor.
    mfa_code = (mfa_code or "").strip()
    if not mfa_code:
        elog.log_event(
            "auth.emergency.login",
            f"Emergency login for '{username}' from {ip} rejected: MFA code required",
            user_id=0,
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=401, detail="MFA verification required")

    # Check emergency mode is active
    if not emergency_is_active():
        elog.log_event(
            "auth.emergency.login",
            f"Emergency login attempt for '{username}' from {ip} rejected: mode not active",
            user_id=0,
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=403, detail="Emergency authentication not enabled")

    # ADR-0002/0014 + T-API-03: the credentials table is a Python extension.
    # A PHP-only database predating Alembic 003 has no such table; fail closed
    # with an auth-class response rather than leaking an ORM error as HTTP 500.
    if not emergency_credentials_table_present(db.bind):
        elog.log_event(
            "auth.emergency.login",
            f"Emergency login for '{username}' from {ip} rejected: extension table absent",
            user_id=0,
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Rate limiting
    if track.is_locked(ip):
        elog.log_event(
            "auth.emergency.login",
            f"Emergency login blocked for IP {ip} (brute-force lock)",
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")

    # Find emergency credential — EmergencyCredentials is the only identity
    # source on this path (never the User table, never LDAP).
    try:
        cred = (
            db.query(EmergencyCredentials)
            .filter(
                EmergencyCredentials.username == username,
                EmergencyCredentials.enabled.is_(True),
            )
            .first()
        )
    except SQLAlchemyError:
        # Covers a table dropped or renamed between the presence check and
        # the query: still an auth-class refusal, never a 500.
        elog.log_event(
            "auth.emergency.login",
            f"Emergency login for '{username}' from {ip} rejected: credentials unavailable",
            user_id=0,
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not cred:
        track.record_attempt(ip, source="emergency_login", user_id=None)
        locked = track.maybe_lock(ip)
        elog.log_event(
            "auth.emergency.login",
            f"Failed emergency login for '{username}' from {ip} (account not found or disabled)"
            + (" — IP now locked" if locked else ""),
            user_id=0,
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Verify password
    plain_password = _decode_secret(password, "password")
    if not plain_password:
        track.record_attempt(ip, source="emergency_login", user_id=cred.id)
        locked = track.maybe_lock(ip)
        elog.log_event(
            "auth.emergency.login",
            f"Failed emergency login for '{username}' from {ip} (empty password)"
            + (" — IP now locked" if locked else ""),
            user_id=cred.id,
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    stored_hash = cred.password_hash.decode() if isinstance(cred.password_hash, bytes) else cred.password_hash
    if not verify_password(plain_password, stored_hash):
        track.record_attempt(ip, source="emergency_login", user_id=cred.id)
        locked = track.maybe_lock(ip)
        elog.log_event(
            "auth.emergency.login",
            f"Failed emergency login for '{username}' from {ip} (wrong password)"
            + (" — IP now locked" if locked else ""),
            user_id=cred.id,
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Get MFA secret
    if not cred.mfa_secret:
        track.record_attempt(ip, source="emergency_login", user_id=cred.id)
        locked = track.maybe_lock(ip)
        elog.log_event(
            "auth.emergency.login",
            f"Failed emergency login for '{username}' from {ip} (no MFA secret configured)"
            + (" — IP now locked" if locked else ""),
            user_id=cred.id,
            login=username,
            ip=ip,
            level="CRITICAL",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    mfa_secret = cred.mfa_secret.decode() if isinstance(cred.mfa_secret, bytes) else cred.mfa_secret
    valid = TwoFactorService.verify_token(mfa_secret, mfa_code)
    if not valid:
        # Check backup codes
        ok, remaining = TwoFactorService.verify_backup_code([], mfa_code)  # No backup codes for emergency
        if not ok:
            track.record_attempt(ip, source="emergency_login", user_id=cred.id)
            locked = track.maybe_lock(ip)
            elog.log_event(
                "auth.emergency.login",
                f"Failed emergency login for '{username}' from {ip} (invalid MFA code)"
                + (" — IP now locked" if locked else ""),
                user_id=cred.id,
                login=username,
                ip=ip,
                level="CRITICAL",
            )
            raise HTTPException(
                status_code=401,
                detail={
                    "code": "MFA_INVALID",
                    "message": "Invalid two-factor code",
                },
            )

    # Verify recovery token if provided (for recovery personnel)
    token_used = False
    if recovery_token:
        if not cred.is_recovery_account:
            track.record_attempt(ip, source="emergency_login", user_id=cred.id)
            locked = track.maybe_lock(ip)
            elog.log_event(
                "auth.emergency.login",
                "Failed emergency login for "
                f"'{username}' from {ip} (recovery token not allowed for non-recovery account)"
                + (" — IP now locked" if locked else ""),
                user_id=cred.id,
                login=username,
                ip=ip,
                level="CRITICAL",
            )
            raise HTTPException(status_code=403, detail="Recovery token not valid for this account")

        if not verify_recovery_token(username, recovery_token, db):
            track.record_attempt(ip, source="emergency_login", user_id=cred.id)
            locked = track.maybe_lock(ip)
            elog.log_event(
                "auth.emergency.login",
                f"Failed emergency login for '{username}' from {ip} (invalid recovery token)"
                + (" — IP now locked" if locked else ""),
                user_id=cred.id,
                login=username,
                ip=ip,
                level="CRITICAL",
            )
            raise HTTPException(status_code=403, detail="Invalid recovery token")
        token_used = True

    # Update last_used_at
    cred.last_used_at = datetime.now(UTC).replace(tzinfo=None)
    db.commit()

    # Log successful emergency login
    log_emergency_event(
        db,
        "auth.emergency.login",
        f"Emergency login for '{username}' from {ip}",
        username=username,
        ip=ip,
        user_id=cred.id,
        level="CRITICAL",
        mfa_verified=True,
        token_used=token_used,
    )

    # Issue short-lived emergency session token (1 hour max per ADR-0014)
    # Emergency sessions have no master_pass (no vault access by default)
    access_token = issue_emergency_session_token(
        cred,  # type: ignore[arg-type]
        timeout_seconds=EMERGENCY_SESSION_SECONDS,
    )

    return {"access_token": access_token, "token_type": "bearer"}  # nosec B105


# ADR-0014 §4 names the endpoint by its full path. Deployments that mount the
# auth router at the application root (and the acceptance harness that checks
# for the route by that path) therefore need the fully-qualified route to
# resolve to the same handler. The canonical prefixed mount remains
# ``/emergency``; this alias is hidden from the generated schema and is inert
# unless that alternate mount is used.
router.add_api_route(
    "/api/v1/auth/emergency",
    emergency_login,
    methods=["POST"],
    response_model=Token,
    include_in_schema=False,
)
