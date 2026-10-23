from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.schemas.config import (
    GeneralSettings, MailSettings, LdapSettings, AllSettings,
    EncryptionStatus, RekeyRequest, AccountsSettings, WikiSettings, SystemInfo,
    TemporaryMasterPasswordCreateRequest, TemporaryMasterPasswordCreateResponse,
    TemporaryMasterPasswordStatus,
)
from app.services.config_service import ConfigService
from app.services.runtime_policy import MAX_FILE_SIZE_KB, invalidate_policy_cache
from app.services.temporary_master_password_service import TemporaryMasterPasswordService
from app.api.deps import require_admin, require_permission

router = APIRouter()


def _count_non_null_column(db: Session, column) -> int:
    """Count a physical column without materializing its ORM entity."""
    statement = (
        select(func.count())
        .select_from(column.table)
        .where(column.is_not(None))
    )
    return db.execute(statement).scalar_one()


def require_master_pass(current_user: dict):
    if not current_user.get("master_pass"):
        raise HTTPException(
            status_code=428,
            detail={
                "code": "MASTER_PASSWORD_REQUIRED",
                "message": "Master password required to perform encryption operations",
            },
        )
    return current_user["master_pass"]


@router.get("/settings", response_model=AllSettings)
async def get_all_settings(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    """Return all configuration settings"""
    return ConfigService(db).get_all_settings()


@router.get("/settings/general", response_model=GeneralSettings)
async def get_general_settings(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    return ConfigService(db).get_general_settings()


@router.put("/settings/general", response_model=GeneralSettings)
async def save_general_settings(
    settings: GeneralSettings,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    svc = ConfigService(db)
    # Force HTTPS redirects every plain-HTTP request. Turning it on from a
    # connection that is not itself HTTPS (or whose proxy does not report
    # it) would lock every user out, so require proof that HTTPS works.
    if settings.https_enabled and not svc.get_general_settings().https_enabled and request.url.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="Enable Force HTTPS from an HTTPS connection; this request arrived over HTTP.",
        )
    svc.save_general_settings(settings)
    invalidate_policy_cache()
    return svc.get_general_settings()


@router.get("/settings/mail", response_model=MailSettings)
async def get_mail_settings(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    return ConfigService(db).get_mail_settings()


@router.put("/settings/mail", response_model=MailSettings)
async def save_mail_settings(
    settings: MailSettings,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    svc = ConfigService(db)
    svc.save_mail_settings(settings)
    return svc.get_mail_settings()


@router.get("/settings/ldap", response_model=LdapSettings)
async def get_ldap_settings(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    return ConfigService(db).get_ldap_settings()


@router.put("/settings/ldap", response_model=LdapSettings)
async def save_ldap_settings(
    settings: LdapSettings,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    svc = ConfigService(db)
    svc.save_ldap_settings(settings)
    return svc.get_ldap_settings()


@router.get("/settings/accounts", response_model=AccountsSettings)
async def get_accounts_settings(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    return ConfigService(db).get_accounts_settings()


@router.put("/settings/accounts", response_model=AccountsSettings)
async def save_accounts_settings(
    settings: AccountsSettings,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    if settings.files_allowed_size is not None and not 1 <= settings.files_allowed_size <= MAX_FILE_SIZE_KB:
        # Same ceiling as sysPass PHP ConfigAccountController (16384 KB).
        raise HTTPException(status_code=422, detail=f"files_allowed_size must be 1-{MAX_FILE_SIZE_KB} KB")
    svc = ConfigService(db)
    svc.save_accounts_settings(settings)
    invalidate_policy_cache()
    return svc.get_accounts_settings()


@router.get("/settings/wiki", response_model=WikiSettings)
async def get_wiki_settings(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    return ConfigService(db).get_wiki_settings()


@router.put("/settings/wiki", response_model=WikiSettings)
async def save_wiki_settings(
    settings: WikiSettings,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    svc = ConfigService(db)
    svc.save_wiki_settings(settings)
    return svc.get_wiki_settings()


@router.post("/settings/mail/test")
async def send_test_email(
    body: dict,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    """Send a test message using the saved mail settings."""
    from app.services.email_service import email_service_from_config

    svc = email_service_from_config(db)
    if svc is None:
        raise HTTPException(
            status_code=400,
            detail="Mail is disabled or the SMTP server is not configured. Save the mail settings first.",
        )
    recipient = (body.get("recipient") or "").strip() or svc.from_email
    ok = svc.send_email(
        recipient,
        "sysPass test email",
        "This is a test message from pySysPass. Your mail settings work.",
    )
    if not ok:
        raise HTTPException(status_code=502, detail="SMTP delivery failed — check the server log for details.")
    return {"success": True, "recipient": recipient}


@router.get("/settings/two-factor")
async def get_two_factor_settings(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    from app.services.two_factor_service import TwoFactorConfig
    return {"mode": TwoFactorConfig(db).get_mode()}


@router.put("/settings/two-factor")
async def save_two_factor_settings(
    body: dict,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    from app.services.two_factor_service import TwoFactorConfig
    try:
        mode = TwoFactorConfig(db).set_mode(str(body.get("mode", "")))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"mode": mode}


@router.get("/settings/info", response_model=SystemInfo)
async def get_system_info(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    return ConfigService(db).get_system_info()


@router.get("/settings/encryption", response_model=EncryptionStatus)
async def get_encryption_status(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_encryption')),
):
    """Return encryption status and stats"""
    from app.core.config import settings as app_settings
    from app.models.account import Account, AccountHistory

    cfg = ConfigService(db)
    db_key = cfg.get("encryption_key")
    default_key = "change-this-in-production-32-byte-key!!"
    active_key = db_key if db_key else app_settings.ENCRYPTION_KEY

    encrypted_accounts = _count_non_null_column(db, Account.pass_)
    encrypted_history = _count_non_null_column(db, AccountHistory.pass_)

    return EncryptionStatus(
        algorithm="AES-256-CTR + PBKDF2-SHA256",
        key_source="database" if db_key else "environment",
        using_default_key=(active_key == default_key),
        encrypted_accounts=encrypted_accounts,
        encrypted_history=encrypted_history,
    )


@router.get("/settings/encryption/temp-master", response_model=TemporaryMasterPasswordStatus)
async def get_temp_master_password_status(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_encryption')),
):
    return TemporaryMasterPasswordService(db).get_status()


@router.post("/settings/encryption/temp-master", response_model=TemporaryMasterPasswordCreateResponse)
async def create_temp_master_password(
    body: TemporaryMasterPasswordCreateRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_encryption')),
):
    master_password = require_master_pass(current_user)

    service = TemporaryMasterPasswordService(db)
    password, meta = service.create(
        master_password=master_password,
        max_time=body.max_time,
        send_email=body.send_email,
        group_id=body.group_id,
    )
    status = service.get_status()
    return TemporaryMasterPasswordCreateResponse(
        password=password,
        emailed_to=meta["emailed_to"],
        email_error=meta["email_error"],
        **status,
    )


@router.post("/settings/encryption/rekey")
async def rekey_encryption(
    body: RekeyRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    """Online rotation stays disabled: it cannot stop other writers or sessions.

    The vault master password is changed offline with
    ``python -m app.rotate_master_password`` (docs/backup-recovery.md).
    """
    raise HTTPException(
        status_code=409,
        detail=(
            "Online key rotation is disabled. Change the master password offline with "
            "'python -m app.rotate_master_password' (see the backup and recovery guide). "
            "Existing keys and encrypted data were not changed."
        ),
    )
