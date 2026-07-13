from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.schemas.config import (
    GeneralSettings, MailSettings, LdapSettings, AllSettings,
    EncryptionStatus, RekeyRequest, AccountsSettings, WikiSettings, SystemInfo,
    TemporaryMasterPasswordCreateRequest, TemporaryMasterPasswordCreateResponse,
    TemporaryMasterPasswordStatus,
)
from app.services.config_service import ConfigService
from app.services.temporary_master_password_service import TemporaryMasterPasswordService
from app.api.deps import require_admin, require_permission

router = APIRouter()


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
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    svc = ConfigService(db)
    svc.save_general_settings(settings)
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
    svc = ConfigService(db)
    svc.save_accounts_settings(settings)
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

    encrypted_accounts = db.query(Account).filter(Account.pass_ != None).count()
    encrypted_history = db.query(AccountHistory).filter(AccountHistory.pass_ != None).count()

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
    """Re-encrypt all stored passwords with a new key.

    Decrypts every Account.pass_ and AccountHistory.pass_ with current_key,
    re-encrypts with new_key, then persists new_key in the Config table.
    The ENCRYPTION_KEY environment variable must also be updated before the
    next application restart so the runtime picks up the new key.
    """
    from app.core.security import EncryptionService
    from app.models.account import Account, AccountHistory

    if body.new_key != body.new_key_confirm:
        raise HTTPException(status_code=422, detail="New keys do not match")
    if len(body.new_key) < 16:
        raise HTTPException(status_code=422, detail="New key must be at least 16 characters")
    if body.current_key == body.new_key:
        raise HTTPException(status_code=422, detail="New key must differ from the current key")

    old_enc = EncryptionService(body.current_key)
    new_enc = EncryptionService(body.new_key)

    # Re-key accounts
    accounts = db.query(Account).filter(Account.pass_ != None).all()
    errors = []
    rekey_count = 0

    for acc in accounts:
        try:
            raw = acc.pass_ if isinstance(acc.pass_, bytes) else acc.pass_.encode()
            plaintext = old_enc.decrypt(raw.decode())
            acc.pass_ = new_enc.encrypt(plaintext).encode()
            rekey_count += 1
        except Exception as e:
            errors.append(f"Account {acc.id}: {e}")

    # Re-key account history snapshots
    history_rows = db.query(AccountHistory).filter(AccountHistory.pass_ != None).all()
    history_count = 0
    for row in history_rows:
        try:
            raw = row.pass_ if isinstance(row.pass_, bytes) else row.pass_.encode()
            plaintext = old_enc.decrypt(raw.decode())
            row.pass_ = new_enc.encrypt(plaintext).encode()
            history_count += 1
        except Exception as e:
            errors.append(f"History {row.id}: {e}")

    if errors:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"Re-key failed — current key may be wrong. Errors: {errors[:5]}"
        )

    # Persist new key in Config table
    ConfigService(db).set("encryption_key", body.new_key)
    db.commit()

    return {
        "message": "Re-key completed successfully",
        "accounts_rekeyed": rekey_count,
        "history_rekeyed": history_count,
        "warning": "Update the ENCRYPTION_KEY environment variable to this new key before restarting the application.",
    }
