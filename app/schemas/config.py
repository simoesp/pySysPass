from pydantic import BaseModel
from typing import Optional, Dict


class ConfigEntry(BaseModel):
    parameter: str
    value: Optional[str] = None


class ConfigUpdate(BaseModel):
    value: Optional[str] = None


class GeneralSettings(BaseModel):
    sitelang: Optional[str] = "en_US"
    sitetheme: Optional[str] = "blue"
    session_timeout: Optional[int] = 300
    app_url: Optional[str] = None
    https_enabled: Optional[bool] = False
    debug: Optional[bool] = False
    maintenance: Optional[bool] = False
    check_updates: Optional[bool] = False
    check_notices: Optional[bool] = False
    log_enabled: Optional[bool] = True
    syslog_enabled: Optional[bool] = False
    syslog_remote_enabled: Optional[bool] = False
    syslog_server: Optional[str] = None
    syslog_port: Optional[int] = 514
    proxy_enabled: Optional[bool] = False
    proxy_server: Optional[str] = None
    proxy_port: Optional[int] = 8080
    proxy_user: Optional[str] = None


class MailSettings(BaseModel):
    mail_enabled: Optional[bool] = False
    mail_server: Optional[str] = None
    mail_port: Optional[int] = 25
    mail_user: Optional[str] = None
    mail_pass: Optional[str] = None
    mail_security: Optional[str] = "tls"
    mail_from: Optional[str] = None
    mail_requests_enabled: Optional[bool] = False
    mail_auth_enabled: Optional[bool] = False
    mail_recipients: Optional[str] = None


class LdapSettings(BaseModel):
    ldap_enabled: Optional[bool] = False
    ldap_server: Optional[str] = None
    ldap_base: Optional[str] = None
    ldap_group: Optional[str] = None
    ldap_binduser: Optional[str] = None
    ldap_bindpass: Optional[str] = None
    ldap_server_type: Optional[int] = 1
    ldap_tls_enabled: Optional[bool] = False
    ldap_defaultgroup: Optional[int] = None
    ldap_defaultprofile: Optional[int] = None


class EncryptionStatus(BaseModel):
    algorithm: str = "AES-256-CTR + PBKDF2-SHA256"
    key_source: str          # "environment" or "database"
    using_default_key: bool  # True if the insecure default key is active
    encrypted_accounts: int  # count of accounts with stored ciphertext
    encrypted_history: int   # count of history rows with stored ciphertext


class RekeyRequest(BaseModel):
    current_key: str
    new_key: str
    new_key_confirm: str


class TemporaryMasterPasswordStatus(BaseModel):
    is_active: bool = False
    created_at: Optional[int] = None
    expires_at: Optional[int] = None
    attempts: int = 0
    max_attempts: int = 50
    remaining_seconds: int = 0


class TemporaryMasterPasswordCreateRequest(BaseModel):
    max_time: int = 3600
    send_email: bool = False
    group_id: Optional[int] = None


class TemporaryMasterPasswordCreateResponse(TemporaryMasterPasswordStatus):
    password: str
    emailed_to: int = 0
    email_error: Optional[str] = None


class AccountsSettings(BaseModel):
    account_count: Optional[int] = 12
    account_link: Optional[bool] = True
    account_pass_to_image: Optional[bool] = False
    account_full_group_access: Optional[bool] = False
    account_expire_enabled: Optional[bool] = False
    account_expire_time: Optional[int] = 10368000  # 120 days in seconds
    global_search: Optional[bool] = True
    results_as_cards: Optional[bool] = False
    demo_enabled: Optional[bool] = False
    files_enabled: Optional[bool] = True
    files_allowed_size: Optional[int] = 1024  # KB
    files_allowed_exts: Optional[str] = None
    publinks_enabled: Optional[bool] = False
    publinks_image_enabled: Optional[bool] = False
    publinks_max_time: Optional[int] = 600
    publinks_max_views: Optional[int] = 3


class WikiSettings(BaseModel):
    wiki_enabled: Optional[bool] = False
    wiki_pageurl: Optional[str] = None
    wiki_searchurl: Optional[str] = None
    wiki_filter: Optional[str] = None
    dokuwiki_enabled: Optional[bool] = False
    dokuwiki_url: Optional[str] = None
    dokuwiki_url_base: Optional[str] = None
    dokuwiki_user: Optional[str] = None
    dokuwiki_pass: Optional[str] = None
    dokuwiki_namespace: Optional[str] = None


class SystemInfo(BaseModel):
    app_version: str
    config_version: Optional[str] = None
    db_version: Optional[str] = None
    db_host: Optional[str] = None
    db_name: Optional[str] = None
    config_date: Optional[int] = None
    user_count: int = 0
    account_count: int = 0
    category_count: int = 0
    client_count: int = 0
    tag_count: int = 0


class AllSettings(BaseModel):
    general: GeneralSettings
    mail: MailSettings
    ldap: LdapSettings
    accounts: Optional[AccountsSettings] = None
    wiki: Optional[WikiSettings] = None
