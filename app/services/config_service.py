from sqlalchemy.orm import Session
from typing import Optional, Dict
from app.core.runtime_json_config import get_runtime_config_value, set_runtime_config_value
from app.models.account import Config
from app.schemas.config import (
    GeneralSettings, MailSettings, LdapSettings, AllSettings,
    AccountsSettings, WikiSettings, SystemInfo,
)


class ConfigService:
    def __init__(self, db: Session):
        self.db = db

    def get(self, parameter: str) -> Optional[str]:
        runtime_value = get_runtime_config_value(parameter)
        if runtime_value is not None:
            return runtime_value
        row = self.db.query(Config).filter(Config.parameter == parameter).first()
        return row.value if row else None

    def set(self, parameter: str, value: Optional[str]) -> None:
        if set_runtime_config_value(parameter, value):
            return
        row = self.db.query(Config).filter(Config.parameter == parameter).first()
        if row:
            row.value = value
        else:
            self.db.add(Config(parameter=parameter, value=value))
        self.db.commit()

    def set_many(self, params: Dict[str, Optional[str]]) -> None:
        for k, v in params.items():
            self.set(k, v)

    def get_all(self) -> Dict[str, Optional[str]]:
        rows = self.db.query(Config).all()
        values = {r.parameter: r.value for r in rows}
        for parameter in (
            "sitelang", "sitetheme", "session_timeout", "app_url", "https_enabled",
            "debug", "maintenance", "check_updates", "check_notices", "log_enabled",
            "syslog_enabled", "syslog_remote_enabled", "syslog_server", "syslog_port",
            "proxy_enabled", "proxy_server", "proxy_port", "proxy_user",
            "mail_enabled", "mail_server", "mail_port", "mail_user", "mail_pass",
            "mail_security", "mail_from", "mail_requests_enabled", "mail_auth_enabled",
            "mail_recipients", "ldap_enabled", "ldap_server", "ldap_base", "ldap_group",
            "ldap_binduser", "ldap_bindpass", "ldap_server_type", "ldap_tls_enabled",
            "ldap_defaultgroup", "ldap_defaultprofile", "account_count", "account_link",
            "account_pass_to_image", "account_full_group_access", "account_expire_enabled",
            "account_expire_time", "global_search", "results_as_cards", "demo_enabled",
            "files_enabled", "files_allowed_size", "files_allowed_exts", "publinks_enabled",
            "publinks_image_enabled", "publinks_max_time", "publinks_max_views",
            "wiki_enabled", "wiki_pageurl", "wiki_searchurl", "wiki_filter",
            "dokuwiki_enabled", "dokuwiki_url", "dokuwiki_url_base", "dokuwiki_user",
            "dokuwiki_pass", "dokuwiki_namespace", "configVersion", "databaseVersion",
            "dbHost", "dbName", "configDate", "passwordSalt",
        ):
            runtime_value = get_runtime_config_value(parameter)
            if runtime_value is not None:
                values[parameter] = runtime_value
        return values

    def _bool_val(self, key: str, default: bool = False) -> bool:
        v = self.get(key)
        if v is None:
            return default
        return v.lower() in ("true", "1", "yes")

    def _int_val(self, key: str, default: int = 0) -> Optional[int]:
        v = self.get(key)
        try:
            return int(v) if v is not None else default
        except ValueError:
            return default

    def get_general_settings(self) -> GeneralSettings:
        return GeneralSettings(
            sitelang=self.get("sitelang") or "en_US",
            sitetheme=self.get("sitetheme") or "blue",
            session_timeout=self._int_val("session_timeout", 300),
            app_url=self.get("app_url"),
            https_enabled=self._bool_val("https_enabled"),
            debug=self._bool_val("debug"),
            maintenance=self._bool_val("maintenance"),
            check_updates=self._bool_val("check_updates"),
            check_notices=self._bool_val("check_notices"),
            log_enabled=self._bool_val("log_enabled", True),
            syslog_enabled=self._bool_val("syslog_enabled"),
            syslog_remote_enabled=self._bool_val("syslog_remote_enabled"),
            syslog_server=self.get("syslog_server"),
            syslog_port=self._int_val("syslog_port", 514),
            proxy_enabled=self._bool_val("proxy_enabled"),
            proxy_server=self.get("proxy_server"),
            proxy_port=self._int_val("proxy_port", 8080),
            proxy_user=self.get("proxy_user"),
        )

    def save_general_settings(self, s: GeneralSettings) -> None:
        self.set_many({
            "sitelang": s.sitelang,
            "sitetheme": s.sitetheme,
            "session_timeout": str(s.session_timeout) if s.session_timeout is not None else None,
            "app_url": s.app_url,
            "https_enabled": str(s.https_enabled).lower() if s.https_enabled is not None else "false",
            "debug": str(s.debug).lower() if s.debug is not None else "false",
            "maintenance": str(s.maintenance).lower() if s.maintenance is not None else "false",
            "check_updates": str(s.check_updates).lower() if s.check_updates is not None else "false",
            "check_notices": str(s.check_notices).lower() if s.check_notices is not None else "false",
            "log_enabled": str(s.log_enabled).lower() if s.log_enabled is not None else "true",
            "syslog_enabled": str(s.syslog_enabled).lower() if s.syslog_enabled is not None else "false",
            "syslog_remote_enabled":
                str(s.syslog_remote_enabled).lower() if s.syslog_remote_enabled is not None else "false",
            "syslog_server": s.syslog_server,
            "syslog_port": str(s.syslog_port) if s.syslog_port is not None else None,
            "proxy_enabled": str(s.proxy_enabled).lower() if s.proxy_enabled is not None else "false",
            "proxy_server": s.proxy_server,
            "proxy_port": str(s.proxy_port) if s.proxy_port is not None else None,
            "proxy_user": s.proxy_user,
        })

    def get_mail_settings(self) -> MailSettings:
        return MailSettings(
            mail_enabled=self._bool_val("mail_enabled"),
            mail_server=self.get("mail_server"),
            mail_port=self._int_val("mail_port", 25),
            mail_user=self.get("mail_user"),
            mail_pass=self.get("mail_pass"),
            mail_security=self.get("mail_security") or "tls",
            mail_from=self.get("mail_from"),
            mail_requests_enabled=self._bool_val("mail_requests_enabled"),
            mail_auth_enabled=self._bool_val("mail_auth_enabled"),
            mail_recipients=self.get("mail_recipients"),
        )

    def save_mail_settings(self, s: MailSettings) -> None:
        self.set_many({
            "mail_enabled": str(s.mail_enabled).lower() if s.mail_enabled is not None else "false",
            "mail_server": s.mail_server,
            "mail_port": str(s.mail_port) if s.mail_port is not None else None,
            "mail_user": s.mail_user,
            "mail_pass": s.mail_pass,
            "mail_security": s.mail_security,
            "mail_from": s.mail_from,
            "mail_requests_enabled":
                str(s.mail_requests_enabled).lower() if s.mail_requests_enabled is not None else "false",
            "mail_auth_enabled": str(s.mail_auth_enabled).lower() if s.mail_auth_enabled is not None else "false",
            "mail_recipients": s.mail_recipients,
        })

    def get_ldap_settings(self) -> LdapSettings:
        return LdapSettings(
            ldap_enabled=self._bool_val("ldap_enabled"),
            ldap_server=self.get("ldap_server"),
            ldap_base=self.get("ldap_base"),
            ldap_group=self.get("ldap_group"),
            ldap_binduser=self.get("ldap_binduser"),
            ldap_bindpass=self.get("ldap_bindpass"),
            ldap_server_type=self._int_val("ldap_server_type", 1),
            ldap_tls_enabled=self._bool_val("ldap_tls_enabled"),
            ldap_defaultgroup=self._int_val("ldap_defaultgroup", None),
            ldap_defaultprofile=self._int_val("ldap_defaultprofile", None),
        )

    def save_ldap_settings(self, s: LdapSettings) -> None:
        self.set_many({
            "ldap_enabled": str(s.ldap_enabled).lower() if s.ldap_enabled is not None else "false",
            "ldap_server": s.ldap_server,
            "ldap_base": s.ldap_base,
            "ldap_group": s.ldap_group,
            "ldap_binduser": s.ldap_binduser,
            "ldap_bindpass": s.ldap_bindpass,
            "ldap_server_type": str(s.ldap_server_type) if s.ldap_server_type is not None else None,
            "ldap_tls_enabled": str(s.ldap_tls_enabled).lower() if s.ldap_tls_enabled is not None else "false",
            "ldap_defaultgroup": str(s.ldap_defaultgroup) if s.ldap_defaultgroup is not None else None,
            "ldap_defaultprofile": str(s.ldap_defaultprofile) if s.ldap_defaultprofile is not None else None,
        })

    def get_accounts_settings(self) -> AccountsSettings:
        return AccountsSettings(
            account_count=self._int_val("account_count", 12),
            account_link=self._bool_val("account_link", True),
            account_pass_to_image=self._bool_val("account_pass_to_image"),
            account_full_group_access=self._bool_val("account_full_group_access"),
            account_expire_enabled=self._bool_val("account_expire_enabled"),
            account_expire_time=self._int_val("account_expire_time", 10368000),
            global_search=self._bool_val("global_search", True),
            results_as_cards=self._bool_val("results_as_cards"),
            demo_enabled=self._bool_val("demo_enabled"),
            files_enabled=self._bool_val("files_enabled", True),
            files_allowed_size=self._int_val("files_allowed_size", 1024),
            files_allowed_exts=self.get("files_allowed_exts"),
            publinks_enabled=self._bool_val("publinks_enabled"),
            publinks_image_enabled=self._bool_val("publinks_image_enabled"),
            publinks_max_time=self._int_val("publinks_max_time", 600),
            publinks_max_views=self._int_val("publinks_max_views", 3),
        )

    def save_accounts_settings(self, s: AccountsSettings) -> None:
        self.set_many({
            "account_count": str(s.account_count) if s.account_count is not None else "12",
            "account_link": str(s.account_link).lower() if s.account_link is not None else "true",
            "account_pass_to_image":
                str(s.account_pass_to_image).lower() if s.account_pass_to_image is not None else "false",
            "account_full_group_access":
                str(s.account_full_group_access).lower() if s.account_full_group_access is not None else "false",
            "account_expire_enabled":
                str(s.account_expire_enabled).lower() if s.account_expire_enabled is not None else "false",
            "account_expire_time": str(s.account_expire_time) if s.account_expire_time is not None else "10368000",
            "global_search": str(s.global_search).lower() if s.global_search is not None else "true",
            "results_as_cards": str(s.results_as_cards).lower() if s.results_as_cards is not None else "false",
            "demo_enabled": str(s.demo_enabled).lower() if s.demo_enabled is not None else "false",
            "files_enabled": str(s.files_enabled).lower() if s.files_enabled is not None else "true",
            "files_allowed_size": str(s.files_allowed_size) if s.files_allowed_size is not None else "1024",
            "files_allowed_exts": s.files_allowed_exts,
            "publinks_enabled": str(s.publinks_enabled).lower() if s.publinks_enabled is not None else "false",
            "publinks_image_enabled":
                str(s.publinks_image_enabled).lower() if s.publinks_image_enabled is not None else "false",
            "publinks_max_time": str(s.publinks_max_time) if s.publinks_max_time is not None else "600",
            "publinks_max_views": str(s.publinks_max_views) if s.publinks_max_views is not None else "3",
        })

    def get_wiki_settings(self) -> WikiSettings:
        return WikiSettings(
            wiki_enabled=self._bool_val("wiki_enabled"),
            wiki_pageurl=self.get("wiki_pageurl"),
            wiki_searchurl=self.get("wiki_searchurl"),
            wiki_filter=self.get("wiki_filter"),
            dokuwiki_enabled=self._bool_val("dokuwiki_enabled"),
            dokuwiki_url=self.get("dokuwiki_url"),
            dokuwiki_url_base=self.get("dokuwiki_url_base"),
            dokuwiki_user=self.get("dokuwiki_user"),
            dokuwiki_pass=self.get("dokuwiki_pass"),
            dokuwiki_namespace=self.get("dokuwiki_namespace"),
        )

    def save_wiki_settings(self, s: WikiSettings) -> None:
        self.set_many({
            "wiki_enabled": str(s.wiki_enabled).lower() if s.wiki_enabled is not None else "false",
            "wiki_pageurl": s.wiki_pageurl,
            "wiki_searchurl": s.wiki_searchurl,
            "wiki_filter": s.wiki_filter,
            "dokuwiki_enabled": str(s.dokuwiki_enabled).lower() if s.dokuwiki_enabled is not None else "false",
            "dokuwiki_url": s.dokuwiki_url,
            "dokuwiki_url_base": s.dokuwiki_url_base,
            "dokuwiki_user": s.dokuwiki_user,
            "dokuwiki_pass": s.dokuwiki_pass,
            "dokuwiki_namespace": s.dokuwiki_namespace,
        })

    def get_system_info(self) -> SystemInfo:
        from app.models.account import User, Account, Category, Client, Tag
        return SystemInfo(
            app_version="3.0.0-python",
            config_version=self.get("configVersion"),
            db_version=self.get("databaseVersion"),
            db_host=self.get("dbHost"),
            db_name=self.get("dbName"),
            config_date=int(self.get("configDate")) if self.get("configDate") else None,
            user_count=self.db.query(User).count(),
            account_count=self.db.query(Account).count(),
            category_count=self.db.query(Category).count(),
            client_count=self.db.query(Client).count(),
            tag_count=self.db.query(Tag).count(),
        )

    def get_all_settings(self) -> AllSettings:
        return AllSettings(
            general=self.get_general_settings(),
            mail=self.get_mail_settings(),
            ldap=self.get_ldap_settings(),
            accounts=self.get_accounts_settings(),
            wiki=self.get_wiki_settings(),
        )
