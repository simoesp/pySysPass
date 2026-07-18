"""LDAP/Active Directory Authentication Service (uses ldap3 - pure Python)"""
from typing import List, Optional, Dict
import logging

logger = logging.getLogger(__name__)

# ldap3 is an optional dependency — only required when LDAP features are used.
try:
    from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE, AUTO_BIND_NO_TLS
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars
    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False
    logger.warning("ldap3 not installed — LDAP features disabled. Install with: pip install ldap3")

    # Provide lightweight stubs so importing the module and route registration
    # remains safe even when LDAP support is not installed.
    class Server:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            pass

    class Connection:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            pass

    ALL = SUBTREE = SIMPLE = AUTO_BIND_NO_TLS = None

    class LDAPException(Exception):
        pass

    def escape_filter_chars(value: str) -> str:
        """Dependency-free RFC 4515 fallback used without ldap3."""
        return (
            value.replace("\\", r"\5c")
            .replace("*", r"\2a")
            .replace("(", r"\28")
            .replace(")", r"\29")
            .replace("\x00", r"\00")
        )


class LdapService:
    """LDAP/Active Directory authentication and import service"""

    def __init__(self, ldap_uri: str, base_dn: str,
                 bind_dn: str = None, bind_password: str = None,
                 use_ssl: bool = False, use_tls: bool = False):
        if not _LDAP_AVAILABLE:
            raise ImportError(
                "ldap3 is not installed. LDAP features require: pip install ldap3"
            )
        self.ldap_uri = ldap_uri
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.use_ssl = use_ssl
        self.use_tls = use_tls
        self._conn: Optional[Connection] = None

    def _server(self) -> Server:
        return Server(self.ldap_uri, use_ssl=self.use_ssl, get_info=ALL)

    def connect(self) -> bool:
        """Establish LDAP connection and bind."""
        try:
            server = self._server()
            if self.bind_dn and self.bind_password:
                self._conn = Connection(
                    server,
                    user=self.bind_dn,
                    password=self.bind_password,
                    authentication=SIMPLE,
                    auto_bind=AUTO_BIND_NO_TLS,
                )
            else:
                self._conn = Connection(server, auto_bind=AUTO_BIND_NO_TLS)
            if self.use_tls:
                self._conn.start_tls()
            self._conn.bind()
            return True
        except LDAPException as exc:
            raise ConnectionError(f"LDAP connection failed: {exc}") from exc

    def disconnect(self):
        if self._conn and self._conn.bound:
            self._conn.unbind()
        self._conn = None

    def search(self, filter_str: str = "(objectClass=*)",
               attributes: List[str] = None) -> List[Dict]:
        """Search LDAP directory; returns list of {dn, attributes} dicts."""
        if not self._conn or not self._conn.bound:
            self.connect()
        attrs = attributes or ["*"]
        ok = self._conn.search(
            search_base=self.base_dn,
            search_filter=filter_str,
            search_scope=SUBTREE,
            attributes=attrs,
        )
        if not ok:
            return []
        results = []
        for entry in self._conn.entries:
            attr_dict: Dict = {}
            for attr in entry.entry_attributes:
                val = entry[attr].value
                attr_dict[attr] = val
            results.append({"dn": entry.entry_dn, "attributes": attr_dict})
        return results

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user; returns the user's DN on success, None on failure."""
        # Reject empty passwords: per RFC 4513 a SIMPLE bind with a valid DN
        # and empty password is an "unauthenticated bind" that many servers
        # accept, which would be an authentication bypass.
        if not password:
            return None
        if not self._conn or not self._conn.bound:
            self.connect()
        # "dn" is not a real attribute and makes ldap3 raise LDAPAttributeError;
        # request cn and take the DN from the entry itself.
        entries = self.search(filter_str=_user_search_filter(username), attributes=["cn"])
        if not entries:
            return None
        user_dn = entries[0]["dn"]
        server = self._server()
        try:
            test_conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=AUTO_BIND_NO_TLS,
            )
            test_conn.bind()
            bound = test_conn.bound
            test_conn.unbind()
            return user_dn if bound else None
        except LDAPException:
            return None

    def user_in_group(self, username: str, user_dn: str, group: str) -> bool:
        """Check group membership like PHP LdapStd/LdapMsAds.

        Accepts the configured group as a CN or full DN. Tries, in order:
        the AD in-chain matching rule (covers nested groups), the group
        entry's member/uniqueMember/memberUid lists, and finally the
        user's own memberOf values.
        """
        group = (group or "").strip()
        if not group:
            return True

        if "=" in group:
            group_dn = group
        else:
            entries = self.search(
                filter_str=f"(&(cn={escape_filter_chars(group)})"
                           f"(|(objectClass=group)(objectClass=groupOfNames)"
                           f"(objectClass=groupOfUniqueNames)(objectClass=posixGroup)))",
                attributes=["cn"],
            )
            if not entries:
                logger.warning("LDAP group %r not found in directory", group)
                return False
            group_dn = entries[0]["dn"]

        # Active Directory nested-group chain (LDAP_MATCHING_RULE_IN_CHAIN)
        try:
            chain = self.search(
                filter_str=f"(&(distinguishedName={escape_filter_chars(user_dn)})"
                           f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)}))",
                attributes=["cn"],
            )
            if chain:
                return True
        except Exception:  # non-AD servers reject the matching rule
            logger.debug("in-chain group match unsupported", exc_info=True)

        # Standard LDAP: membership is stored on the group entry
        group_entries = self.search(
            filter_str=f"(distinguishedName={escape_filter_chars(group_dn)})",
            attributes=["member", "uniqueMember", "memberUid"],
        ) or self.search(
            filter_str=f"(&(cn={escape_filter_chars(_group_cn(group_dn))})"
                       f"(|(objectClass=group)(objectClass=groupOfNames)"
                       f"(objectClass=groupOfUniqueNames)(objectClass=posixGroup)))",
            attributes=["member", "uniqueMember", "memberUid"],
        )
        for entry in group_entries:
            attrs = entry.get("attributes", {})
            for key in ("member", "uniqueMember"):
                values = attrs.get(key) or []
                if isinstance(values, str):
                    values = [values]
                if any(v.lower() == user_dn.lower() for v in values):
                    return True
            member_uids = attrs.get("memberUid") or []
            if isinstance(member_uids, str):
                member_uids = [member_uids]
            if any(v.lower() == username.lower() for v in member_uids):
                return True

        # Fallback: the user's own memberOf attribute (DN or CN match)
        info = self.get_user_info(username) or {}
        member_of = info.get("attributes", {}).get("memberOf") or []
        if isinstance(member_of, str):
            member_of = [member_of]
        needle = group_dn.lower()
        needle_cn = _group_cn(group_dn)
        return any(
            needle == g.lower() or needle_cn == _group_cn(g)
            for g in member_of
        )

    def get_user_info(self, username: str) -> Optional[Dict]:
        """Fetch a single user's attributes from LDAP."""
        results = self.search(
            filter_str=_user_search_filter(username),
            attributes=["cn", "sn", "givenName", "mail", "uid", "sAMAccountName", "memberOf"],
        )
        return results[0] if results else None

    def import_users(self, attributes: List[str] = None) -> List[Dict]:
        """Return normalised user dicts suitable for import into sysPass."""
        attrs = attributes or ["cn", "sn", "givenName", "mail", "uid", "sAMAccountName"]
        raw = self.search(filter_str="(objectClass=person)", attributes=attrs)
        users = []
        for entry in raw:
            a = entry["attributes"]
            username = (
                _first(a.get("uid"))
                or _first(a.get("sAMAccountName"))
                or ""
            )
            users.append({
                "username": username,
                "email": _first(a.get("mail")) or "",
                "first_name": _first(a.get("givenName")) or "",
                "last_name": _first(a.get("sn")) or "",
                "full_name": _first(a.get("cn")) or username,
                "dn": entry["dn"],
                "groups": a.get("memberOf") or [],
            })
        return users


def _user_search_filter(username: str) -> str:
    """User lookup filter matching posix and Active Directory naming.

    Mirrors sysPass PHP LdapStd/LdapMsAds, which match samaccountname, cn
    and uid so one filter works for both directory flavours.
    """
    u = escape_filter_chars(username)
    return f"(|(uid={u})(sAMAccountName={u})(cn={u}))"


def _first(val):
    """Return scalar or first element of list; None if empty."""
    if val is None:
        return None
    if isinstance(val, list):
        return val[0] if val else None
    return val


def authenticate_ldap_login(db, username: str, password: str):
    """Authenticate a login against LDAP and sync the local user row.

    Mirrors sysPass PHP LoginService + LdapAuth: when LDAP is enabled it is
    tried before database auth; on success the local user is created (with
    isLdap set and the configured default group/profile) or updated, so the
    password hash stays usable as a database fallback, exactly like PHP's
    updateOnLogin. Returns the User row on success, None otherwise (the
    caller then falls back to database auth).
    """
    from app.services.config_service import ConfigService

    if not password:
        return None
    cfg = ConfigService(db).get_ldap_settings()
    if not cfg.ldap_enabled or not cfg.ldap_server:
        return None
    if not _LDAP_AVAILABLE:
        logger.warning("LDAP login skipped: ldap3 not installed")
        return None

    svc = LdapService(
        ldap_uri=cfg.ldap_server,
        base_dn=cfg.ldap_base or "",
        bind_dn=cfg.ldap_binduser or None,
        bind_password=cfg.ldap_bindpass or None,
        use_tls=cfg.ldap_tls_enabled or False,
    )
    try:
        svc.connect()
        user_dn = svc.authenticate(username, password)
        if not user_dn:
            return None
        info = svc.get_user_info(username) or {}
        if cfg.ldap_group and not svc.user_in_group(username, user_dn, cfg.ldap_group):
            # PHP LdapAuth denies logins outside the configured group.
            logger.warning("LDAP login denied: %s not in group %s", username, cfg.ldap_group)
            return None
    except Exception:
        logger.exception("LDAP authentication unavailable")
        return None
    finally:
        try:
            svc.disconnect()
        except Exception:
            pass

    attrs = info.get("attributes", {})

    from app.models.account import User
    from app.services.auth_service import get_password_hash
    import secrets

    name = _first(attrs.get("cn")) or username
    email = _first(attrs.get("mail"))
    hashed = get_password_hash(password)
    if isinstance(hashed, str):
        hashed = hashed.encode("utf-8")

    user = db.query(User).filter(User.username == username).first()
    if user:
        if not user.isUserEnabled:
            logger.warning("LDAP login denied: user %s is disabled", username)
            return None
        user.password = hashed
        user.name = name
        if email:
            user.email = email
        user.isLdap = True
    else:
        from app.services.user_profile_service import UserProfileService

        if not cfg.ldap_defaultgroup:
            # Without an explicit default the old fallback was group 1
            # (Admins) — never provision into it implicitly.
            logger.warning(
                "LDAP login for new user %s refused: set the LDAP default group "
                "in Settings before new directory users can be provisioned",
                username,
            )
            return None

        profile_id = cfg.ldap_defaultprofile or UserProfileService(db).ensure_default_profile().id
        user = User(
            userGroupId=cfg.ldap_defaultgroup,
            userProfileId=profile_id,
            name=name,
            username=username,
            email=email or f"{username}@ldap.local",
            password=hashed,
            hashSalt=secrets.token_bytes(32),
            loginCount=0,
            lastUpdateMPass=0,
            isUserEnabled=True,
            isLdap=True,
        )
        db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _group_cn(group_dn: str) -> str:
    """Lower-cased CN of a group DN ('cn=admins,dc=x' -> 'admins')."""
    first_rdn = group_dn.split(",", 1)[0]
    if "=" in first_rdn:
        return first_rdn.split("=", 1)[1].strip().lower()
    return first_rdn.strip().lower()


class LdapImportService:
    """Import LDAP users into the sysPass database."""

    def __init__(self, db, user_group_id: int, user_profile_id: Optional[int] = None):
        self.db = db
        self.user_group_id = user_group_id
        self.user_profile_id = user_profile_id

    def import_ldap_users(self, ldap_users: List[Dict],
                          default_password: str = None) -> Dict:
        from app.models.account import User
        from app.services.auth_service import get_password_hash
        from app.services.user_profile_service import UserProfileService
        import secrets

        stats = {"success": 0, "failed": 0, "skipped": 0}
        profile_id = self.user_profile_id or UserProfileService(self.db).ensure_default_profile().id
        for ldap_user in ldap_users:
            username = ldap_user.get("username")
            if not username:
                stats["failed"] += 1
                continue
            if self.db.query(User).filter(User.username == username).first():
                stats["skipped"] += 1
                continue
            try:
                email = ldap_user.get("email") or f"{username}@ldap.local"
                raw_pass = default_password or secrets.token_urlsafe(16)
                hashed = get_password_hash(raw_pass)
                if isinstance(hashed, str):
                    hashed = hashed.encode("utf-8")
                user = User(
                    userGroupId=self.user_group_id,
                    userProfileId=profile_id,
                    name=ldap_user.get("full_name") or username,
                    username=username,
                    email=email,
                    password=hashed,
                    hashSalt=secrets.token_bytes(32),
                    loginCount=0,
                    lastUpdateMPass=0,
                    isUserEnabled=True,
                    isChangePass=True,
                    isLdap=True,
                )
                self.db.add(user)
                self.db.commit()
                stats["success"] += 1
            except Exception:
                self.db.rollback()
                stats["failed"] += 1
        return stats
