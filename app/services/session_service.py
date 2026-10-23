"""Bearer-session revocation and inactivity timeout (R7 / #51).

sysPass PHP keeps server-side PHP sessions: logout destroys the session and
``session_timeout`` expires it after inactivity. pySysPass issues JWTs, so the
same guarantees come from three mechanisms that need no PHP schema changes:

* Credential fingerprint: every token carries ``sfp``, an HMAC of the user's
  current login password hash. Any password change or reset, whether made by
  pySysPass or PHP, invalidates every token issued before it.
* Ephemeral session state: a small locked JSON file beside the runtime config
  records revoked token IDs (logout, refresh) until they expire, and a per-user
  "not before" time that revokes all of a user's tokens (2FA enrollment
  changes). It is deployment state, not PHP data, and may be deleted safely;
  deleting it only forgets revocations of still-unexpired tokens.
* Inactivity timeout: tokens expire ``session_timeout`` seconds after issue
  (PHP default 300). The SPA refreshes only after real user input, so polling
  does not keep an idle session alive. Refreshes cannot extend a session past
  ``MAX_SESSION_SECONDS`` from the original login.

Changing ``SECRET_KEY`` invalidates every token. Changing ``ENCRYPTION_KEY``
leaves tokens valid but makes their embedded vault key unreadable, which the
API treats as a missing master password.
"""
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Optional

from app.core.config import BASE_DIR, settings
from app.core.runtime_json_config import locked_path, write_text_atomically

DEFAULT_SESSION_TIMEOUT = 300
ALL_USERS = "*"
MIN_SESSION_TIMEOUT = 60
MAX_SESSION_SECONDS = 24 * 3600


def _store_path() -> Path:
    return BASE_DIR / "data" / "sessions.json"


def session_fingerprint(user) -> str:
    password = user.password or b""
    if isinstance(password, str):
        password = password.encode("utf-8")
    message = b"sfp-v1|" + str(user.id).encode() + b"|" + password
    return hmac.new(settings.SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()


def new_session_id() -> str:
    return secrets.token_urlsafe(18)


def resolve_session_timeout(db) -> int:
    """Effective inactivity timeout in seconds, like PHP's getSessionTimeout()."""
    from app.services.config_service import ConfigService

    try:
        value = int(ConfigService(db).get("session_timeout") or DEFAULT_SESSION_TIMEOUT)
    except (TypeError, ValueError):
        value = DEFAULT_SESSION_TIMEOUT
    if value <= 0:
        value = DEFAULT_SESSION_TIMEOUT
    return max(MIN_SESSION_TIMEOUT, min(value, MAX_SESSION_SECONDS))


class SessionStore:
    """Cross-process revocation state in ``data/sessions.json``."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or _store_path()
        self._cache: Optional[tuple] = None

    def _read(self) -> dict:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return {"revoked": {}, "not_before": {}}
        key = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
        if self._cache and self._cache[0] == key:
            return self._cache[1]
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except ValueError:
            # Fail closed would lock everyone out on corruption; this file is
            # an optimization over token expiry, so start over instead.
            document = {}
        document = {
            "revoked": dict(document.get("revoked") or {}),
            "not_before": dict(document.get("not_before") or {}),
        }
        self._cache = (key, document)
        return document

    def _update(self, change) -> None:
        with locked_path(self.path):
            self._cache = None
            document = self._read()
            now = time.time()
            document["revoked"] = {
                jti: exp for jti, exp in document["revoked"].items() if exp > now
            }
            document["not_before"] = {
                uid: ts for uid, ts in document["not_before"].items() if ts > now - MAX_SESSION_SECONDS
            }
            change(document)
            write_text_atomically(self.path, json.dumps(document, sort_keys=True) + "\n")
            self._cache = None

    def revoke_token(self, jti: str, expires_at: float) -> None:
        if float(expires_at) <= time.time():
            return  # already unusable; nothing to remember
        self._update(lambda doc: doc["revoked"].__setitem__(jti, float(expires_at)))

    def revoke_user(self, user_id: int, before: Optional[float] = None) -> None:
        stamp = time.time() if before is None else before
        self._update(lambda doc: doc["not_before"].__setitem__(str(user_id), float(stamp)))

    def revoke_all(self, before: Optional[float] = None) -> None:
        """End every session, e.g. after the vault master password changes."""
        self.revoke_user(ALL_USERS, before)

    def is_revoked(self, payload: dict) -> bool:
        document = self._read()
        jti = payload.get("jti")
        if jti and jti in document["revoked"]:
            return True
        issued = float(payload.get("iat", 0))
        for key in (str(payload.get("user_id")), ALL_USERS):
            not_before = document["not_before"].get(key)
            if not_before is not None and issued < not_before:
                return True
        return False


session_store = SessionStore()


def rotate_user_sessions(db, user, current_user: Optional[dict] = None) -> Optional[str]:
    """Revoke all of ``user``'s sessions; return a fresh token for the caller.

    Used for security-relevant changes (2FA enrollment, own password change)
    so other browsers lose access while the acting session continues.
    """
    from app.services.auth_service import issue_session_token

    session_store.revoke_user(user.id)
    session = (current_user or {}).get("session")
    if not session or current_user.get("id") != user.id:
        return None
    return issue_session_token(
        user,
        master_pass=current_user.get("master_pass"),
        timeout_seconds=resolve_session_timeout(db),
        auth_time=session["auth_time"],
    )
