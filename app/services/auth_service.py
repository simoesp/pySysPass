from datetime import UTC, datetime, timedelta
import hashlib
from time import time
from typing import Optional
import jwt
import bcrypt as bcrypt_lib
from app.core.config import settings
from app.core.syspass_runtime_config import get_password_salt
from app.models.account import Config, User


def verify_password(plain_password: str, hashed_password: str) -> bool:
    hashed = hashed_password if isinstance(hashed_password, bytes) else hashed_password.encode()
    # Normalize PHP $2y$ prefix to $2b$ so Python's bcrypt can verify it
    if hashed.startswith(b"$2y$"):
        hashed = b"$2b$" + hashed[4:]
    return bcrypt_lib.checkpw(plain_password.encode(), hashed)


def get_password_hash(password: str) -> str:
    # Use rounds=10 and $2y$ prefix to match PHP password_hash() output
    salt = bcrypt_lib.gensalt(rounds=10)
    hashed = bcrypt_lib.hashpw(password.encode(), salt)
    return hashed.replace(b"$2b$", b"$2y$").decode()


def set_user_login_password(user: User, password: str) -> None:
    """Change login credentials while preserving PHP vault migration state."""
    user.password = get_password_hash(password).encode("utf-8")
    user.isChangePass = False
    user.isChangedPass = True
    user.isMigrate = False


def make_user_key(login_pass: str, login_user: str) -> str:
    """Replicates PHP UserPassService::makeKeyForUser()."""
    return (login_pass + login_user + get_password_salt()).strip()


def decrypt_user_master_pass(user: User, plain_password: str) -> Optional[str]:
    """
    Decrypt the master password stored in User.mPass / User.mKey.
    Returns None if the columns are empty or decryption fails.
    """
    if not user.mPass or not user.mKey:
        return None
    try:
        from app.core.defuse_compat import decrypt_mpass
        mpass_hex = user.mPass.decode('ascii') if isinstance(user.mPass, bytes) else user.mPass
        mkey_hex  = user.mKey.decode('ascii')  if isinstance(user.mKey,  bytes) else user.mKey
        user_key  = make_user_key(plain_password, user.username)
        return decrypt_mpass(mpass_hex, mkey_hex, user_key)
    except Exception:
        return None


# sysPass PHP SP\Core\Crypt\Hash::MAX_KEY_LENGTH
_PHP_HASH_MAX_KEY_LENGTH = 72


def _php_hash_key_input(key: str) -> bytes:
    """PHP Hash::getKey(): SHA-256 hex for keys over 72 characters (mb_strlen).

    bcrypt itself only uses the first 72 bytes; PHP truncates silently, while
    the Python bcrypt module refuses longer input, so truncate the same way.
    """
    if len(key) > _PHP_HASH_MAX_KEY_LENGTH:
        key = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return key.encode("utf-8")[:72]


def hash_master_key(master_password: str) -> str:
    """PHP Hash::hashKey(): the value sysPass stores in Config.masterPwd."""
    hashed = bcrypt_lib.hashpw(_php_hash_key_input(master_password), bcrypt_lib.gensalt(rounds=10))
    return hashed.replace(b"$2b$", b"$2y$").decode()


def verify_master_password_hash(master_password: str, hashed_master_password: Optional[str]) -> bool:
    """PHP Hash::checkHashKey()."""
    if not hashed_master_password or master_password is None:
        return False
    hashed = hashed_master_password.encode() if isinstance(hashed_master_password, str) else hashed_master_password
    if hashed.startswith(b"$2y$"):
        hashed = b"$2b$" + hashed[4:]
    try:
        return bcrypt_lib.checkpw(_php_hash_key_input(master_password), hashed)
    except ValueError:
        return False


def store_user_master_pass(user: User, login_password: str, master_password: str) -> None:
    from app.core.defuse_compat import encrypt_user_master_pass

    user_key = make_user_key(login_password, user.username)
    mpass_hex, mkey_hex = encrypt_user_master_pass(master_password, user_key)
    user.mPass = mpass_hex.encode("ascii")
    user.mKey = mkey_hex.encode("ascii")


def finalize_user_master_pass(user: User, login_password: str, master_password: str) -> None:
    store_user_master_pass(user, login_password, master_password)
    user.lastUpdateMPass = int(time())
    user.isMigrate = False
    user.isChangedPass = False


def migrate_user_master_pass(
    db,
    user: User,
    old_login_password: str,
    new_login_password: str,
) -> Optional[str]:
    master_password = decrypt_user_master_pass(user, old_login_password)
    if master_password is None:
        return None

    master_hash_row = get_master_password_hash_row(db)
    hashed_master_password = master_hash_row.value if master_hash_row else None
    if hashed_master_password and not verify_master_password_hash(master_password, hashed_master_password):
        return None

    if master_hash_row is None:
        db.add(Config(parameter="masterPwd", value=hash_master_key(master_password)))

    finalize_user_master_pass(user, new_login_password, master_password)
    return master_password


def master_pass_changed_at(db) -> int:
    """Config.lastupdatempass: when the vault master password last changed."""
    row = db.query(Config).filter(Config.parameter == "lastupdatempass").first()
    try:
        return int(row.value) if row and row.value else 0
    except ValueError:
        return 0


def user_master_pass_is_stale(db, user: User) -> bool:
    """PHP MPASS_CHANGED: the user's mPass predates the current master."""
    return int(user.lastUpdateMPass or 0) < master_pass_changed_at(db)


def master_pass_matches_config(db, master_password: str) -> bool:
    """PHP checks the unlocked master against Config.masterPwd when one is set."""
    row = get_master_password_hash_row(db)
    return not (row and row.value) or verify_master_password_hash(master_password, row.value)


def get_master_password_hash_row(db) -> Optional[Config]:
    return db.query(Config).filter(Config.parameter == "masterPwd").first()


_VAULT_CLAIM_INFO = b"pysyspass session vault claim v2"


def _vault_claim_key() -> bytes:
    """A dedicated key for the session vault claim, derived from ENCRYPTION_KEY."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_VAULT_CLAIM_INFO).derive(
        settings.ENCRYPTION_KEY.encode("utf-8")
    )


def _encrypt_short(plaintext: str, user_id=None) -> str:
    """Encrypt the master password for the session token (AES-256-GCM).

    The token is readable by whoever holds it, so the claim is encrypted with
    an authenticated cipher under a key used for nothing else, bound to the
    user ID so it cannot be moved into another user's token.
    """
    import base64
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    sealed = AESGCM(_vault_claim_key()).encrypt(nonce, plaintext.encode("utf-8"), str(user_id).encode())
    return "g2:" + base64.urlsafe_b64encode(nonce + sealed).decode()


def _decrypt_short(token_value: str, user_id=None) -> Optional[str]:
    """Decrypt a claim made by _encrypt_short; None when it does not verify."""
    try:
        import base64

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if not token_value.startswith("g2:"):
            return None
        raw = base64.urlsafe_b64decode(token_value[3:])
        return AESGCM(_vault_claim_key()).decrypt(raw[:12], raw[12:], str(user_id).encode()).decode("utf-8")
    except Exception:
        return None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None,
                        master_pass: Optional[str] = None,
                        is_admin: bool = False,
                        is_admin_app: Optional[bool] = None,
                        is_admin_acc: Optional[bool] = None):
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(hours=24))
    to_encode["exp"] = expire
    # Older callers supplied one composite flag. Preserve those tokens as
    # application-admin tokens, while real PHP users retain the distinct
    # isAdminApp/isAdminAcc scopes used by sysPass ACL checks.
    app_admin = is_admin if is_admin_app is None else is_admin_app
    account_admin = is_admin if is_admin_acc is None else is_admin_acc
    to_encode["is_admin"] = bool(app_admin)
    to_encode["is_admin_app"] = bool(app_admin)
    to_encode["is_admin_acc"] = bool(account_admin)
    if master_pass is not None:
        to_encode["mpass"] = _encrypt_short(master_pass, to_encode.get("user_id"))
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt


def issue_session_token(
    user: User,
    *,
    master_pass: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    auth_time: Optional[float] = None,
) -> str:
    """Mint a revocable, inactivity-limited session token (see session_service)."""
    from app.services.session_service import (
        DEFAULT_SESSION_TIMEOUT, MAX_SESSION_SECONDS, new_session_id, session_fingerprint,
    )

    now = time()
    started = now if auth_time is None else float(auth_time)
    lifetime = min(timeout_seconds or DEFAULT_SESSION_TIMEOUT, max(0.0, started + MAX_SESSION_SECONDS - now))
    data = {
        "user_id": user.id,
        "username": user.username,
        # Float timestamps keep tokens minted right after a revocation valid.
        "iat": now,
        "auth_time": started,
        "jti": new_session_id(),
        "sfp": session_fingerprint(user),
    }
    return create_access_token(
        data,
        expires_delta=timedelta(seconds=lifetime),
        master_pass=master_pass,
        is_admin_app=bool(user.isAdminApp),
        is_admin_acc=bool(user.isAdminAcc),
    )


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if "mpass" in payload:
            payload["master_pass"] = _decrypt_short(payload["mpass"], payload.get("user_id"))
        return payload
    except jwt.PyJWTError:
        return None
