from datetime import UTC, datetime, timedelta
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


def verify_master_password_hash(master_password: str, hashed_master_password: Optional[str]) -> bool:
    if not hashed_master_password:
        return False
    return verify_password(master_password, hashed_master_password)


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
        db.add(Config(parameter="masterPwd", value=get_password_hash(master_password)))

    finalize_user_master_pass(user, new_login_password, master_password)
    return master_password


def get_master_password_hash_row(db) -> Optional[Config]:
    return db.query(Config).filter(Config.parameter == "masterPwd").first()


def _encrypt_short(plaintext: str) -> str:
    """Encrypt a short string (master password) with ENCRYPTION_KEY for JWT embedding."""
    import os
    import base64
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = settings.ENCRYPTION_KEY.encode()[:32].ljust(32, b'\x00')
    iv  = os.urandom(16)
    ct  = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    enc = ct.update(plaintext.encode()) + ct.finalize()
    return base64.b64encode(iv + enc).decode()


def _decrypt_short(token_value: str) -> Optional[str]:
    """Decrypt a value that was encrypted by _encrypt_short."""
    try:
        import base64
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        raw = base64.b64decode(token_value)
        iv, enc = raw[:16], raw[16:]
        key = settings.ENCRYPTION_KEY.encode()[:32].ljust(32, b'\x00')
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return (dec.update(enc) + dec.finalize()).decode()
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
        to_encode["mpass"] = _encrypt_short(master_pass)
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if "mpass" in payload:
            payload["master_pass"] = _decrypt_short(payload["mpass"])
        return payload
    except jwt.PyJWTError:
        return None
