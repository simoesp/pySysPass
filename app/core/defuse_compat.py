"""
Python implementation of PHP defuse/php-encryption v2 decryption.

Wire format (V2):
  hex( \xDE\xF5\x02\x00 | salt[32] | iv[16] | ciphertext | hmac[32] )

Key-in-ASCII format:
  hex( \xDE\xF0\x00\x00 | raw_key[32] | sha256(header+raw_key)[32] )

KeyProtectedByPassword format:
  hex( \xDE\xF1\x00\x00 | encrypted_key_raw | sha256(header+encrypted_key_raw)[32] )
  where encrypted_key_raw is a raw-binary defuse V2 ciphertext whose password
  is sha256(makeKeyForUser_string).
"""

import hashlib
import hmac as _hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_V2_HEADER   = b'\xDE\xF5\x02\x00'
_KEY_HEADER  = b'\xDE\xF0\x00\x00'
_PKEY_HEADER = b'\xDE\xF1\x00\x00'

_HDR  = 4
_SALT = 32
_IV   = 16
_MAC  = 32
_KEY  = 32
_CHK  = 32

_PBKDF2_ITER = 100000
_ENC_INFO  = b'DefusePHP|V2|KeyForEncryption'
_AUTH_INFO = b'DefusePHP|V2|KeyForAuthentication'


def _check_ascii(version: bytes, hex_str: str) -> bytes:
    """Decode a defuse checksummed ASCII-safe hex string, verify header + SHA-256 checksum."""
    data = bytes.fromhex(hex_str)
    if len(data) < _HDR + _CHK:
        raise ValueError("Defuse encoded data too short")
    if data[:_HDR] != version:
        raise ValueError(f"Defuse header mismatch: expected {version.hex()}, got {data[:_HDR].hex()}")
    body, chk = data[:-_CHK], data[-_CHK:]
    if not _hmac.compare_digest(chk, hashlib.sha256(body).digest()):
        raise ValueError("Defuse checksum mismatch — data may be corrupted")
    return data[_HDR:-_CHK]


def _hkdf(ikm: bytes, length: int, info: bytes, salt: bytes) -> bytes:
    """HKDF-Extract + HKDF-Expand (RFC 5869, SHA-256)."""
    prk = _hmac.new(salt, ikm, hashlib.sha256).digest()
    T, okm = b'', b''
    for i in range(1, -(-length // 32) + 1):
        T = _hmac.new(prk, T + info + bytes([i]), hashlib.sha256).digest()
        okm += T
    return okm[:length]


def _aes_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    d = cipher.decryptor()
    return d.update(data) + d.finalize()


def _defuse_decrypt_binary(ct: bytes, akey: bytes, ekey: bytes) -> bytes:
    """Core defuse V2 decrypt given already-derived auth and encryption keys."""
    if len(ct) < _HDR + _SALT + _IV + _MAC or ct[:_HDR] != _V2_HEADER:
        raise ValueError("Invalid defuse V2 ciphertext")
    iv  = ct[_HDR + _SALT : _HDR + _SALT + _IV]
    mac = ct[-_MAC:]
    enc = ct[_HDR + _SALT + _IV : -_MAC]
    expected = _hmac.new(akey, ct[:-_MAC], hashlib.sha256).digest()
    if not _hmac.compare_digest(mac, expected):
        raise ValueError("Defuse HMAC verification failed — wrong key or tampered data")
    return _aes_ctr(enc, ekey, iv)


def _keys_from_raw(raw_key: bytes, salt: bytes):
    return (
        _hkdf(raw_key, _KEY, _AUTH_INFO, salt),
        _hkdf(raw_key, _KEY, _ENC_INFO,  salt),
    )


def _keys_from_password_prehash(prehash: bytes, salt: bytes):
    """
    PHP double-prehash chain:
      sha256(sha256(user_key)) → PBKDF2 → prekey → HKDF → akey/ekey
    The caller passes sha256(user_key) as prehash; we sha256 again inside,
    mirroring KeyOrPassword::deriveKeys() which calls hash(sha256, $this->secret)
    on the already-hashed password that createRandomPasswordProtectedKey() passed in.
    """
    prekey = hashlib.pbkdf2_hmac('sha256', hashlib.sha256(prehash).digest(),
                                 salt, _PBKDF2_ITER, _KEY)
    return (
        _hkdf(prekey, _KEY, _AUTH_INFO, salt),
        _hkdf(prekey, _KEY, _ENC_INFO,  salt),
    )


def unlock_mkey(mkey_hex: str, user_key: str) -> bytes:
    """
    Unlock a KeyProtectedByPassword (User.mKey) with the derived user key.

    user_key = (password + login + passwordSalt).strip()

    Returns the raw 32-byte inner encryption key.
    """
    encrypted_key_raw = _check_ascii(_PKEY_HEADER, mkey_hex)
    salt = encrypted_key_raw[_HDR : _HDR + _SALT]
    # PHP passes hash('sha256', $password, true) to encryptWithPassword,
    # so our password_bytes = sha256(user_key)
    password_bytes = hashlib.sha256(user_key.encode()).digest()
    akey, ekey = _keys_from_password_prehash(password_bytes, salt)
    inner_key_encoded = _defuse_decrypt_binary(encrypted_key_raw, akey, ekey).decode('ascii')
    raw_key = _check_ascii(_KEY_HEADER, inner_key_encoded)
    if len(raw_key) != _KEY:
        raise ValueError(f"Inner key bad length: {len(raw_key)}")
    return raw_key


def decrypt_mpass(mpass_hex: str, mkey_hex: str, user_key: str) -> str:
    """
    Decrypt User.mPass to recover the plaintext master password.

    mpass_hex : hex-encoded defuse V2 ciphertext (User.mPass decoded from varbinary)
    mkey_hex  : hex-encoded KeyProtectedByPassword (User.mKey decoded from varbinary)
    user_key  : (loginPass + loginUser + passwordSalt).strip()
    """
    raw_key = unlock_mkey(mkey_hex, user_key)
    ct = bytes.fromhex(mpass_hex)
    salt = ct[_HDR : _HDR + _SALT]
    akey, ekey = _keys_from_raw(raw_key, salt)
    return _defuse_decrypt_binary(ct, akey, ekey).decode('utf-8')


def _v2_encrypt_raw(plaintext: bytes, akey: bytes, ekey: bytes, salt: bytes, iv: bytes) -> bytes:
    ciphertext = _aes_ctr(plaintext, ekey, iv)
    blob = _V2_HEADER + salt + iv + ciphertext
    mac = _hmac.new(akey, blob, hashlib.sha256).digest()
    return blob + mac


def _wrap_checksum(header: bytes, body: bytes) -> str:
    full = header + body
    return (full + hashlib.sha256(full).digest()).hex()


def encrypt_account_pass(plaintext: str, master_pass: str) -> tuple:
    """
    Encrypt account password PHP-sysPass style.
    Returns (pass_hex, key_hex) to store in Account.pass and Account.key columns.
    """
    return encrypt_with_password(plaintext, master_pass)


def encrypt_with_password(plaintext: str, password: str) -> tuple[str, str]:
    """Encrypt text using PHP Defuse's password-protected-key wire format."""
    raw_key = os.urandom(_KEY)
    key_encoded_hex = _wrap_checksum(_KEY_HEADER, raw_key)

    prehash = hashlib.sha256(password.encode()).digest()
    pkey_salt = os.urandom(_SALT)
    pkey_iv = os.urandom(_IV)
    pkey_akey, pkey_ekey = _keys_from_password_prehash(prehash, pkey_salt)
    inner_ct = _v2_encrypt_raw(key_encoded_hex.encode('ascii'), pkey_akey, pkey_ekey, pkey_salt, pkey_iv)
    key_hex = _wrap_checksum(_PKEY_HEADER, inner_ct)

    pass_salt = os.urandom(_SALT)
    pass_iv = os.urandom(_IV)
    pass_akey, pass_ekey = _keys_from_raw(raw_key, pass_salt)
    pass_binary = _v2_encrypt_raw(plaintext.encode('utf-8'), pass_akey, pass_ekey, pass_salt, pass_iv)
    return pass_binary.hex(), key_hex


def encrypt_user_master_pass(master_pass: str, user_key: str) -> tuple[str, str]:
    """
    Encrypt User.mPass and User.mKey PHP-sysPass style.
    Returns (m_pass_hex, m_key_hex) for the User.mPass and User.mKey columns.
    """
    raw_key = os.urandom(_KEY)
    key_encoded_hex = _wrap_checksum(_KEY_HEADER, raw_key)

    prehash = hashlib.sha256(user_key.encode()).digest()
    pkey_salt = os.urandom(_SALT)
    pkey_iv = os.urandom(_IV)
    pkey_akey, pkey_ekey = _keys_from_password_prehash(prehash, pkey_salt)
    inner_ct = _v2_encrypt_raw(key_encoded_hex.encode('ascii'), pkey_akey, pkey_ekey, pkey_salt, pkey_iv)
    m_key_hex = _wrap_checksum(_PKEY_HEADER, inner_ct)

    mpass_salt = os.urandom(_SALT)
    mpass_iv = os.urandom(_IV)
    mpass_akey, mpass_ekey = _keys_from_raw(raw_key, mpass_salt)
    mpass_binary = _v2_encrypt_raw(master_pass.encode('utf-8'), mpass_akey, mpass_ekey, mpass_salt, mpass_iv)
    return mpass_binary.hex(), m_key_hex


def decrypt_account_pass(pass_hex: str, key_hex: str, master_pass: str) -> str:
    """
    Decrypt an account password stored by PHP sysPass.

    pass_hex    : hex of Account.pass column (defuse V2 ciphertext)
    key_hex     : hex of Account.key column (defuse KeyProtectedByPassword)
    master_pass : plaintext master password (decrypted from User.mPass at login)

    Account keys are locked directly by the master password, using the same
    two-sha256 chain as User.mKey (sha256(master_pass) → sha256 again inside
    _keys_from_password_prehash → PBKDF2).
    """
    return decrypt_with_password(pass_hex, key_hex, master_pass)


def decrypt_with_password(ciphertext_hex: str, key_hex: str, password: str) -> str:
    """Decrypt text using PHP Defuse's password-protected-key wire format."""
    encrypted_key_raw = _check_ascii(_PKEY_HEADER, key_hex)
    salt = encrypted_key_raw[_HDR : _HDR + _SALT]
    prehash = hashlib.sha256(password.encode()).digest()
    akey, ekey = _keys_from_password_prehash(prehash, salt)
    inner_key_encoded = _defuse_decrypt_binary(encrypted_key_raw, akey, ekey).decode('ascii')
    raw_key = _check_ascii(_KEY_HEADER, inner_key_encoded)
    if len(raw_key) != _KEY:
        raise ValueError(f"Account inner key bad length: {len(raw_key)}")
    ct = bytes.fromhex(ciphertext_hex)
    ct_salt = ct[_HDR : _HDR + _SALT]
    akey2, ekey2 = _keys_from_raw(raw_key, ct_salt)
    return _defuse_decrypt_binary(ct, akey2, ekey2).decode('utf-8')
