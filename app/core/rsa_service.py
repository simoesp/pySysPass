from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import os

RSA_PREFIX = 'RSA:'

_private_key = None
_public_key_pem: str | None = None

_KEY_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'rsa_private.pem')


def _load_or_generate():
    global _private_key, _public_key_pem

    key_path = os.path.normpath(_KEY_FILE)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            _private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        _private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, 'wb') as f:
            f.write(_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    _public_key_pem = _private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def get_public_key_pem() -> str:
    if _public_key_pem is None:
        _load_or_generate()
    return _public_key_pem


def decrypt_rsa(ciphertext_b64: str) -> str:
    if _private_key is None:
        _load_or_generate()
    raw = base64.b64decode(ciphertext_b64)
    return _private_key.decrypt(
        raw,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    ).decode()


def maybe_decrypt(value: str) -> str:
    """Transparently decrypt RSA-prefixed values; return others unchanged."""
    if value and value.startswith(RSA_PREFIX):
        return decrypt_rsa(value[len(RSA_PREFIX):])
    return value
