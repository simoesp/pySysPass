from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import hashlib

class EncryptionService:
    def __init__(self, master_key: str):
        self.master_key = master_key.encode() if isinstance(master_key, str) else master_key

    def _derive_key(self, salt: bytes, iterations: int = 100000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(self.master_key)

    def encrypt(self, plaintext: str) -> str:
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self._derive_key(salt)

        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

        data = salt + iv + ciphertext
        return base64.b64encode(data).decode()

    def decrypt(self, encrypted_data: str) -> str:
        data = base64.b64decode(encrypted_data)
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]
        key = self._derive_key(salt)

        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

def get_encryption_service():
    from app.core.config import settings
    return EncryptionService(settings.ENCRYPTION_KEY)
