import pyotp
import base64
import secrets
from typing import Tuple, Optional

class TwoFactorService:
    """TOTP-based two-factor authentication service"""
    
    @staticmethod
    def generate_secret() -> str:
        """Generate a new base32 secret for TOTP"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_provisioning_uri(secret: str, username: str, issuer: str = "sysPass") -> str:
        """Generate a QR code provisioning URI for Google Authenticator, etc."""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)
    
    @staticmethod
    def verify_token(secret: str, token: str, window: int = 1) -> bool:
        """Verify a TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    
    @staticmethod
    def generate_backup_codes(count: int = 8) -> list:
        """Generate backup codes for 2FA recovery"""
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice('0123456789') for _ in range(10))
            codes.append(code)
        return codes
    
    @staticmethod
    def verify_backup_code(codes: list, code: str) -> Tuple[bool, Optional[str]]:
        """Verify a backup code and return remaining codes"""
        if code in codes:
            codes.remove(code)
            return True, codes
        return False, None
