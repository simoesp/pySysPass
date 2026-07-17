import pytest
from app.services.two_factor_service import TwoFactorService

def test_generate_secret():
    """Test secret generation"""
    secret = TwoFactorService.generate_secret()
    assert len(secret) >= 16  # Base32 encoded
    assert isinstance(secret, str)

def test_generate_provisioning_uri():
    """Test provisioning URI generation"""
    secret = TwoFactorService.generate_secret()
    uri = TwoFactorService.generate_provisioning_uri(secret, "test@example.com", "sysPass")

    assert "otpauth://totp" in uri
    assert "test%40example.com" in uri or "test@example.com" in uri  # URL-encoded or not
    assert "sysPass" in uri

def test_verify_token():
    """Test TOTP token verification"""
    secret = TwoFactorService.generate_secret()
    totp = __import__('pyotp').TOTP(secret)

    # Generate a valid token
    token = totp.now()
    assert TwoFactorService.verify_token(secret, token)

    # Invalid token should fail
    assert not TwoFactorService.verify_token(secret, "000000")

def test_generate_backup_codes():
    """Test backup code generation"""
    codes = TwoFactorService.generate_backup_codes(8)

    assert len(codes) == 8
    for code in codes:
        assert len(code) == 10
        assert code.isdigit()

def test_verify_backup_code():
    """Test backup code verification"""
    codes = TwoFactorService.generate_backup_codes(8)
    valid_code = codes[0]

    # Verify valid code
    success, remaining = TwoFactorService.verify_backup_code(codes.copy(), valid_code)
    assert success
    assert len(remaining) == 7

    # Verify invalid code
    success, remaining = TwoFactorService.verify_backup_code(codes, "invalid123")
    assert not success
