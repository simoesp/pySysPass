from app.core.config import Settings, validate_production_settings
import os

# Set all required env vars for production validation
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "a" * 64
os.environ["ENCRYPTION_KEY"] = "b" * 64
os.environ["SYSPASS_PASSWORD_SALT"] = "salt-value"
os.environ["SERVICE_VAULT_KEY"] = "vault-key"

# Test 1: Settings with AUDIT_HMAC_KEY set should pass validation
try:
    validate_production_settings(Settings(AUDIT_HMAC_KEY="a"*64))
    print('Test 1 PASS: validate_production_settings passed with AUDIT_HMAC_KEY set')
except RuntimeError as e:
    print(f'Test 1 FAIL: validate_production_settings raised RuntimeError: {e}')

# Test 2: validate_production_settings should reject when AUDIT_HMAC_KEY is None
try:
    validate_production_settings(Settings())
    print('Test 2 FAIL: validate_production_settings should have raised RuntimeError')
except RuntimeError as e:
    err_msg = str(e)
    if 'AUDIT_HMAC_KEY must be configured' in err_msg:
        print('Test 2 PASS: validate_production_settings correctly requires AUDIT_HMAC_KEY')
    else:
        print(f'Test 2: RuntimeError raised but AUDIT_HMAC_KEY check not in message: {err_msg}')

# Test 3: Settings without AUDIT_HMAC_KEY can still be created (optional field)
try:
    s = Settings()
    print(f'Test 3 PASS: Settings created without AUDIT_HMAC_KEY. AUDIT_HMAC_KEY = {s.AUDIT_HMAC_KEY}')
except Exception as e:
    print(f'Test 3 FAIL: {e}')

# Test 4: Settings with AUDIT_HMAC_KEY
try:
    s = Settings(AUDIT_HMAC_KEY="my-audit-hmac-key")
    print(f'Test 4 PASS: Settings with AUDIT_HMAC_KEY = {s.AUDIT_HMAC_KEY}')
except Exception as e:
    print(f'Test 4 FAIL: {e}')