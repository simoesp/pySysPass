from app.core.config import Settings, validate_production_settings

# Test 1: Empty salt, no PHP config - should fail with SYSPASS_PASSWORD_SALT error
print('Test 1: Empty salt, production mode (also set SECRET_KEY/ENCRYPTION_KEY)')
try:
    config = Settings(_env_file=None, DEBUG=False, DATABASE_URL='sqlite://',
                      SECRET_KEY='a' * 64, ENCRYPTION_KEY='b' * 64)
    validate_production_settings(config)
    print('  FAIL: No exception raised')
except RuntimeError as e:
    msg = str(e)
    if 'SYSPASS_PASSWORD_SALT must be non-empty in production' in msg:
        print(f'  PASS: RuntimeError raised for empty SYSPASS_PASSWORD_SALT: {msg}')
    else:
        print(f'  PARTIAL: RuntimeError raised but different message: {msg}')

# Test 2: Salt set via setting, should pass  
print('Test 2: Salt set via setting, production mode')
try:
    config = Settings(_env_file=None, DEBUG=False, DATABASE_URL='sqlite://',
                      SECRET_KEY='a' * 64, ENCRYPTION_KEY='b' * 64,
                      SYSPASS_PASSWORD_SALT='salt-value')
    validate_production_settings(config)
    print('  PASS: No exception raised')
except RuntimeError as e:
    print(f'  FAIL: RuntimeError raised: {e}')

# Test 3: DEBUG mode with empty salt - should pass (DEBUG bypasses validation)
print('Test 3: DEBUG mode with empty salt')
try:
    config = Settings(_env_file=None, DEBUG=True, DATABASE_URL='sqlite://',
                      SECRET_KEY='a' * 64, ENCRYPTION_KEY='b' * 64)
    validate_production_settings(config)
    print('  PASS: No exception raised (DEBUG bypasses validation)')
except RuntimeError as e:
    print(f'  FAIL: RuntimeError raised: {e}')

# Test 4: Empty salt via .env file (simulating not resolvable from PHP config)
print('Test 4: Empty salt via .env, production mode')
import tempfile, os
from pathlib import Path
with tempfile.TemporaryDirectory() as tmp:
    env_path = Path(tmp) / '.env'
    env_path.write_text('DEBUG=false\\nDATABASE_URL=sqlite://\\nSECRET_KEY=' + 'a' * 64 +
                        '\\nENCRYPTION_KEY=' + 'b' * 64 + '\\n')
    config = Settings(_env_file=env_path, DEBUG=False, DATABASE_URL='sqlite://')
    try:
        validate_production_settings(config)
        print('  FAIL: No exception raised')
    except RuntimeError as e:
        msg = str(e)
        if 'SYSPASS_PASSWORD_SALT must be non-empty in production' in msg:
            print(f'  PASS: RuntimeError raised for empty SYSPASS_PASSWORD_SALT from .env: {msg}')
        else:
            print(f'  PARTIAL: RuntimeError raised but different message: {msg}')