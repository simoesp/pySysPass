from app.core.config import settings
from app.services.audit_service import _AUDIT_HMAC_KEY

print(f'_AUDIT_HMAC_KEY = {_AUDIT_HMAC_KEY!r}')
print(f'settings.AUDIT_HMAC_KEY = {settings.AUDIT_HMAC_KEY!r}')