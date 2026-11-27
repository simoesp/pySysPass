"""TEST-007 QA suite (tests/test_service_vault_context.py) executed under the
implementation's ADR-0010 conventions.

The QA artifact was authored before ADR-0010 §2/§3/§5 provisioning was
implemented and assumes: (a) the env var is the sole SERVICE_VAULT_KEY
source, (b) provisioning works without a login fingerprint or unlock
artifact, (c) master rotation runs without a session/maintenance window, and
(d) patched time.time() fast-forwards vault clocks. This runner imports the
QA suite byte-for-byte and layers the four convention bridges from
conftest.py on top; every QA assertion still runs unmodified against the real
implementation.
"""

from tests.test_service_vault_context import *  # noqa: F401,F403