"""PHP-authored Authenticator plugin data is read natively (R5 / #56)."""
import json
from pathlib import Path

import pyotp
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import auth
from app.core.php_authenticator import decrypt_state, serialize_state
from app.core.defuse_compat import decrypt_with_password
from app.db.base import get_db
from app.models.account import Config, Plugin, PluginData
from app.services.auth_service import hash_master_key, store_user_master_pass
from app.services.two_factor_service import TwoFactorConfig, TwoFactorStore

FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures" / "php_authenticator_plugindata.json").read_text())
MASTER = FIXTURE["master_password"]
ROW = FIXTURE["plugin_data"]
EXPECTED = FIXTURE["expected"]


def test_php_authored_state_decodes():
    state = decrypt_state(ROW["data"].encode(), ROW["key"].encode(), MASTER)
    assert (state.user_id, state.iv, state.enabled, state.expire_days, state.date) == (
        EXPECTED["userId"], EXPECTED["IV"], EXPECTED["twofaEnabled"], EXPECTED["expireDays"], EXPECTED["date"])
    assert state.recovery_codes == EXPECTED["recoveryCodes"]
    assert state.last_recovery_time == EXPECTED["lastRecoveryTime"]


def test_serializer_reproduces_php_bytes():
    php_plaintext = decrypt_with_password(ROW["data"], ROW["key"], MASTER).encode()
    state = decrypt_state(ROW["data"].encode(), ROW["key"].encode(), MASTER)
    assert serialize_state(state) == php_plaintext


def test_login_honours_php_enrolled_2fa(db_session, test_user, encryption_service):
    store_user_master_pass(test_user, "testpassword", MASTER)
    db_session.add(Config(parameter="masterPwd", value=hash_master_key(MASTER)))
    db_session.add(Plugin(name="Authenticator", enabled=True, available=True, versionLevel="310.19012201"))
    db_session.add(PluginData(name="Authenticator", itemId=test_user.id,
                              data=ROW["data"].encode(), key=ROW["key"].encode()))
    db_session.commit()
    assert TwoFactorConfig(db_session).get_mode() == "enabled"
    assert test_user.twoFactorAuth is True

    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    login = lambda **extra: client.post(  # noqa: E731
        "/api/v1/auth/login", data={"username": test_user.username, "password": "testpassword", **extra})

    assert login().json()["detail"]["code"] == "TWO_FACTOR_REQUIRED"
    assert login(otp="000000").status_code == 401
    assert login(otp=pyotp.TOTP(EXPECTED["IV"]).now()).status_code == 200
    # A PHP recovery code works once and is removed from the PHP-format row.
    assert login(otp=EXPECTED["recoveryCodes"][0]).status_code == 200
    assert login(otp=EXPECTED["recoveryCodes"][0]).status_code == 401
    store = TwoFactorStore(db_session, encryption_service, master_pass=MASTER)
    assert store.get_backup_codes(test_user.id) == EXPECTED["recoveryCodes"][1:]
    row = db_session.query(PluginData).filter_by(name="Authenticator", itemId=test_user.id).one()
    assert row.key.startswith(b"def10000")  # still PHP format after the update
