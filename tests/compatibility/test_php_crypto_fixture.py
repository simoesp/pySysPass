import base64
import json
from pathlib import Path

from app.core.defuse_compat import decrypt_account_pass, decrypt_mpass
from app.services.auth_service import verify_master_password_hash, verify_password
from app.services.user_profile_service import _parse_php_serialized_profile


FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "php_syspass_3211_crypto.json"


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_php_authored_password_hashes_verify():
    fixture = _fixture()
    known = fixture["known_values"]

    assert verify_password(known["login_password"], fixture["user"]["pass"])
    assert verify_master_password_hash(
        known["master_password"], fixture["config"]["masterPwd"]
    )


def test_php_authored_user_master_key_decrypts():
    fixture = _fixture()
    known = fixture["known_values"]
    user = fixture["user"]
    user_key = (
        known["login_password"] + user["login"] + known["password_salt"]
    ).strip()

    assert decrypt_mpass(user["mPass"], user["mKey"], user_key) == known["master_password"]


def test_php_authored_account_password_decrypts():
    fixture = _fixture()
    known = fixture["known_values"]
    account = fixture["account"]

    assert account["pass"].startswith("def50200")
    assert account["key"].startswith("def10000")
    assert (
        decrypt_account_pass(account["pass"], account["key"], known["master_password"])
        == known["account_password"]
    )


def test_php_authored_profile_parses_all_permission_flags():
    fixture = _fixture()
    raw_profile = base64.b64decode(fixture["profile"]["profile_base64"])

    assert len(raw_profile) == 815
    permissions = _parse_php_serialized_profile(raw_profile)
    assert permissions is not None
    assert len(permissions) == 30
    assert set(permissions.values()) == {False}
