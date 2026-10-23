"""R8 / #58: offline master password change with PHP semantics."""
import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import auth
from app.core.defuse_compat import decrypt_account_pass, encrypt_account_pass
from app.db.base import get_db
from app.models.account import Account, AccountHistory, Config, User
from app.models.custom_field import CustomFieldDef, CustomFieldType, CustomFieldValue
from app.services.auth_service import (
    hash_master_key, issue_session_token, store_user_master_pass, verify_master_password_hash,
)
from app.services.master_password_rotation import MasterPasswordRotation, RotationError
from tests.account_refs import TEST_CATEGORY_ID, TEST_CLIENT_ID

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "php_syspass_3211_crypto.json").read_text())
PHP_MASTER = FIXTURE["known_values"]["master_password"]
NEW_MASTER = "Rotated-Master-秘密-2026"


@pytest.fixture
def php_vault(db_session, test_user, tmp_path, monkeypatch):
    """PHP-authored masterPwd and account ciphertext, plus history and a custom field."""
    monkeypatch.setattr(
        "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
    )
    db_session.add_all([
        Config(parameter="masterPwd", value=FIXTURE["config"]["masterPwd"]),
        Config(parameter="maintenance", value="true"),
    ])
    php = FIXTURE["account"]
    account = Account(
        id=50, name="PHP account", userId=test_user.id, userEditId=test_user.id, userGroupId=1,
        clientId=TEST_CLIENT_ID, categoryId=TEST_CATEGORY_ID,
        pass_=php["pass"].encode(), key=php["key"].encode(),
    )
    db_session.add(account)
    db_session.flush()
    old_pass, old_key = encrypt_account_pass("history-secret", PHP_MASTER)
    db_session.add_all([
        AccountHistory(accountId=50, userGroupId=1, userId=test_user.id, userEditId=test_user.id,
                       clientId=TEST_CLIENT_ID, categoryId=TEST_CATEGORY_ID, name="h", notes="",
                       pass_=old_pass.encode(), key=old_key.encode(),
                       mPassHash=FIXTURE["config"]["masterPwd"].encode()),
        # Snapshot under an older master: PHP leaves it untouched.
        AccountHistory(accountId=50, userGroupId=1, userId=test_user.id, userEditId=test_user.id,
                       clientId=TEST_CLIENT_ID, categoryId=TEST_CATEGORY_ID, name="old", notes="",
                       pass_=b"older", key=b"older", mPassHash=b"$2y$10$older-master-hash"),
    ])
    db_session.add(CustomFieldType(id=1, name="password", text="Password"))
    db_session.flush()
    definition = CustomFieldDef(name="PIN", moduleId=1, typeId=1, isEncrypted=True)
    db_session.add(definition)
    db_session.flush()
    data_hex, key_hex = encrypt_account_pass("4321", PHP_MASTER)
    db_session.add(CustomFieldValue(moduleId=1, itemId=50, definitionId=definition.id,
                                    data=data_hex.encode(), key=key_hex.encode()))
    db_session.commit()
    return account


def _decrypt(data, key, master):
    return decrypt_account_pass(data.decode(), key.decode(), master)


def test_rotation_rewrites_every_master_encrypted_value(db_session, php_vault):
    plan = MasterPasswordRotation(db_session).rotate(PHP_MASTER, NEW_MASTER, now=1_900_000_000)
    assert (plan.accounts, plan.history, plan.history_skipped, plan.custom_fields) == (1, 1, 1, 1)

    account = db_session.get(Account, 50)
    assert _decrypt(account.pass_, account.key, NEW_MASTER) == FIXTURE["known_values"]["account_password"]
    with pytest.raises(Exception):
        _decrypt(account.pass_, account.key, PHP_MASTER)
    rotated, untouched = sorted(db_session.query(AccountHistory).all(), key=lambda h: h.name)
    assert _decrypt(rotated.pass_, rotated.key, NEW_MASTER) == "history-secret"
    assert untouched.pass_ == b"older" and untouched.mPassHash == b"$2y$10$older-master-hash"
    field = db_session.query(CustomFieldValue).one()
    assert _decrypt(field.data, field.key, NEW_MASTER) == "4321"

    master_hash = db_session.query(Config).filter_by(parameter="masterPwd").one().value
    assert verify_master_password_hash(NEW_MASTER, master_hash)
    assert rotated.mPassHash == master_hash.encode()
    assert db_session.query(Config).filter_by(parameter="lastupdatempass").one().value == "1900000000"


@pytest.mark.parametrize("current,new,message", [
    ("wrong-master", NEW_MASTER, "does not match"),
    (PHP_MASTER, PHP_MASTER, "same"),
    (PHP_MASTER, "", "required"),
])
def test_rotation_preconditions(db_session, php_vault, current, new, message):
    with pytest.raises(RotationError, match=message):
        MasterPasswordRotation(db_session).rotate(current, new)
    assert db_session.get(Account, 50).pass_.decode() == FIXTURE["account"]["pass"]


def test_rotation_requires_maintenance_mode(db_session, php_vault):
    db_session.query(Config).filter_by(parameter="maintenance").update({"value": "false"})
    db_session.commit()
    with pytest.raises(RotationError, match="maintenance"):
        MasterPasswordRotation(db_session).rotate(PHP_MASTER, NEW_MASTER)


def test_any_undecryptable_value_aborts_without_writes(db_session, php_vault):
    other_pass, other_key = encrypt_account_pass("x", "some-other-master")
    db_session.add(Account(id=51, name="foreign", userId=2, userEditId=2, userGroupId=1,
                           clientId=TEST_CLIENT_ID, categoryId=TEST_CATEGORY_ID,
                           pass_=other_pass.encode(), key=other_key.encode()))
    db_session.commit()
    with pytest.raises(RotationError, match="Account 51"):
        MasterPasswordRotation(db_session).rotate(PHP_MASTER, NEW_MASTER)
    db_session.expire_all()
    assert db_session.get(Account, 50).pass_.decode() == FIXTURE["account"]["pass"]
    assert db_session.query(Config).filter_by(parameter="masterPwd").one().value == FIXTURE["config"]["masterPwd"]


def test_legacy_rows_need_explicit_conversion(db_session, php_vault, encryption_service):
    db_session.add(Account(id=52, name="legacy", userId=2, userEditId=2, userGroupId=1,
                           clientId=TEST_CLIENT_ID, categoryId=TEST_CATEGORY_ID,
                           pass_=encryption_service.encrypt("old-format").encode(), key=b""))
    db_session.commit()
    rotation = MasterPasswordRotation(db_session, legacy_decrypt=encryption_service.decrypt)
    with pytest.raises(RotationError, match="legacy"):
        rotation.rotate(PHP_MASTER, NEW_MASTER)
    rotation.rotate(PHP_MASTER, NEW_MASTER, include_legacy=True)
    legacy = db_session.get(Account, 52)
    assert legacy.key.startswith(b"def10000")
    assert _decrypt(legacy.pass_, legacy.key, NEW_MASTER) == "old-format"


def test_failure_during_write_rolls_back(db_session, php_vault, monkeypatch):
    from app.services import master_password_rotation as module

    monkeypatch.setattr(module, "hash_master_key", lambda _: (_ for _ in ()).throw(RuntimeError("disk full")))
    with pytest.raises(RuntimeError):
        MasterPasswordRotation(db_session).rotate(PHP_MASTER, NEW_MASTER)
    db_session.expire_all()
    assert db_session.get(Account, 50).pass_.decode() == FIXTURE["account"]["pass"]


def test_login_requires_master_after_change_like_php(db_session, php_vault, test_user):
    """PHP MPASS_CHANGED: a per-user copy older than lastupdatempass is unusable."""
    store_user_master_pass(test_user, "testpassword", PHP_MASTER)
    test_user.lastUpdateMPass = 1_000
    db_session.commit()
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    db_session.query(Config).filter_by(parameter="maintenance").update({"value": "false"})
    db_session.commit()

    login = lambda **extra: client.post(  # noqa: E731
        "/api/v1/auth/login", data={"username": "testuser", "password": "testpassword", **extra})
    assert login().status_code == 200

    db_session.query(Config).filter_by(parameter="maintenance").update({"value": "true"})
    db_session.commit()
    MasterPasswordRotation(db_session).rotate(PHP_MASTER, NEW_MASTER)
    db_session.query(Config).filter_by(parameter="maintenance").update({"value": "false"})
    db_session.commit()

    response = login()
    assert response.status_code == 428
    assert response.json()["detail"]["code"] == "MASTER_PASSWORD_REQUIRED"
    assert login(mpass=PHP_MASTER).status_code == 401  # old master no longer matches
    assert login(mpass=NEW_MASTER).status_code == 200
    assert login().status_code == 200  # the user's copy was refreshed
    assert db_session.get(User, test_user.id).lastUpdateMPass > 1_000


def test_php_hash_key_parity_for_long_keys():
    long_key = "ü" * 80  # > 72 characters: PHP pre-hashes with SHA-256
    assert verify_master_password_hash(long_key, hash_master_key(long_key))
    assert not verify_master_password_hash("ü" * 81, hash_master_key(long_key))
    assert verify_master_password_hash(PHP_MASTER, FIXTURE["config"]["masterPwd"])


def test_cli_rotates_and_ends_sessions(db_session, php_vault, test_user, monkeypatch, isolated_session_store):
    from app import rotate_master_password as cli
    from app.services.session_service import session_store

    monkeypatch.setattr(cli.settings, "DATABASE_URL", "sqlite://")
    monkeypatch.setattr("app.db.base.SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)
    monkeypatch.setattr(cli.BackupService, "create_full_backup",
                        lambda self, url, include_files=True: {"filename": "pre.zip", "db_included": True})
    monkeypatch.setenv("PYSYSPASS_CURRENT_MASTER_PASSWORD", PHP_MASTER)
    monkeypatch.setenv("PYSYSPASS_NEW_MASTER_PASSWORD", NEW_MASTER)
    token = issue_session_token(test_user, master_pass=PHP_MASTER)
    from app.services.auth_service import decode_token
    payload = decode_token(token)

    with pytest.raises(SystemExit):
        cli.main([])  # --confirm-stopped is mandatory
    assert cli.main(["--confirm-stopped", "--dry-run"]) == 0
    assert db_session.get(Account, 50).pass_.decode() == FIXTURE["account"]["pass"]
    assert cli.main(["--confirm-stopped"]) == 0
    assert session_store.is_revoked(payload)
    account = db_session.get(Account, 50)
    assert _decrypt(account.pass_, account.key, NEW_MASTER) == FIXTURE["known_values"]["account_password"]
