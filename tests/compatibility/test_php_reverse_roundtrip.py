"""Python → PHP round trip (R5 / #56): sysPass PHP must read what pySysPass writes.

Every write path that stores credentials (account API create/update/copy,
CSV/KeePass/XML imports, public links) runs here against SQLite, and the stored
bytes are decoded by the upstream PHP classes via
``scripts/verify-python-writes.php``. Skipped unless ``PYSYSPASS_PHP_VERIFY_CMD``
is a command that runs that script with pinned sysPass/Defuse checkouts, e.g.::

    PYSYSPASS_PHP_VERIFY_CMD="php scripts/verify-python-writes.php ../sysPass ../php-encryption"
"""
import base64
import json
import os
import shlex
import subprocess

import pytest

from app.core.config import settings
from app.models.account import Account, Config
from app.schemas.account import AccountUpdate
from app.services.account_service import AccountService
from app.services.import_export_service import CsvImportService, KeePassImportService, XmlImportService
from app.services.public_link_service import PublicLinkService
from tests.account_refs import TEST_MASTER_PASSWORD, account_create

PHP_VERIFY_CMD = os.environ.get("PYSYSPASS_PHP_VERIFY_CMD")
SALT = "reverse-roundtrip-salt-not-a-secret"

pytestmark = pytest.mark.skipif(
    not PHP_VERIFY_CMD, reason="PYSYSPASS_PHP_VERIFY_CMD not set (upstream sysPass PHP runtime required)"
)


def _php(cases: dict) -> dict:
    result = subprocess.run(  # nosec B603 -- operator-supplied test command
        shlex.split(PHP_VERIFY_CMD), input=json.dumps(cases).encode(), capture_output=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode()
    return json.loads(result.stdout)


def _ciphertext(account: Account) -> dict:
    return {"pass": account.pass_.decode("ascii"), "key": account.key.decode("ascii")}


def test_php_reads_every_python_credential_write(db_session, encryption_service, test_user, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
    )
    monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", SALT)
    monkeypatch.setattr("app.core.syspass_runtime_config.load_syspass_runtime_config", lambda: {"passwordSalt": SALT})
    db_session.add(Config(parameter="publinks_enabled", value="true"))
    db_session.commit()
    service = AccountService(db_session, encryption_service)
    expected = []

    created = service.create_account(
        account_create(title="API create", password="Créé-秘密-1", login="api", url="https://a.example",
                       notes="multi\nline"), test_user.id, master_pass=TEST_MASTER_PASSWORD,
    )
    expected.append(("api create", created.id, "Créé-秘密-1"))
    updated = service.create_account(
        account_create(title="API update", password="before"), test_user.id, master_pass=TEST_MASTER_PASSWORD,
    )
    service.update_account(updated.id, AccountUpdate(password="after-🔑"), test_user.id,
                           master_pass=TEST_MASTER_PASSWORD)
    expected.append(("api update", updated.id, "after-🔑"))
    copied = service.copy_account(created.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)
    expected.append(("copy", copied["id"], "Créé-秘密-1"))
    empty = service.create_account(
        account_create(title="Empty", password=" "), test_user.id, master_pass=TEST_MASTER_PASSWORD,
    )
    expected.append(("whitespace", empty.id, " "))

    csv = CsvImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
    csv.import_accounts(csv.parse_csv("name,client,category,password\ncsv row,Acme,Ops,csv-pässword\n"))
    keepass = KeePassImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
    keepass.import_accounts(keepass.parse_keepass(
        '<KeePassFile><Root><Group><Name>Root</Name><Entry>'
        '<String><Key>Title</Key><Value>kdb row</Value></String>'
        '<String><Key>Password</Key><Value>kdb-密码</Value></String>'
        '</Entry></Group></Root></KeePassFile>'
    ))
    xml = XmlImportService(db_session, encryption_service, test_user.id, current_master_password=TEST_MASTER_PASSWORD)
    xml.import_accounts([{"name": "xml row", "pass": "xml-plain", "client": "Acme", "category": "Ops"}])
    for name, password in (("csv row", "csv-pässword"), ("kdb row", "kdb-密码"), ("xml row", "xml-plain")):
        expected.append((name, db_session.query(Account).filter_by(name=name).one().id, password))

    link = PublicLinkService(db_session).create_public_link(created.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)

    accounts = [_ciphertext(db_session.get(Account, account_id)) for _, account_id, _ in expected]
    result = _php({
        "password_salt": SALT,
        "master_password": TEST_MASTER_PASSWORD,
        "accounts": accounts,
        "links": [{"hash": link.hash.decode("ascii"), "data_base64": base64.b64encode(link.data).decode()}],
    })

    assert result["accounts"] == [password for _, _, password in expected]
    (php_link,) = result["links"]
    assert php_link == {
        "id": created.id, "name": "API create", "login": "api", "url": "https://a.example",
        "notes": "multi\nline", "pass": "Créé-秘密-1", "key": None,
        "clientName": "Test Client", "categoryName": "Test Category", "timeSet": link.dateAdd,
    }


def test_php_accepts_a_python_master_password_change(db_session, test_user, tmp_path, monkeypatch):
    """PHP-authored vault, rotated by pySysPass, then opened by PHP with the new master."""
    from pathlib import Path

    from app.core.defuse_compat import encrypt_account_pass
    from app.models.account import AccountHistory
    from app.services.master_password_rotation import MasterPasswordRotation

    monkeypatch.setattr(
        "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
    )
    fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "php_syspass_3211_crypto.json").read_text())
    old_master, new_master = fixture["known_values"]["master_password"], "Rotated-" + "ü" * 80
    db_session.add_all([Config(parameter="masterPwd", value=fixture["config"]["masterPwd"]),
                        Config(parameter="maintenance", value="true")])
    db_session.add(Account(id=60, name="PHP", userId=test_user.id, userEditId=test_user.id, userGroupId=1,
                           clientId=900, categoryId=900, pass_=fixture["account"]["pass"].encode(),
                           key=fixture["account"]["key"].encode()))
    db_session.flush()
    history_pass, history_key = encrypt_account_pass("history", old_master)
    db_session.add(AccountHistory(accountId=60, userGroupId=1, userId=test_user.id, userEditId=test_user.id,
                                  clientId=900, categoryId=900, name="h", notes="", pass_=history_pass.encode(),
                                  key=history_key.encode(), mPassHash=fixture["config"]["masterPwd"].encode()))
    db_session.commit()

    MasterPasswordRotation(db_session).rotate(old_master, new_master)

    account = db_session.get(Account, 60)
    history = db_session.query(AccountHistory).one()
    master_hash = db_session.query(Config).filter_by(parameter="masterPwd").one().value
    result = _php({
        "master_password": new_master,
        "accounts": [_ciphertext(account), _ciphertext(history)],
        "hash_checks": [{"key": new_master, "hash": master_hash}, {"key": old_master, "hash": master_hash}],
    })
    assert result["accounts"] == [fixture["known_values"]["account_password"], "history"]
    assert result["hash_checks"] == [True, False]
