"""Legacy pySysPass formats are rewritten natively so ENCRYPTION_KEY can rotate."""
import json
import time

import pytest

from app.core.defuse_compat import decrypt_account_pass, encrypt_account_pass
from app.core.security import EncryptionService
from app.models.account import Account, AccountHistory, Config, PluginData, PublicLink
from app.services.auth_service import hash_master_key, issue_session_token, decode_token
from app.services.legacy_migration import LegacyFormatMigration, LegacyMigrationError
from app.services.two_factor_service import TwoFactorStore
from tests.account_refs import TEST_CATEGORY_ID, TEST_CLIENT_ID

MASTER = "legacy-migration-master"
LEGACY_KEY = "legacy-encryption-key-32-bytes!!"


@pytest.fixture
def legacy(db_session, test_user):
    old = EncryptionService(LEGACY_KEY)
    db_session.add_all([
        Config(parameter="masterPwd", value=hash_master_key(MASTER)),
        Config(parameter="maintenance", value="true"),
    ])
    refs = dict(userId=test_user.id, userEditId=test_user.id, userGroupId=1,
                clientId=TEST_CLIENT_ID, categoryId=TEST_CATEGORY_ID)
    native_pass, native_key = encrypt_account_pass("already-native", MASTER)
    db_session.add_all([
        Account(id=70, name="legacy", pass_=old.encrypt("legacy-secret").encode(), key=b"", **refs),
        Account(id=71, name="native", pass_=native_pass.encode(), key=native_key.encode(), **refs),
        Account(id=72, name="empty", pass_=b"", key=b"", **refs),
    ])
    db_session.flush()
    db_session.add(AccountHistory(accountId=70, name="h", notes="", pass_=old.encrypt("old-legacy").encode(),
                                  key=b"", mPassHash=b"", **refs))
    vault = old.encrypt(json.dumps({"secret": "JBSWY3DPEHPK3PXP", "backup_codes": ["1111122222"]}))
    db_session.add_all([
        PluginData(name="Authenticator", itemId=test_user.id,
                   data=json.dumps({"enabled": True, "vault": vault}).encode(), key=b""),
        PluginData(name="Authenticator", itemId=99,
                   data=json.dumps({"enabled": False, "vault": old.encrypt("{}")}).encode(), key=b""),
    ])
    now = int(time.time())
    db_session.add_all([
        PublicLink(accountId=70, hash=b"legacy-a", data=old.encrypt("link-pw").encode(), userId=test_user.id,
                   typeId=1, dateAdd=now, dateExpire=now + 600, maxCountViews=3),
        PublicLink(accountId=71, hash=b"legacy-b", data=None, userId=test_user.id,
                   typeId=1, dateAdd=now, dateExpire=now + 600, maxCountViews=3),
    ])
    db_session.commit()
    return LegacyFormatMigration(db_session, old.decrypt)


def test_inventory_finds_every_legacy_value(legacy):
    found = legacy.inventory()
    assert [a.id for a in found.accounts] == [70]  # native and empty rows are fine
    assert len(found.history) == 1 and len(found.two_factor) == 2 and len(found.links) == 2


def test_links_are_never_converted_silently(legacy, db_session):
    with pytest.raises(LegacyMigrationError, match="public link"):
        legacy.migrate(MASTER)
    db_session.expire_all()
    assert db_session.get(Account, 70).key == b""  # nothing written
    assert db_session.query(PublicLink).count() == 2


def test_migration_rewrites_legacy_values_natively(legacy, db_session, test_user, encryption_service):
    legacy.migrate(MASTER, drop_links=True)
    db_session.expire_all()

    account = db_session.get(Account, 70)
    assert decrypt_account_pass(account.pass_.decode(), account.key.decode(), MASTER) == "legacy-secret"
    native = db_session.get(Account, 71)
    assert decrypt_account_pass(native.pass_.decode(), native.key.decode(), MASTER) == "already-native"
    history = db_session.query(AccountHistory).one()
    assert decrypt_account_pass(history.pass_.decode(), history.key.decode(), MASTER) == "old-legacy"
    assert history.mPassHash.decode() == db_session.query(Config).filter_by(parameter="masterPwd").one().value

    store = TwoFactorStore(db_session, encryption_service, master_pass=MASTER)
    assert store.is_enabled(test_user.id)
    assert store.get_secret(test_user.id) == "JBSWY3DPEHPK3PXP"
    assert store.get_backup_codes(test_user.id) == ["1111122222"]
    assert db_session.query(PluginData).filter_by(itemId=99).count() == 0  # unconfirmed setup dropped
    assert db_session.query(PublicLink).count() == 0
    assert legacy.inventory().remaining == 0


def test_wrong_master_or_key_changes_nothing(legacy, db_session):
    with pytest.raises(LegacyMigrationError, match="does not match"):
        legacy.migrate("wrong", drop_links=True)
    wrong_key = LegacyFormatMigration(db_session, EncryptionService("another-key-32-bytes-long-here!!").decrypt)
    with pytest.raises(LegacyMigrationError, match="do not decrypt"):
        wrong_key.migrate(MASTER, drop_links=True)
    db_session.expire_all()
    assert db_session.get(Account, 70).key == b""
    assert legacy.inventory().remaining == 6


def test_cli_check_migrate_and_end_sessions(legacy, db_session, test_user, monkeypatch, isolated_session_store):
    from app import encryption_key as cli

    monkeypatch.setattr(cli.settings, "DATABASE_URL", "sqlite://")
    monkeypatch.setattr(cli.settings, "ENCRYPTION_KEY", LEGACY_KEY)
    monkeypatch.setattr("app.db.base.SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)
    monkeypatch.setattr(cli.BackupService, "create_full_backup",
                        lambda self, url, include_files=True: {"filename": "pre.zip", "db_included": True})
    monkeypatch.setenv("PYSYSPASS_CURRENT_MASTER_PASSWORD", MASTER)

    assert cli.main(["check"]) == 1
    with pytest.raises(SystemExit):
        cli.main(["migrate"])  # --confirm-stopped is mandatory
    assert cli.main(["migrate", "--confirm-stopped"]) == 1  # legacy links need explicit removal
    assert cli.main(["migrate", "--confirm-stopped", "--drop-legacy-links"]) == 0
    assert cli.main(["check"]) == 0

    payload = decode_token(issue_session_token(test_user))
    assert cli.main(["end-sessions"]) == 0
    assert isolated_session_store.is_revoked(payload)
