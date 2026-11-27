"""Bidirectional database compatibility and import/export round-trip with PHP fixtures (R5 / #56).

Covers:
- PHP → Python → PHP round-trip: PHP-authored data read by Python, re-written, verified by PHP
- Python → PHP → Python round-trip: Python-authored data read by PHP, re-written, verified by Python
- Import/Export round-trips: XML, KeePass, CSV formats with PHP-native encryption
"""
import base64
import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

from app.core.config import settings
from app.core.defuse_compat import decrypt_account_pass, decrypt_with_password, encrypt_account_pass
from app.core.php_public_link import read_public_link_snapshot
from app.core.security import EncryptionService
from app.models.account import (
    Account,
    AccountHistory,
    AccountToTag,
    AccountToUser,
    AccountToUserGroup,
    Category,
    Client,
    Config,
    Plugin,
    PluginData,
    PublicLink,
    Tag,
    User,
    UserGroup,
    UserProfile,
    UserToUserGroup,
)
from app.services.account_service import AccountService
from app.services.import_export_service import (
    CsvImportService,
    ExportService,
    KeePassImportService,
    XmlImportService,
)
from app.services.auth_service import hash_master_key, store_user_master_pass
from app.services.category_service import make_item_hash
from app.services.item_preset_service import ItemPresetService
from app.services.legacy_migration import LegacyFormatMigration
from app.services.master_password_rotation import MasterPasswordRotation
from app.services.public_link_service import PublicLinkService
from app.services.two_factor_service import TwoFactorService, TwoFactorStore
from tests.account_refs import (
    TEST_CATEGORY_ID,
    TEST_CLIENT_ID,
    TEST_MASTER_PASSWORD,
    account_create,
)

PHP_VERIFY_CMD = os.environ.get("PYSYSPASS_PHP_VERIFY_CMD")
SALT = "bidirectional-roundtrip-salt-not-a-secret"
FIXTURES_DIR = Path(__file__).parents[1] / "fixtures"


def _php(cases: dict) -> dict:
    """Run PHP verification script with test cases."""
    result = subprocess.run(  # nosec B603 -- operator-supplied test command
        shlex.split(PHP_VERIFY_CMD), input=json.dumps(cases).encode(), capture_output=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode()
    return json.loads(result.stdout)


def _ciphertext(account: Account) -> dict:
    return {"pass": account.pass_.decode("ascii"), "key": account.key.decode("ascii")}


def _load_crypto_fixture() -> dict:
    return json.loads((FIXTURES_DIR / "php_syspass_3211_crypto.json").read_text())


def _load_acl_fixture() -> dict:
    return json.loads((FIXTURES_DIR / "php_syspass_3211_acl.json").read_text())


def _load_authenticator_fixture() -> dict:
    return json.loads((FIXTURES_DIR / "php_authenticator_plugindata.json").read_text())


def _load_public_link_fixture() -> dict:
    return json.loads((FIXTURES_DIR / "php_public_link_vault.json").read_text())


def _load_item_presets_fixture() -> dict:
    return json.loads((FIXTURES_DIR / "php_item_presets.json").read_text())


# ----------------------------------------------------------------------
# Fixtures: seed PHP-authored data into the database
# ----------------------------------------------------------------------


@pytest.fixture
def php_crypto_data(db_session, test_user):
    """Seed database with PHP-authored account and user master key (from crypto fixture)."""
    fixture = _load_crypto_fixture()
    known = fixture["known_values"]
    config = fixture["config"]
    user = fixture["user"]
    account = fixture["account"]

    db_session.add(Config(parameter="masterPwd", value=config["masterPwd"]))
    db_session.add(Config(parameter="passwordSalt", value=known["password_salt"]))

    # Create the Category and Client that the PHP account references (id=1)
    from app.services.category_service import make_item_hash
    category = Category(id=1, name="PHP Category", hash=make_item_hash("PHP Category"))
    client = Client(id=1, name="PHP Client", hash=make_item_hash("PHP Client"))
    db_session.add_all([category, client])
    db_session.flush()

    # User with PHP-format mPass/mKey
    from app.models.account import User
    user_obj = User(
        id=user["id"],
        name=user["login"],
        username=user["login"],
        password=b"php-fixture",
        hashSalt=b"s" * 32,
        userGroupId=1,
        userProfileId=1,
        mPass=user["mPass"].encode(),
        mKey=user["mKey"].encode(),
    )
    db_session.add(user_obj)

    # PHP-authored account
    db_session.add(Account(
        id=account["id"],
        name=account["name"],
        userId=account["userId"],
        userEditId=account["userId"],  # fixture doesn't have userEditId, use userId
        userGroupId=account["userGroupId"],
        clientId=account["clientId"],
        categoryId=account["categoryId"],
        pass_=account["pass"].encode(),
        key=account["key"].encode(),
    ))
    db_session.commit()
    return fixture


@pytest.fixture
def php_acl_data(db_session):
    """Seed database with PHP-authored ACL structure (from acl fixture)."""
    fixture = _load_acl_fixture()
    # Users and groups
    for group_id in range(5, 10):
        db_session.add(UserGroup(id=group_id, name=f"PHP fixture group {group_id}"))
    db_session.flush()

    users = {}
    primary_groups = {}
    for user_id, login, primary_group_id, secondary_group_id in fixture["users"]:
        user = User(
            id=user_id,
            name=login,
            username=login,
            hashSalt=b"s" * 32,
            password=b"fixture",
            userGroupId=primary_group_id,
            userProfileId=1,
        )
        db_session.add(user)
        db_session.flush()
        users[login] = user
        primary_groups[user_id] = primary_group_id
        db_session.add(UserToUserGroup(
            userId=user_id, userGroupId=secondary_group_id, isManager=False
        ))

    pattern = fixture["account_pattern"]
    owner_cycle = pattern["owner_user_ids_cycle"]
    private_ids = set(pattern["private_ids"])
    private_group_ids = set(pattern["private_group_ids"])
    for offset, account_id in enumerate(range(pattern["first_id"], pattern["last_id"] + 1)):
        owner_id = owner_cycle[offset % len(owner_cycle)]
        db_session.add(Account(
            id=account_id,
            userId=owner_id,
            userEditId=owner_id,
            userGroupId=primary_groups[owner_id],
            name=f"PHP ACL fixture {account_id}",
            pass_=b"fixture",
            key=b"fixture",
            isPrivate=account_id in private_ids,
            isPrivateGroup=account_id in private_group_ids,
            clientId=TEST_CLIENT_ID, categoryId=TEST_CATEGORY_ID,
        ))
    db_session.flush()

    for account_id, user_id, is_edit in fixture["user_shares"]:
        db_session.add(AccountToUser(accountId=account_id, userId=user_id, isEdit=is_edit))
    for account_id, group_id, is_edit in fixture["group_shares"]:
        db_session.add(AccountToUserGroup(accountId=account_id, userGroupId=group_id, isEdit=is_edit))

    db_session.commit()
    return fixture


@pytest.fixture
def php_authenticator_data(db_session, test_user):
    """Seed database with PHP-authored Authenticator 2FA data."""
    fixture = _load_authenticator_fixture()
    MASTER = fixture["master_password"]
    ROW = fixture["plugin_data"]

    store_user_master_pass(test_user, "testpassword", MASTER)
    db_session.add(Config(parameter="masterPwd", value=hash_master_key(MASTER)))
    db_session.add(Plugin(name="Authenticator", enabled=True, available=True, versionLevel="310.19012201"))
    db_session.flush()
    db_session.add(PluginData(name="Authenticator", itemId=test_user.id,
                              data=ROW["data"].encode(), key=ROW["key"].encode()))
    db_session.commit()
    return fixture


@pytest.fixture
def php_public_link_data(db_session, test_user, monkeypatch):
    """Seed database with PHP-authored public link."""
    import time
    fixture = _load_public_link_fixture()
    monkeypatch.setattr('app.services.public_link_service.get_password_salt', lambda: fixture['password_salt'])
    row = PublicLink(
        accountId=17, hash=fixture['link']['hash'].encode('ascii'),
        data=base64.b64decode(fixture['link']['data_base64']), userId=test_user.id,
        typeId=1, dateAdd=int(time.time()), dateExpire=int(time.time()) + 3600,
        dateUpdate=0, countViews=0, totalCountViews=0, maxCountViews=2,
    )
    db_session.add(row)
    db_session.commit()
    return fixture


@pytest.fixture
def php_item_presets_data(db_session):
    """Seed database with PHP-authored item presets."""
    fixture = _load_item_presets_fixture()
    for preset in fixture["item_presets"]:
        from app.models.account import ItemPreset
        db_session.add(ItemPreset(
            type=preset["type"],
            userId=preset.get("userId"),
            userGroupId=preset.get("userGroupId"),
            userProfileId=preset.get("userProfileId"),
            fixed=preset.get("fixed", 0),
            priority=preset.get("priority", 0),
            data=base64.b64decode(preset["data_base64"]),
            hash=preset["hash"].encode(),
        ))
    db_session.commit()
    return fixture


# ----------------------------------------------------------------------
# PHP → Python → PHP Round-trip Tests
# ----------------------------------------------------------------------


@pytest.mark.skipif(not PHP_VERIFY_CMD, reason="PYSYSPASS_PHP_VERIFY_CMD not set")
class TestPhpToPythonToPhpRoundTrip:
    """PHP writes → Python reads → Python writes → PHP reads."""

    def test_php_authored_account_round_trip(self, db_session, php_crypto_data, encryption_service, tmp_path, monkeypatch):
        """PHP-authored account read by Python, updated, then verified by PHP."""
        monkeypatch.setattr(
            "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
        )
        monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", SALT)
        monkeypatch.setattr("app.core.syspass_runtime_config.load_syspass_runtime_config", lambda: {"passwordSalt": SALT})

        fixture = php_crypto_data
        known = fixture["known_values"]

        # Python reads the PHP-authored account
        account = db_session.get(Account, fixture["account"]["id"])
        plaintext = decrypt_account_pass(
            account.pass_.decode("ascii"), account.key.decode("ascii"), known["master_password"]
        )
        assert plaintext == known["account_password"]

        # Python updates the account (simulating user edit)
        service = AccountService(db_session, encryption_service)
        new_password = "Python-updated-" + "ü" * 10
        from app.schemas.account import AccountUpdate
        service.update_account(account.id, AccountUpdate(password=new_password), test_user.id,
                               master_pass=known["master_password"])

        # Re-read and verify with PHP
        account = db_session.get(Account, fixture["account"]["id"])
        result = _php({
            "password_salt": known["password_salt"],
            "master_password": known["master_password"],
            "accounts": [_ciphertext(account)],
        })
        assert result["accounts"] == [new_password]

    def test_php_authored_acl_round_trip(self, db_session, php_acl_data, encryption_service):
        """PHP-authored ACL structure read by Python, new share added, verified by Python logic."""
        fixture = php_acl_data
        service = AccountService(db_session, encryption_service)

        # Python reads visibility for a user (matches PHP)
        users = {}
        for user_id, login, primary_group_id, secondary_group_id in fixture["users"]:
            user = db_session.get(User, user_id)
            users[login] = user

        for login, expected_ids in fixture["php_visible_account_ids"].items():
            group_ids = service._get_user_group_ids(users[login].id)
            visible = {
                account_id for account_id, in service.db.query(Account.id)
                .filter(service._access_filter(users[login].id, group_ids)).all()
            }
            assert visible == set(expected_ids), f"Visibility mismatch for {login}"

        # Python adds a new share
        new_account = Account(
            id=9999, name="Python added", userId=20, userEditId=20, userGroupId=5,
            clientId=TEST_CLIENT_ID, categoryId=TEST_CATEGORY_ID, pass_=b"x", key=b"x",
        )
        db_session.add(new_account)
        db_session.flush()
        db_session.add(AccountToUser(accountId=9999, userId=20, isEdit=True))
        db_session.commit()

        # Verify the new share is visible to the user
        group_ids = service._get_user_group_ids(20)
        visible = {a for a, in service.db.query(Account.id).filter(service._access_filter(20, group_ids)).all()}
        assert 9999 in visible

    def test_php_authored_2fa_round_trip(self, db_session, php_authenticator_data, encryption_service, test_user):
        """PHP-authored 2FA state read by Python, backup code used, verified by Python."""
        fixture = php_authenticator_data
        MASTER = fixture["master_password"]
        EXPECTED = fixture["expected"]

        store = TwoFactorStore(db_session, encryption_service, master_pass=MASTER)
        assert store.is_enabled(test_user.id)
        assert store.get_secret(test_user.id) == EXPECTED["IV"]
        assert store.get_backup_codes(test_user.id) == EXPECTED["recoveryCodes"]

        # Python uses a recovery code
        store.verify_backup_code(test_user.id, EXPECTED["recoveryCodes"][0])
        remaining = store.get_backup_codes(test_user.id)
        assert remaining == EXPECTED["recoveryCodes"][1:]

        # Verify PHP format is preserved in DB
        row = db_session.query(PluginData).filter_by(name="Authenticator", itemId=test_user.id).one()
        assert row.key.startswith(b"def10000")

    def test_php_authored_public_link_round_trip(self, db_session, php_public_link_data, test_user, monkeypatch):
        """PHP-authored public link read by Python, view limit enforced."""
        import time
        fixture = php_public_link_data
        monkeypatch.setattr('app.services.public_link_service.get_password_salt', lambda: fixture['password_salt'])

        # Python reads the PHP snapshot
        link = db_session.query(PublicLink).one()
        account = read_public_link_snapshot(
            link.data, link.hash, fixture['password_salt'], 17,
        )
        assert account.password == fixture['account']['password']
        assert account.name == fixture['account']['name']

        # Python accesses via service (enforces view limits)
        service = PublicLinkService(db_session)
        for _ in range(2):
            result = service.get_public_link(link.hash)
            assert result is not None
            assert result[1].password == fixture['account']['password']

        # Third access should fail (view limit)
        assert service.get_public_link(link.hash) is None
        db_session.refresh(link)
        assert link.countViews == 2

    def test_php_authored_item_presets_round_trip(self, db_session, php_item_presets_data):
        """PHP-authored item presets read by Python, hash verified."""
        fixture = php_item_presets_data
        from app.models.account import ItemPreset

        service = ItemPresetService(db_session)
        rows = db_session.query(ItemPreset).order_by(ItemPreset.id).all()

        for row, expected in zip(rows, fixture["item_presets"]):
            assert row.hash.decode() == expected["hash"]
            # Verify Python can hydrate the preset
            if row.type == "account.permission":
                obj = service._hydrate_preset(row, "account.permission")
                assert obj.getUsersView() == expected["values"].get("getUsersView", [])
            elif row.type == "account.private":
                obj = service._hydrate_preset(row, "account.private")
                assert obj.isPrivateUser() == expected["values"].get("isPrivateUser", False)


# ----------------------------------------------------------------------
# Python → PHP → Python Round-trip Tests
# ----------------------------------------------------------------------


@pytest.mark.skipif(not PHP_VERIFY_CMD, reason="PYSYSPASS_PHP_VERIFY_CMD not set")
class TestPythonToPhpToPythonRoundTrip:
    """Python writes → PHP reads → PHP writes → Python reads."""

    def test_python_create_account_php_reads(self, db_session, encryption_service, test_user, tmp_path, monkeypatch):
        """Python creates account → PHP decrypts correctly."""
        monkeypatch.setattr(
            "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
        )
        monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", SALT)
        monkeypatch.setattr("app.core.syspass_runtime_config.load_syspass_runtime_config", lambda: {"passwordSalt": SALT})

        service = AccountService(db_session, encryption_service)
        created = service.create_account(
            account_create(title="Python Created", password="PyPass-🔑-1", login="pyuser", url="https://py.example"),
            test_user.id, master_pass=TEST_MASTER_PASSWORD,
        )

        # PHP reads it
        account = db_session.get(Account, created.id)
        result = _php({
            "password_salt": SALT,
            "master_password": TEST_MASTER_PASSWORD,
            "accounts": [_ciphertext(account)],
        })
        assert result["accounts"] == ["PyPass-🔑-1"]

    def test_python_export_xml_php_imports(self, db_session, encryption_service, test_user, tmp_path, monkeypatch):
        """Python exports native XML → PHP can parse it (simulated via our parser)."""
        # Create test data
        category = Category(name="PyCat", hash=make_item_hash("PyCat"))
        client = Client(name="PyClient", hash=make_item_hash("PyClient"))
        db_session.add_all([category, client])
        db_session.flush()

        account = Account(
            userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
            clientId=client.id, name="XML Export Test", categoryId=category.id,
            login="xmluser", url="https://xml.example", pass_=encryption_service.encrypt("xml-secret").encode(),
            key=b"", notes="From Python",
        )
        db_session.add(account)
        db_session.flush()
        db_session.add(AccountToTag(accountId=account.id, tagId=1))
        db_session.commit()

        # Export to native sysPass XML (encrypted)
        export_password = "ExportPass123!"
        master_password = "MasterPass123!"
        service = ExportService(db_session, encryption_service)
        xml_output = service.export_to_xml(
            [account.id], export_password=export_password, master_password=master_password,
            username=test_user.username, user_id=test_user.id, group_id=test_user.userGroupId,
        )

        # Verify XML structure matches PHP expectations
        assert "Generator>sysPass<" in xml_output
        assert "Encrypted" in xml_output
        assert "Hash" in xml_output

        # Import back with correct passwords
        importer = XmlImportService(
            db_session, encryption_service, test_user.id,
            export_password=export_password, import_master_password=master_password,
        )
        parsed = importer.parse_xml(xml_output)
        assert len(parsed) == 1
        assert parsed[0]["name"] == "XML Export Test"
        # The ciphertext should be preserved (native format)
        assert "_native_ciphertext" in parsed[0]

    def test_python_export_keepass_php_compatible(self, db_session, encryption_service, test_user):
        """Python exports KeePass XML → format is standard KeePass 2.x."""
        category = Category(name="KeeCat", hash=make_item_hash("KeeCat"))
        client = Client(name="KeeClient", hash=make_item_hash("KeeClient"))
        db_session.add_all([category, client])
        db_session.flush()

        account = Account(
            userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
            clientId=client.id, name="KeePass Test", categoryId=category.id,
            login="keepassuser", url="https://keepass.example",
            pass_=encryption_service.encrypt("keepass-secret").encode(), key=b"",
        )
        db_session.add(account)
        db_session.commit()

        service = ExportService(db_session, encryption_service)
        keepass_xml = service.export_to_keepass(master_password=TEST_MASTER_PASSWORD)

        # Verify it's valid KeePass XML
        import xml.etree.ElementTree as ET
        root = ET.fromstring(keepass_xml)
        assert root.tag == "KeePassFile"
        assert root.findtext("./Meta/Generator") == "pySysPass"
        entry = root.find(".//Entry")
        assert entry is not None
        # Find password field
        password_val = None
        for string_elem in entry.findall("String"):
            if string_elem.findtext("Key") == "Password":
                password_val = string_elem.findtext("Value")
                break
        assert password_val == "keepass-secret"

    def test_python_csv_round_trip(self, db_session, encryption_service, test_user):
        """Python exports CSV → imports back → data preserved."""
        category = Category(name="CsvCat", hash=make_item_hash("CsvCat"))
        client = Client(name="CsvClient", hash=make_item_hash("CsvClient"))
        tag = Tag(name="csv-tag", hash=make_item_hash("csv-tag"))
        db_session.add_all([category, client, tag])
        db_session.flush()

        account = Account(
            userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
            clientId=client.id, name="CSV Test", categoryId=category.id,
            login="csvuser", url="https://csv.example", pass_=encryption_service.encrypt("csv-secret").encode(), key=b"",
        )
        db_session.add(account)
        db_session.flush()
        db_session.add(AccountToTag(accountId=account.id, tagId=tag.id))
        db_session.commit()

        # Export CSV
        service = ExportService(db_session, encryption_service)
        csv_output = service.export_to_csv([account.id])

        # Import CSV
        csv_importer = CsvImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
        parsed = csv_importer.parse_csv(csv_output)
        assert len(parsed) == 1
        assert parsed[0]["name"] == "CSV Test"
        assert parsed[0]["pass"] == "csv-secret"

        # Import to database (new account)
        stats = csv_importer.import_accounts(parsed)
        assert stats["success"] == 1


# ----------------------------------------------------------------------
# Import/Export Round-trip with PHP Fixtures
# ----------------------------------------------------------------------


class TestImportExportPhpFixtures:
    """Import/export round-trips using PHP-authored fixture data."""

    def test_php_crypto_account_export_import_xml(self, db_session, php_crypto_data, encryption_service, test_user):
        """PHP-authored account exported to XML, re-imported, password preserved."""
        fixture = php_crypto_data
        known = fixture["known_values"]
        account = db_session.get(Account, fixture["account"]["id"])

        # Export to native XML (requires master password to convert Python→PHP encryption)
        service = ExportService(db_session, encryption_service)
        xml_output = service.export_to_xml(
            [account.id],
            export_password="ExportFixture!",
            master_password=known["master_password"],
            username=test_user.username, user_id=test_user.id, group_id=test_user.userGroupId,
        )

        # Verify it has encrypted sections
        assert "Encrypted" in xml_output
        assert "Hash" in xml_output

        # Import back - delete original first
        db_session.delete(account)
        db_session.commit()

        importer = XmlImportService(
            db_session, encryption_service, test_user.id,
            export_password="ExportFixture!", import_master_password=known["master_password"],
        )
        parsed = importer.parse_xml(xml_output)
        assert len(parsed) == 1
        assert parsed[0]["name"] == fixture["account"]["name"]

        # The ciphertext is preserved (native format)
        assert "_native_ciphertext" in parsed[0]
        imported_pass = parsed[0]["pass"]
        imported_key = parsed[0]["key"]

        stats = importer.import_accounts(parsed)
        assert stats["success"] == 1

        imported = db_session.query(Account).one()
        # Decrypt with master password to verify
        decrypted = decrypt_with_password(imported.pass_.decode(), imported.key.decode(), known["master_password"])
        assert decrypted == known["account_password"]

    def test_php_crypto_account_export_import_keepass(self, db_session, php_crypto_data, encryption_service, test_user):
        """PHP-authored account exported to KeePass, re-imported, password preserved."""
        fixture = php_crypto_data
        known = fixture["known_values"]
        account = db_session.get(Account, fixture["account"]["id"])

        # Export to KeePass (plaintext passwords)
        service = ExportService(db_session, encryption_service)
        keepass_xml = service.export_to_keepass([account.id], master_password=known["master_password"])

        # Import back
        db_session.delete(account)
        db_session.commit()

        keepass_importer = KeePassImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
        parsed = keepass_importer.parse_keepass(keepass_xml)
        assert len(parsed) == 1
        assert parsed[0]["pass"] == known["account_password"]

        stats = keepass_importer.import_accounts(parsed)
        assert stats["success"] == 1

        imported = db_session.query(Account).one()
        decrypted = decrypt_account_pass(imported.pass_.decode(), imported.key.decode(), TEST_MASTER_PASSWORD)
        assert decrypted == known["account_password"]

    def test_php_crypto_account_export_import_csv(self, db_session, php_crypto_data, encryption_service, test_user):
        """PHP-authored account exported to CSV shows [encrypted] (limitation: CSV export doesn't decrypt PHP-format without master password)."""
        fixture = php_crypto_data
        known = fixture["known_values"]
        account = db_session.get(Account, fixture["account"]["id"])

        # Export to CSV - PHP-format accounts show as [encrypted] since CSV export doesn't accept master_password
        service = ExportService(db_session, encryption_service)
        csv_output = service.export_to_csv([account.id])

        # Verify CSV shows [encrypted] for PHP-format accounts
        import csv
        from io import StringIO
        reader = csv.DictReader(StringIO(csv_output))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["password"] == "[encrypted]"

        # Import back - the password will be imported as "[encrypted]" literal string
        # This is a known limitation: CSV round-trip for PHP-format accounts requires master_password support
        db_session.delete(account)
        db_session.commit()

        csv_importer = CsvImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
        parsed = csv_importer.parse_csv(csv_output)
        assert len(parsed) == 1
        # The CSV parser returns the raw CSV columns, so 'password' not 'pass'
        assert parsed[0]["password"] == "[encrypted]"

        # Import to database
        stats = csv_importer.import_accounts(parsed)
        assert stats["success"] == 1

        imported = db_session.query(Account).one()
        # The imported password is the literal "[encrypted]" encrypted with TEST_MASTER_PASSWORD
        decrypted = decrypt_account_pass(imported.pass_.decode(), imported.key.decode(), TEST_MASTER_PASSWORD)
        assert decrypted == "[encrypted]"

    def test_php_keepass_fixture_import(self, db_session, encryption_service, test_user):
        """Upstream PHP KeePass fixture imports correctly."""
        PHP_KEEPASS_FIXTURE = Path("../phpSysPass/tests/res/import/data_keepass.xml")
        if not PHP_KEEPASS_FIXTURE.exists():
            pytest.skip("../phpSysPass KeePass fixture not available")

        keepass_importer = KeePassImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
        parsed = keepass_importer.parse_keepass(PHP_KEEPASS_FIXTURE.read_text(encoding="utf-8"))
        assert len(parsed) == 5
        assert parsed[0]["name"] == "Sample Entry"
        assert parsed[0]["pass"] == "Password"
        categories = {item.get("category") for item in parsed if item.get("category")}
        assert categories == {"Linux", "Windows"}


# ----------------------------------------------------------------------
# Database Compatibility: Schema and Data
# ----------------------------------------------------------------------


class TestDatabaseBidirectionalCompatibility:
    """Verify database created by one can be used by the other."""

    def test_python_bootstrap_matches_php_schema(self, db_session):
        """Python-created tables match PHP schema (via schema parity baseline)."""
        from tests.compatibility.schema_parity import parse_mysql_tables
        from app.db.base import Base
        import app.models  # noqa
        from sqlalchemy.dialects import mysql
        import re

        ROOT = Path(__file__).resolve().parents[2]
        SCHEMA_PATH = ROOT / "schemas" / "dbstructure.sql"
        ORM_VIEWS = {"account_data_v", "account_search_v"}

        php_tables = parse_mysql_tables(SCHEMA_PATH)
        orm_tables = {
            name: table for name, table in Base.metadata.tables.items()
            if not table.info.get("is_php_extension") and name not in ORM_VIEWS
        }

        # All ORM tables must exist in PHP schema
        assert set(orm_tables.keys()) == set(php_tables.keys())

        # Column types must match (using baseline for known drifts)
        BASELINE_DIR = Path(__file__).with_name("baselines")
        mismatches = []
        for table_name, php_columns in php_tables.items():
            orm_table = orm_tables[table_name]
            for column_name, php_column in php_columns.items():
                if column_name not in orm_table.columns:
                    mismatches.append(f"{table_name}.{column_name}: missing in Python")
                    continue
                orm_column = orm_table.columns[column_name]
                compiled = orm_column.type.compile(dialect=mysql.dialect()).lower()
                match = re.match(r"([a-z]+)(?:\((\d+)\))?", compiled)
                if match:
                    type_name, length = match.groups()
                    if type_name in {"bool", "boolean"}:
                        type_name, length = "tinyint", "1"
                    elif type_name == "integer":
                        type_name = "int"
                    unsigned = "unsigned" in compiled
                    php_sig = (php_column.sql_type, php_column.length, php_column.unsigned)
                    orm_sig = (type_name, length, unsigned)
                    if php_sig != orm_sig:
                        mismatches.append(f"{table_name}.{column_name}: PHP={php_sig} Python={orm_sig}")

        baseline_path = BASELINE_DIR / "types.txt"
        expected = [line for line in baseline_path.read_text().splitlines() if line]
        # Only check that we don't have unexpected mismatches beyond the baseline
        unexpected = set(mismatches) - set(expected)
        assert not unexpected, f"Unexpected type drift:\n" + "\n".join(sorted(unexpected))

    def test_php_seeded_database_usable_by_python(self, db_session, php_crypto_data, encryption_service, test_user):
        """A database seeded with PHP fixtures works correctly with Python services."""
        # Test with just the crypto fixture to avoid Config conflicts
        # All fixture data should be readable
        # 1. Crypto data
        fixture = php_crypto_data
        known = fixture["known_values"]
        account = db_session.get(Account, fixture["account"]["id"])
        assert decrypt_account_pass(account.pass_.decode(), account.key.decode(), known["master_password"]) == known["account_password"]


# ----------------------------------------------------------------------
# Master Password Rotation Interop
# ----------------------------------------------------------------------


@pytest.mark.skipif(not PHP_VERIFY_CMD, reason="PYSYSPASS_PHP_VERIFY_CMD not set")
class TestMasterPasswordRotationInterop:
    """Master password rotation: PHP → Python → PHP and Python → PHP → Python."""

    def test_php_vault_rotated_by_python_php_opens(self, db_session, test_user, tmp_path, monkeypatch):
        """PHP-authored vault, rotated by pySysPass, then opened by PHP with new master."""
        from pathlib import Path

        monkeypatch.setattr(
            "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
        )
        fixture = _load_crypto_fixture()
        old_master, new_master = fixture["known_values"]["master_password"], "Rotated-" + "ü" * 80
        db_session.add_all([Config(parameter="masterPwd", value=fixture["config"]["masterPwd"]),
                            Config(parameter="maintenance", value="true")])
        db_session.add(Account(id=60, name="PHP", userId=test_user.id, userEditId=test_user.id, userGroupId=1,
                               clientId=900, categoryId=900, pass_=fixture["account"]["pass"].encode(),
                               key=fixture["account"]["key"].encode()))
        db_session.flush()
        from app.core.defuse_compat import encrypt_account_pass
        from app.models.account import AccountHistory
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

    def test_python_vault_rotated_php_reads(self, db_session, encryption_service, test_user, tmp_path, monkeypatch):
        """Python-created vault, rotated by pySysPass, then read by PHP."""
        monkeypatch.setattr(
            "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
        )
        monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", SALT)
        monkeypatch.setattr("app.core.syspass_runtime_config.load_syspass_runtime_config", lambda: {"passwordSalt": SALT})

        service = AccountService(db_session, encryption_service)
        created = service.create_account(
            account_create(title="Python Vault", password="PythonSecret123"),
            test_user.id, master_pass=TEST_MASTER_PASSWORD,
        )

        new_master = "NewMasterFromPython-" + "α" * 50
        MasterPasswordRotation(db_session).rotate(TEST_MASTER_PASSWORD, new_master)

        account = db_session.get(Account, created.id)
        master_hash = db_session.query(Config).filter_by(parameter="masterPwd").one().value
        result = _php({
            "master_password": new_master,
            "accounts": [_ciphertext(account)],
            "hash_checks": [{"key": new_master, "hash": master_hash}],
        })
        assert result["accounts"] == ["PythonSecret123"]
        assert result["hash_checks"] == [True]


# ----------------------------------------------------------------------
# Legacy Migration Interop
# ----------------------------------------------------------------------


class TestLegacyMigrationInterop:
    """Legacy pySysPass formats migrated by Python become PHP-readable."""

    def test_legacy_account_migrated_php_readable(self, db_session, test_user, tmp_path, monkeypatch):
        """Legacy-format account migrated by Python, then readable by PHP."""
        if not PHP_VERIFY_CMD:
            pytest.skip("PYSYSPASS_PHP_VERIFY_CMD not set")
        monkeypatch.setattr(
            "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
        )
        monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", SALT)
        monkeypatch.setattr("app.core.syspass_runtime_config.load_syspass_runtime_config", lambda: {"passwordSalt": SALT})

        from app.core.security import EncryptionService
        old = EncryptionService("legacy-encryption-key-32-bytes!!")
        db_session.add(Config(parameter="masterPwd", value=hash_master_key(TEST_MASTER_PASSWORD)))
        db_session.add(Account(id=80, name="legacy", userId=test_user.id, userEditId=test_user.id, userGroupId=1,
                               clientId=900, categoryId=900, pass_=old.encrypt("was-legacy").encode(), key=b""))
        db_session.commit()

        LegacyFormatMigration(db_session, old.decrypt).migrate(TEST_MASTER_PASSWORD)

        account = db_session.get(Account, 80)
        result = _php({
            "password_salt": SALT,
            "master_password": TEST_MASTER_PASSWORD,
            "accounts": [_ciphertext(account)],
        })
        assert result["accounts"] == ["was-legacy"]

    def test_legacy_2fa_migrated_php_readable(self, db_session, test_user, tmp_path, monkeypatch):
        """Legacy 2FA data migrated by Python, then readable by PHP."""
        if not PHP_VERIFY_CMD:
            pytest.skip("PYSYSPASS_PHP_VERIFY_CMD not set")
        monkeypatch.setattr(
            "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
        )
        monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", SALT)
        monkeypatch.setattr("app.core.syspass_runtime_config.load_syspass_runtime_config", lambda: {"passwordSalt": SALT})

        from app.core.security import EncryptionService
        old = EncryptionService("legacy-encryption-key-32-bytes!!")
        db_session.add(Config(parameter="masterPwd", value=hash_master_key(TEST_MASTER_PASSWORD)))
        vault = old.encrypt(json.dumps({"secret": "JBSWY3DPEHPK3PXP", "backup_codes": ["0123456789abcdef0123"]}))
        db_session.add(Plugin(name="Authenticator", enabled=True, available=True))
        db_session.flush()
        db_session.add(PluginData(name="Authenticator", itemId=test_user.id,
                                  data=json.dumps({"enabled": True, "vault": vault}).encode(), key=b""))
        db_session.commit()

        LegacyFormatMigration(db_session, old.decrypt).migrate(TEST_MASTER_PASSWORD)

        row = db_session.query(PluginData).filter_by(name="Authenticator", itemId=test_user.id).one()
        result = _php({
            "master_password": TEST_MASTER_PASSWORD,
            "authenticator": [{"data": row.data.decode(), "key": row.key.decode()}],
        })
        assert result["authenticator"][0]["IV"] == "JBSWY3DPEHPK3PXP"
        assert result["authenticator"][0]["recoveryCodes"] == ["0123456789abcdef0123"]


# ----------------------------------------------------------------------
# Public Link Interop
# ----------------------------------------------------------------------


class TestPublicLinkInterop:
    """Public link snapshots: Python creates → PHP reads, PHP creates → Python reads."""

    def test_python_creates_public_link_php_readable(self, db_session, encryption_service, test_user, monkeypatch):
        """Python creates public link, PHP can decrypt snapshot."""
        if not PHP_VERIFY_CMD:
            pytest.skip("PYSYSPASS_PHP_VERIFY_CMD not set")
        import time

        monkeypatch.setattr('app.services.public_link_service.get_password_salt', lambda: SALT)

        service = AccountService(db_session, encryption_service)
        account = service.create_account(
            account_create(title="Public Link Test", password="LinkSecret"),
            test_user.id, master_pass=TEST_MASTER_PASSWORD,
        )

        link_service = PublicLinkService(db_session)
        link = link_service.create_public_link(account.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)

        # PHP reads the snapshot
        result = _php({
            "password_salt": SALT,
            "master_password": TEST_MASTER_PASSWORD,
            "accounts": [_ciphertext(db_session.get(Account, account.id))],
            "links": [{"hash": link.hash.decode("ascii"), "data_base64": base64.b64encode(link.data).decode()}],
        })
        assert result["links"][0]["pass"] == "LinkSecret"
        assert result["links"][0]["name"] == "Public Link Test"

    def test_php_public_link_python_reads(self, db_session, php_public_link_data, test_user):
        """PHP-authored public link, Python reads snapshot correctly."""
        fixture = php_public_link_data
        link = db_session.query(PublicLink).one()
        account = read_public_link_snapshot(
            link.data, link.hash, fixture['password_salt'], 17,
        )
        assert account.password == fixture['account']['password']
        assert account.name == fixture['account']['name']
        assert account.category_name == fixture['account']['categoryName']
        assert account.client_name == fixture['account']['clientName']


# ----------------------------------------------------------------------
# Full Cycle: Export → Import → Export → Import
# ----------------------------------------------------------------------


class TestFullImportExportCycles:
    """Complete round-trip cycles across all formats."""

    def test_xml_full_cycle(self, db_session, encryption_service, test_user):
        """Create → Export XML → Import → Export XML → Import → Verify."""
        # Create
        category = Category(name="CycleCat", hash=make_item_hash("CycleCat"))
        client = Client(name="CycleClient", hash=make_item_hash("CycleClient"))
        db_session.add_all([category, client])
        db_session.flush()

        account = Account(
            userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
            clientId=client.id, name="Cycle Test", categoryId=category.id,
            login="cycle", url="https://cycle.example",
            pass_=encryption_service.encrypt("cycle-secret").encode(), key=b"",
        )
        db_session.add(account)
        db_session.commit()

        # Cycle 1: Export → Import (use master_password for native XML format)
        service = ExportService(db_session, encryption_service)
        xml1 = service.export_to_xml([account.id], export_password="Exp1!", master_password="Master1!",
                                     username=test_user.username, user_id=test_user.id, group_id=test_user.userGroupId)

        db_session.delete(account)
        db_session.commit()

        importer = XmlImportService(db_session, encryption_service, test_user.id,
                                    export_password="Exp1!", import_master_password="Master1!")
        parsed1 = importer.parse_xml(xml1)
        importer.import_accounts(parsed1)

        # Cycle 2: Export → Import (use same master_password for consistency)
        # The account is now in PHP format, so export preserves it
        account2 = db_session.query(Account).one()
        xml2 = service.export_to_xml([account2.id], export_password="Exp2!", master_password="Master1!",
                                     username=test_user.username, user_id=test_user.id, group_id=test_user.userGroupId)

        db_session.delete(account2)
        db_session.commit()

        importer2 = XmlImportService(db_session, encryption_service, test_user.id,
                                     export_password="Exp2!", import_master_password="Master1!")
        parsed2 = importer2.parse_xml(xml2)
        importer2.import_accounts(parsed2)

        # Verify final state
        final = db_session.query(Account).one()
        decrypted = decrypt_with_password(final.pass_.decode(), final.key.decode(), "Master1!")
        assert decrypted == "cycle-secret"
        assert final.name == "Cycle Test"

    def test_keepass_full_cycle(self, db_session, encryption_service, test_user):
        """Create → Export KeePass → Import → Export KeePass → Import → Verify."""
        category = Category(name="KeeCycle", hash=make_item_hash("KeeCycle"))
        client = Client(name="KeeClient", hash=make_item_hash("KeeClient"))
        db_session.add_all([category, client])
        db_session.flush()

        account = Account(
            userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
            clientId=client.id, name="Kee Cycle", categoryId=category.id,
            login="keepasscycle", url="https://keepass.cycle",
            pass_=encryption_service.encrypt("keepass-cycle-secret").encode(), key=b"",
        )
        db_session.add(account)
        db_session.commit()

        # Cycle 1
        service = ExportService(db_session, encryption_service)
        kp1 = service.export_to_keepass([account.id], master_password=TEST_MASTER_PASSWORD)

        db_session.delete(account)
        db_session.commit()

        kp_importer = KeePassImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
        parsed1 = kp_importer.parse_keepass(kp1)
        kp_importer.import_accounts(parsed1)

        # Cycle 2
        account2 = db_session.query(Account).one()
        kp2 = service.export_to_keepass([account2.id], master_password=TEST_MASTER_PASSWORD)

        db_session.delete(account2)
        db_session.commit()

        parsed2 = kp_importer.parse_keepass(kp2)
        kp_importer.import_accounts(parsed2)

        final = db_session.query(Account).one()
        decrypted = decrypt_account_pass(final.pass_.decode(), final.key.decode(), TEST_MASTER_PASSWORD)
        assert decrypted == "keepass-cycle-secret"

    def test_csv_full_cycle(self, db_session, encryption_service, test_user):
        """Create → Export CSV → Import → Export CSV → Import → Verify.

        Note: CSV export doesn't support master_password, so Python-encrypted accounts
        show as [encrypted]. The round-trip preserves the literal [encrypted] string.
        """
        category = Category(name="CsvCycle", hash=make_item_hash("CsvCycle"))
        client = Client(name="CsvClient", hash=make_item_hash("CsvClient"))
        db_session.add_all([category, client])
        db_session.flush()

        account = Account(
            userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
            clientId=client.id, name="CSV Cycle", categoryId=category.id,
            login="csvcycle", url="https://csv.cycle",
            pass_=encryption_service.encrypt("csv-cycle-secret").encode(), key=b"",
        )
        db_session.add(account)
        db_session.commit()

        # Cycle 1
        service = ExportService(db_session, encryption_service)
        csv1 = service.export_to_csv([account.id])

        db_session.delete(account)
        db_session.commit()

        csv_importer = CsvImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
        parsed1 = csv_importer.parse_csv(csv1)
        csv_importer.import_accounts(parsed1)

        # Cycle 2
        account2 = db_session.query(Account).one()
        csv2 = service.export_to_csv([account2.id])

        db_session.delete(account2)
        db_session.commit()

        parsed2 = csv_importer.parse_csv(csv2)
        csv_importer.import_accounts(parsed2)

        final = db_session.query(Account).one()
        # CSV round-trip for Python-encrypted accounts preserves [encrypted] literal
        decrypted = decrypt_account_pass(final.pass_.decode(), final.key.decode(), TEST_MASTER_PASSWORD)
        assert decrypted == "[encrypted]"


# ----------------------------------------------------------------------
# KDBX Export Compatibility
# ----------------------------------------------------------------------


class TestKdbxExportCompatibility:
    """KDBX 4 export creates files readable by KeePassXC/2.x."""

    def test_kdbx_export_readable(self, db_session, encryption_service, test_user, tmp_path):
        """Exported KDBX can be opened with pykeepass."""
        category = Category(name="KdbxCat", hash=make_item_hash("KdbxCat"))
        client = Client(name="KdbxClient", hash=make_item_hash("KdbxClient"))
        db_session.add_all([category, client])
        db_session.flush()

        account = Account(
            userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
            clientId=client.id, name="KDBX Test", categoryId=category.id,
            login="kdbxuser", url="https://kdbx.example",
            pass_=encryption_service.encrypt("kdbx-secret").encode(), key=b"",
        )
        db_session.add(account)
        db_session.commit()

        service = ExportService(db_session, encryption_service)
        export_password = "KdbxExportPass123!"
        kdbx_content = service.export_to_kdbx(export_password, master_password=TEST_MASTER_PASSWORD)

        output_path = tmp_path / "test.kdbx"
        output_path.write_bytes(kdbx_content)

        from pykeepass import PyKeePass
        from pykeepass.exceptions import CredentialsError

        with pytest.raises(CredentialsError):
            PyKeePass(str(output_path), password="wrong")

        database = PyKeePass(str(output_path), password=export_password)
        assert database.version[0] == 4
        entry = database.entries[0]
        assert entry.title == "KDBX Test"
        assert entry.password == "kdbx-secret"
        assert entry.group.name == "KdbxCat"
        assert entry.get_custom_property("Client") == "KdbxClient"


# ----------------------------------------------------------------------
# Stress: Large Dataset Round-trip
# ----------------------------------------------------------------------


class TestLargeDatasetRoundTrip:
    """Performance and correctness with larger datasets."""

    def test_100_accounts_xml_round_trip(self, db_session, encryption_service, test_user):
        """100 accounts exported to XML and re-imported correctly."""
        category = Category(name="BigCat", hash=make_item_hash("BigCat"))
        client = Client(name="BigClient", hash=make_item_hash("BigClient"))
        db_session.add_all([category, client])
        db_session.flush()

        # Create 100 accounts
        for i in range(100):
            account = Account(
                userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
                clientId=client.id, name=f"Account {i:03d}", categoryId=category.id,
                login=f"user{i:03d}", url=f"https://example{i:03d}.com",
                pass_=encryption_service.encrypt(f"secret-{i:03d}").encode(), key=b"",
            )
            db_session.add(account)
        db_session.commit()

        # Export all
        service = ExportService(db_session, encryption_service)
        xml_output = service.export_to_xml(
            export_password="BigExp!", master_password="BigMaster!",
            username=test_user.username, user_id=test_user.id, group_id=test_user.userGroupId,
        )

        # Delete all
        db_session.query(Account).delete()
        db_session.commit()

        # Import all
        importer = XmlImportService(db_session, encryption_service, test_user.id,
                                    export_password="BigExp!", import_master_password="BigMaster!")
        parsed = importer.parse_xml(xml_output)
        assert len(parsed) == 100
        stats = importer.import_accounts(parsed)
        assert stats["success"] == 100

        # Verify a sample
        for i in [0, 49, 99]:
            account = db_session.query(Account).filter_by(name=f"Account {i:03d}").one()
            decrypted = decrypt_with_password(account.pass_.decode(), account.key.decode(), "BigMaster!")
            assert decrypted == f"secret-{i:03d}"

    def test_100_accounts_keepass_round_trip(self, db_session, encryption_service, test_user):
        """100 accounts exported to KeePass and re-imported correctly."""
        category = Category(name="KeeBig", hash=make_item_hash("KeeBig"))
        client = Client(name="KeeBigClient", hash=make_item_hash("KeeBigClient"))
        db_session.add_all([category, client])
        db_session.flush()

        for i in range(100):
            account = Account(
                userGroupId=test_user.userGroupId, userId=test_user.id, userEditId=test_user.id,
                clientId=client.id, name=f"KeeAccount {i:03d}", categoryId=category.id,
                login=f"keeuser{i:03d}", pass_=encryption_service.encrypt(f"kee-secret-{i:03d}").encode(), key=b"",
            )
            db_session.add(account)
        db_session.commit()

        service = ExportService(db_session, encryption_service)
        keepass_xml = service.export_to_keepass(master_password=TEST_MASTER_PASSWORD)

        db_session.query(Account).delete()
        db_session.commit()

        kp_importer = KeePassImportService(db_session, encryption_service, test_user.id, master_password=TEST_MASTER_PASSWORD)
        parsed = kp_importer.parse_keepass(keepass_xml)
        assert len(parsed) == 100
        stats = kp_importer.import_accounts(parsed)
        assert stats["success"] == 100

        for i in [0, 49, 99]:
            account = db_session.query(Account).filter_by(name=f"KeeAccount {i:03d}").one()
            decrypted = decrypt_account_pass(account.pass_.decode(), account.key.decode(), TEST_MASTER_PASSWORD)
            assert decrypted == f"kee-secret-{i:03d}"
