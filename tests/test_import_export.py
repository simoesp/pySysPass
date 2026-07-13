import xml.etree.ElementTree as ET

import pytest

from app.core.security import EncryptionService
from app.core.defuse_compat import decrypt_with_password
from app.models.account import Account, AccountToTag, Category, Client, Tag
from app.services.category_service import make_item_hash
from app.services.import_export_service import ExportService, XmlImportService


def test_keepass_export_generates_valid_string_entries(db_session):
    encryption = EncryptionService("test-encryption-key-32bytes!!")
    encrypted_password = encryption.encrypt("secret-pass").encode("utf-8")

    account = Account(
        id=1,
        userGroupId=1,
        userId=1,
        userEditId=1,
        clientId=1,
        name="Demo Account",
        categoryId=1,
        login="alice",
        url="https://example.com",
        pass_=encrypted_password,
        key=b"",
        notes="Imported notes",
    )
    db_session.add(account)
    db_session.commit()

    xml_output = ExportService(db_session, encryption).export_to_keepass()
    root = ET.fromstring(xml_output)

    entry = root.find(".//Entry")
    assert entry is not None

    values = {}
    for string_elem in entry.findall("String"):
        key = string_elem.findtext("Key")
        value = string_elem.findtext("Value")
        values[key] = value

    assert values["Title"] == "Demo Account"
    assert values["UserName"] == "alice"
    assert values["Password"] == "secret-pass"
    assert values["URL"] == "https://example.com"
    assert values["Notes"] == "Imported notes"


def test_php_native_protected_xml_round_trip(db_session, test_user):
    encryption = EncryptionService("test-encryption-key-32bytes!!")
    category_name = "Native XML category"
    client_name = "Native XML client"
    tag_name = "Native XML tag"
    category = Category(
        name=category_name,
        description="Category",
        hash=make_item_hash(category_name),
    )
    client = Client(
        name=client_name,
        description="Client",
        hash=make_item_hash(client_name),
    )
    tag = Tag(name=tag_name, hash=make_item_hash(tag_name))
    db_session.add_all([category, client, tag])
    db_session.flush()
    account = Account(
        userGroupId=test_user.userGroupId,
        userId=test_user.id,
        userEditId=test_user.id,
        clientId=client.id,
        name="Native XML account",
        categoryId=category.id,
        login="native-user",
        url="https://native.example.test",
        pass_=encryption.encrypt("native-secret").encode("ascii"),
        key=b"",
        notes="PHP format",
    )
    db_session.add(account)
    db_session.flush()
    account_tag = AccountToTag(accountId=account.id, tagId=tag.id)
    db_session.add(account_tag)
    db_session.commit()

    export_password = "ExportFixture!2026"
    master_password = "MasterFixture!2026"
    xml_output = ExportService(db_session, encryption).export_to_xml(
        [account.id],
        export_password=export_password,
        master_password=master_password,
        username=test_user.username,
        user_id=test_user.id,
        group_id=test_user.userGroupId,
    )
    root = ET.fromstring(xml_output)
    assert root.tag == "Root"
    assert root.findtext("./Meta/Generator") == "sysPass"
    assert len(root.findall("./Encrypted/Data")) == 4
    assert root.find("./Accounts") is None
    assert "password_requires_reencryption" not in xml_output

    # The destination must not already contain exported lookup rows. This is
    # the real PHP restore scenario and exercises all three creation helpers.
    db_session.delete(account_tag)
    db_session.delete(account)
    db_session.flush()
    db_session.delete(category)
    db_session.delete(client)
    db_session.delete(tag)
    db_session.commit()

    with pytest.raises(ValueError):
        XmlImportService(
            db_session,
            encryption,
            test_user.id,
            export_password="wrong-export-password",
        ).parse_xml(xml_output)

    importer = XmlImportService(
        db_session,
        encryption,
        test_user.id,
        export_password=export_password,
        import_master_password=master_password,
    )
    parsed = importer.parse_xml(xml_output)
    assert len(parsed) == 1
    assert parsed[0]["category"] == category_name
    assert parsed[0]["client"] == client_name
    assert parsed[0]["tags"] == tag_name
    assert decrypt_with_password(
        parsed[0]["pass"], parsed[0]["key"], master_password
    ) == "native-secret"

    stats = importer.import_accounts(parsed)
    assert stats == {"success": 1, "failed": 0, "skipped": 0}
    imported = db_session.query(Account).one()
    assert db_session.query(Category).one().hash == make_item_hash(category_name)
    assert db_session.query(Client).one().hash == make_item_hash(client_name)
    assert db_session.query(Tag).one().hash == make_item_hash(tag_name)
    assert decrypt_with_password(
        imported.pass_.decode("ascii"),
        imported.key.decode("ascii"),
        master_password,
    ) == "native-secret"
