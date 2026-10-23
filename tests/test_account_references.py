"""R4 / #55: account data must satisfy the PHP schema's required references.

sysPass PHP requires a client and a category for every account
(AccountForm::checkCommon) and the canonical schema makes Account.clientId /
Account.categoryId NOT NULL foreign keys with RESTRICT deletes. The API must
answer with validation errors, never database errors.
"""
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import accounts, categories, clients
from app.db.base import get_db
from app.models.account import Account, AccountHistory, Category, Client, Tag
from app.schemas.user_profile import ProfilePermissions
from app.services.auth_service import create_access_token
from app.services.category_service import make_item_hash
from app.services.import_export_service import (
    CsvImportService,
    KeePassImportService,
    XmlImportService,
)
from tests.account_refs import TEST_CATEGORY_ID, TEST_CLIENT_ID


def _client(db_session):
    app = FastAPI()
    for module in (accounts, categories, clients):
        app.include_router(module.router, prefix="/api/v1")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _headers(db_session, user):
    user.userProfile.profile = json.dumps(
        {key: True for key in ProfilePermissions.model_fields}
    ).encode("utf-8")
    db_session.commit()
    token = create_access_token({"user_id": user.id, "username": user.username})
    return {"Authorization": f"Bearer {token}"}


def _payload(**overrides):
    payload = {
        "title": "Reference test",
        "password": "secret",
        "is_public": True,
        "client_id": TEST_CLIENT_ID,
        "category_id": TEST_CATEGORY_ID,
    }
    payload.update(overrides)
    return {key: value for key, value in payload.items() if value is not None}


def test_create_requires_client_and_category(db_session, test_user):
    client = _client(db_session)
    headers = _headers(db_session, test_user)

    for missing in ("client_id", "category_id"):
        response = client.post("/api/v1/accounts", json=_payload(**{missing: None}), headers=headers)
        assert response.status_code == 422, missing
        response = client.post("/api/v1/accounts", json=_payload(**{missing: 0}), headers=headers)
        assert response.status_code == 422, missing

    assert db_session.query(Account).count() == 0
    assert client.post("/api/v1/accounts", json=_payload(), headers=headers).status_code == 201


def test_create_rejects_unknown_references(db_session, test_user):
    client = _client(db_session)
    headers = _headers(db_session, test_user)
    cases = {
        "client": _payload(client_id=4242),
        "category": _payload(category_id=4242),
        "tag": _payload(tag_ids=[4242]),
        "user": _payload(shared_users=[{"user_id": 4242}]),
        "user group": _payload(shared_groups=[{"group_id": 4242}]),
    }
    for label, payload in cases.items():
        response = client.post("/api/v1/accounts", json=payload, headers=headers)
        assert response.status_code == 422, label
        assert response.json()["detail"] == f"Unknown {label} id: 4242"
    assert db_session.query(Account).count() == 0


def test_create_enforces_php_column_lengths(db_session, test_user):
    client = _client(db_session)
    headers = _headers(db_session, test_user)
    too_long = {
        "title": "x" * 101,
        "login": "x" * 51,
        "url": "x" * 256,
        "notes": "é" * 32768,  # 65536 UTF-8 bytes exceeds MySQL TEXT
    }
    for field, value in too_long.items():
        response = client.post("/api/v1/accounts", json=_payload(**{field: value}), headers=headers)
        assert response.status_code == 422, field
    accepted = _payload(title="x" * 100, login="x" * 50, url="x" * 255, notes="é" * 32767)
    assert client.post("/api/v1/accounts", json=accepted, headers=headers).status_code == 201


def test_duplicate_tag_and_share_ids_are_collapsed(db_session, test_user):
    db_session.add(Tag(id=7, name="dup", hash=make_item_hash("dup")))
    db_session.commit()
    client = _client(db_session)
    headers = _headers(db_session, test_user)
    response = client.post(
        "/api/v1/accounts",
        json=_payload(tag_ids=[7, 7], shared_users=[{"user_id": test_user.id}] * 2),
        headers=headers,
    )
    assert response.status_code == 201
    assert [tag["id"] for tag in response.json()["tags"]] == [7]


def test_update_rejects_unknown_references_without_changes(db_session, test_user):
    client = _client(db_session)
    headers = _headers(db_session, test_user)
    account_id = client.post("/api/v1/accounts", json=_payload(), headers=headers).json()["id"]

    for body in ({"category_id": 4242}, {"client_id": 4242}, {"category_id": 0}, {"title": ""}):
        response = client.put(f"/api/v1/accounts/{account_id}", json=body, headers=headers)
        assert response.status_code == 422, body

    account = db_session.get(Account, account_id)
    db_session.refresh(account)
    assert (account.clientId, account.categoryId, account.name) == (
        TEST_CLIENT_ID, TEST_CATEGORY_ID, "Reference test"
    )
    assert db_session.query(AccountHistory).count() == 0


def test_in_use_category_and_client_cannot_be_deleted(db_session, test_user):
    client = _client(db_session)
    headers = _headers(db_session, test_user)
    assert client.post("/api/v1/accounts", json=_payload(), headers=headers).status_code == 201

    assert client.delete(f"/api/v1/categories/{TEST_CATEGORY_ID}", headers=headers).status_code == 409
    assert client.delete(f"/api/v1/clients/{TEST_CLIENT_ID}", headers=headers).status_code == 409
    account = db_session.query(Account).one()
    assert (account.clientId, account.categoryId) == (TEST_CLIENT_ID, TEST_CATEGORY_ID)

    unused_category = Category(id=1, name="Unused", hash=make_item_hash("Unused"))
    unused_client = Client(id=1, name="Unused", hash=make_item_hash("Unused"))
    db_session.add_all([unused_category, unused_client])
    db_session.commit()
    assert client.delete("/api/v1/categories/1", headers=headers).status_code == 204
    assert client.delete("/api/v1/clients/1", headers=headers).status_code == 204


def test_category_referenced_only_by_history_cannot_be_deleted(db_session, test_user):
    client = _client(db_session)
    headers = _headers(db_session, test_user)
    db_session.add(Category(id=1, name="Old", hash=make_item_hash("Old")))
    db_session.commit()
    account_id = client.post("/api/v1/accounts", json=_payload(category_id=1), headers=headers).json()["id"]
    response = client.put(
        f"/api/v1/accounts/{account_id}", json={"category_id": TEST_CATEGORY_ID}, headers=headers
    )
    assert response.status_code == 200
    assert db_session.query(AccountHistory).filter_by(categoryId=1).count() == 1
    assert client.delete("/api/v1/categories/1", headers=headers).status_code == 409


def test_csv_import_rejects_rows_without_client_or_category(db_session, encryption_service, test_user):
    importer = CsvImportService(db_session, encryption_service, test_user.id)
    rows = importer.parse_csv(
        "name,client,category,password\n"
        "complete,Acme,Servers,secret\n"
        "no-client,,Servers,secret\n"
        "no-category,Acme,,secret\n"
    )
    stats = importer.import_accounts(rows)
    assert stats == {"success": 1, "failed": 0, "skipped": 2}
    assert [a.name for a in db_session.query(Account).all()] == ["complete"]
    assert "Account 'no-client' requires both a client and a category" in importer.errors
    assert "Account 'no-category' requires both a client and a category" in importer.errors


def test_xml_import_rejects_accounts_without_client_or_category(db_session, encryption_service, test_user):
    importer = XmlImportService(db_session, encryption_service, test_user.id)
    stats = importer.import_accounts([
        {"name": "no-refs", "pass": "secret"},
        {"name": "complete", "pass": "secret", "client": "Acme", "category": "Servers"},
    ])
    assert stats == {"success": 1, "failed": 0, "skipped": 1}
    assert [a.name for a in db_session.query(Account).all()] == ["complete"]


def test_keepass_import_matches_php_client_and_category_mapping(db_session, encryption_service, test_user):
    xml = """<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Root><Group><Name>Database</Name>
  <Entry><String><Key>Title</Key><Value>root entry</Value></String></Entry>
  <Group><Name>Servers</Name>
    <Entry><String><Key>Title</Key><Value>nested entry</Value></String></Entry>
  </Group>
</Group></Root></KeePassFile>"""
    importer = KeePassImportService(db_session, encryption_service, test_user.id)
    stats = importer.import_accounts(importer.parse_keepass(xml))
    assert stats == {"success": 2, "failed": 0, "skipped": 0}

    keepass_client = db_session.query(Client).filter_by(name="KeePass").one()
    by_name = {a.name: a for a in db_session.query(Account).all()}
    assert {a.clientId for a in by_name.values()} == {keepass_client.id}
    categories = {c.id: c for c in db_session.query(Category).all()}
    assert categories[by_name["root entry"].categoryId].name == "Database"
    assert categories[by_name["nested entry"].categoryId].name == "Servers"
    assert categories[by_name["nested entry"].categoryId].description == "KeePass"
