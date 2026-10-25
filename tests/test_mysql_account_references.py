"""Canonical MySQL coverage for R4 / #55 (required account references).

SQLite cannot prove PHP schema behavior, so these tests run against a real
MySQL server bootstrapped from ``schemas/dbstructure.sql``. They are skipped
unless ``PYSYSPASS_MYSQL_TEST_URL`` names a server where the test may create
and drop a disposable database, e.g.::

    PYSYSPASS_MYSQL_TEST_URL=mysql+pymysql://root:root@127.0.0.1:3306/

Never point this at a server holding real sysPass data.
"""
import json
import os
import secrets

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.api.v1 import accounts, categories
from app.db.base import get_db
from app.db.bootstrap import bootstrap_database
from app.models.account import Account, Category, Client, User, UserGroup, UserProfile
from app.schemas.user_profile import ProfilePermissions
from app.services.auth_service import issue_session_token, get_password_hash
from app.services.category_service import make_item_hash
from app.services.import_export_service import CsvImportService
from tests.account_refs import TEST_MASTER_PASSWORD

MYSQL_URL = os.environ.get("PYSYSPASS_MYSQL_TEST_URL")

pytestmark = pytest.mark.skipif(
    not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set (disposable MySQL server required)"
)


@pytest.fixture(scope="module")
def mysql_engine():
    server_url = make_url(MYSQL_URL)
    database = f"pysyspass_test_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    with admin.begin() as conn:
        conn.execute(text(f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
    engine = create_engine(server_url.set(database=database))
    try:
        assert bootstrap_database(engine) is True
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))
        admin.dispose()


@pytest.fixture()
def mysql_session(mysql_engine):
    session = sessionmaker(bind=mysql_engine)()
    profile = UserProfile(
        name=f"profile-{secrets.token_hex(3)}",
        profile=json.dumps({key: True for key in ProfilePermissions.model_fields}).encode("utf-8"),
    )
    group = UserGroup(name=f"group-{secrets.token_hex(3)}")
    session.add_all([profile, group])
    session.flush()
    user = User(
        name="MySQL test",
        username=f"mysql-{secrets.token_hex(3)}",
        email="mysql@example.com",
        password=get_password_hash("unused").encode("utf-8"),
        userGroupId=group.id,
        userProfileId=profile.id,
        hashSalt=secrets.token_bytes(32),
    )
    client = Client(name=f"client-{secrets.token_hex(3)}")
    category = Category(name=f"category-{secrets.token_hex(3)}")
    client.hash = make_item_hash(client.name)
    category.hash = make_item_hash(category.name)
    session.add_all([user, client, category])
    session.commit()
    try:
        yield session, user, client, category
    finally:
        session.rollback()
        session.close()


def _api(session):
    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1")
    app.include_router(categories.router, prefix="/api/v1")

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _headers(user):
    token = issue_session_token(user, master_pass=TEST_MASTER_PASSWORD)
    return {"Authorization": f"Bearer {token}"}


def test_canonical_schema_rejects_null_references(mysql_session):
    session, user, client, category = mysql_session
    session.add(Account(
        name="null client", userId=user.id, userEditId=user.id, userGroupId=user.userGroupId,
        categoryId=category.id, pass_=b"x", key=b"",
    ))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_api_returns_validation_errors_instead_of_mysql_errors(mysql_session):
    session, user, client, category = mysql_session
    api = _api(session)
    headers = _headers(user)
    base = {"title": "MySQL account", "password": "secret", "is_public": True}

    for body in (
        base,
        {**base, "client_id": client.id},
        {**base, "category_id": category.id},
        {**base, "client_id": 16000000, "category_id": category.id},
        {**base, "client_id": client.id, "category_id": 16000000},
        {**base, "client_id": client.id, "category_id": category.id, "title": "x" * 101},
    ):
        assert api.post("/api/v1/accounts", json=body, headers=headers).status_code == 422, body

    created = api.post(
        "/api/v1/accounts",
        json={**base, "client_id": client.id, "category_id": category.id},
        headers=headers,
    )
    assert created.status_code == 201
    account_id = created.json()["id"]

    updated = api.put(f"/api/v1/accounts/{account_id}", json={"category_id": 16000000}, headers=headers)
    assert updated.status_code == 422
    assert api.delete(f"/api/v1/categories/{category.id}", headers=headers).status_code == 409

    session.expire_all()
    account = session.get(Account, account_id)
    assert (account.clientId, account.categoryId) == (client.id, category.id)


def test_csv_import_on_canonical_schema(mysql_session, encryption_service):
    session, user, client, category = mysql_session
    importer = CsvImportService(session, encryption_service, user.id, master_password=TEST_MASTER_PASSWORD)
    rows = importer.parse_csv(
        "name,client,category,password\n"
        f"mysql-import,{client.name},new-mysql-category,secret\n"
        "mysql-missing,,new-mysql-category,secret\n"
    )
    assert importer.import_accounts(rows) == {"success": 1, "failed": 0, "skipped": 1}
    imported = session.query(Account).filter_by(name="mysql-import").one()
    assert imported.clientId == client.id
    assert session.get(Category, imported.categoryId).name == "new-mysql-category"
    assert session.query(Account).filter_by(name="mysql-missing").count() == 0


def test_failed_import_row_does_not_abort_later_rows(mysql_session, encryption_service):
    session, user, client, category = mysql_session
    importer = CsvImportService(session, encryption_service, user.id, master_password=TEST_MASTER_PASSWORD)
    rows = importer.parse_csv(
        "name,client,category,login,password\n"
        f"too-long-login,{client.name},{category.name},{'x' * 51},secret\n"
        f"after-failure,{client.name},{category.name},ok,secret\n"
    )
    assert importer.import_accounts(rows) == {"success": 1, "failed": 1, "skipped": 0}
    assert session.query(Account).filter_by(name="after-failure").count() == 1
    assert session.query(Account).filter_by(name="too-long-login").count() == 0


def test_master_password_rotation_is_atomic_on_mysql(mysql_session, monkeypatch):
    """R8 / #58: an aborted rotation leaves no partial rewrite on InnoDB."""
    from app.core.defuse_compat import decrypt_account_pass, encrypt_account_pass
    from app.models.account import Config
    from app.services import master_password_rotation as rotation_module
    from app.services.auth_service import hash_master_key

    session, user, client, category = mysql_session
    old, new = "mysql-old-master", "mysql-new-master"
    for parameter, value in (("masterPwd", hash_master_key(old)), ("maintenance", "true")):
        row = session.query(Config).filter_by(parameter=parameter).first()
        if row:
            row.value = value
        else:
            session.add(Config(parameter=parameter, value=value))
    ids = []
    for index in range(3):
        pass_hex, key_hex = encrypt_account_pass(f"secret-{index}", old)
        account = Account(name=f"rotate-{index}-{user.id}", userId=user.id, userEditId=user.id,
                          userGroupId=user.userGroupId, clientId=client.id, categoryId=category.id,
                          pass_=pass_hex.encode(), key=key_hex.encode())
        session.add(account)
        session.flush()
        ids.append(account.id)
    session.commit()
    # Other tests' accounts in this module use other masters; rotate only ours.
    others = session.query(Account).filter(Account.id.notin_(ids)).all()
    for other in others:
        session.delete(other)
    session.commit()

    monkeypatch.setattr(rotation_module, "hash_master_key", lambda _: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        rotation_module.MasterPasswordRotation(session).rotate(old, new)
    session.expire_all()
    for index, account_id in enumerate(ids):
        account = session.get(Account, account_id)
        assert decrypt_account_pass(account.pass_.decode(), account.key.decode(), old) == f"secret-{index}"

    monkeypatch.undo()
    rotation_module.MasterPasswordRotation(session).rotate(old, new)
    session.expire_all()
    for index, account_id in enumerate(ids):
        account = session.get(Account, account_id)
        assert decrypt_account_pass(account.pass_.decode(), account.key.decode(), new) == f"secret-{index}"
