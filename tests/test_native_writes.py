"""R5 / #56: credential writes are native sysPass ciphertext or refused."""
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import accounts, import_export
from app.db.base import get_db
from app.models.account import Account, Config
from app.schemas.user_profile import ProfilePermissions
from app.services.account_service import AccountService
from app.services.auth_service import get_password_hash, issue_session_token
from app.services.auth_token_service import AuthTokenService
from tests.account_refs import TEST_CATEGORY_ID, TEST_CLIENT_ID, TEST_MASTER_PASSWORD, account_create

NEW_ACCOUNT = {"title": "x", "password": "y", "client_id": TEST_CLIENT_ID,
               "category_id": TEST_CATEGORY_ID, "is_public": True}


def _client(db_session):
    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1")
    app.include_router(import_export.router, prefix="/api/v1")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _grant_all(db_session, user):
    user.userProfile.profile = json.dumps({k: True for k in ProfilePermissions.model_fields}).encode()
    db_session.commit()


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_sessions_without_a_vault_key_cannot_write_passwords(db_session, test_user):
    _grant_all(db_session, test_user)
    client = _client(db_session)
    locked = _bearer(issue_session_token(test_user))  # no master password in this session

    response = client.post("/api/v1/accounts", json=NEW_ACCOUNT, headers=locked)
    assert response.status_code == 428
    assert response.json()["detail"]["code"] == "MASTER_PASSWORD_REQUIRED"
    assert db_session.query(Account).count() == 0

    unlocked = _bearer(issue_session_token(test_user, master_pass=TEST_MASTER_PASSWORD))
    account_id = client.post("/api/v1/accounts", json=NEW_ACCOUNT, headers=unlocked).json()["id"]
    assert client.put(f"/api/v1/accounts/{account_id}", json={"password": "z"}, headers=locked).status_code == 428
    # Metadata edits never touch ciphertext, so they stay allowed.
    assert client.put(f"/api/v1/accounts/{account_id}", json={"title": "renamed"}, headers=locked).status_code == 200
    assert client.post(f"/api/v1/accounts/{account_id}/copy", headers=locked).status_code == 428
    assert client.get(f"/api/v1/accounts/{account_id}/password", headers=locked).status_code == 428
    assert client.get(f"/api/v1/accounts/{account_id}/password", headers=unlocked).json()["password"] == "y"


def test_api_tokens_cannot_create_python_only_ciphertext(db_session, test_user):
    _grant_all(db_session, test_user)
    token = AuthTokenService(db_session).create_token(test_user.id, 5, test_user.id).token
    response = _client(db_session).post("/api/v1/accounts", json=NEW_ACCOUNT, headers=_bearer(token))
    assert response.status_code == 428  # Account Add scope, but no vault key
    assert db_session.query(Account).count() == 0


def test_imports_require_an_unlocked_vault(db_session, test_user):
    _grant_all(db_session, test_user)
    client = _client(db_session)
    csv = ("rows.csv", b"name,client,category,password\nrow,Acme,Ops,secret\n", "text/csv")
    locked = _bearer(issue_session_token(test_user))

    def upload(headers):
        return client.post(
            "/api/v1/import-export/import/csv", files={"file": csv}, data={"user_id": test_user.id}, headers=headers,
        )

    response = upload(locked)
    assert response.status_code == 428
    response = upload(_bearer(issue_session_token(test_user, master_pass=TEST_MASTER_PASSWORD)))
    assert response.status_code == 200, response.text
    stored = db_session.query(Account).filter_by(name="row").one()
    assert stored.key.startswith(b"def10000")
    service = AccountService(db_session, None)
    assert service.get_decrypted_password(stored.id, master_pass=TEST_MASTER_PASSWORD) == "secret"


def test_xml_import_rejects_a_target_master_that_is_not_the_vault(db_session, test_user):
    _grant_all(db_session, test_user)
    db_session.add(Config(parameter="masterPwd", value=get_password_hash(TEST_MASTER_PASSWORD)))
    db_session.commit()
    client = _client(db_session)
    xml = ("export.xml", b"<Root/>", "application/xml")
    response = client.post(
        "/api/v1/import-export/import/xml", files={"file": xml},
        data={"user_id": test_user.id, "current_master_password": "not-the-vault"},
        headers=_bearer(issue_session_token(test_user, master_pass=TEST_MASTER_PASSWORD)),
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "current_master_password does not match the vault"


def test_copy_reencrypts_natively(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    source = service.create_account(
        account_create(title="x" * 100, password="copied"), test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    copy = service.copy_account(source.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)
    stored = db_session.get(Account, copy["id"])
    assert stored.key.startswith(b"def10000") and stored.key != db_session.get(Account, source.id).key
    assert len(stored.name) <= 100  # PHP Account.name is varchar(100)
    assert service.get_decrypted_password(copy["id"], master_pass=TEST_MASTER_PASSWORD) == "copied"
