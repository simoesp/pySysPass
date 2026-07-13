import json

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.deps import require_permission
from app.api.v1 import accounts, custom_fields
from app.core.security import get_encryption_service
from app.db.base import get_db
from app.schemas.account import AccountCreate
from app.schemas.user_profile import ProfilePermissions
from app.models.account import User, UserGroup
from app.models.custom_field import CustomFieldDef, CustomFieldType, CustomFieldValue
from app.services.account_service import AccountService
from app.services.auth_service import create_access_token, decode_token, get_password_hash


def _client(db_session):
    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1")
    app.include_router(custom_fields.router, prefix="/api/v1")

    @app.get("/config-probe")
    def config_probe(current_user=Depends(require_permission("config_general"))):
        return {"ok": True}

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _set_permissions(db_session, user, **grants):
    values = {key: False for key in ProfilePermissions.model_fields}
    values.update(grants)
    user.userProfile.profile = json.dumps(values).encode("utf-8")
    db_session.commit()


def _headers(user, *, is_admin_app=False, is_admin_acc=False):
    token = create_access_token(
        {"user_id": user.id, "username": user.username},
        is_admin_app=is_admin_app,
        is_admin_acc=is_admin_acc,
    )
    return {"Authorization": f"Bearer {token}"}


def test_php_admin_scopes_remain_distinct(db_session, test_user):
    _set_permissions(db_session, test_user)
    client = _client(db_session)

    account_admin_headers = _headers(test_user, is_admin_acc=True)
    assert client.get("/api/v1/accounts", headers=account_admin_headers).status_code == 200
    assert client.get("/config-probe", headers=account_admin_headers).status_code == 403

    app_admin_headers = _headers(test_user, is_admin_app=True)
    assert client.get("/config-probe", headers=app_admin_headers).status_code == 200

    claims = decode_token(account_admin_headers["Authorization"].removeprefix("Bearer "))
    assert claims["is_admin_app"] is False
    assert claims["is_admin_acc"] is True
    assert claims["is_admin"] is False


def test_php_account_view_accepts_view_or_edit_permission(db_session, test_user):
    client = _client(db_session)
    headers = _headers(test_user)

    _set_permissions(db_session, test_user)
    assert client.get("/api/v1/accounts", headers=headers).status_code == 403

    _set_permissions(db_session, test_user, acc_edit=True)
    assert client.get("/api/v1/accounts", headers=headers).status_code == 200


def test_php_account_create_and_private_capabilities_are_separate(db_session, test_user):
    client = _client(db_session)
    headers = _headers(test_user)
    payload = {"title": "Capability test", "password": "secret", "is_public": True}

    _set_permissions(db_session, test_user, acc_view=True)
    assert client.post("/api/v1/accounts", json=payload, headers=headers).status_code == 403

    _set_permissions(db_session, test_user, acc_add=True)
    assert client.post("/api/v1/accounts", json=payload, headers=headers).status_code == 201

    private_payload = {**payload, "title": "Private capability", "is_public": False}
    assert client.post("/api/v1/accounts", json=private_payload, headers=headers).status_code == 403

    _set_permissions(db_session, test_user, acc_add=True, acc_private=True)
    assert client.post("/api/v1/accounts", json=private_payload, headers=headers).status_code == 201


def test_php_password_permissions_are_independent_from_account_edit(db_session, test_user):
    account = AccountService(db_session, get_encryption_service()).create_account(
        AccountCreate(title="Protected password", password="secret", is_public=True),
        test_user.id,
    )
    client = _client(db_session)
    headers = _headers(test_user)

    _set_permissions(db_session, test_user, acc_view=True, acc_edit=True)
    password_url = f"/api/v1/accounts/{account.id}/password"
    assert client.get(password_url, headers=headers).status_code == 403
    assert client.put(
        f"/api/v1/accounts/{account.id}",
        json={"password": "replacement"},
        headers=headers,
    ).status_code == 403

    _set_permissions(
        db_session,
        test_user,
        acc_view=True,
        acc_view_pass=True,
        acc_edit=True,
        acc_edit_pass=True,
    )
    response = client.get(password_url, headers=headers)
    assert response.status_code == 200
    assert response.json()["password"] == "secret"
    assert client.put(
        f"/api/v1/accounts/{account.id}",
        json={"password": "replacement"},
        headers=headers,
    ).status_code == 200


def test_account_custom_fields_inherit_profile_and_object_acl(db_session, test_user):
    account_service = AccountService(db_session, get_encryption_service())
    own_account = account_service.create_account(
        AccountCreate(title="Custom fields owner", password="secret", is_public=True),
        test_user.id,
    )
    other_group = UserGroup(name="Custom field outsiders")
    db_session.add(other_group)
    db_session.flush()
    other_user = User(
        username="custom-field-owner",
        password=get_password_hash("testpassword"),
        userGroupId=other_group.id,
        userProfileId=1,
    )
    db_session.add(other_user)
    db_session.flush()
    hidden_account = account_service.create_account(
        AccountCreate(title="Hidden custom fields", password="secret", is_public=True),
        other_user.id,
    )
    field_type = CustomFieldType(id=1, name="text", text="Text")
    db_session.add(field_type)
    db_session.flush()
    definition = CustomFieldDef(
        id=1,
        name="Environment",
        moduleId=1,
        typeId=field_type.id,
        isEncrypted=False,
    )
    db_session.add(definition)
    db_session.flush()
    db_session.add_all([
        CustomFieldValue(
            id=1,
            moduleId=1,
            itemId=own_account.id,
            definitionId=definition.id,
            data=b"production",
        ),
        CustomFieldValue(
            id=2,
            moduleId=1,
            itemId=hidden_account.id,
            definitionId=definition.id,
            data=b"restricted",
        ),
    ])
    db_session.commit()

    client = _client(db_session)
    headers = _headers(test_user)
    _set_permissions(db_session, test_user, acc_view=True)

    own_url = f"/api/v1/custom-fields/values/account/{own_account.id}"
    response = client.get(own_url, headers=headers)
    assert response.status_code == 200
    assert response.json()[0]["value"] == "production"
    assert client.get(
        f"/api/v1/custom-fields/values/account/{hidden_account.id}",
        headers=headers,
    ).status_code == 404
    assert client.post(
        "/api/v1/custom-fields/values",
        json={
            "def_id": definition.id,
            "item_id": own_account.id,
            "module_id": 1,
            "value": "staging",
        },
        headers=headers,
    ).status_code == 403

    _set_permissions(db_session, test_user, acc_edit=True)
    assert client.post(
        "/api/v1/custom-fields/values",
        json={
            "def_id": definition.id,
            "item_id": own_account.id,
            "module_id": 1,
            "value": "staging",
        },
        headers=headers,
    ).status_code == 200
