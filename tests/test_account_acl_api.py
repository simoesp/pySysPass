from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import accounts
from app.db.base import get_db
from app.models.account import User, UserGroup
from app.schemas.account import AccountCreate
from app.services.account_service import AccountService
from app.services.auth_service import create_access_token, get_password_hash


def _make_client(db_session):
    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1")

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    return app, TestClient(app)


def _auth_headers(user_id: int, username: str):
    token = create_access_token({"user_id": user_id, "username": username})
    return {"Authorization": f"Bearer {token}"}


def _make_user(db_session, username: str, group_id: int) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password=get_password_hash("testpassword"),
        isUserAdmin=False,
        userGroupId=group_id,
        userProfileId=1,
        hashSalt=b"salt",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _make_group(db_session, name: str) -> UserGroup:
    group = UserGroup(name=name, description="API ACL group")
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)
    return group


def test_accounts_api_shared_user_view_only_cannot_update(db_session, encryption_service, test_user):
    viewer_group = _make_group(db_session, "API view-only group")
    viewer = _make_user(db_session, "api-viewer", viewer_group.id)
    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(
            title="API Shared",
            password="secret123",
            is_public=True,
            shared_users=[{"user_id": viewer.id, "is_edit": False}],
        ),
        test_user.id,
    )

    app, client = _make_client(db_session)
    headers = _auth_headers(viewer.id, viewer.username)

    fetch = client.get(f"/api/v1/accounts/{account.id}", headers=headers)
    assert fetch.status_code == 200
    assert fetch.json()["can_edit"] is False

    update = client.put(
        f"/api/v1/accounts/{account.id}",
        json={"title": "Should not change"},
        headers=headers,
    )
    assert update.status_code == 404

    app.dependency_overrides.clear()


def test_accounts_api_owner_can_grant_and_revoke_user_acl(db_session, encryption_service, test_user):
    other_group = _make_group(db_session, "Other API Group")
    viewer = _make_user(db_session, "acl-target", other_group.id)
    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(title="ACL Route", password="secret123", is_public=True),
        test_user.id,
    )

    app, client = _make_client(db_session)
    owner_headers = _auth_headers(test_user.id, test_user.username)
    viewer_headers = _auth_headers(viewer.id, viewer.username)

    before = client.get(f"/api/v1/accounts/{account.id}", headers=viewer_headers)
    assert before.status_code == 404

    grant = client.put(
        f"/api/v1/accounts/{account.id}/users/{viewer.id}",
        json={"is_edit": True},
        headers=owner_headers,
    )
    assert grant.status_code == 200

    after_grant = client.get(f"/api/v1/accounts/{account.id}", headers=viewer_headers)
    assert after_grant.status_code == 200
    assert after_grant.json()["can_edit"] is True

    revoke = client.delete(
        f"/api/v1/accounts/{account.id}/users/{viewer.id}",
        headers=owner_headers,
    )
    assert revoke.status_code == 204

    after_revoke = client.get(f"/api/v1/accounts/{account.id}", headers=viewer_headers)
    assert after_revoke.status_code == 404

    app.dependency_overrides.clear()


def test_accounts_api_non_owner_cannot_manage_user_acl(db_session, encryption_service, test_user):
    outsider = _make_user(db_session, "outsider-api", 1)
    target = _make_user(db_session, "target-api", 1)
    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(title="Owner Only ACL", password="secret123", is_public=True),
        test_user.id,
    )

    app, client = _make_client(db_session)
    outsider_headers = _auth_headers(outsider.id, outsider.username)

    grant = client.put(
        f"/api/v1/accounts/{account.id}/users/{target.id}",
        json={"is_edit": True},
        headers=outsider_headers,
    )
    assert grant.status_code == 404

    app.dependency_overrides.clear()


def test_accounts_api_group_acl_grant_allows_group_member_visibility(db_session, encryption_service, test_user):
    shared_group = _make_group(db_session, "Shared API Group")
    member = _make_user(db_session, "group-api-member", shared_group.id)

    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(title="Group ACL API", password="secret123", is_public=True),
        test_user.id,
    )

    app, client = _make_client(db_session)
    owner_headers = _auth_headers(test_user.id, test_user.username)
    member_headers = _auth_headers(member.id, member.username)

    before = client.get(f"/api/v1/accounts/{account.id}", headers=member_headers)
    assert before.status_code == 404

    grant = client.put(
        f"/api/v1/accounts/{account.id}/groups/{shared_group.id}",
        json={"is_edit": False},
        headers=owner_headers,
    )
    assert grant.status_code == 200

    after = client.get(f"/api/v1/accounts/{account.id}", headers=member_headers)
    assert after.status_code == 200
    assert after.json()["can_edit"] is False

    app.dependency_overrides.clear()
