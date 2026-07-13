from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import account_sharing
from app.db.base import get_db
from app.models.account import User, UserGroup, UserToUserGroup
from app.schemas.account import AccountCreate
from app.services.account_service import AccountService
from app.services.auth_service import create_access_token, get_password_hash


def _make_client(db_session):
    app = FastAPI()
    app.include_router(account_sharing.router, prefix="/api/v1")

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    return app, TestClient(app)


def _auth_headers(user_id: int, username: str, is_admin: bool = False):
    token = create_access_token({"user_id": user_id, "username": username}, is_admin=is_admin)
    return {"Authorization": f"Bearer {token}"}


def _make_group(db_session, name: str) -> UserGroup:
    group = UserGroup(name=name, description="Sharing API group")
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)
    return group


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


def test_account_sharing_api_requires_authentication(db_session, encryption_service, test_user):
    target_group = _make_group(db_session, "Target Group")
    target = _make_user(db_session, "share-target", target_group.id)
    account = AccountService(db_session, encryption_service).create_account(
        AccountCreate(title="Protected Sharing", password="secret123", is_public=True),
        test_user.id,
    )

    app, client = _make_client(db_session)
    response = client.post(f"/api/v1/accounts/{account.id}/share/users", params={"user_id": target.id})

    assert response.status_code == 403

    app.dependency_overrides.clear()


def test_account_sharing_api_only_owner_can_share_account(db_session, encryption_service, test_user):
    other_group = _make_group(db_session, "Other Group")
    outsider = _make_user(db_session, "outsider-share", other_group.id)
    target = _make_user(db_session, "target-share", other_group.id)
    account = AccountService(db_session, encryption_service).create_account(
        AccountCreate(title="Owner Controlled", password="secret123", is_public=True),
        test_user.id,
    )

    app, client = _make_client(db_session)
    headers = _auth_headers(outsider.id, outsider.username)
    response = client.post(
        f"/api/v1/accounts/{account.id}/share/users",
        params={"user_id": target.id, "is_edit": "true"},
        headers=headers,
    )

    assert response.status_code == 403

    app.dependency_overrides.clear()


def test_account_sharing_api_owner_can_list_shared_users(db_session, encryption_service, test_user):
    target_group = _make_group(db_session, "Shared Users Group")
    target = _make_user(db_session, "listed-user", target_group.id)
    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(
            title="Share Listing",
            password="secret123",
            is_public=True,
            shared_users=[{"user_id": target.id, "is_edit": True}],
        ),
        test_user.id,
    )

    app, client = _make_client(db_session)
    owner_headers = _auth_headers(test_user.id, test_user.username)
    response = client.get(f"/api/v1/accounts/{account.id}/share/users", headers=owner_headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["user_id"] == target.id
    assert body[0]["is_edit"] is True

    app.dependency_overrides.clear()


def test_account_sharing_api_non_owner_cannot_list_shared_users(db_session, encryption_service, test_user):
    owner_group = _make_group(db_session, "Owner Group")
    outsider_group = _make_group(db_session, "Outsider Group")
    target = _make_user(db_session, "shared-person", owner_group.id)
    outsider = _make_user(db_session, "outsider-list", outsider_group.id)
    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(
            title="Hidden Share List",
            password="secret123",
            is_public=True,
            shared_users=[{"user_id": target.id, "is_edit": False}],
        ),
        test_user.id,
    )

    app, client = _make_client(db_session)
    outsider_headers = _auth_headers(outsider.id, outsider.username)
    response = client.get(f"/api/v1/accounts/{account.id}/share/users", headers=outsider_headers)

    assert response.status_code == 403

    app.dependency_overrides.clear()


def test_account_sharing_api_user_shared_accounts_are_self_only(db_session, encryption_service, test_user):
    owner_group = _make_group(db_session, "Owner Self Group")
    target_group = _make_group(db_session, "Target Self Group")
    owner = _make_user(db_session, "owner-self", owner_group.id)
    target = _make_user(db_session, "target-self", target_group.id)
    viewer = _make_user(db_session, "viewer-self", target_group.id)
    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(
            title="Shared Self",
            password="secret123",
            is_public=True,
            shared_users=[{"user_id": target.id, "is_edit": False}],
        ),
        owner.id,
    )
    assert account.id is not None

    app, client = _make_client(db_session)

    self_headers = _auth_headers(target.id, target.username)
    self_response = client.get(f"/api/v1/accounts/users/{target.id}/shared-accounts", headers=self_headers)
    assert self_response.status_code == 200
    assert len(self_response.json()) == 1

    viewer_headers = _auth_headers(viewer.id, viewer.username)
    blocked = client.get(f"/api/v1/accounts/users/{target.id}/shared-accounts", headers=viewer_headers)
    assert blocked.status_code == 403

    app.dependency_overrides.clear()


def test_account_sharing_api_group_accounts_require_membership(db_session, encryption_service, test_user):
    shared_group = _make_group(db_session, "Visible Group")
    member_primary = _make_group(db_session, "Member Primary")
    outsider_primary = _make_group(db_session, "Outsider Primary")
    member = _make_user(db_session, "group-member", member_primary.id)
    outsider = _make_user(db_session, "group-outsider", outsider_primary.id)
    db_session.add(UserToUserGroup(userId=member.id, userGroupId=shared_group.id, isManager=False))
    db_session.commit()

    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(
            title="Group Visible",
            password="secret123",
            is_public=True,
            shared_groups=[{"group_id": shared_group.id, "is_edit": False}],
        ),
        test_user.id,
    )
    assert account.id is not None

    app, client = _make_client(db_session)

    member_headers = _auth_headers(member.id, member.username)
    member_response = client.get(f"/api/v1/accounts/user-groups/{shared_group.id}/accounts", headers=member_headers)
    assert member_response.status_code == 200
    assert len(member_response.json()) == 1

    outsider_headers = _auth_headers(outsider.id, outsider.username)
    outsider_response = client.get(f"/api/v1/accounts/user-groups/{shared_group.id}/accounts", headers=outsider_headers)
    assert outsider_response.status_code == 403

    app.dependency_overrides.clear()
