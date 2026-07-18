import pytest

from app.models.account import Account, AccountHistory, Config
from app.schemas.account import AccountCreate, AccountUpdate
from app.services.account_service import AccountService
from app.services.history_service import HistoryService


def _create_account(db_session, encryption_service, user, title="Test Account", password="secret"):
    return AccountService(db_session, encryption_service).create_account(
        AccountCreate(title=title, password=password), user.id
    )


@pytest.mark.asyncio
async def test_account_update_creates_php_compatible_preupdate_snapshot(
    db_session, encryption_service, test_user
):
    db_session.add(Config(parameter="masterPwd", value="$2y$10$php-master-hash"))
    db_session.commit()
    created = _create_account(db_session, encryption_service, test_user,
                              title="Original Title", password="old-secret")
    original = db_session.query(Account).filter(Account.id == created.id).one()
    original_password = original.pass_

    updated = AccountService(db_session, encryption_service).update_account(
        created.id,
        AccountUpdate(title="Updated Title", password="new-secret"),
        test_user.id,
    )

    rows = HistoryService(db_session).get_account_history(created.id, test_user.id)
    assert updated.title == "Updated Title"
    assert len(rows) == 1
    assert rows[0].name == "Original Title"
    assert rows[0].pass_ == original_password
    assert rows[0].mPassHash == b"$2y$10$php-master-hash"
    assert rows[0].isModify is True
    assert rows[0].isDeleted is False
    assert rows[0].action == "update"
    assert rows[0].old_value is None
    assert rows[0].new_value is None


@pytest.mark.asyncio
async def test_multiple_updates_create_ordered_restore_snapshots(
    db_session, encryption_service, test_user
):
    created = _create_account(db_session, encryption_service, test_user, title="Version 1")
    service = AccountService(db_session, encryption_service)
    service.update_account(created.id, AccountUpdate(title="Version 2"), test_user.id)
    service.update_account(created.id, AccountUpdate(title="Version 3"), test_user.id)

    rows = HistoryService(db_session).get_account_history(created.id, test_user.id)
    assert [row.name for row in rows] == ["Version 2", "Version 1"]
    assert all(row.action == "update" for row in rows)


@pytest.mark.asyncio
async def test_delete_preserves_php_compatible_snapshot(
    db_session, encryption_service, test_user
):
    created = _create_account(db_session, encryption_service, test_user, title="Deleted Account")

    assert AccountService(db_session, encryption_service).delete_account(
        created.id, test_user.id
    ) is True

    row = db_session.query(AccountHistory).filter(
        AccountHistory.accountId == created.id
    ).one()
    assert row.name == "Deleted Account"
    assert row.isModify is False
    assert row.isDeleted is True
    assert row.action == "delete"


@pytest.mark.asyncio
async def test_view_and_decrypt_counts_use_php_account_counters(
    db_session, encryption_service, test_user
):
    created = _create_account(db_session, encryption_service, test_user)
    accounts = AccountService(db_session, encryption_service)
    accounts.get_account(created.id, test_user.id)
    accounts.get_account(created.id, test_user.id)
    accounts.get_decrypted_password(created.id, test_user.id)

    history = HistoryService(db_session)
    assert history.get_account_view_count(created.id) == 2
    assert history.get_account_decrypt_count(created.id) == 1
    assert history.get_account_history(created.id, test_user.id) == []


@pytest.mark.asyncio
async def test_audit_only_helpers_do_not_invent_php_history_rows(
    db_session, encryption_service, test_user
):
    created = _create_account(db_session, encryption_service, test_user)
    history = HistoryService(db_session)

    assert history.log_view(created.id, test_user.id) is None
    assert history.log_decrypt(created.id, test_user.id) is None
    assert history.log_file_upload(created.id, test_user.id, "document.pdf") is None
    assert history.log_file_download(created.id, test_user.id, "document.pdf") is None
    assert db_session.query(AccountHistory).count() == 0


def test_account_history_has_no_python_only_physical_columns():
    columns = set(AccountHistory.__table__.columns.keys())
    assert {"action", "oldValue", "newValue"}.isdisjoint(columns)


def test_history_api_returns_snapshots_to_shared_users(
    db_session, encryption_service, test_user
):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.v1 import history as history_api
    from app.db.base import get_db
    from app.models.account import User
    from app.services.auth_service import create_access_token, get_password_hash

    viewer = User(
        username="history-viewer",
        email="history-viewer@example.com",
        password=get_password_hash("testpassword"),
        isUserAdmin=False,
        userGroupId=1,
        userProfileId=1,
        hashSalt=b"history-viewer-salt",
    )
    db_session.add(viewer)
    db_session.commit()
    db_session.refresh(viewer)

    created = AccountService(db_session, encryption_service).create_account(
        AccountCreate(
            title="Shared History Version 1",
            password="secret",
            is_public=True,
            shared_users=[{"user_id": viewer.id, "is_edit": False}],
        ),
        test_user.id,
    )
    AccountService(db_session, encryption_service).update_account(
        created.id, AccountUpdate(title="Shared History Version 2"), test_user.id
    )

    app = FastAPI()
    app.include_router(history_api.router, prefix="/api/v1")

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    token = create_access_token({"user_id": viewer.id, "username": viewer.username})
    response = TestClient(app).get(
        f"/api/v1/accounts/{created.id}/history",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()[0]["action"] == "update"
    assert response.json()[0]["old_value"] is None
    assert response.json()[0]["new_value"] is None


def test_history_routes_are_registered():
    from app.main import app

    from tests.conftest import api_route_paths
    route_paths = api_route_paths(app)
    assert "/api/v1/accounts/{account_id}/history" in route_paths
    assert "/api/v1/accounts/{account_id}/history/decrypt-count" in route_paths
    assert "/api/v1/accounts/{account_id}/history/view-count" in route_paths
    assert "/api/v1/users/{user_id}/history" in route_paths


@pytest.mark.asyncio
async def test_history_visibility_follows_snapshot_group(
    db_session, encryption_service, test_user
):
    """PHP getFilterHistory parity: snapshots are visible per their own
    userGroupId, not the account's current group."""
    from app.models.account import Account, User, UserGroup
    from app.services.account_service import AccountService
    from app.services.auth_service import get_password_hash

    db_session.add(Config(parameter="masterPwd", value="$2y$10$php-master-hash"))
    for gid, name in ((20, "Era A"), (21, "Era B")):
        db_session.add(UserGroup(id=gid, name=name, description=""))
    db_session.commit()

    account = _create_account(db_session, encryption_service, test_user)
    acc_row = db_session.query(Account).filter(Account.id == account.id).first()
    acc_row.isPrivate = False
    acc_row.userGroupId = 20
    db_session.commit()

    history = HistoryService(db_session)
    history.create_snapshot(acc_row, is_modify=True)  # snapshot from group-20 era

    acc_row.userGroupId = 21
    db_session.commit()
    history.create_snapshot(acc_row, is_modify=True)  # snapshot from group-21 era

    viewer = User(
        username="era-b-viewer", email="erab@example.com",
        password=get_password_hash("x"), userGroupId=21,
    )
    db_session.add(viewer)
    db_session.commit()
    db_session.refresh(viewer)

    service = AccountService(db_session, encryption_service)
    # Viewer's group matches the account's CURRENT main group → account visible
    assert service.can_access_account(account.id, viewer.id)

    rows = history.get_account_history(
        account.id, access_filter=service.history_access_filter(viewer.id)
    )
    assert [r.userGroupId for r in rows] == [21]

    # The owner sees both eras (snapshot userId matches)
    owner_rows = history.get_account_history(
        account.id,
        access_filter=AccountService(db_session, encryption_service)
        .history_access_filter(test_user.id),
    )
    assert {r.userGroupId for r in owner_rows} == {20, 21}
