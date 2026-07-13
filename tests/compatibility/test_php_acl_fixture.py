import json
from pathlib import Path

from app.models.account import (
    Account,
    AccountToUser,
    AccountToUserGroup,
    Config,
    User,
    UserGroup,
    UserToUserGroup,
)
from app.services.account_service import AccountService


FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "php_syspass_3211_acl.json"


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _seed_php_acl_fixture(db_session, fixture: dict) -> dict[str, User]:
    for group_id in range(5, 10):
        db_session.add(UserGroup(id=group_id, name=f"PHP fixture group {group_id}"))
        db_session.flush()

    users = {}
    primary_groups = {}
    for user_id, login, primary_group_id, secondary_group_id in fixture["users"]:
        user = User(
            id=user_id,
            username=login,
            password=b"fixture",
            userGroupId=primary_group_id,
            userProfileId=1,
        )
        db_session.add(user)
        db_session.flush()
        users[login] = user
        primary_groups[user_id] = primary_group_id
        db_session.add(
            UserToUserGroup(
                userId=user_id,
                userGroupId=secondary_group_id,
                isManager=False,
            )
        )
    pattern = fixture["account_pattern"]
    owner_cycle = pattern["owner_user_ids_cycle"]
    private_ids = set(pattern["private_ids"])
    private_group_ids = set(pattern["private_group_ids"])
    for offset, account_id in enumerate(range(pattern["first_id"], pattern["last_id"] + 1)):
        owner_id = owner_cycle[offset % len(owner_cycle)]
        db_session.add(
            Account(
                id=account_id,
                userId=owner_id,
                userEditId=owner_id,
                userGroupId=primary_groups[owner_id],
                name=f"PHP ACL fixture {account_id}",
                pass_=b"fixture",
                key=b"fixture",
                isPrivate=account_id in private_ids,
                isPrivateGroup=account_id in private_group_ids,
            )
        )
    db_session.flush()

    for account_id, user_id, is_edit in fixture["user_shares"]:
        db_session.add(
            AccountToUser(accountId=account_id, userId=user_id, isEdit=is_edit)
        )
    for account_id, group_id, is_edit in fixture["group_shares"]:
        db_session.add(
            AccountToUserGroup(
                accountId=account_id,
                userGroupId=group_id,
                isEdit=is_edit,
            )
        )
    db_session.commit()
    return users


def _visible_account_ids(service: AccountService, user: User) -> set[int]:
    group_ids = service._get_user_group_ids(user.id)
    return {
        account_id
        for account_id, in service.db.query(Account.id)
        .filter(service._access_filter(user.id, group_ids))
        .all()
    }


def test_php_authored_acl_fixture_matches_all_ten_users(
    db_session, encryption_service
):
    fixture = _fixture()
    users = _seed_php_acl_fixture(db_session, fixture)
    service = AccountService(db_session, encryption_service)

    for login, expected_ids in fixture["php_visible_account_ids"].items():
        assert _visible_account_ids(service, users[login]) == set(expected_ids), login


def test_php_full_group_access_enables_secondary_group_shares(
    db_session, encryption_service
):
    fixture = _fixture()
    users = _seed_php_acl_fixture(db_session, fixture)
    db_session.add(Config(parameter="account_full_group_access", value="true"))
    db_session.commit()

    service = AccountService(db_session, encryption_service)
    visible = _visible_account_ids(service, users["bulk_security_editor"])
    secondary_group_share_ids = {
        account_id
        for account_id, group_id, _ in fixture["group_shares"]
        if group_id == 5
    }

    assert secondary_group_share_ids <= visible
