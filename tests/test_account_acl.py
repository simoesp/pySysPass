from app.models.account import AccountToUser, AccountToUserGroup, Config, User, UserGroup, UserToUserGroup
from app.schemas.account import AccountCreate, AccountUpdate
from app.services.account_service import AccountService
from app.services.auth_service import get_password_hash


def create_user(db_session, username, email, group_id):
    user = User(
        username=username,
        email=email,
        password=get_password_hash("testpassword"),
        isUserAdmin=False,
        userGroupId=group_id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def create_group(db_session, name, description="ACL group"):
    group = UserGroup(name=name, description=description)
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)
    return group


def test_shared_user_can_view_and_edit_when_acl_allows(db_session, encryption_service, test_user):
    viewer = create_user(db_session, "viewer", "viewer@example.com", test_user.userGroupId)
    service = AccountService(db_session, encryption_service)

    account = service.create_account(
        AccountCreate(
            title="Shared Account",
            password="secret123",
            is_public=True,
            shared_users=[{"user_id": viewer.id, "is_edit": True}],
        ),
        test_user.id,
    )

    visible = service.get_account(account["id"], viewer.id)
    assert visible is not None
    assert visible["can_edit"] is True
    assert visible["shared_users"][0].user_id == viewer.id

    updated = service.update_account(account["id"], AccountUpdate(title="Edited by viewer"), viewer.id)
    assert updated is not None
    assert updated["title"] == "Edited by viewer"


def test_secondary_group_share_requires_php_full_group_access(db_session, encryption_service, test_user):
    shared_group = create_group(db_session, "Shared Group")
    primary_group = create_group(db_session, "Primary Group")

    member = create_user(db_session, "groupmember", "groupmember@example.com", primary_group.id)
    db_session.add(UserToUserGroup(userId=member.id, userGroupId=shared_group.id, isManager=False))
    db_session.commit()

    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(
            title="Group Shared",
            password="secret123",
            is_public=True,
            shared_groups=[{"group_id": shared_group.id, "is_edit": True}],
        ),
        test_user.id,
    )

    assert service.get_account(account["id"], member.id) is None

    db_session.add(Config(parameter="account_full_group_access", value="true"))
    db_session.commit()
    service = AccountService(db_session, encryption_service)
    visible = service.get_account(account["id"], member.id)
    assert visible is not None
    assert visible["can_edit"] is True
    assert visible["shared_groups"][0].group_id == shared_group.id


def test_owner_flags_and_pass_date_change_round_trip(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(
            title="Flags",
            password="secret123",
            is_public=False,
            is_private_group=True,
            other_user_edit=True,
            other_user_group_edit=True,
            pass_date_change=1893456000,
        ),
        test_user.id,
    )

    fetched = service.get_account(account["id"], test_user.id)
    assert fetched["is_private_group"] is True
    assert fetched["other_user_edit"] is True
    assert fetched["other_user_group_edit"] is True
    assert fetched["pass_date_change"] == 1893456000


def test_shared_user_with_view_access_cannot_edit(db_session, encryption_service, test_user):
    viewer_group = create_group(db_session, "Read-only viewer group")
    viewer = create_user(db_session, "readonly", "readonly@example.com", viewer_group.id)
    service = AccountService(db_session, encryption_service)

    account = service.create_account(
        AccountCreate(
            title="View Only Account",
            password="secret123",
            is_public=True,
            shared_users=[{"user_id": viewer.id, "is_edit": False}],
        ),
        test_user.id,
    )

    visible = service.get_account(account["id"], viewer.id)
    assert visible is not None
    assert visible["can_edit"] is False

    updated = service.update_account(account["id"], AccountUpdate(title="Should not change"), viewer.id)
    assert updated is None


def test_remove_user_access_revokes_visibility_for_unrelated_user(db_session, encryption_service, test_user):
    outsider_group = create_group(db_session, "Outsiders")
    outsider = create_user(db_session, "outsider", "outsider@example.com", outsider_group.id)
    service = AccountService(db_session, encryption_service)

    account = service.create_account(
        AccountCreate(title="Temporary Share", password="secret123", is_public=True),
        test_user.id,
    )

    assert service.set_user_access(account["id"], test_user.id, outsider.id, False) is True
    assert service.get_account(account["id"], outsider.id) is not None

    assert service.remove_user_access(account["id"], test_user.id, outsider.id) is True
    assert service.get_account(account["id"], outsider.id) is None


def test_primary_group_member_can_edit_like_php_acl(db_session, encryption_service, test_user):
    teammate = create_user(db_session, "teammate", "teammate@example.com", test_user.userGroupId)
    service = AccountService(db_session, encryption_service)

    account = service.create_account(
        AccountCreate(
            title="Group Editable",
            password="secret123",
            is_public=True,
        ),
        test_user.id,
    )

    visible = service.get_account(account["id"], teammate.id)
    assert visible is not None
    assert visible["can_edit"] is True

    updated = service.update_account(account["id"], AccountUpdate(title="Edited by teammate"), teammate.id)
    assert updated is not None
    assert updated["title"] == "Edited by teammate"


def test_group_access_grant_and_revoke_controls_visibility(db_session, encryption_service, test_user):
    shared_group = create_group(db_session, "Project Group")
    member = create_user(db_session, "projectmember", "projectmember@example.com", shared_group.id)

    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(title="Group Grant", password="secret123", is_public=True),
        test_user.id,
    )

    assert service.get_account(account["id"], member.id) is None

    assert service.set_group_access(account["id"], test_user.id, shared_group.id, False) is True
    visible = service.get_account(account["id"], member.id)
    assert visible is not None
    assert visible["can_edit"] is False

    assert service.remove_group_access(account["id"], test_user.id, shared_group.id) is True
    assert service.get_account(account["id"], member.id) is None
