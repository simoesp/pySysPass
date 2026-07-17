import pytest
from app.schemas.user import UserCreate, UserUpdate
from app.services.user_service import UserService
from app.services.auth_service import get_password_hash

@pytest.mark.asyncio
async def test_create_user(db_session):
    service = UserService(db_session)
    user_data = UserCreate(
        username="testuser",
        email="test@example.com",
        password="securepassword123",
        is_admin=False
    , user_group_id=1)

    user = service.create_user(user_data)

    assert user.id is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert not user.isUserAdmin

@pytest.mark.asyncio
async def test_get_users(db_session):
    service = UserService(db_session)

    # Create test users
    for i in range(3):
        service.create_user(UserCreate(
            username=f"user{i}",
            email=f"user{i}@example.com",
            password="password123"
        , user_group_id=1))

    users = service.get_users()

    assert len(users) == 3

@pytest.mark.asyncio
async def test_get_user(db_session):
    service = UserService(db_session)
    user = service.create_user(UserCreate(
        username="singleuser",
        email="single@example.com",
        password="password123"
    , user_group_id=1))

    found = service.get_user(user.id)

    assert found is not None
    assert found.id == user.id

@pytest.mark.asyncio
async def test_get_user_by_username(db_session):
    service = UserService(db_session)
    user = service.create_user(UserCreate(
        username="uniqueuser",
        email="unique@example.com",
        password="password123"
    , user_group_id=1))

    found = service.get_user_by_username("uniqueuser")

    assert found is not None
    assert found.username == "uniqueuser"

@pytest.mark.asyncio
async def test_update_user(db_session):
    service = UserService(db_session)
    user = service.create_user(UserCreate(
        username="updateuser",
        email="old@example.com",
        password="password123"
    , user_group_id=1))

    updated = service.update_user(user.id, UserUpdate(
        email="new@example.com",
        is_admin=True
    ))

    assert updated.email == "new@example.com"
    assert updated.isUserAdmin

@pytest.mark.asyncio
async def test_delete_user(db_session):
    service = UserService(db_session)
    user = service.create_user(UserCreate(
        username="deleteuser",
        email="delete@example.com",
        password="password123"
    , user_group_id=1))

    result = service.delete_user(user.id)

    assert result
    assert service.get_user(user.id) is None

@pytest.mark.asyncio
async def test_verify_password(db_session):
    service = UserService(db_session)
    user = service.create_user(UserCreate(
        username="passworduser",
        email="password@example.com",
        password="correctpassword"
    , user_group_id=1))

    assert service.verify_user_password(user, "correctpassword")
    assert not service.verify_user_password(user, "wrongpassword")

@pytest.mark.asyncio
async def test_update_password(db_session):
    service = UserService(db_session)
    user = service.create_user(UserCreate(
        username="newpassuser",
        email="newpass@example.com",
        password="oldpassword"
    , user_group_id=1))

    updated = service.update_user_password(user.id, "newpassword")

    assert service.verify_user_password(updated, "newpassword")
    assert not service.verify_user_password(updated, "oldpassword")
    assert updated.isChangedPass is True
    assert updated.isChangePass is False

@pytest.mark.asyncio
async def test_cannot_create_duplicate_username(db_session):
    service = UserService(db_session)
    service.create_user(UserCreate(
        username="duplicate",
        email="first@example.com",
        password="password123"
    , user_group_id=1))

    with pytest.raises(Exception):
        service.create_user(UserCreate(
            username="duplicate",
            email="second@example.com",
            password="password123"
        , user_group_id=1))


@pytest.mark.asyncio
async def test_user_group_assignment_round_trip(db_session):
    from app.models.account import UserGroup
    from app.schemas.user import UserCreate, UserUpdate
    from app.services.user_service import UserService

    for name in ("Admins", "Ops"):
        if not db_session.query(UserGroup).filter(UserGroup.name == name).first():
            db_session.add(UserGroup(name=name, description=""))
            db_session.commit()
    admins = db_session.query(UserGroup).filter(UserGroup.name == "Admins").first()
    ops = db_session.query(UserGroup).filter(UserGroup.name == "Ops").first()

    service = UserService(db_session)
    user = service.create_user(UserCreate(
        username="grouped", password="secret123", user_group_id=admins.id,
    ))
    assert user.userGroupId == admins.id
    assert service.to_response(user)["user_group_id"] == admins.id

    updated = service.update_user(user.id, UserUpdate(user_group_id=ops.id))
    assert updated.userGroupId == ops.id
    assert service.to_response(updated)["user_group_id"] == ops.id
