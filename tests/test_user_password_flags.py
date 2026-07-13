from app.models.account import User
from app.services.auth_service import get_password_hash
from app.services.user_service import UserService


def test_update_user_password_marks_master_key_for_migration(db_session):
    user = User(
        id=1,
        name="alice",
        username="alice",
        email="alice@example.com",
        password=get_password_hash("oldpassword").encode("utf-8"),
        userGroupId=1,
        userProfileId=1,
        hashSalt=b"salt",
        isChangePass=True,
        isChangedPass=False,
    )
    db_session.add(user)
    db_session.commit()

    updated = UserService(db_session).update_user_password(user.id, "newpassword")

    assert updated is not None
    assert updated.isChangePass is False
    assert updated.isChangedPass is True
    assert updated.isMigrate is False
