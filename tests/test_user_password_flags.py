import json
import time
from pathlib import Path

from app.models.account import Config
from app.models.account import User
from app.models.account import UserPassRecover
from app.schemas.user import UserUpdate
from app.services import auth_service
from app.services.auth_service import get_password_hash
from app.services.password_reset_service import PasswordResetService
from app.services.user_service import UserService
from tests.test_auth_login import _make_client


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


# Both password replacement paths must preserve PHP-created mPass/mKey until
# the normal login flow can migrate them using the previous login password.
def test_password_changes_preserve_php_vault_recovery(db_session, monkeypatch):
    fixture = json.loads((Path(__file__).parent / 'fixtures/php_syspass_3211_crypto.json').read_text())
    known = fixture['known_values']
    original = fixture['user']
    monkeypatch.setattr(auth_service, 'get_password_salt', lambda: known['password_salt'])
    user = User(
        id=1, name='PHP fixture', username=original['login'], email='fixture@example.test',
        password=original['pass'].encode(), mPass=original['mPass'].encode(), mKey=original['mKey'].encode(),
        userGroupId=1, userProfileId=1, hashSalt=b'fixture', isChangePass=True,
    )
    db_session.add(user)
    db_session.add(Config(parameter='masterPwd', value=fixture['config']['masterPwd']))
    db_session.commit()
    _, client = _make_client(db_session)
    previous = known['login_password']
    for method, new_password in [('admin', 'admin-changed-password'), ('reset', 'reset-password')]:
        old_vault = (user.mPass, user.mKey)
        if method == 'admin':
            UserService(db_session).update_user(user.id, UserUpdate(password=new_password))
        else:
            service = PasswordResetService(db_session)
            db_session.add(UserPassRecover(
                userId=user.id, hash=service._hash_token('recovery-token'), date=int(time.time()), used=False,
            ))
            db_session.commit()
            assert service.confirm_reset('recovery-token', new_password)
            assert not service.confirm_reset('recovery-token', 'reused-token-password')
        assert user.isChangedPass is True
        assert user.isChangePass is False
        assert (user.mPass, user.mKey) == old_vault
        response = client.post('/api/v1/auth/login', data={
            'username': user.username, 'password': new_password,
        })
        assert response.status_code == 428
        assert response.json()['detail']['code'] == 'OLD_PASSWORD_REQUIRED'
        response = client.post('/api/v1/auth/login', data={
            'username': user.username, 'password': new_password, 'oldpass': previous,
        })
        assert response.status_code == 200
        assert auth_service.decrypt_user_master_pass(user, new_password) == known['master_password']
        assert user.isChangedPass is False
        previous = new_password
