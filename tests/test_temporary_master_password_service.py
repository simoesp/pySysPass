from app.models.account import Config
from app.services.auth_service import get_password_hash
from app.services.temporary_master_password_service import TemporaryMasterPasswordService


def test_create_and_resolve_temporary_master_password(db_session):
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()

    service = TemporaryMasterPasswordService(db_session)
    password, meta = service.create("vault-master", max_time=3600)

    assert password
    assert meta["expires_at"] > meta["created_at"]
    assert service.check_temp_master_pass(password) is True
    assert service.resolve_master_password(password) == "vault-master"

    status = service.get_status()
    assert status["is_active"] is True
    assert status["attempts"] == 0


def test_invalid_temporary_master_password_increments_attempts(db_session):
    service = TemporaryMasterPasswordService(db_session)
    service.create("vault-master", max_time=3600)

    assert service.check_temp_master_pass("wrong-pass") is False
    status = service.get_status()
    assert status["attempts"] == 1
