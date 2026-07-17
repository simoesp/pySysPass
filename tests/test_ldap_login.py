"""Tests for LDAP login integration (PHP LoginService/LdapAuth parity)."""
import pytest

import app.services.ldap_service as ldap_module
from app.core import runtime_json_config
from app.models.account import User
from app.services.auth_service import verify_password
from app.services.ldap_service import authenticate_ldap_login


@pytest.fixture
def runtime_config(tmp_path, monkeypatch):
    runtime_path = tmp_path / "runtime-config.json"
    monkeypatch.setattr(
        runtime_json_config.settings,
        "SYSPASS_RUNTIME_CONFIG_JSON_PATH",
        str(runtime_path),
    )
    return runtime_path


@pytest.fixture
def ldap_enabled(runtime_config):
    runtime_json_config.set_runtime_config_value("ldap_enabled", "true")
    runtime_json_config.set_runtime_config_value("ldap_server", "ldap://ldap.example:389")
    runtime_json_config.set_runtime_config_value("ldap_base", "dc=example,dc=com")


class FakeLdapService:
    """Stands in for LdapService against a directory with one user."""

    directory = {
        "unixuser": {
            "dn": "uid=unixuser,ou=people,dc=example,dc=com",
            "password": "QazWsxEdc!!",
            "attributes": {
                "cn": "Unix User",
                "mail": "unixuser@example.com",
                "memberOf": ["cn=syspass,ou=groups,dc=example,dc=com"],
            },
        }
    }

    def __init__(self, *args, **kwargs):
        pass

    def connect(self):
        return True

    def disconnect(self):
        pass

    def authenticate(self, username, password):
        entry = self.directory.get(username)
        if entry and entry["password"] == password:
            return entry["dn"]
        return None

    def get_user_info(self, username):
        entry = self.directory.get(username)
        if not entry:
            return None
        return {"dn": entry["dn"], "attributes": entry["attributes"]}


class UnreachableLdapService(FakeLdapService):
    def connect(self):
        raise ConnectionError("LDAP connection failed")


@pytest.fixture
def fake_ldap(monkeypatch):
    monkeypatch.setattr(ldap_module, "LdapService", FakeLdapService)
    monkeypatch.setattr(ldap_module, "_LDAP_AVAILABLE", True)


def test_ldap_login_disabled_returns_none(db_session, runtime_config, fake_ldap):
    assert authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!") is None


def test_ldap_login_provisions_new_user(db_session, ldap_enabled, fake_ldap):
    user = authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!")

    assert user is not None
    assert user.isLdap
    assert user.username == "unixuser"
    assert user.name == "Unix User"
    assert user.email == "unixuser@example.com"
    assert user.isUserEnabled
    # Password hash is stored so database auth works as a fallback (PHP parity)
    assert verify_password("QazWsxEdc!!", user.password)


def test_ldap_login_wrong_password_returns_none(db_session, ldap_enabled, fake_ldap):
    assert authenticate_ldap_login(db_session, "unixuser", "wrong") is None
    assert db_session.query(User).filter(User.username == "unixuser").first() is None


def test_ldap_login_unknown_user_returns_none(db_session, ldap_enabled, fake_ldap):
    assert authenticate_ldap_login(db_session, "ghost", "whatever") is None


def test_ldap_login_updates_existing_user(db_session, ldap_enabled, fake_ldap, test_user):
    test_user.username = "unixuser"
    db_session.commit()

    user = authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!")

    assert user is not None
    assert user.id == test_user.id
    assert user.isLdap
    assert user.name == "Unix User"
    assert verify_password("QazWsxEdc!!", user.password)


def test_ldap_login_denies_disabled_user(db_session, ldap_enabled, fake_ldap, test_user):
    test_user.username = "unixuser"
    test_user.isUserEnabled = False
    db_session.commit()

    assert authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!") is None


def test_ldap_login_group_filter(db_session, ldap_enabled, fake_ldap):
    runtime_json_config.set_runtime_config_value("ldap_group", "syspass")
    assert authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!") is not None

    runtime_json_config.set_runtime_config_value("ldap_group", "other-group")
    assert authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!") is None


def test_ldap_login_group_filter_accepts_full_dn(db_session, ldap_enabled, fake_ldap):
    runtime_json_config.set_runtime_config_value(
        "ldap_group", "cn=syspass,ou=groups,dc=example,dc=com"
    )
    assert authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!") is not None


def test_ldap_unreachable_falls_back_to_none(db_session, ldap_enabled, monkeypatch):
    monkeypatch.setattr(ldap_module, "LdapService", UnreachableLdapService)
    monkeypatch.setattr(ldap_module, "_LDAP_AVAILABLE", True)
    assert authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!") is None


def test_user_response_exposes_ldap_origin(db_session, ldap_enabled, fake_ldap, test_user):
    from app.schemas.user import UserResponse
    from app.services.user_service import UserService

    ldap_user = authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!")
    assert UserResponse.model_validate(ldap_user).is_ldap is True
    assert UserResponse.model_validate(test_user).is_ldap is False

    # The /users list endpoint serializes through UserService.to_response
    service = UserService(db_session)
    assert service.to_response(ldap_user)["is_ldap"] is True
    assert service.to_response(test_user)["is_ldap"] is False


def test_ldap_login_uses_default_group_and_profile(db_session, ldap_enabled, fake_ldap):
    runtime_json_config.set_runtime_config_value("ldap_defaultgroup", "3")
    user = authenticate_ldap_login(db_session, "unixuser", "QazWsxEdc!!")
    assert user.userGroupId == 3
