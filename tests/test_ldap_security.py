from app.services import ldap_service
from app.services.ldap_service import LdapService


def test_username_is_escaped_before_ldap_filter_interpolation(monkeypatch):
    monkeypatch.setattr(ldap_service, "_LDAP_AVAILABLE", True)
    service = LdapService("ldap://directory.example", "dc=example,dc=test")
    service._conn = type("BoundConnection", (), {"bound": True})()
    captured = {}

    def fake_search(*, filter_str, attributes):
        captured["filter"] = filter_str
        return []

    monkeypatch.setattr(service, "search", fake_search)

    assert service.authenticate("alice*)(|(uid=*))", "irrelevant") is None
    assert captured["filter"] == r"(uid=alice\2a\29\28|\28uid=\2a\29\29)"


def test_user_info_escapes_ldap_filter_metacharacters(monkeypatch):
    monkeypatch.setattr(ldap_service, "_LDAP_AVAILABLE", True)
    service = LdapService("ldap://directory.example", "dc=example,dc=test")
    captured = {}

    def fake_search(*, filter_str, attributes):
        captured["filter"] = filter_str
        return []

    monkeypatch.setattr(service, "search", fake_search)

    assert service.get_user_info("name\\with\x00null") is None
    assert captured["filter"] == r"(uid=name\5cwith\00null)"
