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
    escaped = r"alice\2a\29\28|\28uid=\2a\29\29"
    assert captured["filter"] == f"(|(uid={escaped})(sAMAccountName={escaped})(cn={escaped}))"


def test_user_info_escapes_ldap_filter_metacharacters(monkeypatch):
    monkeypatch.setattr(ldap_service, "_LDAP_AVAILABLE", True)
    service = LdapService("ldap://directory.example", "dc=example,dc=test")
    captured = {}

    def fake_search(*, filter_str, attributes):
        captured["filter"] = filter_str
        return []

    monkeypatch.setattr(service, "search", fake_search)

    assert service.get_user_info("name\\with\x00null") is None
    escaped = r"name\5cwith\00null"
    assert captured["filter"] == f"(|(uid={escaped})(sAMAccountName={escaped})(cn={escaped}))"


def _service_with_search(monkeypatch, responses):
    """LdapService whose search() replays canned responses per filter substring."""
    monkeypatch.setattr(ldap_service, "_LDAP_AVAILABLE", True)
    service = LdapService("ldap://directory.example", "dc=example,dc=test")
    service._conn = type("BoundConnection", (), {"bound": True})()
    calls = []

    def fake_search(*, filter_str, attributes):
        calls.append(filter_str)
        for needle, result in responses:
            if needle in filter_str:
                return result
        return []

    monkeypatch.setattr(service, "search", fake_search)
    service._calls = calls
    return service


USER_DN = "cn=Unix User,ou=users,dc=example,dc=test"
GROUP_DN = "cn=syspass,ou=groups,dc=example,dc=test"


def test_user_in_group_via_ad_nested_chain(monkeypatch):
    service = _service_with_search(monkeypatch, [
        ("1.2.840.113556.1.4.1941", [{"dn": USER_DN, "attributes": {"cn": "Unix User"}}]),
    ])
    assert service.user_in_group("unixuser", USER_DN, GROUP_DN) is True


def test_user_in_group_via_group_member_attribute(monkeypatch):
    # chain and DN lookups miss; the cn+objectClass group lookup carries the member list
    service = _service_with_search(monkeypatch, [
        ("distinguishedName=", []),
        ("objectClass=group", [{"dn": GROUP_DN, "attributes": {"member": [USER_DN]}}]),
    ])
    assert service.user_in_group("unixuser", USER_DN, GROUP_DN) is True


def test_user_in_group_via_posix_memberuid(monkeypatch):
    service = _service_with_search(monkeypatch, [
        ("objectClass=group", [{"dn": GROUP_DN, "attributes": {"memberUid": ["unixuser"]}}]),
    ])
    assert service.user_in_group("unixuser", USER_DN, "syspass") is True


def test_user_in_group_resolves_cn_and_rejects_missing_group(monkeypatch):
    service = _service_with_search(monkeypatch, [])
    # CN-form group that doesn't exist in the directory → deny
    assert service.user_in_group("unixuser", USER_DN, "ghost-group") is False


def test_user_in_group_memberof_fallback(monkeypatch):
    service = _service_with_search(monkeypatch, [])
    monkeypatch.setattr(service, "get_user_info", lambda u: {
        "dn": USER_DN, "attributes": {"memberOf": [GROUP_DN]},
    })
    assert service.user_in_group("unixuser", USER_DN, GROUP_DN) is True
    assert service.user_in_group("unixuser", USER_DN, "cn=other,ou=groups,dc=example,dc=test") is False


def test_user_in_group_empty_filter_allows(monkeypatch):
    service = _service_with_search(monkeypatch, [])
    assert service.user_in_group("unixuser", USER_DN, "") is True
