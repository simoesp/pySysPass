"""Item presets use sysPass PHP's format and rules (R5 / #56, R9 / #52)."""
import base64
import json
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import accounts, auth, item_presets
from app.core import php_item_presets as presets
from app.db.base import get_db
from app.models.account import AccountToUser, AccountToUserGroup, Config, ItemPreset, User, UserGroup, UserToUserGroup
from app.schemas.user_profile import ProfilePermissions
from app.services.account_service import AccountService, AccountValidationError
from app.services.auth_service import decode_token, get_password_hash, issue_session_token, store_user_master_pass
from app.services.item_preset_service import ItemPresetService
from tests.account_refs import TEST_MASTER_PASSWORD, account_create

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "php_item_presets.json").read_text())
EXPECTED = {
    "account.permission": {"users_view": [3, 4], "users_edit": [5], "user_groups_view": [2], "user_groups_edit": [6]},
    "account.private": {"private_user": True, "private_group": False},
    "session.timeout": {"ip_address": "192.168.10.0/24", "address": "192.168.10.0", "mask": "255.255.255.0",
                        "timeout": 900},
    "account.password": {"length": 14, "use_numbers": True, "use_letters": True, "use_symbols": True,
                         "use_upper": True, "use_lower": True, "use_image": False, "expire_days": 30,
                         "score": 2, "regex": "[A-Z].*[0-9]"},
}


@pytest.mark.parametrize("case", FIXTURE["presets"], ids=lambda c: c["type"])
def test_php_authored_presets_round_trip(case):
    raw = base64.b64decode(case["data_base64"])
    preset_type, data, legacy = presets.decode_row(case["type"], raw)
    assert (preset_type, legacy) == (case["type"], False)
    assert data == EXPECTED[case["type"]]
    assert presets.serialize(case["type"], data) == raw  # byte-identical to PHP serialize()
    assert presets.preset_hash(case["type"], case["userId"], case["userGroupId"], case["userProfileId"],
                               case["priority"]).decode() == case["hash"]


def _add(db, preset_type, data, *, fixed=True, **scope):
    return ItemPresetService(db).create(preset_type, fixed=fixed, data=data, **scope)


def test_lookup_follows_php_score(db_session, test_user):
    db_session.add(UserGroup(id=5, name="secondary"))
    db_session.add(UserToUserGroup(userId=test_user.id, userGroupId=5))
    db_session.commit()
    service = ItemPresetService(db_session)
    _add(db_session, "account.private", {"private_user": True}, user_profile_id=1, priority=10)
    _add(db_session, "account.private", {"private_group": True}, user_group_id=5, priority=2)
    _add(db_session, "account.private", {}, user_id=test_user.id, priority=0)
    # profile 10+1 beats secondary group 2+2 and user 0+3 (PHP score = priority + scope bonus)
    assert service.get_for_user("account.private", test_user.id).data["private_user"] is True
    db_session.query(ItemPreset).filter_by(userProfileId=1).delete()
    db_session.commit()
    assert service.get_for_user("account.private", test_user.id).data["private_group"] is True  # 4 > 3
    assert service.get_for_user("session.timeout", test_user.id) is None


def test_scope_is_required_and_legacy_rows_are_not_applied(db_session, test_user):
    with pytest.raises(presets.PresetError, match="user, group or profile"):
        ItemPresetService(db_session).create("account.private", data={})
    db_session.add(ItemPreset(type="AccountPrivate", userId=test_user.id, fixed=1, priority=9,
                              data=json.dumps({"private_user": True}).encode(), hash=b"legacy"))
    db_session.commit()
    listed = ItemPresetService(db_session).list("account.private")
    assert listed[0]["legacy"] is True and listed[0]["type"] == "account.private"
    assert ItemPresetService(db_session).get_for_user("account.private", test_user.id) is None


def test_fixed_account_presets_are_enforced(db_session, encryption_service, test_user):
    db_session.add_all([UserGroup(id=8, name="auditors"),
                        User(id=9, name="peer", username="peer", email="p@example.com", userGroupId=1,
                             userProfileId=1, hashSalt=b"s" * 32, password=b"x")])
    db_session.add(Config(parameter="account_expire_enabled", value="true"))
    db_session.commit()
    _add(db_session, "account.private", {"private_user": True, "private_group": True}, user_id=test_user.id)
    _add(db_session, "account.permission", {"users_view": [9, test_user.id], "user_groups_edit": [8, 1]},
         user_id=test_user.id)
    _add(db_session, "account.password", {"length": 10, "use_numbers": True, "use_letters": True,
                                          "use_upper": True, "expire_days": 30}, user_id=test_user.id)
    service = AccountService(db_session, encryption_service)

    with pytest.raises(AccountValidationError, match="10 characters"):
        service.create_account(account_create(title="weak", password="Ab1", is_public=True), test_user.id,
                               master_pass=TEST_MASTER_PASSWORD)
    with pytest.raises(AccountValidationError, match="numbers"):
        service.create_account(account_create(title="weak", password="Abcdefghijk", is_public=True), test_user.id,
                               master_pass=TEST_MASTER_PASSWORD)

    before = int(time.time())
    created = service.create_account(account_create(title="ok", password="Abcdefgh123", is_public=True),
                                     test_user.id, master_pass=TEST_MASTER_PASSWORD)
    assert created["is_public"] is False and created["is_private_group"] is True  # fixed privacy wins
    assert created["pass_date_change"] >= before + 30 * 86400
    shares = {(s.userId, bool(s.isEdit)) for s in db_session.query(AccountToUser).filter_by(accountId=created["id"])}
    groups = {(g.userGroupId, bool(g.isEdit))
              for g in db_session.query(AccountToUserGroup).filter_by(accountId=created["id"])}
    assert shares == {(9, False)}  # the creator and own group are skipped, as in PHP
    assert groups == {(8, True)}


def _client(db_session):
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1/auth")
    app.include_router(accounts.router, prefix="/api/v1")
    app.include_router(item_presets.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db_session
    return app


def test_session_timeout_preset_applies_inside_its_network(db_session, test_user):
    store_user_master_pass(test_user, "testpassword", "vault-master")
    db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
    db_session.commit()
    _add(db_session, "session.timeout", {"ip_address": "203.0.113.0/24", "timeout": 1200}, user_id=test_user.id)

    def lifetime(peer):
        client = TestClient(_client(db_session), client=(peer, 4000))
        token = client.post("/api/v1/auth/login", data={"username": "testuser", "password": "testpassword"})
        payload = decode_token(token.json()["access_token"])
        return payload["exp"] - payload["iat"]

    assert lifetime("203.0.113.40") == pytest.approx(1200, abs=1)
    assert lifetime("198.51.100.7") == pytest.approx(300, abs=1)  # outside the network: global default


def test_presets_require_the_management_permission(db_session, test_user):
    client = TestClient(_client(db_session))
    headers = {"Authorization": f"Bearer {issue_session_token(test_user)}"}
    body = {"type": "account.private", "user_id": test_user.id, "data": {"private_user": True}}

    def grant(value):
        test_user.userProfile.profile = json.dumps(
            {k: (k == "mgm_items_preset" and value) for k in ProfilePermissions.model_fields}).encode()
        db_session.commit()

    grant(False)
    assert client.post("/api/v1/item-presets", json=body, headers=headers).status_code == 403
    assert client.get("/api/v1/item-presets", headers=headers).status_code == 403
    grant(True)
    created = client.post("/api/v1/item-presets", json=body, headers=headers)
    assert created.status_code == 201 and created.json()["type"] == "account.private"
    # Any user may read the preset that applies to themselves, never someone else's.
    mine = client.get("/api/v1/item-presets/context/account.private", headers=headers)
    assert mine.status_code == 200 and mine.json()["data"]["private_user"] is True
    bad = client.post("/api/v1/item-presets", json={**body, "type": "session.timeout",
                                                    "data": {"ip_address": "not-an-ip"}}, headers=headers)
    assert bad.status_code == 400
