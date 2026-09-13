"""Native PHP Vault fixtures and fail-closed public-link access regressions."""

import base64
import json
from pathlib import Path
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.v1 import public_links
from app.core.php_public_link import ACCOUNT_CLASS
from app.core.php_public_link import MAX_SERIALIZED_BYTES
from app.core.php_public_link import VAULT_CLASS
from app.core.php_public_link import _object
from app.core.php_public_link import read_public_link_snapshot
from app.db.base import get_db
from app.models.account import Account
from app.models.account import PublicLink
from app.services.public_link_service import PublicLinkService


FIXTURE_PATH = Path(__file__).parents[1] / 'fixtures/php_public_link_vault.json'


@pytest.fixture
def native_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding='utf-8'))


@pytest.fixture
def native_link(db_session, test_user, monkeypatch, native_fixture):
    monkeypatch.setattr('app.services.public_link_service.get_password_salt', lambda: native_fixture['password_salt'])
    row = PublicLink(
        accountId=17, hash=native_fixture['link']['hash'].encode('ascii'),
        data=base64.b64decode(native_fixture['link']['data_base64']), userId=test_user.id,
        typeId=1, dateAdd=int(time.time()), dateExpire=int(time.time()) + 3600,
        dateUpdate=0, countViews=0, totalCountViews=0, maxCountViews=2,
    )
    db_session.add(row)
    db_session.commit()
    return row


def test_native_php_vault_decrypts_utf8_and_pdo_string_id(native_fixture):
    account = read_public_link_snapshot(
        base64.b64decode(native_fixture['link']['data_base64']),
        native_fixture['link']['hash'].encode('ascii'), native_fixture['password_salt'], 17,
    )
    expected = native_fixture['account']
    assert account.id == 17
    assert account.name == expected['name']
    assert account.password == expected['password']
    assert account.category_id is None
    assert account.client_id is None
    assert account.category_name == expected['categoryName']
    assert account.client_name == expected['clientName']


@pytest.mark.parametrize('change', ['salt', 'hash', 'account', 'tamper', 'missing-salt', 'trailing'])
def test_native_vault_rejects_wrong_context_or_modified_payload(native_fixture, change):
    raw = base64.b64decode(native_fixture['link']['data_base64'])
    salt = native_fixture['password_salt']
    link_hash = native_fixture['link']['hash'].encode('ascii')
    account_id = 17
    if change == 'salt':
        salt = 'wrong-salt'
    elif change == 'missing-salt':
        salt = ''
    elif change == 'hash':
        link_hash = b'ff' * 32
    elif change == 'account':
        account_id = 18
    elif change == 'trailing':
        raw += b'N;'
    else:
        position = raw.index(b'def50200') + 12
        raw = raw[:position] + (b'0' if raw[position:position + 1] != b'0' else b'1') + raw[position + 1:]
    with pytest.raises(ValueError):
        read_public_link_snapshot(raw, link_hash, salt, account_id)


@pytest.mark.parametrize('raw', [
    b'R:1;', b'C:4:"Evil":0:{}', b'O:4:"Evil":0:{}',
    b'O:19:"SP\\Core\\Crypt\\Vault":1:{s:999:"x";N;}',
    b'O:19:"SP\\Core\\Crypt\\Vault":999999:{}',
    b'O:19:"SP\\Core\\Crypt\\Vault":2:{s:1:"x";N;s:1:"x";N;}',
    b'a:1:{i:0;' * 20 + b'N;' + b'}' * 20,
])
def test_serialized_objects_are_bounded_data_not_executable(raw):
    with pytest.raises(ValueError):
        _object(raw, VAULT_CLASS)


def test_oversized_payload_is_rejected_before_parsing():
    with pytest.raises(ValueError, match='too large'):
        _object(b'x' * (MAX_SERIALIZED_BYTES + 1), ACCOUNT_CLASS)


def test_public_route_serves_php_snapshot_with_view_limits(db_session, native_link, native_fixture):
    # PHP snapshots remain readable independently of the live account row.
    assert db_session.get(Account, 17) is None
    app = FastAPI()
    app.include_router(public_links.router)
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    url = f'/public-links/{native_link.hash.decode()}/access'
    for _ in range(2):
        response = client.get(url)
        assert response.status_code == 200
        assert response.json()['password'] == native_fixture['account']['password']
        assert response.json()['account_title'] == native_fixture['account']['name']
        assert response.json()['category_name'] == native_fixture['account']['categoryName']
    assert client.get(url).status_code == 404
    db_session.refresh(native_link)
    assert native_link.countViews == 2
    assert native_link.totalCountViews == 2
    assert native_link.has_password is False


@pytest.mark.parametrize('change', ['malformed', 'wrong-type', 'missing-salt', 'expired'])
def test_invalid_php_links_do_not_consume_views(db_session, native_link, monkeypatch, change):
    if change == 'malformed':
        native_link.data = b'O:19:"SP\\Core\\Crypt\\Vault":0:{}'
    elif change == 'wrong-type':
        native_link.typeId = 999
    elif change == 'missing-salt':
        monkeypatch.setattr('app.services.public_link_service.get_password_salt', lambda: '')
    else:
        native_link.dateExpire = int(time.time()) - 1
    db_session.commit()
    assert PublicLinkService(db_session).get_public_link(native_link.hash) is None
    db_session.refresh(native_link)
    assert native_link.countViews == 0
    assert native_link.totalCountViews == 0


def test_php_snapshot_ignores_live_edits_and_updates_account_counters(
    db_session, native_link, native_fixture, test_user,
):
    account = Account(
        id=17, name='Changed after link creation', login='new-login',
        pass_=b'new-ciphertext', key=b'new-key', userId=test_user.id,
        userEditId=test_user.id, userGroupId=test_user.userGroupId,
        countView=10, countDecrypt=20,
    )
    db_session.add(account)
    db_session.commit()
    result = PublicLinkService(db_session).get_public_link(native_link.hash)
    assert result is not None
    assert result[1].name == native_fixture['account']['name']
    assert result[1].password == native_fixture['account']['password']
    db_session.refresh(account)
    assert account.name == 'Changed after link creation'
    assert account.pass_ == b'new-ciphertext'
    assert account.countView == 11
    assert account.countDecrypt == 21
