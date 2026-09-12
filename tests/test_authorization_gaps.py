"""Regressions for live user state and PHP profile gates on account children."""

import base64
import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import accounts, auth, files, item_presets, notifications, public_links, two_factor, users
from app.db.base import get_db
from app.models.account import AccountToUser, User, UserGroup, UserProfile
from app.schemas.account import AccountCreate
from app.services.account_service import AccountService
from app.services.auth_service import create_access_token
from app.services.file_service import FileService
from app.services.public_link_service import PublicLinkService


@pytest.fixture
def gap_client(db_session):
    app = FastAPI()
    for module in (accounts, files, public_links, notifications, item_presets, two_factor, users):
        app.include_router(module.router, prefix='/api/v1')
    app.include_router(auth.router, prefix='/api/v1/auth')
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as client:
        yield client


def _headers(user, **claims):
    token = create_access_token({'user_id': user.id, 'username': user.username}, **claims)
    return {'Authorization': 'Bearer ' + token}


@pytest.mark.parametrize('path', [
    '/accounts', '/accounts/1/files', '/accounts/1/public-links',
    '/notifications', '/item-presets', '/2fa/status', '/auth/me',
])
def test_disabled_php_user_is_rejected_with_preexisting_jwt(gap_client, db_session, test_user, path):
    headers = _headers(test_user)
    test_user.isDisabled = True
    db_session.commit()
    assert gap_client.get('/api/v1' + path, headers=headers).status_code == 401


def test_deleted_user_is_rejected(gap_client, db_session, test_user):
    headers = _headers(test_user)
    db_session.delete(test_user)
    db_session.commit()
    assert gap_client.get('/api/v1/accounts', headers=headers).status_code == 401


def test_admin_claim_does_not_survive_demotion(gap_client, db_session, test_user):
    test_user.isAdminApp = True
    db_session.commit()
    headers = _headers(test_user, is_admin_app=True)
    test_user.isAdminApp = False
    db_session.get(UserProfile, test_user.userProfileId).profile = b'{}'
    db_session.commit()
    assert gap_client.get('/api/v1/users', headers=headers).status_code == 403


def _account(db_session, encryption_service, user):
    return AccountService(db_session, encryption_service).create_account(
        AccountCreate(title='Authorization regression', password='test-only', is_public=True), user.id)


def test_php_profile_denies_files_and_link_creation(gap_client, db_session, encryption_service, test_user):
    account = _account(db_session, encryption_service, test_user)
    fixture_path = Path(__file__).parent / 'fixtures/php_syspass_3211_crypto.json'
    fixture = json.loads(fixture_path.read_text())
    profile = db_session.get(UserProfile, test_user.userProfileId)
    profile.profile = base64.b64decode(fixture['profile']['profile_base64'])
    db_session.commit()
    headers = _headers(test_user)
    assert gap_client.get(f'/api/v1/accounts/{account.id}/files', headers=headers).status_code == 403
    assert gap_client.post(f'/api/v1/accounts/{account.id}/public-links', headers=headers,
                           json={'account_id': account.id}).status_code == 403


def test_public_link_create_permission_does_not_grant_management(
    gap_client, db_session, encryption_service, test_user,
):
    account = _account(db_session, encryption_service, test_user)
    profile = db_session.get(UserProfile, test_user.userProfileId)
    profile.profile = b'{"acc_public_links": true}'
    db_session.commit()
    headers = _headers(test_user)
    url = f'/api/v1/accounts/{account.id}/public-links'
    assert gap_client.post(url, headers=headers, json={'account_id': account.id}).status_code == 201
    assert gap_client.get(url, headers=headers).status_code == 403


def test_explicit_read_share_can_download_but_not_delete(gap_client, db_session, encryption_service, test_user):
    account = _account(db_session, encryption_service, test_user)
    viewer_group = UserGroup(name='Viewer group')
    db_session.add(viewer_group)
    db_session.flush()
    viewer = User(name='Viewer', username='viewer', password=test_user.password, hashSalt=b'viewer-salt',
                  userGroupId=viewer_group.id, userProfileId=test_user.userProfileId)
    db_session.add(viewer)
    db_session.flush()
    db_session.add(AccountToUser(accountId=account.id, userId=viewer.id, isEdit=False))
    db_session.commit()
    file = FileService(db_session).create_file(account.id, 'sample.txt', 'text/plain', 4, b'test', 'txt')
    headers = _headers(viewer)
    url = f'/api/v1/accounts/{account.id}/files/{file.id}'
    assert gap_client.get(url, headers=headers).content == b'test'
    assert gap_client.delete(url, headers=headers).status_code == 404
    assert gap_client.get(f'/api/v1/accounts/{account.id}/files/count', headers=headers).json()['file_count'] == 1


def test_nested_resources_must_belong_to_url_account(gap_client, db_session, encryption_service, test_user):
    first = _account(db_session, encryption_service, test_user)
    second = _account(db_session, encryption_service, test_user)
    file = FileService(db_session).create_file(second.id, 'sample.txt', 'text/plain', 4, b'test', 'txt')
    link = PublicLinkService(db_session).create_public_link(second.id, test_user.id)
    headers = _headers(test_user)
    for suffix in (f'files/{file.id}', f'files/{file.id}/metadata', f'public-links/{link.id}'):
        assert gap_client.get(f'/api/v1/accounts/{first.id}/{suffix}', headers=headers).status_code == 404
    for suffix in (f'files/{file.id}', f'public-links/{link.id}'):
        assert gap_client.delete(f'/api/v1/accounts/{first.id}/{suffix}', headers=headers).status_code == 404
