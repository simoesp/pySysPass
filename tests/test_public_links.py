import time

import pytest
from app.core.config import settings
from app.core.security import EncryptionService
from app.models.account import Config, PublicLink
from app.services.public_link_service import PublicLinkService, PublicLinksDisabledError
from tests.account_refs import account_create, TEST_MASTER_PASSWORD
from app.services.account_service import AccountService, VaultRequiredError

LINK_SALT = "public-link-test-salt-not-a-secret"


@pytest.fixture(autouse=True)
def links_enabled(db_session, tmp_path, monkeypatch):
    """sysPass ships with public links disabled; these tests enable them."""
    monkeypatch.setattr(
        "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(tmp_path / "rt.json")
    )
    monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", LINK_SALT)
    monkeypatch.setattr(
        "app.core.syspass_runtime_config.load_syspass_runtime_config", lambda: {"passwordSalt": LINK_SALT}
    )
    db_session.add(Config(parameter="publinks_enabled", value="true"))
    db_session.commit()


def _legacy_link(db_session, account, user, password=None):
    """A link row as earlier pySysPass releases wrote it (read support only)."""
    now = int(time.time())
    data = EncryptionService(settings.ENCRYPTION_KEY).encrypt(password).encode() if password else None
    link = PublicLink(accountId=account.id, hash=b"legacy" + bytes(str(account.id), "ascii"), data=data,
                      userId=user.id, typeId=1, dateAdd=now, dateExpire=now + 3600, maxCountViews=3)
    db_session.add(link)
    db_session.commit()
    return link

@pytest.mark.asyncio
async def test_create_public_link(db_session, encryption_service, test_user):
    """Test creating a public link"""

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        master_pass=TEST_MASTER_PASSWORD
    )

    assert link.id is not None
    assert link.accountId == account.id
    assert link.hash is not None
    assert len(link.hash) == 60  # PHP PasswordUtil::generateRandomBytes(): 30 bytes as hex
    assert link.data.startswith(b'O:19:"SP\\Core\\Crypt\\Vault"')
    assert link.has_password is False

@pytest.mark.asyncio
async def test_create_public_link_with_password(db_session, encryption_service, test_user):
    """PHP links have no access password, so none can be stored natively."""

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    with pytest.raises(ValueError, match="access passwords"):
        PublicLinkService(db_session).create_public_link(
            account_id=account.id, user_id=test_user.id, password="protect123", master_pass=TEST_MASTER_PASSWORD,
        )
    assert db_session.query(PublicLink).count() == 0

@pytest.mark.asyncio
async def test_create_public_link_with_expiration(db_session, encryption_service, test_user):
    """Test creating a public link with expiration"""

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        expire_seconds=3600,  # 1 hour
        master_pass=TEST_MASTER_PASSWORD
    )

    assert link.expire == 3600

@pytest.mark.asyncio
async def test_get_public_links_for_account(db_session, encryption_service, test_user):
    """Test getting all public links for an account"""

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    service = PublicLinkService(db_session)

    service.create_public_link(account_id=account.id, user_id=test_user.id, master_pass=TEST_MASTER_PASSWORD)

    links = service.get_public_links_for_account(account.id, test_user.id)

    assert len(links) == 1


@pytest.mark.asyncio
async def test_account_can_only_have_one_public_link(db_session, encryption_service, test_user):
    """Match the PHP uk_PublicLink_02 unique constraint on itemId."""

    account = AccountService(db_session, encryption_service).create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    service = PublicLinkService(db_session)
    service.create_public_link(account_id=account.id, user_id=test_user.id, master_pass=TEST_MASTER_PASSWORD)

    with pytest.raises(ValueError, match="already has a public link"):
        service.create_public_link(account_id=account.id, user_id=test_user.id, master_pass=TEST_MASTER_PASSWORD)

@pytest.mark.asyncio
async def test_get_public_link_by_hash(db_session, encryption_service, test_user):
    """Test getting a public link by hash"""

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        master_pass=TEST_MASTER_PASSWORD
    )

    result = service.get_public_link(link.hash)

    assert result is not None
    retrieved_link, account = result
    assert retrieved_link.hash == link.hash
    assert account.id == account.id

@pytest.mark.asyncio
async def test_public_link_requires_correct_password(db_session, encryption_service, test_user):
    """Legacy password-protected links keep their access check."""

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    link = _legacy_link(db_session, account, test_user, password="correct123")
    service = PublicLinkService(db_session)

    assert service.get_public_link(link.hash, "wrong123") is None
    assert service.get_public_link(link.hash, "correct123") is not None

@pytest.mark.asyncio
async def test_cannot_access_public_link_without_password(db_session, encryption_service, test_user):
    """Legacy password-protected links cannot be opened without the password."""

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    link = _legacy_link(db_session, account, test_user, password="protect123")

    assert PublicLinkService(db_session).get_public_link(link.hash) is None

@pytest.mark.asyncio
async def test_delete_public_link(db_session, encryption_service, test_user):
    """Test deleting a public link"""

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Test Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        master_pass=TEST_MASTER_PASSWORD
    )

    result = service.delete_public_link(link.id, test_user.id)

    assert result

    # Verify link is deleted
    result = service.get_public_link(link.hash)
    assert result is None

@pytest.mark.asyncio
async def test_cannot_create_public_link_for_nonexistent_account(db_session, encryption_service, test_user):
    """Test that public links cannot be created for non-existent accounts"""
    service = PublicLinkService(db_session)

    with pytest.raises(ValueError):
        service.create_public_link(
            account_id=99999,
            user_id=test_user.id,
        master_pass=TEST_MASTER_PASSWORD
        )

@pytest.mark.asyncio
async def test_cannot_access_others_public_links(db_session, encryption_service, test_user):
    """Test that users cannot access other users' public links"""
    from app.models.account import User
    from app.services.auth_service import get_password_hash

    # Create another user
    other_user = User(
        name="otheruser", userProfileId=1, hashSalt=b"s" * 32, username="otheruser",
        email="other@example.com",
        password=get_password_hash("password"),
        isUserAdmin=False,
        userGroupId=1
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        account_create(title="Private Account", password="secret"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        master_pass=TEST_MASTER_PASSWORD
    )

    # Other user should not be able to get the link
    assert service.get_public_link_by_id(link.id, other_user.id) is None
    assert service.get_public_links_for_account(account.id, other_user.id) == []

def test_public_link_routes_are_registered():
    """Test that public link routes are registered"""
    from app.main import app

    from tests.conftest import api_route_paths
    route_paths = api_route_paths(app)

    assert "/api/v1/accounts/{account_id}/public-links" in route_paths
    assert "/api/v1/accounts/{account_id}/public-links/{link_id}" in route_paths
    assert "/api/v1/public-links/{link_hash}/access" in route_paths


@pytest.mark.parametrize('limit', [0, 1, 2])
def test_php_public_link_view_limit_and_counters(db_session, encryption_service, test_user, limit):

    account = AccountService(db_session, encryption_service).create_account(
        account_create(title='View limit', password='test-only'), test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    service = PublicLinkService(db_session)
    link = service.create_public_link(account.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)
    link.maxCountViews = limit
    link.totalCountViews = 7
    db_session.commit()
    for _ in range(limit):
        assert service.get_public_link(link.hash) is not None
    assert service.get_public_link(link.hash) is None
    db_session.refresh(link)
    assert link.countViews == limit
    assert link.totalCountViews == 7 + limit


@pytest.mark.parametrize('expiry_offset', [-1, 0, 1])
def test_php_public_link_expiration_boundary(db_session, encryption_service, test_user, monkeypatch, expiry_offset):

    monkeypatch.setattr('app.services.public_link_service.time.time', lambda: 2000000000)
    account = AccountService(db_session, encryption_service).create_account(
        account_create(title='Expiry', password='test-only'), test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    service = PublicLinkService(db_session)
    link = service.create_public_link(account.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)
    link.dateExpire = 2000000000 + expiry_offset
    db_session.commit()
    assert (service.get_public_link(link.hash) is not None) == (expiry_offset > 0)


def test_rejected_link_password_does_not_consume_view(db_session, encryption_service, test_user):

    account = AccountService(db_session, encryption_service).create_account(
        account_create(title='Protected limit', password='test-only'), test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    service = PublicLinkService(db_session)
    link = _legacy_link(db_session, account, test_user, password='link-password')
    assert service.get_public_link(link.hash, 'wrong') is None
    assert link.countViews == 0
    assert service.get_public_link(link.hash, 'link-password') is not None
    assert link.countViews == 1


def test_created_link_is_native_and_readable(db_session, encryption_service, test_user):
    from app.core.php_public_link import read_public_link_snapshot

    account = AccountService(db_session, encryption_service).create_account(
        account_create(title='Native — café', login='nat', url='https://n.example', notes='n',
                       password='Snap-秘密!'), test_user.id, master_pass=TEST_MASTER_PASSWORD,
    )
    before = int(time.time())
    link = PublicLinkService(db_session).create_public_link(account.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)
    snapshot = read_public_link_snapshot(link.data, link.hash, LINK_SALT, account.id)
    assert (snapshot.name, snapshot.login, snapshot.password) == ('Native — café', 'nat', 'Snap-秘密!')
    assert (snapshot.client_name, snapshot.category_name) == ('Test Client', 'Test Category')
    # Default lifetime is PHP's publinks_max_time (600 s), not a Python constant.
    assert before + 600 <= link.dateExpire <= int(time.time()) + 600
    result = PublicLinkService(db_session).get_public_link(link.hash)
    assert result is not None and result[1].password == 'Snap-秘密!'


def test_link_creation_requires_vault_salt_and_enablement(db_session, encryption_service, test_user, monkeypatch):
    account = AccountService(db_session, encryption_service).create_account(
        account_create(title='Gates', password='x'), test_user.id, master_pass=TEST_MASTER_PASSWORD,
    )
    service = PublicLinkService(db_session)
    with pytest.raises(VaultRequiredError):
        service.create_public_link(account.id, test_user.id)
    with pytest.raises(ValueError, match="could not be decrypted"):
        service.create_public_link(account.id, test_user.id, master_pass='wrong-master')

    monkeypatch.setattr("app.core.syspass_runtime_config.load_syspass_runtime_config", lambda: {})
    monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", "")
    with pytest.raises(ValueError, match="salt"):
        service.create_public_link(account.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)

    db_session.query(Config).filter_by(parameter="publinks_enabled").update({"value": "false"})
    db_session.commit()
    with pytest.raises(PublicLinksDisabledError):
        service.create_public_link(account.id, test_user.id, master_pass=TEST_MASTER_PASSWORD)
    assert db_session.query(PublicLink).count() == 0
