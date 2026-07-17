import pytest
from app.services.public_link_service import PublicLinkService

@pytest.mark.asyncio
async def test_create_public_link(db_session, encryption_service, test_user):
    """Test creating a public link"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id
    )

    assert link.id is not None
    assert link.accountId == account.id
    assert link.hash is not None
    assert len(link.hash) == 64  # SHA256 hex

@pytest.mark.asyncio
async def test_create_public_link_with_password(db_session, encryption_service, test_user):
    """Test creating a public link with password protection"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        password="protect123"
    )

    assert link.password is not None  # Should be encrypted

@pytest.mark.asyncio
async def test_create_public_link_with_expiration(db_session, encryption_service, test_user):
    """Test creating a public link with expiration"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        expire_seconds=3600  # 1 hour
    )

    assert link.expire == 3600

@pytest.mark.asyncio
async def test_get_public_links_for_account(db_session, encryption_service, test_user):
    """Test getting all public links for an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)

    service.create_public_link(account_id=account.id, user_id=test_user.id)

    links = service.get_public_links_for_account(account.id, test_user.id)

    assert len(links) == 1


@pytest.mark.asyncio
async def test_account_can_only_have_one_public_link(db_session, encryption_service, test_user):
    """Match the PHP uk_PublicLink_02 unique constraint on itemId."""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account = AccountService(db_session, encryption_service).create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id,
    )
    service = PublicLinkService(db_session)
    service.create_public_link(account_id=account.id, user_id=test_user.id)

    with pytest.raises(ValueError, match="already has a public link"):
        service.create_public_link(account_id=account.id, user_id=test_user.id)

@pytest.mark.asyncio
async def test_get_public_link_by_hash(db_session, encryption_service, test_user):
    """Test getting a public link by hash"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id
    )

    result = service.get_public_link(link.hash)

    assert result is not None
    retrieved_link, account = result
    assert retrieved_link.hash == link.hash
    assert account.id == account.id

@pytest.mark.asyncio
async def test_public_link_requires_correct_password(db_session, encryption_service, test_user):
    """Test that password-protected links require correct password"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        password="correct123"
    )

    # Try with wrong password
    result = service.get_public_link(link.hash, "wrong123")
    assert result is None

    # Try with correct password
    result = service.get_public_link(link.hash, "correct123")
    assert result is not None

@pytest.mark.asyncio
async def test_cannot_access_public_link_without_password(db_session, encryption_service, test_user):
    """Test that password-protected links cannot be accessed without password"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id,
        password="protect123"
    )

    # Try without password
    result = service.get_public_link(link.hash)
    assert result is None

@pytest.mark.asyncio
async def test_delete_public_link(db_session, encryption_service, test_user):
    """Test deleting a public link"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id
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
            user_id=test_user.id
        )

@pytest.mark.asyncio
async def test_cannot_access_others_public_links(db_session, encryption_service, test_user):
    """Test that users cannot access other users' public links"""
    from app.services.account_service import AccountService
    from app.models.account import User
    from app.services.auth_service import get_password_hash
    from app.schemas.account import AccountCreate

    # Create another user
    other_user = User(
        username="otheruser",
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
        AccountCreate(title="Private Account", password="secret"),
        test_user.id
    )

    service = PublicLinkService(db_session)
    link = service.create_public_link(
        account_id=account.id,
        user_id=test_user.id
    )

    # Other user should not be able to get the link
    assert service.get_public_link_by_id(link.id, other_user.id) is None
    assert service.get_public_links_for_account(account.id, other_user.id) == []

def test_public_link_routes_are_registered():
    """Test that public link routes are registered"""
    from app.main import app

    route_paths = [route.path for route in app.routes]

    assert "/api/v1/accounts/{account_id}/public-links" in route_paths
    assert "/api/v1/accounts/{account_id}/public-links/{link_id}" in route_paths
    assert "/api/v1/public-links/{link_hash}/access" in route_paths
