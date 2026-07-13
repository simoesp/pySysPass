import pytest
from app.schemas.account import AccountCreate, AccountUpdate
from app.services.account_service import AccountService
from app.core.security import EncryptionService

@pytest.mark.asyncio
async def test_create_account(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    account_data = AccountCreate(
        title="Test Account",
        description="Test Description",
        login="testuser",
        password="secret123",
        url="https://example.com"
    )
    
    account = service.create_account(account_data, test_user.id)
    
    assert account.id is not None
    assert account.title == "Test Account"
    assert account.login == "testuser"
    assert account.user_id == test_user.id
    assert account.password != "secret123"  # Should be encrypted

@pytest.mark.asyncio
async def test_get_accounts(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    
    # Create test accounts
    for i in range(3):
        account_data = AccountCreate(
            title=f"Account {i}",
            password="secret123"
        )
        service.create_account(account_data, test_user.id)
    
    accounts = service.get_accounts(test_user.id)
    
    assert len(accounts) == 3

@pytest.mark.asyncio
async def test_get_decrypted_password(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    
    account_data = AccountCreate(
        title="Secret Account",
        password="my-secret-password"
    )
    account = service.create_account(account_data, test_user.id)
    
    decrypted = service.get_decrypted_password(account.id)
    
    assert decrypted == "my-secret-password"

@pytest.mark.asyncio
async def test_update_account(db_session, encryption_service, test_user):
    from app.schemas.account import AccountUpdate
    
    service = AccountService(db_session, encryption_service)
    account_data = AccountCreate(title="Original", password="pass1")
    account = service.create_account(account_data, test_user.id)
    
    update_data = AccountUpdate(title="Updated Title", is_favorite=True)
    updated = service.update_account(account.id, update_data, test_user.id)
    
    assert updated.title == "Updated Title"
    assert updated.is_favorite == True

@pytest.mark.asyncio
async def test_delete_account(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    account_data = AccountCreate(title="To Delete", password="pass1")
    account = service.create_account(account_data, test_user.id)
    
    result = service.delete_account(account.id, test_user.id)
    
    assert result == True
    assert service.get_account(account.id) is None

@pytest.mark.asyncio
async def test_search_accounts(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    
    # Create accounts
    service.create_account(AccountCreate(title="GitHub Account", login="github_user", password="pass"), test_user.id)
    service.create_account(AccountCreate(title="GitLab Account", login="gitlab_user", password="pass"), test_user.id)
    service.create_account(AccountCreate(title="Other Account", login="other_user", password="pass"), test_user.id)
    
    # Search
    results = service.search_accounts(test_user.id, "GitHub")
    
    assert len(results) == 1
    assert "GitHub" in results[0].title

@pytest.mark.asyncio
async def test_account_access_is_scoped_to_owner(db_session, encryption_service, test_user):
    from app.models.account import User
    from app.services.auth_service import get_password_hash

    other_user = User(
        username="otheruser",
        email="other@example.com",
        password=get_password_hash("testpassword"),
        isUserAdmin=False,
        userGroupId=1
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)

    service = AccountService(db_session, encryption_service)
    account = service.create_account(
        AccountCreate(title="Private Account", password="secret123"),
        test_user.id,
    )

    assert service.get_account(account.id, other_user.id) is None
    assert service.get_decrypted_password(account.id, other_user.id) is None
    assert service.update_account(account.id, AccountUpdate(title="Stolen"), other_user.id) is None
    assert service.delete_account(account.id, other_user.id) is False
    assert service.get_account(account.id, test_user.id) is not None


def test_search_route_is_registered_before_account_id_route():
    from app.main import app

    route_paths = [route.path for route in app.routes]
    assert route_paths.index("/api/v1/accounts/search") < route_paths.index("/api/v1/accounts/{account_id}")
