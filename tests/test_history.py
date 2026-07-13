import pytest
from app.services.history_service import HistoryService
from app.schemas.history import AccountHistoryCreate

@pytest.mark.asyncio
async def test_create_history_entry(db_session, encryption_service, test_user):
    """Test creating a history entry"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    history = service.create_history(
        account_id=account.id,
        user_id=test_user.id,
        action="create",
        new_value="Account created"
    )
    
    assert history.id is not None
    assert history.accountId == account.id
    assert history.userId == test_user.id
    assert history.action == "create"
    assert history.newValue == "Account created"

@pytest.mark.asyncio
async def test_get_account_history(db_session, encryption_service, test_user):
    """Test getting history for an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    
    # Create multiple history entries
    service.create_history(account.id, test_user.id, "create", new_value="Created")
    service.create_history(account.id, test_user.id, "update", old_value="Title: Old", new_value="Title: New")
    service.create_history(account.id, test_user.id, "decrypt")
    
    history = service.get_account_history(account.id, test_user.id)
    
    assert len(history) == 3

@pytest.mark.asyncio
async def test_get_user_history(db_session, encryption_service, test_user):
    """Test getting all history for a user"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    
    # Create multiple accounts
    account1 = account_service.create_account(
        AccountCreate(title="Account 1", password="secret"),
        test_user.id
    )
    account2 = account_service.create_account(
        AccountCreate(title="Account 2", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    service.create_history(account1.id, test_user.id, "create")
    service.create_history(account2.id, test_user.id, "create")
    service.create_history(account1.id, test_user.id, "view")
    
    history = service.get_user_history(test_user.id)
    
    assert len(history) == 3

@pytest.mark.asyncio
async def test_log_view(db_session, encryption_service, test_user):
    """Test logging a view event"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    history = service.log_view(account.id, test_user.id)
    
    assert history.action == "view"

@pytest.mark.asyncio
async def test_log_decrypt(db_session, encryption_service, test_user):
    """Test logging a decrypt event"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    history = service.log_decrypt(account.id, test_user.id)
    
    assert history.action == "decrypt"

@pytest.mark.asyncio
async def test_log_password_change(db_session, encryption_service, test_user):
    """Test logging a password change"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    history = service.log_password_change(account.id, test_user.id)
    
    assert history.action == "password_change"

@pytest.mark.asyncio
async def test_get_decrypt_count(db_session, encryption_service, test_user):
    """Test getting decrypt count for an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    
    # Log multiple decrypt events
    service.log_decrypt(account.id, test_user.id)
    service.log_decrypt(account.id, test_user.id)
    service.log_decrypt(account.id, test_user.id)
    
    count = service.get_account_decrypt_count(account.id)
    
    assert count == 3

@pytest.mark.asyncio
async def test_get_view_count(db_session, encryption_service, test_user):
    """Test getting view count for an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    
    # Log multiple view events
    service.log_view(account.id, test_user.id)
    service.log_view(account.id, test_user.id)
    service.log_view(account.id, test_user.id)
    service.log_view(account.id, test_user.id)
    
    count = service.get_account_view_count(account.id)
    
    assert count == 4

@pytest.mark.asyncio
async def test_history_includes_old_and_new_values(db_session, encryption_service, test_user):
    """Test that update history includes old and new values"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Original Title", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    history = service.log_update(
        account.id,
        test_user.id,
        "title",
        "Original Title",
        "Updated Title"
    )
    
    assert "title: Original Title" in history.oldValue
    assert "title: Updated Title" in history.newValue

@pytest.mark.asyncio
async def test_history_logged_for_file_operations(db_session, encryption_service, test_user):
    """Test that file upload/download events are logged"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate
    
    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )
    
    service = HistoryService(db_session)
    
    # Log file operations
    service.log_file_upload(account.id, test_user.id, "document.pdf")
    service.log_file_download(account.id, test_user.id, "document.pdf")
    
    history = service.get_account_history(account.id, test_user.id)
    
    file_ops = [h for h in history if h.action in ["file_upload", "file_download"]]
    assert len(file_ops) == 2

def test_history_routes_are_registered():
    """Test that history routes are registered"""
    from app.main import app
    
    route_paths = [route.path for route in app.routes]
    
    assert "/api/v1/accounts/{account_id}/history" in route_paths
    assert "/api/v1/accounts/{account_id}/history/decrypt-count" in route_paths
    assert "/api/v1/accounts/{account_id}/history/view-count" in route_paths
    assert "/api/v1/users/{user_id}/history" in route_paths
