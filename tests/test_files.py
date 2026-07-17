import pytest
import base64
from app.services.file_service import FileService

@pytest.mark.asyncio
async def test_create_file(db_session, encryption_service, test_user):
    """Test creating a file attachment"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = FileService(db_session)
    content = b"Test file content"

    file = service.create_file(
        account_id=account.id,
        name="test.txt",
        file_type="text/plain",
        size=len(content),
        content=content,
        extension="txt"
    )

    assert file.id is not None
    assert file.accountId == account.id
    assert file.name == "test.txt"
    assert file.type == "text/plain"
    assert file.size == len(content)
    assert file.extension == "txt"

@pytest.mark.asyncio
async def test_get_files(db_session, encryption_service, test_user):
    """Test listing files for an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = FileService(db_session)

    # Create multiple files
    for i in range(3):
        content = f"File {i} content".encode()
        service.create_file(
            account_id=account.id,
            name=f"file{i}.txt",
            file_type="text/plain",
            size=len(content),
            content=content,
            extension="txt"
        )

    files = service.get_files(account.id, test_user.id)

    assert len(files) == 3

@pytest.mark.asyncio
async def test_get_file(db_session, encryption_service, test_user):
    """Test getting a specific file"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = FileService(db_session)
    content = b"Test content"
    file = service.create_file(
        account_id=account.id,
        name="test.txt",
        file_type="text/plain",
        size=len(content),
        content=content,
        extension="txt"
    )

    retrieved = service.get_file(file.id, test_user.id)

    assert retrieved is not None
    assert retrieved.id == file.id
    assert retrieved.name == "test.txt"

@pytest.mark.asyncio
async def test_get_file_content(db_session, encryption_service, test_user):
    """Test getting file content"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = FileService(db_session)
    content = b"Secret file content"
    file = service.create_file(
        account_id=account.id,
        name="secret.txt",
        file_type="text/plain",
        size=len(content),
        content=content,
        extension="txt"
    )

    file_content, file_type = service.get_file_content(file.id, test_user.id)

    assert file_content == content
    assert file_type == "text/plain"

@pytest.mark.asyncio
async def test_delete_file(db_session, encryption_service, test_user):
    """Test deleting a file"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = FileService(db_session)
    content = b"Test content"
    file = service.create_file(
        account_id=account.id,
        name="test.txt",
        file_type="text/plain",
        size=len(content),
        content=content,
        extension="txt"
    )

    result = service.delete_file(file.id, test_user.id)

    assert result
    assert service.get_file(file.id, test_user.id) is None

@pytest.mark.asyncio
async def test_get_file_count(db_session, encryption_service, test_user):
    """Test getting file count for an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = FileService(db_session)

    # Create multiple files
    for i in range(5):
        content = f"File {i}".encode()
        service.create_file(
            account_id=account.id,
            name=f"file{i}.txt",
            file_type="text/plain",
            size=len(content),
            content=content,
            extension="txt"
        )

    count = service.get_file_count(account.id, test_user.id)

    assert count == 5

@pytest.mark.asyncio
async def test_cannot_access_others_files(db_session, encryption_service, test_user):
    """Test that users cannot access other users' files"""
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

    service = FileService(db_session)
    content = b"Secret content"
    file = service.create_file(
        account_id=account.id,
        name="secret.txt",
        file_type="text/plain",
        size=len(content),
        content=content,
        extension="txt"
    )

    # Other user should not be able to access the file
    assert service.get_file(file.id, other_user.id) is None
    assert service.get_files(account.id, other_user.id) == []

@pytest.mark.asyncio
async def test_file_with_various_types(db_session, encryption_service, test_user):
    """Test creating files with different MIME types"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    service = FileService(db_session)

    # Create files with different types
    files_data = [
        ("document.pdf", "application/pdf", b"%PDF-content", "pdf"),
        ("image.png", "image/png", b"\x89PNG-content", "png"),
        ("script.py", "text/x-python", b"print('hello')", "py"),
    ]

    for name, file_type, content, ext in files_data:
        file = service.create_file(
            account_id=account.id,
            name=name,
            file_type=file_type,
            size=len(content),
            content=content,
            extension=ext
        )
        assert file.id is not None

    files = service.get_files(account.id, test_user.id)
    assert len(files) == 3

def test_file_routes_are_registered():
    """Test that file routes are registered"""
    from app.main import app

    route_paths = [route.path for route in app.routes]

    assert "/api/v1/accounts/{account_id}/files" in route_paths
    assert "/api/v1/accounts/{account_id}/files/{file_id}" in route_paths
    assert "/api/v1/accounts/{account_id}/files/{file_id}/metadata" in route_paths
    assert "/api/v1/accounts/{account_id}/files/count" in route_paths
