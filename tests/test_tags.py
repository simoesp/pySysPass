import pytest
from app.schemas.tag import TagCreate, TagUpdate
from app.services.tag_service import TagService
from app.models.account import Tag, AccountToTag

@pytest.mark.asyncio
async def test_create_tag(db_session, test_user):
    """Test creating a new tag"""
    service = TagService(db_session)
    tag_data = TagCreate(name="Work", color="#FF5733")

    tag = service.create_tag(tag_data, test_user.id)

    assert tag.id is not None
    assert tag.name == "Work"
    assert tag.color == "#FF5733"
    assert tag.userId == test_user.id

@pytest.mark.asyncio
async def test_get_tags(db_session, test_user):
    """Test listing tags"""
    service = TagService(db_session)

    # Create multiple tags
    for name in ["Work", "Personal", "Finance"]:
        service.create_tag(TagCreate(name=name), test_user.id)

    tags = service.get_tags(test_user.id)

    assert len(tags) == 3

@pytest.mark.asyncio
async def test_get_tag(db_session, test_user):
    """Test getting a specific tag"""
    service = TagService(db_session)
    tag_data = TagCreate(name="Test Tag", color="#00FF00")
    tag = service.create_tag(tag_data, test_user.id)

    retrieved = service.get_tag(tag.id)

    assert retrieved is not None
    assert retrieved.id == tag.id
    assert retrieved.name == "Test Tag"

@pytest.mark.asyncio
async def test_update_tag(db_session, test_user):
    """Test updating a tag"""
    service = TagService(db_session)
    tag_data = TagCreate(name="Original", color="#000000")
    tag = service.create_tag(tag_data, test_user.id)

    update_data = TagUpdate(name="Updated", color="#FFFFFF")
    updated = service.update_tag(tag.id, update_data)

    assert updated.name == "Updated"
    assert updated.color == "#FFFFFF"

@pytest.mark.asyncio
async def test_delete_tag(db_session, test_user):
    """Test deleting a tag"""
    service = TagService(db_session)
    tag_data = TagCreate(name="To Delete")
    tag = service.create_tag(tag_data, test_user.id)

    result = service.delete_tag(tag.id)

    assert result
    assert service.get_tag(tag.id) is None

@pytest.mark.asyncio
async def test_add_tag_to_account(db_session, encryption_service, test_user):
    """Test adding a tag to an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    tag_service = TagService(db_session)

    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    tag = tag_service.create_tag(TagCreate(name="Important"), test_user.id)

    result = tag_service.add_tag_to_account(account.id, tag.id)

    assert result

    # Verify association exists
    association = db_session.query(AccountToTag).filter(
        AccountToTag.accountId == account.id,
        AccountToTag.tagId == tag.id
    ).first()

    assert association is not None

@pytest.mark.asyncio
async def test_remove_tag_from_account(db_session, encryption_service, test_user):
    """Test removing a tag from an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    tag_service = TagService(db_session)

    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    tag = tag_service.create_tag(TagCreate(name="Test Tag"), test_user.id)
    tag_service.add_tag_to_account(account.id, tag.id)

    result = tag_service.remove_tag_from_account(account.id, tag.id)

    assert result

    # Verify association is removed
    association = db_session.query(AccountToTag).filter(
        AccountToTag.accountId == account.id,
        AccountToTag.tagId == tag.id
    ).first()

    assert association is None

@pytest.mark.asyncio
async def test_get_account_tags(db_session, encryption_service, test_user):
    """Test getting all tags for an account"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    tag_service = TagService(db_session)

    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    # Add multiple tags
    for name in ["Work", "Important", "Urgent"]:
        tag = tag_service.create_tag(TagCreate(name=name), test_user.id)
        tag_service.add_tag_to_account(account.id, tag.id)

    tags = tag_service.get_account_tags(account.id)

    assert len(tags) == 3

@pytest.mark.asyncio
async def test_cannot_add_duplicate_tag_to_account(db_session, encryption_service, test_user):
    """Test that adding the same tag twice returns False"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    tag_service = TagService(db_session)

    account = account_service.create_account(
        AccountCreate(title="Test Account", password="secret"),
        test_user.id
    )

    tag = tag_service.create_tag(TagCreate(name="Test Tag"), test_user.id)

    # Add tag first time
    result1 = tag_service.add_tag_to_account(account.id, tag.id)
    assert result1

    # Try to add same tag again
    result2 = tag_service.add_tag_to_account(account.id, tag.id)
    assert not result2

@pytest.mark.asyncio
async def test_search_accounts_by_tag(db_session, encryption_service, test_user):
    """Test searching accounts by tag"""
    from app.services.account_service import AccountService
    from app.schemas.account import AccountCreate

    account_service = AccountService(db_session, encryption_service)
    tag_service = TagService(db_session)

    # Create accounts
    account1 = account_service.create_account(
        AccountCreate(title="GitHub Account", password="secret"),
        test_user.id
    )

    account2 = account_service.create_account(
        AccountCreate(title="GitLab Account", password="secret"),
        test_user.id
    )

    account3 = account_service.create_account(
        AccountCreate(title="Other Account", password="secret"),
        test_user.id
    )

    # Create "Work" tag and apply to first two accounts
    work_tag = tag_service.create_tag(TagCreate(name="Work"), test_user.id)
    tag_service.add_tag_to_account(account1.id, work_tag.id)
    tag_service.add_tag_to_account(account2.id, work_tag.id)

    # Search accounts by tag
    results = tag_service.search_accounts_by_tag(work_tag.id, test_user.id)

    assert len(results) == 2
    assert account1.id in [a.id for a in results]
    assert account2.id in [a.id for a in results]
    assert account3.id not in [a.id for a in results]

def test_tag_route_is_registered():
    """Test that tag routes are registered"""
    from app.main import app

    from tests.conftest import api_route_paths
    route_paths = api_route_paths(app)

    # Check main tag routes exist
    assert "/api/v1/tags" in route_paths
    assert "/api/v1/tags/{tag_id}" in route_paths
    assert "/api/v1/accounts/{account_id}/tags" in route_paths
    assert "/api/v1/accounts/{account_id}/tags/{tag_id}" in route_paths
