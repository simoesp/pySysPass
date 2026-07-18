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
    assert updated.is_favorite

@pytest.mark.asyncio
async def test_delete_account(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    account_data = AccountCreate(title="To Delete", password="pass1")
    account = service.create_account(account_data, test_user.id)

    result = service.delete_account(account.id, test_user.id)

    assert result
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

    from tests.conftest import api_route_paths
    route_paths = api_route_paths(app)
    assert route_paths.index("/api/v1/accounts/search") < route_paths.index("/api/v1/accounts/{account_id}")


def test_count_route_is_registered_before_account_id_route():
    from app.main import app

    from tests.conftest import api_route_paths
    route_paths = api_route_paths(app)
    assert route_paths.index("/api/v1/accounts/count") < route_paths.index("/api/v1/accounts/{account_id}")


@pytest.mark.asyncio
async def test_get_accounts_pagination(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)

    for i in range(5):
        service.create_account(AccountCreate(title=f"Account {i}", password="pass"), test_user.id)

    all_accounts = service.get_accounts(test_user.id)
    assert len(all_accounts) == 5

    first_page = service.get_accounts(test_user.id, skip=0, limit=2)
    second_page = service.get_accounts(test_user.id, skip=2, limit=2)
    last_page = service.get_accounts(test_user.id, skip=4, limit=2)

    assert len(first_page) == 2
    assert len(second_page) == 2
    assert len(last_page) == 1

    seen_ids = [a.id for a in first_page + second_page + last_page]
    assert sorted(seen_ids) == sorted(a.id for a in all_accounts)
    assert len(set(seen_ids)) == 5

    assert service.count_accounts(test_user.id) == 5


@pytest.mark.asyncio
async def test_get_accounts_filters_and_count(db_session, encryption_service, test_user):
    from app.models.account import Tag, AccountToTag
    from app.services.category_service import make_item_hash

    service = AccountService(db_session, encryption_service)

    tag = Tag(name="prod", hash=make_item_hash("prod"))
    db_session.add(tag)
    db_session.commit()
    db_session.refresh(tag)

    github = service.create_account(
        AccountCreate(title="GitHub", login="gh_user", password="pass",
                      category_id=1, client_id=1),
        test_user.id,
    )
    service.create_account(
        AccountCreate(title="GitLab", login="gl_user", password="pass",
                      category_id=2, client_id=1),
        test_user.id,
    )
    service.create_account(
        AccountCreate(title="Mail", login="mail_user", password="pass",
                      category_id=2, client_id=2),
        test_user.id,
    )
    db_session.add(AccountToTag(accountId=github.id, tagId=tag.id))
    db_session.commit()

    assert {a.title for a in service.get_accounts(test_user.id, q="Git")} \
        == {"GitHub", "GitLab"}
    assert service.count_accounts(test_user.id, q="Git") == 2

    assert len(service.get_accounts(test_user.id, category_id=2)) == 2
    assert service.count_accounts(test_user.id, category_id=2) == 2

    assert len(service.get_accounts(test_user.id, client_id=1)) == 2
    assert service.count_accounts(test_user.id, client_id=1) == 2

    tagged = service.get_accounts(test_user.id, tag_id=tag.id)
    assert [a.id for a in tagged] == [github.id]
    assert service.count_accounts(test_user.id, tag_id=tag.id) == 1

    assert service.count_accounts(test_user.id, q="Git", client_id=1) == 2
    assert service.count_accounts(test_user.id, q="Git", category_id=2) == 1


@pytest.mark.asyncio
async def test_count_accounts_is_scoped_to_user(db_session, encryption_service, test_user):
    from app.models.account import User
    from app.services.auth_service import get_password_hash

    other_user = User(
        username="counter",
        email="counter@example.com",
        password=get_password_hash("testpassword"),
        isUserAdmin=False,
        userGroupId=99,
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)

    service = AccountService(db_session, encryption_service)
    service.create_account(AccountCreate(title="Mine", password="pass"), test_user.id)

    assert service.count_accounts(test_user.id) == 1
    assert service.count_accounts(other_user.id) == 0
