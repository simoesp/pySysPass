import pytest
from app.models.account import Account
from app.schemas.account import AccountUpdate
from tests.account_refs import account_create, TEST_MASTER_PASSWORD
from app.services.account_service import AccountService, VaultRequiredError
from app.core.security import EncryptionService

@pytest.mark.asyncio
async def test_create_account(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    account_data = account_create(
        title="Test Account",
        description="Test Description",
        login="testuser",
        password="secret123",
        url="https://example.com"
    )

    account = service.create_account(account_data, test_user.id, master_pass=TEST_MASTER_PASSWORD)

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
        account_data = account_create(
            title=f"Account {i}",
            password="secret123"
        )
        service.create_account(account_data, test_user.id, master_pass=TEST_MASTER_PASSWORD)

    accounts = service.get_accounts(test_user.id)

    assert len(accounts) == 3

@pytest.mark.asyncio
async def test_get_decrypted_password(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)

    account_data = account_create(
        title="Secret Account",
        password="my-secret-password"
    )
    account = service.create_account(account_data, test_user.id, master_pass=TEST_MASTER_PASSWORD)

    assert service.get_decrypted_password(account.id, master_pass=TEST_MASTER_PASSWORD) == "my-secret-password"
    stored = db_session.get(Account, account.id)
    assert stored.key.startswith(b"def10000")  # native Defuse, not a Python format
    with pytest.raises(VaultRequiredError):
        service.get_decrypted_password(account.id)
    assert service.get_decrypted_password(account.id, master_pass="wrong-master") is None
    db_session.refresh(stored)
    assert stored.countDecrypt == 1  # failed decryptions are not counted

@pytest.mark.asyncio
async def test_update_account(db_session, encryption_service, test_user):
    from app.schemas.account import AccountUpdate

    service = AccountService(db_session, encryption_service)
    account_data = account_create(title="Original", password="pass1")
    account = service.create_account(account_data, test_user.id, master_pass=TEST_MASTER_PASSWORD)

    update_data = AccountUpdate(title="Updated Title", is_favorite=True)
    updated = service.update_account(account.id, update_data, test_user.id, master_pass=TEST_MASTER_PASSWORD)

    assert updated.title == "Updated Title"
    assert updated.is_favorite

@pytest.mark.asyncio
async def test_delete_account(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)
    account_data = account_create(title="To Delete", password="pass1")
    account = service.create_account(account_data, test_user.id, master_pass=TEST_MASTER_PASSWORD)

    result = service.delete_account(account.id, test_user.id)

    assert result
    assert service.get_account(account.id) is None

@pytest.mark.asyncio
async def test_search_accounts(db_session, encryption_service, test_user):
    service = AccountService(db_session, encryption_service)

    # Create accounts
    service.create_account(
        account_create(title="GitHub Account", login="github_user", password="pass"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    service.create_account(
        account_create(title="GitLab Account", login="gitlab_user", password="pass"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    service.create_account(
        account_create(title="Other Account", login="other_user", password="pass"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    # Search
    results = service.search_accounts(test_user.id, "GitHub")

    assert len(results) == 1
    assert "GitHub" in results[0].title

@pytest.mark.asyncio
async def test_account_access_is_scoped_to_owner(db_session, encryption_service, test_user):
    from app.models.account import User
    from app.services.auth_service import get_password_hash

    other_user = User(
        name="otheruser", userProfileId=1, hashSalt=b"s" * 32, username="otheruser",
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
        account_create(title="Private Account", password="secret123"),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    assert service.get_account(account.id, other_user.id) is None
    assert service.get_decrypted_password(account.id, other_user.id) is None
    assert service.update_account(
        account.id, AccountUpdate(title="Stolen"), other_user.id, master_pass=TEST_MASTER_PASSWORD
    ) is None
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
        service.create_account(
            account_create(title=f"Account {i}", password="pass"), test_user.id, master_pass=TEST_MASTER_PASSWORD
        )

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

    from app.models.account import Category, Client

    tag = Tag(name="prod", hash=make_item_hash("prod"))
    db_session.add(tag)
    db_session.add_all([
        Category(id=1, name="Cat 1", hash=make_item_hash("Cat 1")),
        Category(id=2, name="Cat 2", hash=make_item_hash("Cat 2")),
        Client(id=1, name="Client 1", hash=make_item_hash("Client 1")),
        Client(id=2, name="Client 2", hash=make_item_hash("Client 2")),
    ])
    db_session.commit()
    db_session.refresh(tag)

    github = service.create_account(
        account_create(title="GitHub", login="gh_user", password="pass",
                      category_id=1, client_id=1),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    service.create_account(
        account_create(title="GitLab", login="gl_user", password="pass",
                      category_id=2, client_id=1),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
    )
    service.create_account(
        account_create(title="Mail", login="mail_user", password="pass",
                      category_id=2, client_id=2),
        test_user.id, master_pass=TEST_MASTER_PASSWORD
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
    from app.models.account import User, UserGroup
    from app.services.auth_service import get_password_hash

    db_session.add(UserGroup(id=99, name="Counters"))
    other_user = User(
        name="counter", userProfileId=1, hashSalt=b"s" * 32, username="counter",
        email="counter@example.com",
        password=get_password_hash("testpassword"),
        isUserAdmin=False,
        userGroupId=99,
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)

    service = AccountService(db_session, encryption_service)
    service.create_account(
        account_create(title="Mine", password="pass"), test_user.id, master_pass=TEST_MASTER_PASSWORD
    )

    assert service.count_accounts(test_user.id) == 1
    assert service.count_accounts(other_user.id) == 0


def test_account_listing_queries_do_not_grow_with_rows(db_session, encryption_service, test_user):
    """Listing builds every row from a fixed number of queries (no N+1)."""
    from sqlalchemy import event

    from app.models.account import AccountToFavorite, Tag
    from app.schemas.account import SharedGroupEntry, SharedUserEntry
    from app.services.category_service import make_item_hash

    service = AccountService(db_session, encryption_service)
    db_session.add(Tag(id=5, name="t", hash=make_item_hash("t")))
    db_session.commit()

    def build(count):
        for index in range(count):
            created = service.create_account(account_create(
                title=f"q{count}-{index}", password="p", is_public=True, tag_ids=[5],
                shared_users=[SharedUserEntry(user_id=test_user.id)], shared_groups=[SharedGroupEntry(group_id=1)],
            ), test_user.id, master_pass=TEST_MASTER_PASSWORD)
            db_session.add(AccountToFavorite(accountId=created["id"], userId=test_user.id))
        db_session.commit()

    def queries_for_listing():
        engine = db_session.get_bind()
        seen = []
        listener = lambda *args: seen.append(1)  # noqa: E731
        event.listen(engine, "before_cursor_execute", listener)
        try:
            rows = AccountService(db_session, encryption_service).get_accounts(test_user.id, 0, 500)
        finally:
            event.remove(engine, "before_cursor_execute", listener)
        return len(rows), len(seen), rows

    build(5)
    small_rows, small, _ = queries_for_listing()
    build(45)
    large_rows, large, rows = queries_for_listing()
    assert (small_rows, large_rows) == (5, 50)
    assert large == small  # constant, not proportional to rows
    assert all(r["is_favorite"] and [t.id for t in r["tags"]] == [5] for r in rows)
    assert all(r["shared_users"][0].username == test_user.username for r in rows)
    assert all(r["shared_groups"][0].group_id == 1 for r in rows)
