"""Reference rows every test database provides for PHP-required account FKs.

sysPass PHP requires ``Account.clientId`` and ``Account.categoryId`` (NOT NULL
with foreign keys), so test accounts must point at real Client/Category rows.
"""
from app.models.account import Category, Client
from app.services.category_service import make_item_hash
from app.schemas.account import AccountCreate

TEST_CLIENT_ID = 900
TEST_CATEGORY_ID = 900


def add_reference_rows(db) -> None:
    db.add(Client(id=TEST_CLIENT_ID, name="Test Client", hash=make_item_hash("Test Client")))
    db.add(Category(id=TEST_CATEGORY_ID, name="Test Category", hash=make_item_hash("Test Category")))
    db.flush()


def account_create(**kwargs) -> AccountCreate:
    kwargs.setdefault("client_id", TEST_CLIENT_ID)
    kwargs.setdefault("category_id", TEST_CATEGORY_ID)
    return AccountCreate(**kwargs)
