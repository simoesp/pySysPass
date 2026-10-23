import pytest
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db.base import Base, get_db
from app.core.security import EncryptionService
from app.services.account_service import AccountService
from app.models.account import User, UserGroup, UserProfile
from app.schemas.user_profile import ProfilePermissions
import secrets

from tests.account_refs import add_reference_rows
from tests.seed_data import seed_demo_workspace

# Test database (SQLite in-memory)
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
PHYSICAL_TABLES = [
    table for table in Base.metadata.sorted_tables if not table.info.get("is_view")
]


def _bootstrap_test_fixtures(db) -> UserGroup:
    """Create the minimum reference rows tests depend on."""
    permissions = {key: True for key in ProfilePermissions.model_fields}
    profile = UserProfile(
        id=1,
        name="Default Profile",
        profile=json.dumps(permissions).encode("utf-8"),
    )
    db.add(profile)
    db.flush()
    group = UserGroup(id=1, name="Default Group", description="Test group")
    db.add(group)
    db.flush()
    add_reference_rows(db)
    return group


@pytest.fixture(autouse=True)
def isolated_session_store(tmp_path, monkeypatch):
    """Keep session revocation state out of the checkout's data/ directory."""
    from app.services.session_service import session_store

    monkeypatch.setattr(session_store, "path", tmp_path / "sessions.json")
    monkeypatch.setattr(session_store, "_cache", None)
    return session_store


@pytest.fixture(autouse=True)
def isolated_runtime_json(tmp_path, monkeypatch):
    """Never let a test write the checkout's config/runtime-config.json."""
    monkeypatch.setattr(
        "app.core.runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH",
        str(tmp_path / "runtime-config.json"),
    )


@pytest.fixture(autouse=True)
def isolated_two_factor_pending(tmp_path, monkeypatch):
    """Keep pending 2FA enrollment secrets out of the checkout's data/ directory."""
    from app.services import two_factor_service

    monkeypatch.setattr(two_factor_service._PendingSetups, "_path",
                        staticmethod(lambda: tmp_path / "two-factor-pending.json"))


@pytest.fixture(autouse=True)
def fresh_runtime_policy():
    """Runtime policy is cached per process; never carry it across tests."""
    from app.services.runtime_policy import invalidate_policy_cache

    invalidate_policy_cache()
    yield
    invalidate_policy_cache()


@pytest.fixture(scope="function")
def db_session():
    # Mapped PHP views must not be materialized as tables. Tests should fail
    # honestly until bootstrap creates real views and a test explicitly opts in.
    Base.metadata.create_all(bind=engine, tables=PHYSICAL_TABLES)
    db = TestingSessionLocal()
    try:
        _bootstrap_test_fixtures(db)
        db.commit()
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine, tables=PHYSICAL_TABLES)

@pytest.fixture(scope="function")
def encryption_service():
    return EncryptionService("test-encryption-key-32bytes!!")

@pytest.fixture(scope="function")
def test_user(db_session):
    from app.services.auth_service import get_password_hash
    hashed = get_password_hash("testpassword")
    if isinstance(hashed, str):
        hashed = hashed.encode("utf-8")
    user = User(
        id=2,
        name="Test User",
        username="testuser",
        email="test@example.com",
        password=hashed,
        isUserAdmin=False,
        userGroupId=1,
        userProfileId=1,
        hashSalt=secrets.token_bytes(32),
        loginCount=0,
        lastUpdateMPass=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def demo_workspace(db_session, encryption_service, test_user):
    return seed_demo_workspace(db_session, encryption_service, test_user)


def api_route_paths(app):
    """Flattened route paths in registration order.

    FastAPI >= 0.139 wraps included routers in _IncludedRouter objects
    without a .path attribute; walk through them via include_context.
    """
    paths = []

    def walk(routes, prefix=""):
        for route in routes:
            ctx = getattr(route, "include_context", None)
            if ctx is not None:
                walk(ctx.included_router.routes, prefix + (ctx.prefix or ""))
                continue
            path = getattr(route, "path", None)
            if path is not None:
                paths.append(prefix + path)

    walk(app.routes)
    return paths
