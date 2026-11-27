"""Test alembic upgrade on a database bootstrapped from PHP schema with fixture data.

This test validates that alembic migrations can be applied cleanly on top of a
database that was initialized from schemas/dbstructure.sql (the canonical PHP
schema) and populated with fixture/reference data. This is the exact scenario
for existing sysPass installations upgrading to pySysPass.

Threats covered: T-TEST-01, T-TEST-02 (ADR-0019).
"""
import json
import os
import secrets

import pytest
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.db.bootstrap import bootstrap_database
from app.models.account import (
    Category,
    Client,
    Config as ConfigModel,
    User,
    UserGroup,
    UserProfile,
)
from app.schemas.user_profile import ProfilePermissions
from app.services.auth_service import get_password_hash, hash_master_key


def _run_alembic_upgrade(engine, revision="head", stamp_first=False):
    """Run alembic upgrade on the given engine."""
    import os
    # Set DATABASE_URL env var so alembic/env.py picks it up
    # Use render_as_string(hide_password=False) to include password in URL
    db_url = engine.url.render_as_string(hide_password=False)
    os.environ["DATABASE_URL"] = db_url
    # Also update the cached settings object
    from app.core.config import settings
    settings.DATABASE_URL = db_url
    cfg = Config("alembic.ini")
    if stamp_first:
        # Stamp the database at revision 002 (PHP schema + views already exist from bootstrap)
        command.stamp(cfg, "002")
    # Now upgrade to head (applies 003, 004, 005)
    command.upgrade(cfg, revision)


MYSQL_URL = os.environ.get("PYSYSPASS_MYSQL_TEST_URL")

pytestmark = pytest.mark.skipif(
    not MYSQL_URL, reason="PYSYSPASS_MYSQL_TEST_URL not set (disposable MySQL server required)"
)


@pytest.fixture(scope="function")
def mysql_engine():
    """Create a disposable MySQL database bootstrapped from PHP schema."""
    server_url = make_url(MYSQL_URL)
    database = f"pysyspass_alembic_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    with admin.begin() as conn:
        conn.execute(
            text(
                f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        )
    engine = create_engine(server_url.set(database=database))
    try:
        # Bootstrap from schemas/dbstructure.sql (PHP-compatible schema)
        assert bootstrap_database(engine) is True
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))
        admin.dispose()


def _seed_fixture_data(engine):
    """Seed the bootstrapped database with realistic fixture/reference data."""
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine)  # noqa: N806
    session = Session()
    try:
        # Create default profile with all permissions
        permissions = {key: True for key in ProfilePermissions.model_fields}
        profile = UserProfile(
            name="Default Profile",
            profile=json.dumps(permissions).encode("utf-8"),
        )
        session.add(profile)
        session.flush()

        # Create default group
        group = UserGroup(name="Default Group", description="Test group")
        session.add(group)
        session.flush()

        # Create a test user
        user = User(
            name="Test User",
            username="testuser",
            email="test@example.com",
            password=get_password_hash("testpassword").encode("utf-8"),
            userGroupId=group.id,
            userProfileId=profile.id,
            hashSalt=secrets.token_bytes(32),
            loginCount=0,
            lastUpdateMPass=0,
        )
        session.add(user)
        session.flush()

        # Create client and category
        client = Client(name="Test Client")
        category = Category(name="Test Category")
        from app.services.category_service import make_item_hash
        client.hash = make_item_hash(client.name)
        category.hash = make_item_hash(category.name)
        session.add_all([client, category])
        session.flush()

        # Create an account
        from app.models.account import Account
        account = Account(
            name="Test Account",
            userId=user.id,
            userEditId=user.id,
            userGroupId=group.id,
            clientId=client.id,
            categoryId=category.id,
            pass_=b"encrypted_password",
            key=b"encryption_key",
        )
        session.add(account)

        # Set master password in Config
        master_hash = hash_master_key("testpassword")
        config = ConfigModel(parameter="masterPwd", value=master_hash)
        session.add(config)

        session.commit()
        return {
            "user_id": user.id,
            "group_id": group.id,
            "profile_id": profile.id,
            "client_id": client.id,
            "category_id": category.id,
            "account_id": account.id,
        }
    finally:
        session.close()


def _verify_data_intact(engine, fixture_ids):
    """Verify that seeded fixture data survives alembic upgrade."""
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=engine)  # noqa: N806
    session = Session()
    try:
        # Verify User
        user = session.get(User, fixture_ids["user_id"])
        assert user is not None, "User should exist after alembic upgrade"
        assert user.username == "testuser"
        assert user.userGroupId == fixture_ids["group_id"]
        assert user.userProfileId == fixture_ids["profile_id"]

        # Verify UserGroup
        group = session.get(UserGroup, fixture_ids["group_id"])
        assert group is not None, "UserGroup should exist after alembic upgrade"
        assert group.name == "Default Group"

        # Verify UserProfile
        profile = session.get(UserProfile, fixture_ids["profile_id"])
        assert profile is not None, "UserProfile should exist after alembic upgrade"
        assert profile.name == "Default Profile"

        # Verify Client
        client = session.get(Client, fixture_ids["client_id"])
        assert client is not None, "Client should exist after alembic upgrade"
        assert client.name == "Test Client"

        # Verify Category
        category = session.get(Category, fixture_ids["category_id"])
        assert category is not None, "Category should exist after alembic upgrade"
        assert category.name == "Test Category"

        # Verify Account
        from app.models.account import Account
        account = session.get(Account, fixture_ids["account_id"])
        assert account is not None, "Account should exist after alembic upgrade"
        assert account.name == "Test Account"

        # Verify Config (master password)
        config = session.query(ConfigModel).filter_by(parameter="masterPwd").first()
        assert config is not None, "Config.masterPwd should exist after alembic upgrade"
        assert config.value is not None

        # Verify CustomFieldType fixture data (from dbstructure.sql)
        result = session.execute(text("SELECT COUNT(*) FROM CustomFieldType")).scalar()
        assert result == 10, f"Expected 10 CustomFieldType rows, got {result}"

        print("All fixture data verified intact after alembic upgrade")
    finally:
        session.close()


def test_alembic_upgrade_on_php_bootstrapped_database(mysql_engine):
    """Test that alembic upgrade head works on a PHP-schema-bootstrapped database with fixture data."""
    # Seed fixture data onto the bootstrapped schema
    fixture_ids = _seed_fixture_data(mysql_engine)

    # Verify data exists before alembic upgrade
    _verify_data_intact(mysql_engine, fixture_ids)

    # Run alembic upgrade head (first time, needs stamping)
    _run_alembic_upgrade(mysql_engine, "head", stamp_first=True)

    # Verify alembic_version matches head (005)
    with mysql_engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == "005", f"Expected alembic_version '005', got '{version}'"

    # Verify alembic extension tables were created
    with mysql_engine.connect() as conn:
        tables = conn.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
            )
        ).fetchall()
        table_names = {row[0] for row in tables}
        assert "service_accounts" in table_names, "service_accounts table should exist after upgrade"
        assert "service_auth_tokens" in table_names, "service_auth_tokens table should exist after upgrade"
        assert "service_vault_contexts" in table_names, "service_vault_contexts table should exist after upgrade"

    # Verify original fixture data is still intact
    _verify_data_intact(mysql_engine, fixture_ids)

    # Verify PHP views still exist
    with mysql_engine.connect() as conn:
        views = conn.execute(
            text(
                "SELECT table_name FROM information_schema.views "
                "WHERE table_schema = DATABASE()"
            )
        ).fetchall()
        view_names = {row[0] for row in views}
        assert "account_data_v" in view_names, "account_data_v view should exist after upgrade"
        assert "account_search_v" in view_names, "account_search_v view should exist after upgrade"


def test_alembic_upgrade_idempotent_on_php_bootstrapped_database(mysql_engine):
    """Test that running alembic upgrade head twice is idempotent."""
    # Seed fixture data
    fixture_ids = _seed_fixture_data(mysql_engine)

    # First upgrade (needs stamping)
    _run_alembic_upgrade(mysql_engine, "head", stamp_first=True)

    # Second upgrade should be a no-op (no stamping)
    _run_alembic_upgrade(mysql_engine, "head", stamp_first=False)

    # Verify alembic_version still matches head
    with mysql_engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == "005"

    # Verify data still intact
    _verify_data_intact(mysql_engine, fixture_ids)


def test_alembic_current_shows_head_after_upgrade(mysql_engine):
    """Test that 'alembic current' shows head revision after upgrade."""
    _seed_fixture_data(mysql_engine)

    _run_alembic_upgrade(mysql_engine, "head", stamp_first=True)

    # Check current revision via alembic API
    from alembic.script import ScriptDirectory
    from alembic.migration import MigrationContext
    from alembic.config import Config

    with mysql_engine.connect() as conn:
        context = MigrationContext.configure(conn)
        current_rev = context.get_current_revision()
        assert current_rev == "005", f"Expected current revision '005', got '{current_rev}'"

        # Also verify via script directory
        cfg = Config("alembic.ini")
        script = ScriptDirectory.from_config(cfg)
        heads = script.get_heads()
        assert "005" in heads, f"Expected head '005' in {heads}"


if __name__ == "__main__":
    # Allow running directly for debugging (requires MYSQL_URL env var)
    pytest.main([__file__, "-v", "-s"])
