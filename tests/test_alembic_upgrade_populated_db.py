"""Test Alembic upgrade on a database populated from schemas/dbstructure.sql.

ADR-0019 verification items V-01 and V-02, and threats T-TEST-01 and T-TEST-02:

* V-01/T-TEST-01 — the Alembic migration chain must run cleanly on top of a
  real, data-populated database bootstrapped from the canonical PHP schema
  (the upgrade path every existing sysPass installation will take). A test
  that only migrates a virgin database does not prove that: seeded runtime
  rows can turn schema steps into constraint or FK failures.
* V-02/T-TEST-02 — after the upgrade, ``alembic_version`` must equal the head
  revision and every runtime row seeded before the upgrade must be intact
  (the migration chain must never lose or rewrite PHP-owned data).

The test reconstructs the production upgrade path:

  1. Create a fresh database and apply ``schemas/dbstructure.sql`` via the
     canonical bootstrap (``alembic upgrade 001`` executes that very script).
  2. Populate it with realistic runtime fixture data (users, groups, clients,
     categories, accounts, config, …) the way a live installation has.
  3. Snapshot every table's content.
  4. ``alembic upgrade head`` with the fixture rows in place.
  5. Assert: no errors, ``alembic_version`` matches head, and every snapshot
     row is still byte-identical (the chain may add tables, never rewrite
     existing content).

This is a MySQL-only proof: the bootstrap schema is MySQL-dialect DDL
(SQLite test databases are built from ORM metadata instead, so "bootstrap
from schemas/dbstructure.sql" cannot be exercised there). The tests skip
unless ``PYSYSPASS_MYSQL_TEST_URL`` names a disposable MySQL 8 server — the
same server the canonical-MySQL CI jobs bring up.
"""

import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, inspect, select, func, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[1]

MYSQL_SERVER_URL = os.environ.get("PYSYSPASS_MYSQL_TEST_URL")

pytestmark = pytest.mark.skipif(
    not MYSQL_SERVER_URL,
    reason="PYSYSPASS_MYSQL_TEST_URL not set (disposable MySQL 8 server required)",
)


@pytest.fixture(autouse=True)
def _restore_config_globals():
    """Never leak per-test DATABASE_URL / engine bindings into other tests."""
    import app.core.config as config_module
    import app.db.base as base_module

    prev_settings_url = config_module.settings.DATABASE_URL
    prev_settings_env = os.environ.get("DATABASE_URL")
    prev_base_url = base_module.settings.DATABASE_URL
    prev_engine = base_module.engine
    yield
    config_module.settings.DATABASE_URL = prev_settings_url
    base_module.settings.DATABASE_URL = prev_base_url
    base_module.engine = prev_engine
    if prev_settings_env is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = prev_settings_env


def _rebind_base_engine(url: str):
    """Point app.db.base's module-level engine at ``url`` (no guard).

    The app binds its SessionLocal to a module-level engine created from
    settings.DATABASE_URL; the model ``before_insert`` listeners query through
    the session's own connection, so rebinding SessionLocal (plus the
    settings both modules read) routes all ORM work at the test database.
    """
    import app.core.config as config_module
    import app.db.base as base_module

    if base_module.engine is not None:
        base_module.engine.dispose()
    engine = create_engine(url, pool_pre_ping=True)
    base_module.engine = engine
    base_module.SessionLocal.configure(bind=engine)
    config_module.settings.DATABASE_URL = url
    base_module.settings.DATABASE_URL = url
    return engine


def _alembic_config(url: str):
    """An Alembic Config repointed at ``url`` for both env.py engine paths."""
    from alembic.config import Config

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    # env.py builds its engines from settings.DATABASE_URL (sync) and the
    # ini's sqlalchemy.url (async); point both at the per-test database.
    cfg.set_main_option("sqlalchemy.url", url)
    import app.core.config as config_module
    import app.db.base as base_module

    config_module.settings.DATABASE_URL = url
    base_module.settings.DATABASE_URL = url
    os.environ["DATABASE_URL"] = url
    return cfg


def _head_revision() -> str:
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(_alembic_config(str(make_url(MYSQL_SERVER_URL))))
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head, got {heads}"
    return heads[0]


def _current_revision(engine):
    if "alembic_version" not in inspect(engine).get_table_names():
        return None
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


# ---------------------------------------------------------------------------
# Runtime fixture data (post-bootstrap, pre-upgrade)
# ---------------------------------------------------------------------------


def _insert_unique(session, instance) -> None:
    """Insert one row with PHP-style MAX(id)+1 sequencing, fully committed.

    The application's own ``before_insert`` listeners (User / UserGroup)
    compute sequential PKs via ``MAX(id) + 1`` against the bound connection.
    To stay faithful to that runtime behaviour without racing it, each row is
    inserted and committed individually and its ``id`` is pinned explicitly
    from ``MAX(id) + 1`` (what the listeners would have produced).
    """
    table = instance.__table__
    next_id = (session.scalar(select(func.max(table.c["id"]).label("mid"))) or 0) + 1
    instance.id = next_id
    session.add(instance)
    session.flush()


def _populate_fixtures(engine) -> dict:
    """Insert realistic runtime data into a bootstrapped PHP schema.

    Returns {"snapshot": {table: [row-tuples]}, "account_ids": [...]} where
    the snapshot is taken immediately after insertion so the upgrade test can
    compare the exact bytes afterwards.
    """
    from app.models.account import (
        Account,
        Category,
        Client,
        Config as ConfigModel,
        EventLog,
        Tag,
        Track,
        User,
        UserGroup,
        UserProfile,
    )
    from app.schemas.user_profile import ProfilePermissions
    from app.services.auth_service import get_password_hash, hash_master_key
    from app.services.category_service import make_item_hash

    factory = sessionmaker(bind=engine)
    session = factory()
    try:
        permissions = {key: True for key in ProfilePermissions.model_fields}

        _insert_unique(
            session,
            UserProfile(
                name="Default Profile",
                profile=json.dumps(permissions).encode("utf-8"),
            ),
        )
        profile = session.query(UserProfile).order_by(UserProfile.id.desc()).first()
        _insert_unique(session, UserGroup(name="Administrators", description="Admin group"))
        admin_group = (
            session.query(UserGroup)
            .filter(UserGroup.name == "Administrators")
            .one()
        )
        _insert_unique(session, UserGroup(name="Users", description="Standard group"))
        user_group = session.query(UserGroup).filter(UserGroup.name == "Users").one()
        session.commit()

        password = get_password_hash("upgrade-path-login").encode("utf-8")
        _insert_unique(
            session,
            User(
                name="Upgrade Admin",
                username=f"upgrade-admin-{secrets.token_hex(3)}",
                email="admin@example.com",
                password=password,
                userGroupId=admin_group.id,
                userProfileId=profile.id,
                hashSalt=secrets.token_bytes(32),
                loginCount=3,
                lastUpdateMPass=0,
                isAdminApp=True,
            ),
        )
        admin = session.query(User).order_by(User.id.desc()).first()
        _insert_unique(
            session,
            User(
                name="Upgrade Member",
                username=f"upgrade-member-{secrets.token_hex(3)}",
                email="member@example.com",
                password=password,
                userGroupId=user_group.id,
                userProfileId=profile.id,
                hashSalt=secrets.token_bytes(32),
                loginCount=1,
                lastUpdateMPass=0,
            ),
        )
        member = session.query(User).order_by(User.id.desc()).first()
        session.commit()

        client_name = f"Upgrade Client {secrets.token_hex(3)}"
        category_name = f"Upgrade Category {secrets.token_hex(3)}"
        tag_name = f"upgrade-{secrets.token_hex(3)}"
        _insert_unique(session, Client(name=client_name, hash=make_item_hash(client_name)))
        client = session.query(Client).filter(Client.name == client_name).one()
        _insert_unique(session, Category(name=category_name, hash=make_item_hash(category_name)))
        category = session.query(Category).filter(Category.name == category_name).one()
        _insert_unique(session, Tag(name=tag_name, hash=make_item_hash(tag_name)))
        session.commit()

        now = datetime(2026, 11, 27, 12, 0, 0)
        account_ids = []
        for index in range(5):
            _insert_unique(
                session,
                Account(
                    name=f"upgrade-account-{index}",
                    userId=admin.id,
                    userEditId=member.id,
                    userGroupId=admin_group.id,
                    clientId=client.id,
                    categoryId=category.id,
                    login=f"user{index}",
                    url=f"https://example{index}.invalid",
                    pass_=hashlib.sha256(f"pass-{index}".encode()).digest(),
                    key=hashlib.sha256(f"key-{index}".encode()).digest(),
                    notes=f"runtime notes {index}",
                    countView=index,
                    countDecrypt=index * 2,
                    dateAdd=now + timedelta(days=index),
                    isPrivate=bool(index % 2),
                ),
            )
            account = (
                session.query(Account)
                .filter(Account.name == f"upgrade-account-{index}")
                .one()
            )
            account_ids.append(account.id)
        session.commit()

        for i in range(3):
            _insert_unique(
                session,
                EventLog(
                    date=1764240000 + i,
                    login=admin.username,
                    userId=admin.id,
                    ipAddress="10.0.0.1",
                    action="CLI.login",
                    description="upgrade fixture event",
                    level="info",
                ),
            )
        session.commit()
        for i in range(2):
            _insert_unique(
                session,
                Track(
                    userId=member.id,
                    source="pytest-upgrade",
                    time=1764240000 + i,
                    timeUnlock=1764243600 + i,
                    ipv4=bytes([10, 0, 0, i]),
                ),
            )
        session.commit()

        # masterPwd is normally set by the install flow; production databases
        # being upgraded always have it (Config rows are PHP-owned data the
        # migration chain must never disturb).
        session.add(
            ConfigModel(parameter="masterPwd", value=hash_master_key("upgrade-path-master"))
        )
        session.add(ConfigModel(parameter="lastUpdate", value="1764240000"))
        session.commit()

        # Snapshot every physical table's rows for byte-exact comparison
        # after the upgrade.
        snapshot: dict[str, list[tuple]] = {}
        inspector = inspect(engine)
        with engine.connect() as conn:
            for name in sorted(inspector.get_table_names()):
                if name == "alembic_version":
                    continue
                columns = [col["name"] for col in inspector.get_columns(name)]
                order_col = "parameter" if name == "Config" else (
                    "id" if "id" in columns else columns[0]
                )
                cols = ", ".join(f"`{c}`" for c in columns)
                rows = [
                    tuple(row)
                    for row in conn.execute(
                        text(f"SELECT {cols} FROM `{name}` ORDER BY `{order_col}`")
                    )
                ]
                if rows:
                    snapshot[name] = rows
        return {"snapshot": snapshot, "account_ids": account_ids}
    finally:
        session.close()


def _assert_fixtures_intact(engine, populated: dict) -> None:
    """Every pre-upgrade row must still be present and byte-identical."""
    inspector = inspect(engine)
    live_tables = set(inspector.get_table_names())
    for name, rows in populated["snapshot"].items():
        assert name in live_tables, f"table {name} disappeared during alembic upgrade"
        columns = [col["name"] for col in inspector.get_columns(name)]
        order_col = "parameter" if name == "Config" else (
            "id" if "id" in columns else columns[0]
        )
        cols = ", ".join(f"`{c}`" for c in columns)
        with engine.connect() as conn:
            actual = [
                tuple(row)
                for row in conn.execute(
                    text(f"SELECT {cols} FROM `{name}` ORDER BY `{order_col}`")
                )
            ]
        assert actual == rows, f"runtime data in {name} changed during alembic upgrade"

    # The account rows must also still be reachable through the ORM and the
    # canonical PHP view (the chain must not break PHP read paths).
    from app.models.account import Account

    factory = sessionmaker(bind=engine)
    session = factory()
    try:
        for account_id in populated["account_ids"]:
            account = session.get(Account, account_id)
            assert account is not None, f"account {account_id} lost during upgrade"
            assert account.name.startswith("upgrade-account-")
        view_rows = session.execute(
            text("SELECT COUNT(*) FROM account_search_v WHERE name LIKE 'upgrade-account-%'")
        ).scalar()
        assert view_rows == len(populated["account_ids"]), "PHP account view lost migrated rows"
    finally:
        session.close()


def _create_scratch_database(admin, database: str) -> None:
    with admin.begin() as conn:
        conn.execute(
            text(
                f"CREATE DATABASE `{database}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        )


def _drop_scratch_database(admin, database: str) -> None:
    with admin.begin() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS `{database}`"))


@pytest.fixture()
def populated_mysql_database():
    """A disposable MySQL DB bootstrapped from schemas/dbstructure.sql via
    revision 001 (the canonical bootstrap itself), populated with runtime
    fixture data, stamped at the bootstrap-equivalent revision 002 — i.e. the
    exact state of a live PHP-era installation that is about to be upgraded.
    """
    from alembic import command

    server_url = make_url(MYSQL_SERVER_URL)
    database = f"pysyspass_upg_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    _create_scratch_database(admin, database)
    url = server_url.set(database=database).render_as_string(hide_password=False)
    engine = _rebind_base_engine(url)
    try:
        # 1. Bootstrap the canonical PHP schema through revision 001 itself
        #    (it executes schemas/dbstructure.sql verbatim on MySQL).
        command.upgrade(_alembic_config(url), "001")
        assert _current_revision(engine) == "001"

        # 2. Runtime fixture data on top of the freshly bootstrapped schema.
        populated = _populate_fixtures(engine)
        assert populated["snapshot"], "fixture seeding produced no rows"

        # 3. Alembic 002 is a no-op view-repair for a complete bootstrap;
        #    stamp it so the upgrade starts from the bootstrap-equivalent
        #    revision, exactly like the deployment flow after a bootstrap.
        command.stamp(_alembic_config(url), "002")

        yield {"engine": engine, "url": url, "populated": populated}
    finally:
        _drop_scratch_database(admin, database)
        admin.dispose()


def test_alembic_upgrade_head_no_errors_on_populated_db(populated_mysql_database):
    """V-01/T-TEST-01: 'alembic upgrade head' completes without errors."""
    from alembic import command

    env = populated_mysql_database
    # An exception here is exactly the T-TEST-01 failure mode: migrations
    # that only work on a virgin database.
    command.upgrade(_alembic_config(env["url"]), "head")


def test_alembic_version_matches_head_after_populated_upgrade(populated_mysql_database):
    """V-02 part 1: alembic_version equals the head revision after upgrade."""
    from alembic import command

    env = populated_mysql_database
    head = _head_revision()
    command.upgrade(_alembic_config(env["url"]), "head")
    assert _current_revision(env["engine"]) == head, (
        "alembic_version must equal head after upgrade"
    )


def test_runtime_data_intact_after_alembic_upgrade(populated_mysql_database):
    """V-02/T-TEST-02: all runtime rows survive the upgrade byte-for-byte."""
    from alembic import command

    env = populated_mysql_database
    before_tables = set(inspect(env["engine"]).get_table_names())
    command.upgrade(_alembic_config(env["url"]), "head")
    _assert_fixtures_intact(env["engine"], env["populated"])

    # The newly created Python-extension tables must exist but be empty:
    # upgrades must never synthesize runtime rows. Which extension tables
    # exist depends on the migration chain on this branch, so derive the set
    # by diffing the table inventory before and after the upgrade (works for
    # any chain: head-002 chains add nothing; longer chains add e.g.
    # emergency_credentials, service_accounts, service_vault_contexts).
    new_tables = sorted(set(inspect(env["engine"]).get_table_names()) - before_tables)
    with env["engine"].connect() as conn:
        for extension_table in new_tables:
            count = conn.execute(text(f"SELECT COUNT(*) FROM `{extension_table}`")).scalar()
            # audit_retention_policies ships defaults from the audit migration;
            # that is intended seed data, not runtime data, so it may be
            # non-empty.
            if extension_table != "audit_retention_policies":
                assert count == 0, (
                    f"{extension_table} has {count} rows after upgrade "
                    "(migrations must not synthesize runtime data)"
                )


def test_upgrade_is_idempotent_on_populated_db(populated_mysql_database):
    """Re-running 'alembic upgrade head' after a successful upgrade is a no-op."""
    from alembic import command

    env = populated_mysql_database
    head = _head_revision()
    cfg = _alembic_config(env["url"])
    command.upgrade(cfg, "head")
    command.upgrade(_alembic_config(env["url"]), "head")  # must not error or re-run
    assert _current_revision(env["engine"]) == head
    _assert_fixtures_intact(env["engine"], env["populated"])


def test_bootstrap_database_then_alembic_upgrade_head_on_populated_db():
    """Startup path: bootstrap_database() on a virgin DB, then live data,
    then 'alembic upgrade head' — must succeed, stamp head, keep data."""
    from alembic import command

    from app.db.bootstrap import bootstrap_database

    server_url = make_url(MYSQL_SERVER_URL)
    database = f"pysyspass_bs_{secrets.token_hex(4)}"
    admin = create_engine(server_url.set(database=None))
    _create_scratch_database(admin, database)
    url = server_url.set(database=database).render_as_string(hide_password=False)
    engine = _rebind_base_engine(url)
    try:
        # Application startup hook materializes the PHP schema on a virgin DB.
        assert bootstrap_database(engine) is True
        assert bootstrap_database(engine) is False  # idempotent

        # Runtime rows arrive (PHP-era usage), then the deployment runs the
        # migration chain over the populated database. The startup path does
        # not stamp alembic (ADR-0016), so stamp at the bootstrap-equivalent
        # revision 001 first (all physical tables already exist; 002 is a
        # no-op repair on a complete schema and is included in the upgrade).
        populated = _populate_fixtures(engine)
        command.stamp(_alembic_config(url), "001")
        head = _head_revision()
        command.upgrade(_alembic_config(url), "head")  # must not error

        assert _current_revision(engine) == head
        _assert_fixtures_intact(engine, populated)
    finally:
        _drop_scratch_database(admin, database)
        admin.dispose()
