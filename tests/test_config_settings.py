import asyncio

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.v1 import config_settings


def test_encryption_status_supports_php_account_history_schema(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            'CREATE TABLE "Account" (id INTEGER PRIMARY KEY, pass BLOB)'
        )
        connection.exec_driver_sql(
            'CREATE TABLE "AccountHistory" (id INTEGER PRIMARY KEY, pass BLOB)'
        )
        connection.exec_driver_sql(
            'INSERT INTO "Account" (id, pass) VALUES (1, X\'01\'), (2, NULL)'
        )
        connection.exec_driver_sql(
            'INSERT INTO "AccountHistory" (id, pass) VALUES (1, X\'02\'), (2, NULL)'
        )

    monkeypatch.setattr(config_settings.ConfigService, "get", lambda self, key: None)

    with Session(engine) as db:
        result = asyncio.run(
            config_settings.get_encryption_status(db=db, current_user={})
        )

    assert result.encrypted_accounts == 1
    assert result.encrypted_history == 1
