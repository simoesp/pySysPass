import asyncio
from unittest.mock import Mock

from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.v1 import config_settings
from app.schemas.config import RekeyRequest


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


def test_unsafe_rekey_cannot_read_or_modify_persisted_secrets():
    db = Mock()
    with pytest.raises(HTTPException) as error:
        asyncio.run(config_settings.rekey_encryption(
            body=RekeyRequest(current_key="old-key", new_key="new-key", new_key_confirm="new-key"),
            db=db,
            current_user={"is_admin_app": True},
        ))
    assert error.value.status_code == 409
    assert db.mock_calls == []
