"""TEST-017: JWT rotation overlapping validity test.

Verifies that tokens signed with the old SECRET_KEY can still decode
within the grace period (when SECRET_KEY_PREVIOUS is set), and that
tokens signed with the PREVIOUS key are rejected after the grace period
(when SECRET_KEY_PREVIOUS is removed).

Depends on: IMPL-021
"""
from datetime import datetime, UTC, timedelta
import jwt
import pytest

from app.services.auth_service import create_access_token, decode_token
from app.models.account import User


def test_jwt_rotation_within_grace_period(db_session, test_user):
    """Token signed with old SECRET_KEY still decodes within grace period.

    When SECRET_KEY_PREVIOUS is set, decode_token() tries the current key
    first, then the previous key. A token signed with the old key should
    be decodable during the overlap window.
    """
    from app.core.config import settings

    old_key = "old-secret-key-32-bytes!!!!"  # 32 bytes minimum
    new_key = "new-super-secret-key-64-bytes!!"  # 32+ bytes

    # Set up: new key is current, old key is previous
    settings.SECRET_KEY = new_key
    settings.SECRET_KEY_PREVIOUS = old_key

    # Create a token signed with the OLD key using jwt.encode directly
    old_signed_token = jwt.encode(
        {"username": test_user.username, "user_id": test_user.id, "exp": datetime.now(UTC) + timedelta(hours=1)},
        old_key,
        algorithm="HS256",
    )

    # Within grace period: token signed with old key should decode
    payload = decode_token(old_signed_token)
    assert payload is not None
    assert payload["username"] == test_user.username
    assert payload["user_id"] == test_user.id


def test_jwt_rotation_rejected_after_grace_period(db_session, test_user):
    """Token signed with PREVIOUS key rejected after grace period.

    After the grace period, SECRET_KEY_PREVIOUS is removed, and tokens
    signed exclusively with the previous key should be rejected.
    """
    from app.core.config import settings
    from datetime import datetime, UTC, timedelta

    old_key = "old-secret-key-32-bytes!!!!"  # 32 bytes minimum

    # Set up: only new key is set, NO previous key
    settings.SECRET_KEY = "new-another-key-32-bytes-long!!!!!"  # 32 bytes
    settings.SECRET_KEY_PREVIOUS = None  # No previous key

    # Create a token signed with the OLD key
    old_signed_token = jwt.encode(
        {"username": test_user.username, "user_id": test_user.id, "exp": datetime.now(UTC) + timedelta(hours=1)},
        old_key,
        algorithm="HS256",
    )

    # After grace period: token signed with old key should be rejected
    payload = decode_token(old_signed_token)
    assert payload is None


def test_jwt_rotation_both_keys_work(db_session, test_user):
    """Both current and previous keys can decode their respective tokens.

    Verifies the overlap: current key signs new tokens, previous key
    can still decode old tokens during the grace period.
    """
    from app.core.config import settings

    old_key = "old-key-32-bytes!!!!!"  # 32 bytes
    new_key = "new-key-32-bytes!!!!!"  # 32 bytes

    settings.SECRET_KEY = new_key
    settings.SECRET_KEY_PREVIOUS = old_key

    # Token signed with current (new) key
    new_token = jwt.encode(
        {"username": test_user.username, "user_id": test_user.id, "exp": datetime.now(UTC) + timedelta(hours=1)},
        new_key,
        algorithm="HS256",
    )

    # Token signed with previous (old) key
    old_token = jwt.encode(
        {"username": test_user.username, "user_id": test_user.id, "exp": datetime.now(UTC) + timedelta(hours=1)},
        old_key,
        algorithm="HS256",
    )

    # Both should decode
    new_payload = decode_token(new_token)
    assert new_payload is not None
    assert new_payload["username"] == test_user.username

    old_payload = decode_token(old_token)
    assert old_payload is not None
    assert old_payload["username"] == test_user.username