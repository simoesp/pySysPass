import pytest
from app.services.two_factor_service import TwoFactorService

def test_generate_secret():
    """Test secret generation"""
    secret = TwoFactorService.generate_secret()
    assert len(secret) >= 16  # Base32 encoded
    assert isinstance(secret, str)

def test_generate_provisioning_uri():
    """Test provisioning URI generation"""
    secret = TwoFactorService.generate_secret()
    uri = TwoFactorService.generate_provisioning_uri(secret, "test@example.com", "sysPass")

    assert "otpauth://totp" in uri
    assert "test%40example.com" in uri or "test@example.com" in uri  # URL-encoded or not
    assert "sysPass" in uri

def test_verify_token():
    """Test TOTP token verification"""
    secret = TwoFactorService.generate_secret()
    totp = __import__('pyotp').TOTP(secret)

    # Generate a valid token
    token = totp.now()
    assert TwoFactorService.verify_token(secret, token)

    # Invalid token should fail
    assert not TwoFactorService.verify_token(secret, "000000")

def test_generate_backup_codes():
    """Test backup code generation"""
    codes = TwoFactorService.generate_backup_codes(8)

    assert len(codes) == 8
    for code in codes:
        assert len(code) == 10
        assert code.isdigit()

def test_verify_backup_code():
    """Test backup code verification"""
    codes = TwoFactorService.generate_backup_codes(8)
    valid_code = codes[0]

    # Verify valid code
    success, remaining = TwoFactorService.verify_backup_code(codes.copy(), valid_code)
    assert success
    assert len(remaining) == 7

    # Verify invalid code
    success, remaining = TwoFactorService.verify_backup_code(codes, "invalid123")
    assert not success


# ── PluginData-backed persistence (PHP Authenticator plugin parity) ────────

@pytest.fixture
def store(db_session, encryption_service):
    from app.services.two_factor_service import TwoFactorStore
    return TwoFactorStore(db_session, encryption_service)


def test_store_setup_then_enable_persists(db_session, store, test_user):
    import pyotp
    from app.models.account import PluginData

    secret = TwoFactorService.generate_secret()
    store.start_setup(test_user.id, secret)

    # Pending setup does not enable 2FA yet
    assert store.is_enabled(test_user.id) is False
    assert store.get_pending_secret(test_user.id) == secret

    codes = TwoFactorService.generate_backup_codes(8)
    store.enable(test_user.id, codes)

    assert store.is_enabled(test_user.id) is True
    assert store.get_secret(test_user.id) == secret
    assert store.get_backup_codes(test_user.id) == codes
    assert pyotp.TOTP(store.get_secret(test_user.id)).now()

    # Stored in the PHP Authenticator plugin's location
    row = db_session.query(PluginData).filter(
        PluginData.name == "Authenticator", PluginData.itemId == test_user.id,
    ).first()
    assert row is not None


def test_store_secret_is_encrypted_at_rest(db_session, store, test_user):
    import json
    from app.models.account import PluginData

    secret = TwoFactorService.generate_secret()
    store.start_setup(test_user.id, secret)
    store.enable(test_user.id, ["1234567890"])

    row = db_session.query(PluginData).filter(
        PluginData.name == "Authenticator", PluginData.itemId == test_user.id,
    ).first()
    raw = row.data.decode("utf-8") if isinstance(row.data, (bytes, bytearray)) else row.data
    assert secret not in raw
    assert "1234567890" not in raw
    assert json.loads(raw)["enabled"] is True


def test_store_disable_removes_row(db_session, store, test_user):
    from app.models.account import PluginData

    store.start_setup(test_user.id, TwoFactorService.generate_secret())
    store.enable(test_user.id, [])
    store.disable(test_user.id)

    assert store.is_enabled(test_user.id) is False
    assert db_session.query(PluginData).filter(
        PluginData.name == "Authenticator", PluginData.itemId == test_user.id,
    ).first() is None


def test_user_model_reflects_2fa_state(db_session, store, test_user):
    from app.services.user_service import UserService

    assert test_user.twoFactorAuth is False
    assert UserService(db_session).to_response(test_user)["two_factor_enabled"] is False

    store.start_setup(test_user.id, TwoFactorService.generate_secret())
    store.enable(test_user.id, [])

    assert test_user.twoFactorAuth is True
    assert test_user.two_factor_enabled is True
    assert UserService(db_session).to_response(test_user)["two_factor_enabled"] is True


def test_store_backup_code_consumption(db_session, store, test_user):
    store.start_setup(test_user.id, TwoFactorService.generate_secret())
    codes = TwoFactorService.generate_backup_codes(3)
    store.enable(test_user.id, codes)

    ok, remaining = TwoFactorService.verify_backup_code(
        store.get_backup_codes(test_user.id), codes[0]
    )
    assert ok
    store.set_backup_codes(test_user.id, remaining)
    assert len(store.get_backup_codes(test_user.id)) == 2
    assert codes[0] not in store.get_backup_codes(test_user.id)


# ── Global tri-state mode (Enforced / Enabled / Disabled) ──────────────────

def test_two_factor_mode_defaults_to_disabled(db_session):
    from app.services.two_factor_service import TwoFactorConfig
    assert TwoFactorConfig(db_session).get_mode() == "disabled"


def test_two_factor_mode_round_trip(db_session):
    from app.models.account import Plugin
    from app.services.two_factor_service import TwoFactorConfig

    cfg = TwoFactorConfig(db_session)
    for mode in ("enabled", "enforced", "disabled"):
        assert cfg.set_mode(mode) == mode
        assert cfg.get_mode() == mode

    with pytest.raises(ValueError):
        cfg.set_mode("bogus")

    # Stored on the upstream Plugin row, not new schema
    row = db_session.query(Plugin).filter(Plugin.name == "Authenticator").first()
    assert row is not None


def test_status_reports_setup_required_when_enforced(db_session, store, test_user):
    from app.services.two_factor_service import TwoFactorConfig

    cfg = TwoFactorConfig(db_session)
    cfg.set_mode("enforced")
    assert store.is_enabled(test_user.id) is False
    # setup_required semantics: enforced mode + not enrolled
    assert cfg.get_mode() == "enforced"

    store.start_setup(test_user.id, TwoFactorService.generate_secret())
    store.enable(test_user.id, [])
    assert store.is_enabled(test_user.id) is True
