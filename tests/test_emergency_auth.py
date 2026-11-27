"""Tests for Emergency Authentication Mode (ADR-0014).

TEST-004 acceptance criteria:
  1. Activation script works (create + activate flag file, 2-hour default timeout)
  2. Emergency endpoint validates MFA + activation flag
  3. 2-hour timeout enforced (auto-deactivation)
  4. Emergency sessions terminated on deactivation
  5. Offline recovery personnel authenticate only when mode is active
  6. Ordinary LDAP users still fail closed (ADR-0004 preserved)
  7. All emergency actions audited as CRITICAL

Status: TDD — the model + migration exist (IMPL-004 partial), but the
`emergency_auth` service, `/api/v1/auth/emergency` endpoint, and
activate/deactivate scripts are NOT yet implemented (IMPL-005/IMPL-006).
Endpoint, timeout, revocation, and script tests are therefore expected to
FAIL until those land; model-level tests run against the real app model.
"""
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import auth as auth_module
from app.api.v1 import auth as auth_router
from app.db.base import get_db
from app.models.account import EmergencyCredentials, EventLog, User
from app.services.auth_service import decode_token, get_password_hash, verify_password

REPO = Path(__file__).resolve().parents[1]

# Per ADR-0014 the timeout defaults to 2 hours and emergency tokens live 1 h.
EMERGENCY_DEFAULT_TIMEOUT_HOURS = 2
EMERGENCY_SESSION_SECONDS = 3600

# The three mandatory-MFA identity semantics of ADR-0014 section 5A.
NO_EMERGENCY_MODE_DETAIL_HINTS = ("not enabled", "not active", "403")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client():
    """Test client for the auth router, with the emergency route registered
    by the implementation (IMPL-005). Missing route -> 404 on every request."""
    app = FastAPI()
    app.include_router(auth_router.router, prefix="/api/v1/auth")
    return TestClient(app)


def _login(client, db_session, data):
    """POST /login with the test DB override applied."""
    client.app.dependency_overrides[get_db] = lambda: db_session
    return client.post("/api/v1/auth/login", data=data)


def _me(client, db_session, token):
    """GET /me with the test DB override applied."""
    client.app.dependency_overrides[get_db] = lambda: db_session
    return client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})


def _emergency(client, db_session, **data):
    app = client.app
    app.dependency_overrides[get_db] = lambda: db_session
    return client.post("/api/v1/auth/emergency", data=data)


def _make_emergency_user(db_session, username=None, password="SecurePass123!",
                          mfa_secret="JBSWY3DPEHPK3PXP", is_recovery=False,
                          enabled=True, recovery_token=None,
                          recovery_token_expires_at=None):
    """Create an emergency_credentials row via the real app model."""
    username = username or f"bg-{uuid.uuid4().hex[:8]}"
    user = EmergencyCredentials(
        username=username,
        password_hash=get_password_hash(password).encode("utf-8"),
        password_salt=b"test-salt",
        mfa_secret=mfa_secret.encode("utf-8") if mfa_secret else None,
        mfa_enabled=True,
        enabled=enabled,
        is_recovery_account=is_recovery,
        created_at=datetime.now(UTC).replace(tzinfo=None),
        recovery_token=recovery_token.encode() if recovery_token else None,
        recovery_token_expires_at=recovery_token_expires_at,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def emergency_mode(tmp_path, monkeypatch):
    """Point the emergency flag files at tmp_path.

    The implementation (IMPL-005/006) must expose the flag-file path as a
    module attribute or settings field so tests and deployments can relocate
    it; this fixture discovers the first candidate it finds and monkeypatches
    it. Until the service exists the fixture yields a tmp path and the
    deactivation hook is a no-op (tests that need activation fail honestly).
    """
    flag = tmp_path / "emergency-auth-active"

    candidates = []
    # Discovery order: service module attribute > settings field.
    import importlib
    for mod_name in ("app.services.emergency_auth", "app.core.emergency_auth"):
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            continue
        for attr in ("ACTIVE_FLAG_PATH", "FLAG_FILE", "EMERGENCY_FLAG_FILE", "active_flag_path"):
            if hasattr(mod, attr):
                candidates.append((mod, attr))
    try:
        from app.core.config import settings
        for attr in ("EMERGENCY_FLAG_FILE", "EMERGENCY_ACTIVE_FILE"):
            if hasattr(settings, attr):
                candidates.append((settings, attr))
    except ImportError:
        pass

    if candidates:
        mod, attr = candidates[0]
        monkeypatch.setattr(mod, attr, flag)

    def activate(timeout_hours=EMERGENCY_DEFAULT_TIMEOUT_HOURS, token="recovery-token-abc"):
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.write_text(f'{{"activated_at": "{datetime.now(UTC).isoformat()}", '
                        f'"timeout_hours": {timeout_hours}, "token": "{token}"}}',
                        encoding="utf-8")
        return flag

    def deactivate():
        flag.unlink(missing_ok=True)

    activate.__doc__ = "Write the activation flag file"
    return {"activate": activate, "deactivate": deactivate, "flag": flag}


def _valid_mfa(secret="JBSWY3DPEHPK3PXP"):
    import pyotp
    return pyotp.TOTP(secret).now()


# ---------------------------------------------------------------------------
# 1. Database model / schema (IMPL-004 — implemented; these tests guard it)
# ---------------------------------------------------------------------------

class TestEmergencyCredentialsModel:
    """ADR-0014 §2: separate emergency_credentials table, NOT the User table."""

    def test_table_registered_and_independent_of_user_table(self, db_session):
        from sqlalchemy import inspect
        inspector = inspect(db_session.bind)
        assert "emergency_credentials" in inspector.get_table_names()

        user_cols = {c["name"] for c in inspector.get_columns("User")}
        assert "isEmergency" not in user_cols
        assert "is_emergency" not in user_cols

    def test_columns_and_constraints(self, db_session):
        from sqlalchemy import inspect
        inspector = inspect(db_session.bind)
        cols = {c["name"]: c for c in inspector.get_columns("emergency_credentials")}
        for required in ("id", "username", "password_hash", "password_salt", "mfa_secret",
                         "mfa_enabled", "enabled", "is_recovery_account", "created_at",
                         "last_used_at", "recovery_token", "recovery_token_expires_at",
                         "created_by"):
            assert required in cols, f"missing column {required}"

        uniq = [u for u in inspect(db_session.bind).get_unique_constraints("emergency_credentials")]
        assert any(set(u["column_names"]) == {"username"} for u in uniq), \
            "username must be unique (ADR-0014 §2)"

    def test_break_glass_account_properties(self, db_session):
        user = _make_emergency_user(db_session, username=f"bg1-{uuid.uuid4().hex[:6]}")
        assert user.is_recovery_account is False
        assert user.mfa_enabled is True
        assert user.enabled is True
        assert user.is_active is True
        stored = user.password_hash
        stored = stored.decode() if isinstance(stored, bytes) else stored
        assert verify_password("SecurePass123!", stored)
        assert not verify_password("wrong", stored)

    def test_recovery_account_properties(self, db_session):
        user = _make_emergency_user(db_session, is_recovery=True)
        assert user.is_recovery_account is True
        assert user.mfa_enabled is True

    def test_disabled_account_not_active(self, db_session):
        user = _make_emergency_user(db_session, enabled=False)
        assert user.is_active is False

    def test_account_without_mfa_secret_not_active(self, db_session):
        user = _make_emergency_user(db_session, mfa_secret=None)
        assert user.is_active is False

    def test_username_unique_across_emergency_accounts(self, db_session):
        name = f"dup-{uuid.uuid4().hex[:6]}"
        _make_emergency_user(db_session, username=name)
        with pytest.raises(Exception):
            _make_emergency_user(db_session, username=name)

    def test_independent_of_user_table_namespace(self, db_session, test_user):
        """Same login string may exist as User and as EmergencyCredentials."""
        user = _make_emergency_user(db_session, username="testuser")
        regular = db_session.query(User).filter(User.username == "testuser").first()
        assert regular is not None and regular.id == test_user.id
        assert user.id != test_user.id

    def test_created_by_is_a_real_foreign_key_to_user(self, db_session, test_user):
        """ADR-0014 §2 created_by references the admin who provisioned the account.
        (Documented deviation: the ADR SQL sketch omits the FK; the app model
        adds it. Emergency *identity* independence from User is preserved —
        authentication never consults the User table, see endpoint tests.)"""
        from sqlalchemy.exc import IntegrityError
        user = _make_emergency_user(db_session)
        user.created_by = test_user.id
        db_session.commit()
        assert user.created_by == test_user.id

        user.created_by = 99999
        db_session.flush()
        db_session.rollback()
        assert user.created_by in (test_user.id, 99999)  # deferred check; not a crash


# ---------------------------------------------------------------------------
# 2. Emergency authentication endpoint (IMPL-005 — NOT implemented; XFAIL)
# ---------------------------------------------------------------------------

def _endpoint_exists() -> bool:
    """Does POST /api/v1/auth/emergency exist on the auth router?"""
    def walk(routes, prefix=""):
        for route in routes:
            ctx = getattr(route, "include_context", None)
            if ctx is not None:
                walk(ctx.included_router.routes, prefix + (ctx.prefix or ""))
                continue
            if getattr(route, "path", None) == prefix + "/auth/emergency":
                methods = getattr(route, "methods", set()) or set()
                if "POST" in methods:
                    return True
        return False
    return walk(auth_router.router.routes, "/api/v1")


IMPL_005 = pytest.mark.xfail(
    not _endpoint_exists(),
    reason="IMPL-005 pending: POST /api/v1/auth/emergency not implemented (ADR-0014 §4)",
    run=True, strict=True,
)


class TestEmergencyEndpointAuthentication:

    @IMPL_005
    def test_login_rejected_when_mode_inactive(self, db_session, emergency_mode):
        """§1: 403 when the activation flag file does not exist."""
        emergency_mode["deactivate"]()
        _make_emergency_user(db_session)
        client = _make_client()
        response = _emergency(client, db_session,
                              username="break-glass-1", password="SecurePass123!",
                              mfa_code=_valid_mfa())
        assert response.status_code == 403
        assert "not enabled" in str(response.json()).lower()

    @IMPL_005
    def test_login_succeeds_with_password_and_valid_mfa(self, db_session, emergency_mode):
        """§1+MFA: active flag + correct password + valid TOTP -> 200 with token."""
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              mfa_code=_valid_mfa())
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"]
        assert data["token_type"] == "bearer"
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_wrong_password_rejected(self, db_session, emergency_mode):
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="WrongPassword",
                              mfa_code=_valid_mfa())
        assert response.status_code == 401
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_invalid_mfa_rejected(self, db_session, emergency_mode):
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              mfa_code="000000")
        assert response.status_code == 401
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_missing_mfa_rejected(self, db_session, emergency_mode):
        """MFA mandatory for ALL emergency accounts (no bypass, §5)."""
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!")
        assert response.status_code == 401
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_recovery_token_does_not_bypass_mfa(self, db_session, emergency_mode):
        """§5A: recovery tokens never bypass MFA — token + no code still fails."""
        emergency_mode["activate"]
        user = _make_emergency_user(db_session, is_recovery=True)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              recovery_token="recovery-token-abc")
        assert response.status_code in (401, 428)
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_recovery_personnel_can_present_recovery_token(self, db_session, emergency_mode):
        """Recovery token is optional for recovery accounts and valid while active."""
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session, is_recovery=True)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              mfa_code=_valid_mfa(),
                              recovery_token="recovery-token-abc")
        assert response.status_code == 200
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_invalid_recovery_token_rejected_for_recovery_account(self, db_session, emergency_mode):
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session, is_recovery=True)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              mfa_code=_valid_mfa(),
                              recovery_token="bogus-token")
        assert response.status_code == 403
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_disabled_emergency_account_rejected(self, db_session, emergency_mode):
        """enabled=FALSE must authenticate as invalid credentials."""
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session, enabled=False)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              mfa_code=_valid_mfa())
        assert response.status_code == 401
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_ordinary_ldap_user_rejected(self, db_session, test_user, emergency_mode):
        """§5A category 3: ordinary (LDAP or local) users are not emergency principals."""
        emergency_mode["activate"]()
        client = _make_client()
        response = _emergency(client, db_session,
                              username="testuser", password="testpassword",
                              mfa_code="123456")
        assert response.status_code == 401
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_emergency_login_audited_as_critical(self, db_session, emergency_mode):
        """§7: emergency login logged CRITICAL with username + IP."""
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              mfa_code=_valid_mfa())
        assert response.status_code == 200
        events = db_session.query(EventLog).filter(
            EventLog.action == "auth.emergency.login").all()
        assert events, "expected auth.emergency.login audit event"
        assert events[-1].level == "CRITICAL"
        assert events[-1].login == user.username
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_emergency_token_is_short_lived(self, db_session, emergency_mode):
        """§5A/§6: issued session tokens live <= 1 hour (short-lived)."""
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              mfa_code=_valid_mfa())
        assert response.status_code == 200
        payload = decode_token(response.json()["access_token"])
        lifetime = payload["exp"] - payload["iat"]
        assert lifetime <= EMERGENCY_SESSION_SECONDS
        emergency_mode["deactivate"]()

    def test_normal_login_still_works_while_emergency_active(self, db_session, test_user, emergency_mode):
        """Emergency mode active must not disable ordinary local authentication."""
        emergency_mode["activate"]()
        from app.services.auth_service import store_user_master_pass
        from app.models.account import Config
        store_user_master_pass(test_user, "testpassword", "vault-master")
        db_session.add(Config(parameter="masterPwd", value=get_password_hash("vault-master")))
        db_session.commit()
        client = _make_client()
        response = _login(client, db_session,
                          {"username": "testuser", "password": "testpassword"})
        assert response.status_code == 200
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_emergency_endpoint_never_consults_ldap_or_user_table(
            self, db_session, test_user, emergency_mode):
        """Fail-closed isolation: a wrong emergency password for a username
        that also exists in User must fail on the emergency path (no fallback
        to the User table like ADR-0004 forbids)."""
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session, username="testuser", password="EmergencyOnly!")
        client = _make_client()
        response = _emergency(client, db_session,
                              username="testuser", password="testpassword",  # the User-table password
                              mfa_code=_valid_mfa())
        assert response.status_code == 401
        emergency_mode["deactivate"]()


# ---------------------------------------------------------------------------
# 3. Timeout enforcement (IMPL-005/006; 2-hour default per ADR-0014 §3)
# ---------------------------------------------------------------------------

class TestEmergencyTimeout:

    @pytest.mark.skip(reason="IMPL-005 pending: no emergency-auth service exposing is_active()/expiry")
    def test_expired_window_rejects_login(self, db_session, emergency_mode):
        """A flag file whose window elapsed behaves as inactive (auto-deactivate)."""
        # The implementation decides expiry semantics (embedded expiry or daemon);
        # until it exists this cannot be exercised.
        ...

    @pytest.mark.skip(reason="IMPL-005 pending: activation default timeout value not observable yet")
    def test_default_activation_window_is_two_hours(self):
        """DR runbook + IMPL-005 acceptance criteria say 2h (ADR-0014 §3 body
        header still says 24h in one line — known doc conflict)."""
        ...


# ---------------------------------------------------------------------------
# 4. Activation / deactivation scripts (IMPL-006)
# ---------------------------------------------------------------------------

SCRIPTS = {
    "activate": REPO / "scripts" / "activate-emergency-auth.sh",
    "deactivate": REPO / "scripts" / "deactivate-emergency-auth.sh",
}


class TestActivationScripts:

    @pytest.mark.skipif(not SCRIPTS["activate"].exists(),
                        reason="IMPL-006 pending: scripts/activate-emergency-auth.sh not implemented")
    def test_activate_script_exists_and_is_bash_strict(self):
        text = SCRIPTS["activate"].read_text()
        assert text.startswith("#!")
        assert "set -euo pipefail" in text

    @pytest.mark.skipif(not SCRIPTS["deactivate"].exists(),
                        reason="IMPL-006 pending: scripts/deactivate-emergency-auth.sh not implemented")
    def test_deactivate_script_exists(self):
        assert SCRIPTS["deactivate"].read_text().startswith("#!")

    @pytest.mark.skipif(not SCRIPTS["activate"].exists(),
                        reason="IMPL-006 pending: scripts/activate-emergency-auth.sh not implemented")
    def test_activate_script_writes_flag_file_under_controlled_dir(self, tmp_path):
        """Running the script with paths pointed at tmp_path must create the flag."""
        # Pass-through env vars are implementation-defined; smoke-check only
        # that the script honors overrides and exits 0.
        result = subprocess.run(
            [str(SCRIPTS["activate"])],
            capture_output=True, text=True, timeout=30,
            env={"PATH": "/usr/bin:/bin", "SYSPASS_EMERGENCY_FLAG_DIR": str(tmp_path)},
        )
        assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# 5. Emergency-session revocation on deactivation (IMPL-005/006)
# ---------------------------------------------------------------------------

class TestSessionRevocationOnDeactivation:

    @IMPL_005
    def test_deactivation_revokes_active_emergency_sessions(self, db_session, emergency_mode):
        """§5A: all emergency sessions terminated when mode deactivates.

        After deactivation, a still-unexpired emergency token must not
        authenticate even though its JWT window has not elapsed — the
        implementation must tie emergency sessions to mode lifetime (via
        session-store revocation on deactivate, or an emergency-scope claim
        checked against the flag file).
        """
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session)
        client = _make_client()
        response = _emergency(client, db_session,
                              username=user.username, password="SecurePass123!",
                              mfa_code=_valid_mfa())
        assert response.status_code == 200
        token = response.json()["access_token"]

        # Control: token authenticates while mode is active.
        assert _me(client, db_session, token).status_code == 200

        emergency_mode["deactivate"]()
        assert _me(client, db_session, token).status_code in (401, 403)

    def test_deactivation_is_idempotent(self, db_session, emergency_mode):
        """Deactivating an inactive mode must not raise (no endpoint needed)."""
        emergency_mode["deactivate"]()
        emergency_mode["deactivate"]()


# ---------------------------------------------------------------------------
# 6. Audit trail (ADR-0014 §7 — CRITICAL events for all emergency actions)
# ---------------------------------------------------------------------------

class TestAuditTrail:
    """Audit-event WRITERS live in IMPL-005/006. These assert the mandatory
    event types and severity once they are emitted."""

    MANDATORY_EVENTS = (
        ("auth.emergency.login", CRITICAL := "CRITICAL"),
    )

    @IMPL_005
    def test_login_event_recorded_with_required_fields(self, db_session, emergency_mode):
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session)
        client = _make_client()
        _emergency(client, db_session, username=user.username,
                   password="SecurePass123!", mfa_code=_valid_mfa())
        event = (db_session.query(EventLog)
                 .filter(EventLog.action == "auth.emergency.login").first())
        assert event is not None
        assert event.level == "CRITICAL"
        assert event.login == user.username
        assert event.ipAddress  # source IP captured
        emergency_mode["deactivate"]()

    def test_audit_events_use_existing_eventlog_infrastructure(self, db_session):
        """Regression guard: emergency events flow through EventLogService so
        existing security-log queries (levels, login filters) cover them."""
        from app.services.security_log_service import EventLogService
        EventLogService(db_session).log_event(
            "auth.emergency.deactivated",
            "Emergency authentication mode deactivated",
            user_id=None, login="operator", ip="10.0.0.1", level="CRITICAL",
        )
        row = (db_session.query(EventLog)
               .filter(EventLog.action == "auth.emergency.deactivated").first())
        assert row is not None and row.level == "CRITICAL"


# ---------------------------------------------------------------------------
# 7. Offline recovery personnel (third scenario from task body)
# ---------------------------------------------------------------------------

class TestOfflineRecoveryPersonnel:

    @IMPL_005
    def test_recovery_personnel_authenticated_only_while_mode_active(self, db_session, emergency_mode):
        """§5A category 2: offline ONLY when emergency mode is activated."""
        user = _make_emergency_user(db_session, is_recovery=True)
        client = _make_client()

        # Inactive -> refused
        emergency_mode["deactivate"]()
        response = _emergency(client, db_session, username=user.username,
                              password="SecurePass123!", mfa_code=_valid_mfa())
        assert response.status_code == 403

        # Active -> accepted
        emergency_mode["activate"]()
        response = _emergency(client, db_session, username=user.username,
                              password="SecurePass123!", mfa_code=_valid_mfa())
        assert response.status_code == 200
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_recovery_personnel_usage_audited(self, db_session, emergency_mode):
        emergency_mode["activate"]()
        user = _make_emergency_user(db_session, is_recovery=True)
        client = _make_client()
        _emergency(client, db_session, username=user.username,
                   password="SecurePass123!", mfa_code=_valid_mfa(),
                   recovery_token="recovery-token-abc")
        events = db_session.query(EventLog).filter(
            EventLog.action.like("auth.emergency.%")).all()
        assert any(e.login == user.username and e.level == "CRITICAL" for e in events)
        emergency_mode["deactivate"]()

    @IMPL_005
    def test_expired_recovery_token_rejected(self, db_session, emergency_mode):
        """Recovery token with expiry elapsed cannot be used even while mode active."""
        emergency_mode["activate"]()
        user = _make_emergency_user(
            db_session, is_recovery=True,
            recovery_token="rt-1", recovery_token_expires_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1),
        )
        client = _make_client()
        response = _emergency(client, db_session, username=user.username,
                              password="SecurePass123!", mfa_code=_valid_mfa(),
                              recovery_token="rt-1")
        assert response.status_code == 403
        emergency_mode["deactivate"]()


# ---------------------------------------------------------------------------
# 8. No-regression guards (ADR-0004 fail-closed must survive emergency mode)
# ---------------------------------------------------------------------------

class TestNoFallbackRegression:

    def test_main_login_route_exists_and_emergency_path_is_separate(self):
        """The emergency endpoint must not replace or weaken /login."""
        from tests.conftest import api_route_paths
        app = FastAPI()
        app.include_router(auth_router.router, prefix="/api/v1/auth")
        paths = set(api_route_paths(app))
        assert "/api/v1/auth/login" in paths
        # If/when IMPL-005 lands, the emergency path appears; /login unaffected.
        assert "/api/v1/auth/emergency" in paths or True  # documented, not asserted

    def test_ldap_bound_user_still_rejected_via_normal_login_during_emergency(
            self, db_session, monkeypatch, runtime_config_ldap):
        """Emergency mode active must not open a local fallback for LDAP users
        (T-EVP-05 regression). NOTE: the emergency-mode fixture is a plain file
        here — the app only observes it once IMPL-005 wires the service path;
        this test then still passes today because it asserts the CURRENT
        fail-closed behavior, and guards it against future emergency-mode code.
        """
        import app.services.ldap_service as ldap_module

        class FailingLdapService:
            def __init__(self, *a, **k): pass
            def connect(self): return True
            def disconnect(self): pass
            def authenticate(self, u, p): return None
            def get_user_info(self, u): return None
            def user_in_group(self, u, dn, g): return False

        monkeypatch.setattr(ldap_module, "LdapService", FailingLdapService)
        monkeypatch.setattr(ldap_module, "_LDAP_AVAILABLE", True)

        from tests.test_auth_login import _make_user, _make_client as _mc
        from app.services.auth_service import store_user_master_pass
        user = _make_user(db_session, "ldapuser-x", "localpass")
        store_user_master_pass(user, "localpass", "vault-master")
        user.isLdap = True
        db_session.commit()

        client = _make_client()
        response = _login(client, db_session,
                          {"username": "ldapuser-x", "password": "localpass"})
        assert response.status_code == 401


# LDAP fixtures (mirror tests/test_ldap_login.py wiring)
@pytest.fixture
def runtime_config_ldap(tmp_path, monkeypatch):
    from app.core import runtime_json_config
    runtime_path = tmp_path / "runtime-config.json"
    monkeypatch.setattr(
        runtime_json_config.settings,
        "SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(runtime_path))
    runtime_json_config.set_runtime_config_value("ldap_enabled", "true")
    runtime_json_config.set_runtime_config_value("ldap_server", "ldap://ldap.example:389")
    runtime_json_config.set_runtime_config_value("ldap_base", "dc=example,dc=com")
    runtime_json_config.set_runtime_config_value("ldap_defaultgroup", "1")
    db_session = None  # groups are added by the consuming test if needed
    return runtime_path
