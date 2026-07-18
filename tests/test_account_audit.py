"""Per-account audit trail (who opened / viewed password / edited)."""
import pytest

from app.models.account import EventLog, User
from app.schemas.account import AccountCreate
from app.services.account_service import AccountService
from app.services.account_audit_service import AccountAuditService, account_marker
from app.services.auth_service import get_password_hash


def _account(db_session, encryption_service, user, title="Secret"):
    return AccountService(db_session, encryption_service).create_account(
        AccountCreate(title=title, password="pass", is_public=True), user.id,
    )


def test_log_and_list_scoped_to_account(db_session, encryption_service, test_user):
    a = _account(db_session, encryption_service, test_user, "Acct A")
    b = _account(db_session, encryption_service, test_user, "Acct B")
    audit = AccountAuditService(db_session)

    audit.log(a.id, "account.view.pass", test_user.id, "tester", "10.0.0.9")
    audit.log(a.id, "account.view", test_user.id, "tester", "10.0.0.9")
    audit.log(b.id, "account.view", test_user.id, "tester", "10.0.0.9")

    entries = audit.list_for_account(a.id)
    assert [e["action"] for e in entries] == ["account.view", "account.view.pass"]  # newest first
    # username is resolved from userId (real User row), ip preserved
    assert all(e["username"] == test_user.username and e["ip"] == "10.0.0.9" for e in entries)
    assert entries[0]["action_label"] == "Opened account"

    # b's single event is not visible under a
    assert len(audit.list_for_account(b.id)) == 1


def test_marker_does_not_cross_match_similar_ids(db_session, encryption_service, test_user):
    a5 = _account(db_session, encryption_service, test_user, "Five")
    audit = AccountAuditService(db_session)
    # write an event whose id-suffix could confuse a naive LIKE
    ev = EventLog(date=1, login="x", userId=test_user.id, ipAddress="0.0.0.0",
                  action="account.view", description=f"Opened: Fifty {account_marker(a5.id * 10 + 5)}",
                  level="INFO")
    db_session.add(ev)
    db_session.commit()
    audit.log(a5.id, "account.view", test_user.id, "x", "0.0.0.0")

    entries = audit.list_for_account(a5.id)
    assert len(entries) == 1  # only the real one, not the [acc:<a5*10+5>] decoy


def test_middleware_marked_mutation_surfaces_in_audit(db_session, encryption_service, test_user):
    # Mutations are logged by the global audit middleware as
    # "<METHOD> <path> [acc:<id>]"; the audit list must pick them up.
    a = _account(db_session, encryption_service, test_user, "Edited")
    ev = EventLog(date=1, login="tester", userId=test_user.id, ipAddress="0.0.0.0",
                  action="account.edit",
                  description=f"PUT /api/v1/accounts/{a.id} {account_marker(a.id)}",
                  level="INFO")
    db_session.add(ev)
    db_session.commit()

    entries = AccountAuditService(db_session).list_for_account(a.id)
    assert entries[0]["action"] == "account.edit"
    assert entries[0]["action_label"] == "Edited account"


def test_audit_endpoint_records_and_gates_access(db_session, encryption_service, test_user, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.db.base import get_db
    from app.api.v1 import accounts
    from app.api.deps import get_current_user

    monkeypatch.setattr(accounts, "get_encryption_service", lambda: encryption_service)

    a = _account(db_session, encryption_service, test_user, "Prod DB")

    app = FastAPI()
    app.include_router(accounts.router, prefix="/api/v1")

    def override_db():
        yield db_session
    app.dependency_overrides[get_db] = override_db

    # Owner (as admin, to pass the acc_view_pass profile gate) reveals the
    # password, then reads the audit
    app.dependency_overrides[get_current_user] = lambda: {
        "id": test_user.id, "username": test_user.username,
        "is_admin": True, "is_admin_app": True, "is_admin_acc": True, "master_pass": None,
    }
    client = TestClient(app)
    assert client.get(f"/api/v1/accounts/{a.id}/password").status_code == 200

    audit = client.get(f"/api/v1/accounts/{a.id}/audit")
    assert audit.status_code == 200
    actions = [e["action"] for e in audit.json()]
    assert "account.view.pass" in actions
    assert audit.json()[0]["username"] == test_user.username

    # An outsider (different user, no group/share) is refused
    outsider = User(username="outsider", email="o@x", password=get_password_hash("x"), userGroupId=99)
    db_session.add(outsider)
    db_session.commit()
    db_session.refresh(outsider)
    app.dependency_overrides[get_current_user] = lambda: {
        "id": outsider.id, "username": "outsider",
        "is_admin": False, "is_admin_app": False, "is_admin_acc": False, "master_pass": None,
    }
    assert client.get(f"/api/v1/accounts/{a.id}/audit").status_code == 403
