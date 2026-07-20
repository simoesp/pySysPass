"""Per-account audit trail, read from and written to the EventLog table.

sysPass PHP has no accountId column on EventLog; the account is referenced
in the free-text description. We embed a stable ``[acc:<id>]`` marker in the
description so one account's events can be filtered back out with no schema
change (PHP-compatibility: EventLog keeps its upstream columns).
"""
import time
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.account import Account, EventLog, User

# Audited account actions and their human labels. view/view.pass are logged
# by the account routes; edit/delete/clone by the global audit middleware.
ACTION_LABELS = {
    "account.view": "Opened account",
    "account.view.pass": "Viewed password",
    "account.edit": "Edited account",
    "account.delete": "Deleted account",
    "account.clone": "Cloned account",
}


def account_marker(account_id: int) -> str:
    return f"[acc:{account_id}]"


class AccountAuditService:
    def __init__(self, db: Session):
        self.db = db

    def log(self, account_id: int, action: str, user_id: Optional[int],
            login: Optional[str], ip: Optional[str]) -> None:
        """Record one account read event (view / view.pass) in EventLog.

        Mutations (edit/delete/clone) are recorded by the global audit
        middleware; this is only used for the read actions it doesn't cover.
        """
        account_name = self.db.query(Account.name).filter(Account.id == account_id).scalar()
        label = ACTION_LABELS.get(action, action)
        display = account_name or f"#{account_id}"
        row = EventLog(
            date=int(time.time()),
            login=login or "",
            userId=user_id,
            ipAddress=ip or "0.0.0.0",  # nosec B104 - default log IP, not a bind
            action=action,
            description=f"{label}: {display} {account_marker(account_id)}",
            level="INFO",
        )
        self.db.add(row)
        self.db.commit()

    def list_for_account(self, account_id: int, skip: int = 0,
                         limit: int = 100) -> List[dict]:
        """Return this account's audit events, newest first."""
        marker = account_marker(account_id)
        rows = (
            self.db.query(EventLog)
            .filter(EventLog.description.like(f"%{marker}%"))
            .order_by(EventLog.id.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )
        user_ids = {r.userId for r in rows if r.userId}
        names = {}
        if user_ids:
            names = {
                u.id: u.username
                for u in self.db.query(User).filter(User.id.in_(user_ids)).all()
            }
        return [
            {
                "id": r.id,
                "action": r.action,
                "action_label": ACTION_LABELS.get(r.action, r.action),
                "user_id": r.userId,
                "username": names.get(r.userId) or (r.login or None),
                "ip": r.ipAddress,
                "date": r.date,
            }
            for r in rows
        ]
