import socket
import time as _time
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.account import EventLog, Track, User
from app.schemas.security_log import EventLogResponse, TrackResponse

# Number of failed attempts before locking an IP
TRACK_MAX_ATTEMPTS = 5
# Sliding window in seconds to count attempts (15 min)
TRACK_WINDOW_SECS = 900
# Base lock duration (5 min); doubles on each consecutive lock, capped at 24 h
TRACK_LOCK_SECS = 300
TRACK_LOCK_MAX_SECS = 86400


def _ip_to_bytes(ip_str: str) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Return (ipv4_bytes, ipv6_bytes) from an IP string. Unknown format → (None, None)."""
    try:
        return socket.inet_aton(ip_str), None
    except OSError:
        pass
    try:
        return None, socket.inet_pton(socket.AF_INET6, ip_str)
    except OSError:
        return None, None


def _ipv4_str(raw) -> Optional[str]:
    if not raw:
        return None
    if isinstance(raw, bytes) and len(raw) == 4:
        return socket.inet_ntoa(raw)
    return str(raw)


def _ipv6_str(raw) -> Optional[str]:
    if not raw:
        return None
    if isinstance(raw, bytes) and len(raw) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return None


class EventLogService:
    def __init__(self, db: Session):
        self.db = db

    def _to_response(self, row: EventLog) -> EventLogResponse:
        return EventLogResponse(
            id=row.id,
            date=row.date,
            login=row.login,
            user_id=row.userId,
            ip_address=row.ipAddress,
            action=row.action,
            description=row.description,
            level=row.level,
        )

    def list(self, skip: int = 0, limit: int = 100,
             level: Optional[str] = None,
             login: Optional[str] = None) -> List[EventLogResponse]:
        q = self.db.query(EventLog)
        if level:
            q = q.filter(EventLog.level == level.upper())
        if login:
            q = q.filter(EventLog.login.ilike(f"%{login}%"))
        rows = q.order_by(desc(EventLog.date)).offset(skip).limit(limit).all()
        return [self._to_response(r) for r in rows]

    def count(self, level: Optional[str] = None, login: Optional[str] = None) -> int:
        q = self.db.query(EventLog)
        if level:
            q = q.filter(EventLog.level == level.upper())
        if login:
            q = q.filter(EventLog.login.ilike(f"%{login}%"))
        return q.count()

    def clear(self) -> int:
        n = self.db.query(EventLog).count()
        self.db.query(EventLog).delete()
        self.db.commit()
        return n

    def log_event(
        self,
        action: str,
        description: str = None,
        user_id: int = None,
        login: str = None,
        ip: str = "0.0.0.0",
        level: str = "INFO",
    ) -> EventLog:
        """Write one entry to EventLog. Level: INFO | WARN | ERROR | NOTICE."""
        row = EventLog(
            date=int(_time.time()),
            login=login or "",
            userId=user_id,
            ipAddress=ip,
            action=action,
            description=description or action,
            level=level.upper(),
        )
        self.db.add(row)
        self.db.commit()
        return row


class TrackService:
    def __init__(self, db: Session):
        self.db = db

    def _to_response(self, row: Track, usernames: dict) -> TrackResponse:
        ip = _ipv4_str(row.ipv4) or _ipv6_str(row.ipv6)
        now = int(_time.time())
        is_locked = bool(row.timeUnlock and row.timeUnlock > now)
        return TrackResponse(
            id=row.id,
            user_id=row.userId,
            username=usernames.get(row.userId),
            source=row.source,
            time=row.time,
            time_unlock=row.timeUnlock,
            ip=ip,
            is_locked=is_locked,
        )

    def _load_usernames(self, rows) -> dict:
        ids = {r.userId for r in rows if r.userId}
        if not ids:
            return {}
        users = self.db.query(User).filter(User.id.in_(ids)).all()
        return {u.id: u.username for u in users}

    def list(self, skip: int = 0, limit: int = 100,
             locked_only: bool = False) -> List[TrackResponse]:
        now = int(_time.time())
        q = self.db.query(Track)
        if locked_only:
            q = q.filter(Track.timeUnlock > now)
        rows = q.order_by(desc(Track.time)).offset(skip).limit(limit).all()
        usernames = self._load_usernames(rows)
        return [self._to_response(r, usernames) for r in rows]

    def count(self, locked_only: bool = False) -> int:
        now = int(_time.time())
        q = self.db.query(Track)
        if locked_only:
            q = q.filter(Track.timeUnlock > now)
        return q.count()

    def unlock(self, track_id: int) -> bool:
        row = self.db.query(Track).filter(Track.id == track_id).first()
        if not row:
            return False
        row.timeUnlock = None
        self.db.commit()
        return True

    def delete(self, track_id: int) -> bool:
        row = self.db.query(Track).filter(Track.id == track_id).first()
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    def clear(self) -> int:
        n = self.db.query(Track).count()
        self.db.query(Track).delete()
        self.db.commit()
        return n

    # ------------------------------------------------------------------
    # Brute-force helpers (called from auth layer)
    # ------------------------------------------------------------------

    def record_attempt(self, ip_str: str, source: str, user_id: Optional[int] = None) -> Track:
        """Write a failed-login track entry for the given IP."""
        ipv4, ipv6 = _ip_to_bytes(ip_str)
        row = Track(
            userId=user_id,
            source=source,
            time=int(_time.time()),
            ipv4=ipv4,
            ipv6=ipv6,
        )
        self.db.add(row)
        self.db.commit()
        return row

    def is_locked(self, ip_str: str) -> bool:
        """Return True if this IP has an active lock (timeUnlock in the future)."""
        ipv4, ipv6 = _ip_to_bytes(ip_str)
        now = int(_time.time())
        q = self.db.query(Track).filter(Track.timeUnlock > now)
        if ipv4:
            q = q.filter(Track.ipv4 == ipv4)
        elif ipv6:
            q = q.filter(Track.ipv6 == ipv6)
        else:
            return False
        return q.first() is not None

    def _consecutive_locks(self, ipv4: bytes, ipv6: bytes) -> int:
        """Count how many prior lock events exist for this IP (for exponential backoff)."""
        q = self.db.query(Track).filter(Track.timeUnlock.isnot(None))
        if ipv4:
            q = q.filter(Track.ipv4 == ipv4)
        elif ipv6:
            q = q.filter(Track.ipv6 == ipv6)
        return q.count()

    def maybe_lock(self, ip_str: str,
                   max_attempts: int = TRACK_MAX_ATTEMPTS,
                   window_secs: int = TRACK_WINDOW_SECS,
                   base_lock_secs: int = TRACK_LOCK_SECS) -> bool:
        """
        Count recent attempts for this IP within the window.
        If >= max_attempts: lock with exponential backoff (doubles each consecutive lock,
        capped at TRACK_LOCK_MAX_SECS). Returns True if locked.
        """
        ipv4, ipv6 = _ip_to_bytes(ip_str)
        if not ipv4 and not ipv6:
            return False
        cutoff = int(_time.time()) - window_secs
        q = self.db.query(Track).filter(Track.time >= cutoff)
        if ipv4:
            q = q.filter(Track.ipv4 == ipv4)
        else:
            q = q.filter(Track.ipv6 == ipv6)
        rows = q.all()
        if len(rows) < max_attempts:
            return False
        prior = self._consecutive_locks(ipv4, ipv6)
        lock_secs = min(base_lock_secs * (2 ** prior), TRACK_LOCK_MAX_SECS)
        unlock_at = int(_time.time()) + lock_secs
        for row in rows:
            row.timeUnlock = unlock_at
        self.db.commit()
        return True
