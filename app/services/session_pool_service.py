"""Session pool service using database-backed storage.

This module provides a database-backed session store that replaces the
file-based ``data/sessions.json`` implementation. It supports multi-replica
correctness without requiring Redis - all session state lives in the
configured database.

Key design points per ADR-0009:
- No master password material in session data
- Session metadata distinct from vault material
- Immediate revocation propagation (database-level)
- Secure failure mode: backend outage -> 503/secure-deny
- Works without Redis; Redis is only an optional optimization
"""
from __future__ import annotations

import time
from typing import Optional, Dict, Any, List, Tuple

from sqlalchemy import select, and_

from app.db.base import get_db, engine, Session as DBSession


# Constants needed by session_service; defined here to avoid circular import
DEFAULT_SESSION_TIMEOUT = 300
ALL_USERS = "*"
MIN_SESSION_TIMEOUT = 60
MAX_SESSION_SECONDS = 24 * 3600


class SessionPoolService:
    """Database-backed session pool providing authoritative session state.

    This service replaces the file-based SessionStore for multi-replica
    deployments. Session data lives in the configured database, providing
    immediate consistency across all workers.

    In single-instance development mode (no DATABASE_URL), it falls back
    to the file-based SessionStore in app.services.session_service.
    """

    def __init__(self, db: Optional[object] = None):
        self.db = db

    # -----------------------------------------------------------------
    # Core session operations
    # -----------------------------------------------------------------

    def create_session(
        self,
        user_id: int,
        session_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> object:
        """Create a new session record in the database."""
        from app.db.base import Session as DBSession

        now = time.time()
        db_session = DBSession(
            session_id=session_id,
            user_id=user_id,
            authenticated_until=None,
            vault_until=None,
            revoked=False,
            revoked_until=None,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now,
        )
        from app.db.base import engine as eng

        eng.add(db_session)  # type: ignore[attr-defined]
        # Note: actual commit is handled by the caller's session management
        return db_session

    def get_session(self, session_id: str) -> Optional[object]:
        """Retrieve a session by session_id."""
        from app.db.base import engine as eng

        with eng.begin() as conn:
            result = conn.execute(
                select(Session).where(Session.session_id == session_id)
            ).scalar_one_or_none()
        return result

    def get_user_sessions(self, user_id: int) -> List[object]:
        """Retrieve all sessions for a given user."""
        from app.db.base import engine as eng

        with eng.begin() as conn:
            result = conn.execute(
                select(Session).where(Session.user_id == user_id)
            ).scalars().all()
        return list(result)

    def revoke_session(self, session_id: str, now: Optional[float] = None) -> bool:
        """Revoke a session by session_id."""
        if now is None:
            now = time.time()

        from app.db.base import engine as eng

        with eng.begin() as conn:
            conn.execute(
                Session.__table__.update()
                .where(Session.session_id == session_id)
                .values(revoked=True, revoked_until=now + MAX_SESSION_SECONDS)
            )
        return True

    def revoke_user_sessions(self, user_id: int, before: Optional[float] = None) -> int:
        """Revoke all sessions for a given user."""
        if before is None:
            before = time.time()

        from app.db.base import engine as eng

        with eng.begin() as conn:
            count = conn.execute(
                Session.__table__.update()
                .where(
                    and_(Session.user_id == user_id, not Session.revoked)
                )
                .values(revoked=True, revoked_until=before)
            )
        return count.rowcount

    def is_revoked(self, session_id: str) -> bool:
        """Check if a session is revoked."""
        from app.db.base import engine as eng

        with eng.begin() as conn:
            result = conn.execute(
                select(Session.revoked).where(Session.session_id == session_id)
            ).scalar_one_or_none()
        return bool(result)

    def prune_expired(self) -> int:
        """Remove expired sessions and revoked entries older than MAX_SESSION_SECONDS."""
        now = time.time()
        cutoff = now - MAX_SESSION_SECONDS

        from app.db.base import engine as eng

        with eng.begin() as conn:
            deleted_non_revoked = conn.execute(
                Session.__table__.delete().where(
                    and_(not Session.revoked, Session.created_at < cutoff)
                )
            )
            deleted_revoked = conn.execute(
                Session.__table__.delete().where(
                    and_(Session.revoked, Session.revoked_until < cutoff)
                )
            )
        return deleted_non_revoked.rowcount + deleted_revoked.rowcount

    # -----------------------------------------------------------------
    # Compatibility with the existing SessionStore API
    # -----------------------------------------------------------------

    def get_revoked_tokens(self) -> Dict[str, float]:
        """Return a dict of {jti: expires_at} for all revoked sessions."""
        from app.db.base import engine as eng

        with eng.begin() as conn:
            result = conn.execute(
                select(Session.session_id, Session.revoked_until).where(
                    Session.revoked
                )
            ).fetchall()
        return {row[0]: row[1] for row in result if row[1] is not None and row[1] > time.time()}

    def get_not_before(self, user_id: int) -> float:
        """Return the not_before timestamp for a user (all sessions revoked)."""
        from app.db.base import engine as eng

        with eng.begin() as conn:
            result = conn.execute(
                select(Session.revoked_until).where(
                    and_(Session.user_id == user_id, Session.revoked)
                )
            ).scalar_one_or_none()
        if result is None:
            return 0.0
        return float(result)

    # -----------------------------------------------------------------
    # Fallback for single-instance development
    # -----------------------------------------------------------------

    @staticmethod
    def _in_memory_store() -> "SessionPoolService":
        """Get a best-effort in-memory store for single-instance dev.

        Note: This is a placeholder; callers should use the
        module-level get_service() factory instead.
        """
        return None

    @classmethod
    def get_service(
        cls, db: Optional[object] = None
    ) -> "SessionPoolService":
        """Factory method: return DB-backed service or fallback to file store."""
        from app.core.config import settings

        if db is not None:
            return cls(db)
        if settings.DATABASE_URL:
            from app.db.base import engine as eng
            return cls()
        # Fall back to file-based store for single-instance dev
        from app.services.session_service import SessionStore as FileSessionStore
        from pathlib import Path

        store_path = Path(__file__).parent.parent.parent / "data" / "sessions.json"
        return FileSessionStore(path=store_path)


# Convenience instance for direct import
_instance: Optional[object] = None


def get_pool_service() -> object:
    """Convenience function to get the appropriate session service instance.

    Returns the database-backed service when DATABASE_URL is configured,
    otherwise falls back to the file-based SessionStore for development.
    """
    global _instance
    if _instance is None:
        from app.core.config import settings
        if settings.DATABASE_URL:
            from app.db.base import engine as eng
            _instance = SessionPoolService()
        else:
            from app.services.session_service import SessionStore as FileSessionStore
            from pathlib import Path

            store_path = Path(__file__).parent.parent.parent / "data" / "sessions.json"
            _instance = FileSessionStore(path=store_path)
    return _instance
