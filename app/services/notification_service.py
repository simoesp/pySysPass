from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.account import Notification, User
from app.services.email_service import email_service_from_config
import time

class NotificationService:
    def __init__(self, db: Session):
        self.db = db

    def _try_email(self, user_id: int, notification_type: str, message: str):
        """Best-effort: email the user if mail_notifications_enabled."""
        try:
            from app.services.config_service import ConfigService
            cfg = ConfigService(self.db).get_mail_settings()
            if not cfg.mail_enabled or not getattr(cfg, "mail_requests_enabled", False):
                return
            svc = email_service_from_config(self.db)
            if not svc:
                return
            user = self.db.get(User, user_id)
            if user and user.email:
                svc.send_notification(user.email, notification_type, message)
        except Exception:
            pass

    def create_notification(
        self,
        user_id: int,
        notification_type: str,
        message: str,
        send_email: bool = False,
    ) -> Notification:
        """Create a new notification for a user, optionally emailing them."""
        notification = Notification(
            userId=user_id,
            type=notification_type,
            component=notification_type or "Python",
            description=message,
            checked=False,
            date=int(time.time()),
        )
        self.db.add(notification)
        self.db.commit()
        self.db.refresh(notification)
        if send_email:
            self._try_email(user_id, notification_type, message)
        return notification

    def get_notifications(
        self,
        user_id: int,
        unread_only: bool = False,
        limit: int = 50,
        skip: int = 0
    ) -> List[Notification]:
        """Get notifications for a user"""
        query = self.db.query(Notification).filter(
            Notification.userId == user_id
        )

        if unread_only:
            query = query.filter(Notification.checked.is_(False))

        return query.order_by(
            Notification.date.desc()
        ).offset(skip).limit(limit).all()

    def get_notification(self, notification_id: int, user_id: int) -> Optional[Notification]:
        """Get a specific notification"""
        notification = self.db.query(Notification).filter(
            Notification.id == notification_id
        ).first()
        if notification is None:
            return None
        if getattr(notification, "userId", None) != user_id:
            return None
        return notification

    def mark_as_read(self, notification_id: int, user_id: int) -> Optional[Notification]:
        """Mark a notification as read"""
        notification = self.get_notification(notification_id, user_id)

        if not notification:
            return None

        notification.checked = True
        self.db.commit()
        self.db.refresh(notification)
        return notification

    def mark_all_as_read(self, user_id: int) -> int:
        """Mark all notifications as read for a user"""
        count = self.db.query(Notification).filter(
            Notification.userId == user_id,
            Notification.checked.is_(False)
        ).update({"checked": True})

        self.db.commit()
        return count

    def delete_notification(self, notification_id: int, user_id: int) -> bool:
        """Delete a notification"""
        notification = self.get_notification(notification_id, user_id)

        if not notification:
            return False

        self.db.delete(notification)
        self.db.commit()
        return True

    def delete_all_notifications(self, user_id: int) -> int:
        """Delete all notifications for a user"""
        count = self.db.query(Notification).filter(
            Notification.userId == user_id
        ).delete()

        self.db.commit()
        return count

    def get_unread_count(self, user_id: int) -> int:
        """Get the number of unread notifications for a user"""
        return self.db.query(Notification).filter(
            Notification.userId == user_id,
            Notification.checked.is_(False)
        ).count()

    def get_notifications_by_type(
        self,
        user_id: int,
        notification_type: str
    ) -> List[Notification]:
        """Get notifications of a specific type for a user"""
        return self.db.query(Notification).filter(
            Notification.userId == user_id,
            Notification.type == notification_type
        ).order_by(
            Notification.date.desc()
        ).all()
