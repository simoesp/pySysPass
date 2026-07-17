"""Task/Scheduled Task Service"""
from typing import List, Optional, Callable, Dict
from datetime import UTC, datetime, timedelta
import time
import threading
from enum import Enum

try:
    import schedule
except ImportError:  # pragma: no cover - optional dependency in test env
    class _FallbackJob:
        def at(self, *args, **kwargs):
            return self
        def do(self, *args, **kwargs):
            return self
        def tag(self, *args, **kwargs):
            return self

    class _FallbackSchedule:
        @staticmethod
        def clear(*args, **kwargs):
            return None
        @staticmethod
        def every():
            return _FallbackJob()
        @staticmethod
        def run_pending():
            return None

    schedule = _FallbackSchedule()


class TaskType(Enum):
    """Task types"""
    DAILY_PASSWORD_EXPIRY_CHECK = "daily_password_expiry_check"  # nosec B105
    WEEKLY_BACKUP = "weekly_backup"
    MONTHLY_REPORT = "monthly_report"
    CLEANUP_OLD_NOTIFICATIONS = "cleanup_old_notifications"
    CUSTOM = "custom"


class Task:
    """Task definition"""
    def __init__(self, name: str, task_type: TaskType, schedule_type: str,
                 schedule_time: str = None, enabled: bool = True,
                 callback: Callable = None, config: Dict = None):
        self.name = name
        self.task_type = task_type
        self.schedule_type = schedule_type  # 'daily', 'weekly', 'hourly'
        self.schedule_time = schedule_time  # Format: "HH:MM"
        self.enabled = enabled
        self.callback = callback
        self.config = config or {}
        self.last_run = None
        self.next_run = None
        self.status = "pending"

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'task_type': self.task_type.value,
            'schedule_type': self.schedule_type,
            'schedule_time': self.schedule_time,
            'enabled': self.enabled,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'status': self.status
        }


class TaskService:
    """Service for managing and executing scheduled tasks"""

    def __init__(self, db=None):
        self.tasks: Dict[str, Task] = {}
        self.db = db
        self._running = False
        self._thread = None

    @staticmethod
    def _utc_now_naive() -> datetime:
        return datetime.now(UTC).replace(tzinfo=None)

    def register_task(self, task: Task) -> bool:
        """Register a new task"""
        try:
            self._schedule_task(task)
            self.tasks[task.name] = task
            return True
        except Exception as e:
            raise Exception(f"Failed to register task: {str(e)}")

    def unregister_task(self, task_name: str) -> bool:
        """Unregister a task"""
        if task_name in self.tasks:
            schedule.clear(task_name)
            del self.tasks[task_name]
            return True
        return False

    def get_all_tasks(self) -> List[Dict]:
        """Get all registered tasks"""
        return [task.to_dict() for task in self.tasks.values()]

    def get_task(self, task_name: str) -> Optional[Dict]:
        """Get a specific task"""
        if task_name in self.tasks:
            return self.tasks[task_name].to_dict()
        return None

    def enable_task(self, task_name: str) -> bool:
        """Enable a task"""
        if task_name in self.tasks:
            self.tasks[task_name].enabled = True
            return True
        return False

    def disable_task(self, task_name: str) -> bool:
        """Disable a task"""
        if task_name in self.tasks:
            self.tasks[task_name].enabled = False
            schedule.clear(task_name)
            return True
        return False

    def run_task_now(self, task_name: str) -> bool:
        """Run a task immediately"""
        if task_name not in self.tasks:
            return False

        task = self.tasks[task_name]
        return self._execute_task(task)

    def _schedule_task(self, task: Task):
        """Schedule a task based on its configuration"""
        if not task.enabled:
            return

        schedule.clear(task.name)
        if task.schedule_type == 'daily':
            if task.schedule_time:
                self._parse_schedule_time(task.schedule_time)
                schedule.every().day.at(task.schedule_time).do(
                    self._execute_task, task
                ).tag(task.name)
            else:
                raise ValueError("Daily tasks require schedule_time")
        elif task.schedule_type == 'weekly':
            schedule_time = task.schedule_time or "00:00"
            self._parse_schedule_time(schedule_time)
            schedule.every().monday.at(schedule_time).do(
                self._execute_task, task
            ).tag(task.name)
        elif task.schedule_type == 'hourly':
            schedule.every().hour.do(self._execute_task, task).tag(task.name)
        else:
            raise ValueError(f"Unsupported schedule_type: {task.schedule_type}")

    def _execute_task(self, task: Task) -> bool:
        """Execute a task"""
        try:
            task.status = "running"
            task.last_run = datetime.now()

            if task.callback:
                task.callback()

            task.status = "completed"
            task.next_run = self._calculate_next_run(task)
            return True

        except Exception as e:
            task.status = f"failed: {str(e)}"
            return False

    def _calculate_next_run(self, task: Task) -> datetime:
        """Calculate next run time for a task"""
        now = datetime.now()

        if task.schedule_type == 'daily' and task.schedule_time:
            hour, minute = self._parse_schedule_time(task.schedule_time)
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run < now:
                next_run += timedelta(days=1)
            return next_run

        elif task.schedule_type == 'hourly':
            return now + timedelta(hours=1)

        elif task.schedule_type == 'weekly':
            hour, minute = self._parse_schedule_time(task.schedule_time or "00:00")
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            next_run += timedelta(days=(0 - now.weekday()) % 7)
            if next_run <= now:
                next_run += timedelta(weeks=1)
            return next_run

        return now + timedelta(days=1)

    def _parse_schedule_time(self, value: str) -> tuple[int, int]:
        try:
            hour, minute = map(int, value.split(':'))
        except (AttributeError, ValueError) as exc:
            raise ValueError("schedule_time must use HH:MM format") from exc
        if hour not in range(24) or minute not in range(60):
            raise ValueError("schedule_time must use HH:MM format")
        return hour, minute

    def start_scheduler(self):
        """Start the task scheduler in background thread"""
        if self._running:
            return

        self._running = True

        def run_scheduler():
            while self._running:
                schedule.run_pending()
                threading.Event().wait(1)

        self._thread = threading.Thread(target=run_scheduler, daemon=True)
        self._thread.start()

    def stop_scheduler(self):
        """Stop the task scheduler"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    # Default task implementations
    def check_password_expiry(self) -> Dict:
        """Check for expired account passwords, create notifications, and email users."""
        if self.db is None:
            return {"checked": 0, "expiring": 0, "notifications_created": 0, "emails_sent": 0}

        from app.models.account import Account, Notification, User
        from app.services.email_service import email_service_from_config

        email_svc = email_service_from_config(self.db)
        now = self._utc_now_naive()
        checked = expiring = created = emails_sent = 0
        accounts = self.db.query(Account).all()
        for account in accounts:
            checked += 1
            if not account.passDateChange:
                continue
            age_days = (now - (account.dateEdit or account.dateAdd or now)).days
            if age_days < account.passDateChange:
                continue
            expiring += 1
            self.db.add(Notification(
                userId=account.userId,
                type="password_expiry",
                component="TaskService",
                description=f"Password for {account.name} should be changed.",
                date=int(time.time()),
                checked=False,
            ))
            created += 1
            if email_svc and account.userId:
                user = self.db.get(User, account.userId)
                if user and user.email:
                    try:
                        email_svc.send_password_expiry_warning(
                            user.email, account.name, now
                        )
                        emails_sent += 1
                    except Exception:
                        pass
        self.db.commit()
        return {"checked": checked, "expiring": expiring, "notifications_created": created, "emails_sent": emails_sent}

    def cleanup_old_notifications(self, days: int = 30) -> Dict:
        """Delete notifications older than specified days"""
        if self.db is None:
            return {"deleted": 0}

        from app.models.account import Notification

        cutoff = int(time.time()) - (days * 86400)
        deleted = self.db.query(Notification).filter(Notification.date < cutoff).delete()
        self.db.commit()
        return {"deleted": deleted}

    def generate_weekly_report(self) -> Dict:
        """Generate weekly activity report counters."""
        if self.db is None:
            return {"accounts_created": 0, "history_events": 0, "notifications": 0}

        from app.models.account import Account, AccountHistory, Notification

        since = self._utc_now_naive() - timedelta(days=7)
        return {
            "accounts_created": self.db.query(Account).filter(Account.dateAdd >= since).count(),
            "history_events": self.db.query(AccountHistory).filter(AccountHistory.dateAdd >= since).count(),
            "notifications": self.db.query(Notification).filter(Notification.date >= int(since.timestamp())).count(),
        }


# Initialize global task service
task_service = TaskService()
