import os

from fastapi import APIRouter, Depends

from app.api.deps import require_admin
from app.core.operations import failure_snapshot
from app.core.rsa_service import get_public_key_pem

router = APIRouter()


@router.get("/security/public-key")
def public_key():
    """Return the RSA public key used for client-side password encryption."""
    return {"public_key": get_public_key_pem()}


@router.get("/security/operations")
def operations_status(current_user=Depends(require_admin)):
    """Operational failures and background-job state for this worker process.

    Counters are per process and reset on restart; alert on the ERROR log
    lines instead for fleet-wide monitoring.
    """
    from app.services.task_service import task_service

    return {
        "worker_pid": os.getpid(),
        "failures": failure_snapshot(),
        "scheduler": {
            "running": bool(task_service._running),
            "registered_tasks": sorted(task_service.tasks),
            "automated_backups": False,
            "automated_expiry_notices": False,
        },
    }
