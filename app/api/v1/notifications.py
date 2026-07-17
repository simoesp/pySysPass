from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.db.base import get_db
from app.schemas.notification import NotificationCreate, NotificationResponse
from app.services.notification_service import NotificationService
from app.services.auth_service import decode_token
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter()
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"id": payload.get("user_id")}

@router.get("/notifications", response_model=List[NotificationResponse])
async def list_notifications(
    unread_only: bool = False,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List notifications for the current user"""
    service = NotificationService(db)
    return service.get_notifications(
        current_user["id"],
        unread_only=unread_only,
        limit=limit,
        skip=skip
    )

@router.get("/notifications/unread-count")
async def get_unread_count(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get the number of unread notifications"""
    service = NotificationService(db)
    count = service.get_unread_count(current_user["id"])
    return {"unread_count": count}

@router.post("/notifications", response_model=NotificationResponse, status_code=status.HTTP_201_CREATED)
async def create_notification(
    notification: NotificationCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a notification (admin/system only)"""
    # In production, add admin check here
    if notification.user_id != current_user["id"] and not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Not authorized")

    service = NotificationService(db)
    return service.create_notification(
        user_id=notification.user_id,
        notification_type=notification.type,
        message=notification.message
    )

@router.get("/notifications/{notification_id}", response_model=NotificationResponse)
async def get_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get a specific notification"""
    service = NotificationService(db)
    notification = service.get_notification(notification_id, current_user["id"])

    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    return notification

@router.post("/notifications/{notification_id}/read")
async def mark_as_read(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Mark a notification as read"""
    service = NotificationService(db)
    updated = service.mark_as_read(notification_id, current_user["id"])

    if not updated:
        raise HTTPException(status_code=404, detail="Notification not found")

    return {"message": "Notification marked as read"}

@router.post("/notifications/read-all")
async def mark_all_as_read(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Mark all notifications as read"""
    service = NotificationService(db)
    count = service.mark_all_as_read(current_user["id"])

    return {"message": f"{count} notifications marked as read"}

@router.delete("/notifications/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete a notification"""
    service = NotificationService(db)

    if not service.delete_notification(notification_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Notification not found")

    return None

@router.delete("/notifications")
async def delete_all_notifications(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete all notifications for the current user"""
    service = NotificationService(db)
    count = service.delete_all_notifications(current_user["id"])

    return {"message": f"{count} notifications deleted"}

@router.get("/notifications/type/{notification_type}", response_model=List[NotificationResponse])
async def get_notifications_by_type(
    notification_type: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get notifications of a specific type"""
    service = NotificationService(db)
    return service.get_notifications_by_type(current_user["id"], notification_type)
