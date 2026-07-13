import pytest
from app.services.notification_service import NotificationService

@pytest.mark.asyncio
async def test_create_notification(db_session, test_user):
    """Test creating a notification"""
    service = NotificationService(db_session)
    notification = service.create_notification(
        user_id=test_user.id,
        notification_type="system_warning",
        message="Test notification message"
    )
    
    assert notification.id is not None
    assert notification.userId == test_user.id
    assert notification.type == "system_warning"
    assert notification.message == "Test notification message"
    assert notification.isRead == False

@pytest.mark.asyncio
async def test_get_notifications(db_session, test_user):
    """Test listing notifications"""
    service = NotificationService(db_session)
    
    # Create multiple notifications
    for i in range(5):
        service.create_notification(
            user_id=test_user.id,
            notification_type="system_warning",
            message=f"Notification {i}"
        )
    
    notifications = service.get_notifications(test_user.id)
    
    assert len(notifications) == 5

@pytest.mark.asyncio
async def test_get_unread_notifications(db_session, test_user):
    """Test getting only unread notifications"""
    service = NotificationService(db_session)
    
    # Create notifications
    service.create_notification(test_user.id, "type1", "Message 1")
    service.create_notification(test_user.id, "type2", "Message 2")
    
    # Mark one as read
    notifications = service.get_notifications(test_user.id)
    service.mark_as_read(notifications[0].id, test_user.id)
    
    unread = service.get_notifications(test_user.id, unread_only=True)
    
    assert len(unread) == 1

@pytest.mark.asyncio
async def test_get_notification_by_id(db_session, test_user):
    """Test getting a specific notification"""
    service = NotificationService(db_session)
    notification = service.create_notification(
        user_id=test_user.id,
        notification_type="test_type",
        message="Test message"
    )
    
    retrieved = service.get_notification(notification.id, test_user.id)
    
    assert retrieved is not None
    assert retrieved.id == notification.id
    assert retrieved.type == "test_type"

@pytest.mark.asyncio
async def test_mark_as_read(db_session, test_user):
    """Test marking a notification as read"""
    service = NotificationService(db_session)
    notification = service.create_notification(
        user_id=test_user.id,
        notification_type="test_type",
        message="Test message"
    )
    
    updated = service.mark_as_read(notification.id, test_user.id)
    
    assert updated is not None
    assert updated.isRead == True

@pytest.mark.asyncio
async def test_mark_all_as_read(db_session, test_user):
    """Test marking all notifications as read"""
    service = NotificationService(db_session)
    
    # Create multiple notifications
    for i in range(3):
        service.create_notification(test_user.id, "type", f"Message {i}")
    
    count = service.mark_all_as_read(test_user.id)
    
    assert count == 3
    
    # Verify all are read
    unread = service.get_notifications(test_user.id, unread_only=True)
    assert len(unread) == 0

@pytest.mark.asyncio
async def test_delete_notification(db_session, test_user):
    """Test deleting a notification"""
    service = NotificationService(db_session)
    notification = service.create_notification(
        user_id=test_user.id,
        notification_type="test_type",
        message="Test message"
    )
    
    result = service.delete_notification(notification.id, test_user.id)
    
    assert result == True
    assert service.get_notification(notification.id, test_user.id) is None

@pytest.mark.asyncio
async def test_delete_all_notifications(db_session, test_user):
    """Test deleting all notifications"""
    service = NotificationService(db_session)
    
    # Create multiple notifications
    for i in range(4):
        service.create_notification(test_user.id, "type", f"Message {i}")
    
    count = service.delete_all_notifications(test_user.id)
    
    assert count == 4
    assert len(service.get_notifications(test_user.id)) == 0

@pytest.mark.asyncio
async def test_get_unread_count(db_session, test_user):
    """Test getting unread notification count"""
    service = NotificationService(db_session)
    
    # Create notifications
    service.create_notification(test_user.id, "type1", "Message 1")
    service.create_notification(test_user.id, "type2", "Message 2")
    service.create_notification(test_user.id, "type3", "Message 3")
    
    # Mark one as read
    notifications = service.get_notifications(test_user.id)
    service.mark_as_read(notifications[0].id, test_user.id)
    
    count = service.get_unread_count(test_user.id)
    
    assert count == 2

@pytest.mark.asyncio
async def test_get_notifications_by_type(db_session, test_user):
    """Test getting notifications by type"""
    service = NotificationService(db_session)
    
    # Create different types of notifications
    service.create_notification(test_user.id, "account_created", "Account created")
    service.create_notification(test_user.id, "login_success", "Login successful")
    service.create_notification(test_user.id, "account_created", "Another account")
    service.create_notification(test_user.id, "login_failed", "Login failed")
    
    account_notifications = service.get_notifications_by_type(test_user.id, "account_created")
    
    assert len(account_notifications) == 2
    assert all(n.type == "account_created" for n in account_notifications)

@pytest.mark.asyncio
async def test_cannot_access_others_notifications(db_session, test_user):
    """Test that users cannot access other users' notifications"""
    from app.models.account import User
    from app.services.auth_service import get_password_hash
    
    # Create another user
    other_user = User(
        username="otheruser",
        email="other@example.com",
        password=get_password_hash("password"),
        isUserAdmin=False,
        userGroupId=1
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)
    
    service = NotificationService(db_session)
    notification = service.create_notification(
        user_id=test_user.id,
        notification_type="test",
        message="Private notification"
    )
    
    # Other user should not be able to access
    assert service.get_notification(notification.id, other_user.id) is None
    assert service.get_notifications(other_user.id) == []

def test_notification_routes_are_registered():
    """Test that notification routes are registered"""
    from app.main import app
    
    route_paths = [route.path for route in app.routes]
    
    assert "/api/v1/notifications" in route_paths
    assert "/api/v1/notifications/unread-count" in route_paths
    assert "/api/v1/notifications/{notification_id}" in route_paths
    assert "/api/v1/notifications/{notification_id}/read" in route_paths
    assert "/api/v1/notifications/read-all" in route_paths
    assert "/api/v1/notifications/type/{notification_type}" in route_paths
