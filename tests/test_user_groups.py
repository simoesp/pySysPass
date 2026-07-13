import pytest
from app.services.user_group_service import UserGroupService
from app.schemas.user_group import UserGroupCreate, UserGroupUpdate

@pytest.mark.asyncio
async def test_create_user_group(db_session):
    """Test creating a user group"""
    service = UserGroupService(db_session)
    group_data = UserGroupCreate(
        name="Developers",
        description="Development team",
        is_user_admin=False,
        is_user_enabled=True
    )
    
    group = service.create_user_group(group_data)
    
    assert group.id is not None
    assert group.name == "Developers"
    assert group.description == "Development team"
    assert group.isUserAdmin == False
    assert group.isUserEnabled == True

@pytest.mark.asyncio
async def test_get_user_groups(db_session):
    """Test listing all user groups"""
    service = UserGroupService(db_session)
    
    # Create multiple groups
    for name in ["Developers", "Managers", "Admins"]:
        service.create_user_group(UserGroupCreate(name=name))
    
    groups = service.get_user_groups()

    created_names = {group.name for group in groups if group.name in {"Developers", "Managers", "Admins"}}
    assert created_names == {"Developers", "Managers", "Admins"}

@pytest.mark.asyncio
async def test_get_user_group(db_session):
    """Test getting a specific user group"""
    service = UserGroupService(db_session)
    group_data = UserGroupCreate(name="Test Group", description="Test Description")
    group = service.create_user_group(group_data)
    
    retrieved = service.get_user_group(group.id)
    
    assert retrieved is not None
    assert retrieved.id == group.id
    assert retrieved.name == "Test Group"

@pytest.mark.asyncio
async def test_update_user_group(db_session):
    """Test updating a user group"""
    service = UserGroupService(db_session)
    group_data = UserGroupCreate(name="Original", description="Original Desc")
    group = service.create_user_group(group_data)
    
    update_data = UserGroupUpdate(
        name="Updated",
        is_user_admin=True
    )
    updated = service.update_user_group(group.id, update_data)
    
    assert updated.name == "Updated"
    assert updated.description == "Original Desc"  # Unchanged
    assert updated.isUserAdmin == True

@pytest.mark.asyncio
async def test_delete_user_group(db_session):
    """Test deleting a user group"""
    service = UserGroupService(db_session)
    group_data = UserGroupCreate(name="To Delete")
    group = service.create_user_group(group_data)
    
    result = service.delete_user_group(group.id)
    
    assert result == True
    assert service.get_user_group(group.id) is None

@pytest.mark.asyncio
async def test_add_user_to_group(db_session, test_user):
    """Test adding a user to a group"""
    service = UserGroupService(db_session)
    group = service.create_user_group(UserGroupCreate(name="Test Group"))
    
    result = service.add_user_to_group(test_user.id, group.id)
    
    assert result == True
    
    # Verify user is in group
    members = service.get_group_members(group.id)
    assert len(members) == 1
    assert members[0].id == test_user.id

@pytest.mark.asyncio
async def test_cannot_add_duplicate_user_to_group(db_session, test_user):
    """Test that adding the same user twice returns False"""
    service = UserGroupService(db_session)
    group = service.create_user_group(UserGroupCreate(name="Test Group"))
    
    # Add user first time
    result1 = service.add_user_to_group(test_user.id, group.id)
    assert result1 == True
    
    # Try to add again
    result2 = service.add_user_to_group(test_user.id, group.id)
    assert result2 == False

@pytest.mark.asyncio
async def test_remove_user_from_group(db_session, test_user):
    """Test removing a user from a group"""
    service = UserGroupService(db_session)
    group = service.create_user_group(UserGroupCreate(name="Test Group"))
    service.add_user_to_group(test_user.id, group.id)
    
    result = service.remove_user_from_group(test_user.id, group.id)
    
    assert result == True
    
    # Verify user is removed
    members = service.get_group_members(group.id)
    assert len(members) == 0

@pytest.mark.asyncio
async def test_get_user_groups_for_user(db_session, test_user):
    """Test getting all groups for a user"""
    service = UserGroupService(db_session)
    
    # Create multiple groups and add user to them
    for name in ["Group1", "Group2", "Group3"]:
        group = service.create_user_group(UserGroupCreate(name=name))
        service.add_user_to_group(test_user.id, group.id)
    
    groups = service.get_user_groups_for_user(test_user.id)
    
    assert len(groups) == 3

@pytest.mark.asyncio
async def test_get_group_members_with_details(db_session, test_user):
    """Test getting group members with their details"""
    from app.services.auth_service import get_password_hash
    from app.models.account import User
    
    service = UserGroupService(db_session)
    group = service.create_user_group(UserGroupCreate(name="Test Group"))
    
    # Add multiple users
    service.add_user_to_group(test_user.id, group.id)
    
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
    
    service.add_user_to_group(other_user.id, group.id)
    
    members = service.get_group_members_with_details(group.id)
    
    assert len(members) == 2
    member_ids = [m["user_id"] for m in members]
    assert test_user.id in member_ids
    assert other_user.id in member_ids

def test_user_group_routes_are_registered():
    """Test that user group routes are registered"""
    from app.main import app
    
    route_paths = [route.path for route in app.routes]
    
    assert "/api/v1/user-groups" in route_paths
    assert "/api/v1/user-groups/{group_id}" in route_paths
    assert "/api/v1/user-groups/{group_id}/members" in route_paths
    assert "/api/v1/user-groups/{group_id}/members/{user_id}" in route_paths
    assert "/api/v1/users/{user_id}/groups" in route_paths
