from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.account import UserGroup, UserToUserGroup, User
from app.schemas.user_group import UserGroupCreate, UserGroupUpdate

class UserGroupService:
    def __init__(self, db: Session):
        self.db = db
    
    def get_user_groups(self) -> List[UserGroup]:
        """Get all user groups"""
        return self.db.query(UserGroup).all()
    
    def get_user_group(self, group_id: int) -> Optional[UserGroup]:
        """Get a specific user group"""
        return self.db.query(UserGroup).filter(
            UserGroup.id == group_id
        ).first()
    
    def create_user_group(
        self,
        group_data: UserGroupCreate
    ) -> UserGroup:
        """Create a new user group"""
        group = UserGroup(
            name=group_data.name,
            description=group_data.description,
        )
        self.db.add(group)
        self.db.commit()
        self.db.refresh(group)
        group.isUserAdmin = group_data.is_user_admin
        group.isUserEnabled = group_data.is_user_enabled
        group.isUserForcePwdChange = group_data.is_user_force_pwd_change
        return group
    
    def update_user_group(
        self,
        group_id: int,
        group_data: UserGroupUpdate
    ) -> Optional[UserGroup]:
        """Update a user group"""
        group = self.get_user_group(group_id)
        
        if not group:
            return None
        
        if group_data.name is not None:
            group.name = group_data.name
        if group_data.description is not None:
            group.description = group_data.description
        self.db.commit()
        self.db.refresh(group)
        if group_data.is_user_admin is not None:
            group.isUserAdmin = group_data.is_user_admin
        if group_data.is_user_enabled is not None:
            group.isUserEnabled = group_data.is_user_enabled
        if group_data.is_user_force_pwd_change is not None:
            group.isUserForcePwdChange = group_data.is_user_force_pwd_change
        return group
    
    def delete_user_group(self, group_id: int) -> bool:
        """Delete a user group"""
        group = self.get_user_group(group_id)
        
        if not group:
            return False
        
        # Remove all user group associations first
        self.db.query(UserToUserGroup).filter(
            UserToUserGroup.userGroupId == group_id
        ).delete()
        
        self.db.delete(group)
        self.db.commit()
        return True
    
    def get_group_members(self, group_id: int) -> List[User]:
        """Get all members of a user group"""
        return (
            self.db.query(User)
            .join(UserToUserGroup, User.id == UserToUserGroup.userId)
            .filter(UserToUserGroup.userGroupId == group_id)
            .all()
        )
    
    def get_user_groups_for_user(self, user_id: int) -> List[UserGroup]:
        """Get all groups a user belongs to"""
        return (
            self.db.query(UserGroup)
            .join(UserToUserGroup, UserGroup.id == UserToUserGroup.userGroupId)
            .filter(UserToUserGroup.userId == user_id)
            .all()
        )
    
    def add_user_to_group(
        self,
        user_id: int,
        group_id: int,
        is_manager: bool = False
    ) -> bool:
        """Add a user to a group"""
        # sysPass PHP stores only membership in UserToUserGroup; there is no
        # persisted per-membership manager flag in the legacy schema.
        _ = is_manager
        # Check if user already in group
        existing = self.db.query(UserToUserGroup).filter(
            UserToUserGroup.userId == user_id,
            UserToUserGroup.userGroupId == group_id
        ).first()
        
        if existing:
            return False  # Already a member
        
        association = UserToUserGroup(
            userId=user_id,
            userGroupId=group_id,
        )
        self.db.add(association)
        self.db.commit()
        return True
    
    def remove_user_from_group(self, user_id: int, group_id: int) -> bool:
        """Remove a user from a group"""
        association = self.db.query(UserToUserGroup).filter(
            UserToUserGroup.userId == user_id,
            UserToUserGroup.userGroupId == group_id
        ).first()
        
        if not association:
            return False
        
        self.db.delete(association)
        self.db.commit()
        return True
    
    def get_group_members_with_details(self, group_id: int) -> List[dict]:
        """Get group members with their details"""
        associations = self.db.query(UserToUserGroup).filter(
            UserToUserGroup.userGroupId == group_id
        ).all()
        
        result = []
        for assoc in associations:
            user = self.db.query(User).filter(User.id == assoc.userId).first()
            if user:
                result.append({
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                })
        
        return result
