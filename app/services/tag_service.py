from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.account import Tag, AccountToTag, Account
from app.schemas.tag import TagCreate, TagUpdate
from app.services.category_service import make_item_hash

class TagService:
    def __init__(self, db: Session):
        self.db = db
    
    def get_tags(self, user_id: Optional[int] = None) -> List[Tag]:
        """Get all tags or user-specific tags"""
        query = self.db.query(Tag)
        return query.all()
    
    def get_tag(self, tag_id: int) -> Optional[Tag]:
        """Get a specific tag by ID"""
        return self.db.query(Tag).filter(Tag.id == tag_id).first()
    
    def create_tag(self, tag_data: TagCreate, user_id: Optional[int] = None) -> Tag:
        """Create a new tag"""
        tag = Tag(
            name=tag_data.name,
            hash=make_item_hash(tag_data.name),
        )
        if getattr(tag_data, "color", None) is not None:
            tag.color = tag_data.color
        if user_id is not None:
            tag.userId = user_id
        self.db.add(tag)
        self.db.commit()
        self.db.refresh(tag)
        return tag
    
    def update_tag(self, tag_id: int, tag_data: TagUpdate, user_id: Optional[int] = None) -> Optional[Tag]:
        """Update a tag"""
        tag = self.get_tag(tag_id)
        if not tag:
            return None
        
        if tag_data.name is not None:
            tag.name = tag_data.name
            tag.hash = make_item_hash(tag.name)
        if tag_data.color is not None:
            tag.color = tag_data.color
        
        self.db.commit()
        self.db.refresh(tag)
        return tag
    
    def delete_tag(self, tag_id: int, user_id: Optional[int] = None) -> bool:
        """Delete a tag and its associations"""
        tag = self.get_tag(tag_id)
        if not tag:
            return False
        
        # Remove all associations first
        self.db.query(AccountToTag).filter(AccountToTag.tagId == tag_id).delete()
        self.db.delete(tag)
        self.db.commit()
        return True
    
    def get_account_tags(self, account_id: int) -> List[Tag]:
        """Get all tags for an account"""
        return (
            self.db.query(Tag)
            .join(AccountToTag, Tag.id == AccountToTag.tagId)
            .filter(AccountToTag.accountId == account_id)
            .all()
        )
    
    def add_tag_to_account(self, account_id: int, tag_id: int) -> bool:
        """Add a tag to an account"""
        # Check if association already exists
        existing = self.db.query(AccountToTag).filter(
            AccountToTag.accountId == account_id,
            AccountToTag.tagId == tag_id
        ).first()
        
        if existing:
            return False  # Already tagged
        
        association = AccountToTag(
            accountId=account_id,
            tagId=tag_id
        )
        self.db.add(association)
        self.db.commit()
        return True
    
    def remove_tag_from_account(self, account_id: int, tag_id: int) -> bool:
        """Remove a tag from an account"""
        association = self.db.query(AccountToTag).filter(
            AccountToTag.accountId == account_id,
            AccountToTag.tagId == tag_id
        ).first()
        
        if not association:
            return False
        
        self.db.delete(association)
        self.db.commit()
        return True
    
    def search_accounts_by_tag(self, tag_id: int, user_id: int) -> List[Account]:
        """Get all accounts with a specific tag for a user"""
        return (
            self.db.query(Account)
            .join(AccountToTag, Account.id == AccountToTag.accountId)
            .filter(
                AccountToTag.tagId == tag_id,
                Account.userId == user_id
            )
            .all()
        )
