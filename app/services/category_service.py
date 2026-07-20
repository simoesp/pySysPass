from typing import List, Optional
import hashlib
from sqlalchemy.orm import Session
from app.models.account import Category, Client
from app.schemas.category import CategoryCreate, CategoryUpdate
from app.schemas.client import ClientCreate, ClientUpdate


def make_item_hash(name: str) -> bytes:
    # PHP sysPass persists this exact SHA-1 hex identifier in varbinary(40).
    # It is a lookup fingerprint, never a password or authenticity primitive.
    return hashlib.sha1(name.encode("utf-8"), usedforsecurity=False).hexdigest().encode("ascii")


class CategoryService:
    def __init__(self, db: Session):
        self.db = db

    def get_categories(self) -> List[Category]:
        return self.db.query(Category).all()

    def get_category(self, category_id: int) -> Optional[Category]:
        return self.db.query(Category).filter(Category.id == category_id).first()

    def create_category(self, category_data: CategoryCreate) -> Category:
        category = Category(
            name=category_data.name,
            description=getattr(category_data, "description", None),
            hash=make_item_hash(category_data.name),
        )
        category.icon = getattr(category_data, "icon", "folder")
        self.db.add(category)
        self.db.commit()
        self.db.refresh(category)
        return category

    def update_category(self, category_id: int, category_data: CategoryUpdate) -> Optional[Category]:
        category = self.get_category(category_id)
        if not category:
            return None

        update_data = category_data.model_dump(exclude_unset=True)
        if "icon" in update_data:
            category.icon = update_data["icon"]
            update_data.pop("icon")
        for field, value in update_data.items():
            setattr(category, field, value)
        if "name" in update_data:
            category.hash = make_item_hash(category.name)

        self.db.commit()
        self.db.refresh(category)
        return category

    def delete_category(self, category_id: int) -> bool:
        category = self.get_category(category_id)
        if not category:
            return False

        self.db.delete(category)
        self.db.commit()
        return True


class ClientService:
    def __init__(self, db: Session):
        self.db = db

    def get_clients(self) -> List[Client]:
        return self.db.query(Client).all()

    def get_client(self, client_id: int) -> Optional[Client]:
        return self.db.query(Client).filter(Client.id == client_id).first()

    def create_client(self, client_data: ClientCreate) -> Client:
        client = Client(
            name=client_data.name,
            description=client_data.notes,
            isGlobal=getattr(client_data, "is_global", False),
            hash=make_item_hash(client_data.name),
        )
        client.contact = getattr(client_data, "contact", None)
        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)
        return client

    def update_client(self, client_id: int, client_data: ClientUpdate) -> Optional[Client]:
        client = self.get_client(client_id)
        if not client:
            return None

        update_data = client_data.model_dump(exclude_unset=True)
        if "contact" in update_data:
            client.contact = update_data["contact"]
            update_data.pop("contact")
        if "notes" in update_data:
            update_data["description"] = update_data.pop("notes")
        if "is_global" in update_data:
            update_data["isGlobal"] = update_data.pop("is_global")
        for field, value in update_data.items():
            setattr(client, field, value)
        if "name" in update_data:
            client.hash = make_item_hash(client.name)

        self.db.commit()
        self.db.refresh(client)
        return client

    def delete_client(self, client_id: int) -> bool:
        client = self.get_client(client_id)
        if not client:
            return False

        self.db.delete(client)
        self.db.commit()
        return True
