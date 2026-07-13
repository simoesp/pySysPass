import pytest
from app.schemas.category import CategoryCreate, CategoryUpdate
from app.schemas.client import ClientCreate, ClientUpdate
from app.services.category_service import CategoryService, ClientService

@pytest.mark.asyncio
async def test_create_category(db_session):
    service = CategoryService(db_session)
    category_data = CategoryCreate(name="Work", icon="briefcase")
    
    category = service.create_category(category_data)
    
    assert category.id is not None
    assert category.name == "Work"
    assert category.icon == "briefcase"

@pytest.mark.asyncio
async def test_get_categories(db_session):
    service = CategoryService(db_session)
    
    # Create test categories
    for i in range(3):
        service.create_category(CategoryCreate(name=f"Category {i}"))
    
    categories = service.get_categories()
    
    assert len(categories) == 3

@pytest.mark.asyncio
async def test_get_category(db_session):
    service = CategoryService(db_session)
    category = service.create_category(CategoryCreate(name="Test"))
    
    found = service.get_category(category.id)
    
    assert found is not None
    assert found.id == category.id

@pytest.mark.asyncio
async def test_update_category(db_session):
    service = CategoryService(db_session)
    category = service.create_category(CategoryCreate(name="Original"))
    
    updated = service.update_category(category.id, CategoryUpdate(name="Updated", icon="star"))
    
    assert updated.name == "Updated"
    assert updated.icon == "star"

@pytest.mark.asyncio
async def test_delete_category(db_session):
    service = CategoryService(db_session)
    category = service.create_category(CategoryCreate(name="To Delete"))
    
    result = service.delete_category(category.id)
    
    assert result == True
    assert service.get_category(category.id) is None

@pytest.mark.asyncio
async def test_create_client(db_session):
    service = ClientService(db_session)
    client_data = ClientCreate(name="Acme Corp", contact="john@acme.com", notes="Important client")
    
    client = service.create_client(client_data)
    
    assert client.id is not None
    assert client.name == "Acme Corp"
    assert client.contact == "john@acme.com"

@pytest.mark.asyncio
async def test_get_clients(db_session):
    service = ClientService(db_session)
    
    # Create test clients
    for i in range(3):
        service.create_client(ClientCreate(name=f"Client {i}"))
    
    clients = service.get_clients()
    
    assert len(clients) == 3

@pytest.mark.asyncio
async def test_update_client(db_session):
    service = ClientService(db_session)
    client = service.create_client(ClientCreate(name="Original"))
    
    updated = service.update_client(client.id, ClientUpdate(name="Updated", contact="new@email.com"))
    
    assert updated.name == "Updated"
    assert updated.contact == "new@email.com"

@pytest.mark.asyncio
async def test_delete_client(db_session):
    service = ClientService(db_session)
    client = service.create_client(ClientCreate(name="To Delete"))
    
    result = service.delete_client(client.id)
    
    assert result == True
    assert service.get_client(client.id) is None
