from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db.base import get_db
from app.schemas.client import ClientCreate, ClientResponse, ClientUpdate
from app.services.category_service import ClientService
from app.api.deps import get_current_user, require_permission

router = APIRouter()


@router.get("/clients", response_model=List[ClientResponse])
async def list_clients(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return ClientService(db).get_clients()


@router.post("/clients", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
async def create_client(
    client: ClientCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_customers')),
):
    return ClientService(db).create_client(client)


@router.get("/clients/{client_id}", response_model=ClientResponse)
async def get_client(
    client_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    client = ClientService(db).get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.put("/clients/{client_id}", response_model=ClientResponse)
async def update_client(
    client_id: int,
    client: ClientUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_customers')),
):
    updated = ClientService(db).update_client(client_id, client)
    if not updated:
        raise HTTPException(status_code=404, detail="Client not found")
    return updated


@router.delete("/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_client(
    client_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('mgm_customers')),
):
    if not ClientService(db).delete_client(client_id):
        raise HTTPException(status_code=404, detail="Client not found")
    return None
