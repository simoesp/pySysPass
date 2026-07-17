from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from fastapi.responses import Response
from app.db.base import get_db
from app.schemas.file import FileCreate, FileResponse, FileUploadResponse
from app.services.file_service import FileService
from app.services.auth_service import decode_token
from app.services.history_service import HistoryService
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import base64

router = APIRouter()
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"id": payload.get("user_id")}

@router.get("/accounts/{account_id}/files", response_model=List[FileResponse])
async def list_files(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all files attached to an account"""
    from app.models.account import Account

    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)
    return service.get_files(account_id, current_user["id"])

@router.post("/accounts/{account_id}/files", response_model=FileUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_file(
    account_id: int,
    file_data: FileCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Upload a file to an account"""
    from app.models.account import Account

    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # Decode base64 content
    try:
        content = base64.b64decode(file_data.content)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 content")

    service = FileService(db)

    # Create the file
    file = service.create_file(
        account_id=account_id,
        name=file_data.name,
        file_type=file_data.type,
        size=file_data.size,
        content=content,
        extension=file_data.extension
    )

    # Log the upload
    history_service = HistoryService(db)
    history_service.log_file_upload(account_id, current_user["id"], file_data.name)

    return FileUploadResponse(
        id=file.id,
        account_id=account_id,
        name=file.name,
        type=file.type,
        size=file.size,
        extension=file.extension,
        date_add=file.date_add,
        message="File uploaded successfully"
    )

@router.get("/accounts/{account_id}/files/{file_id}")
async def get_file(
    account_id: int,
    file_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get a specific file and its content"""
    from app.models.account import Account

    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)
    file = service.get_file(file_id, current_user["id"])

    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    # Log the download
    history_service = HistoryService(db)
    history_service.log_file_download(account_id, current_user["id"], file.name)

    # Return file content
    return Response(
        content=file.content,
        media_type=file.type,
        headers={
            "Content-Disposition": f'attachment; filename="{file.name}"'
        }
    )

@router.get("/accounts/{account_id}/files/{file_id}/metadata", response_model=FileResponse)
async def get_file_metadata(
    account_id: int,
    file_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get file metadata without downloading content"""
    from app.models.account import Account

    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)
    file = service.get_file(file_id, current_user["id"])

    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    return file

@router.delete("/accounts/{account_id}/files/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file(
    account_id: int,
    file_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete a file from an account"""
    from app.models.account import Account

    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)

    if not service.delete_file(file_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="File not found")

    return None

@router.get("/accounts/{account_id}/files/count")
async def get_file_count(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get the number of files attached to an account"""
    from app.models.account import Account

    # Verify user has access
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.userId == current_user["id"]
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)
    count = service.get_file_count(account_id, current_user["id"])

    return {"account_id": account_id, "file_count": count}
