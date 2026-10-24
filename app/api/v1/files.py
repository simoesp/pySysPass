from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from fastapi.responses import Response
from app.db.base import get_db
from app.schemas.file import FileCreate, FileResponse, FileUploadResponse
from app.services.file_service import FileService
from app.api.deps import require_any_permission
from app.core.security import get_encryption_service
from app.core.mime_detect import detect_mime
from app.services.account_service import AccountService
from app.services.history_service import HistoryService
from app.services.runtime_policy import get_policy
import base64
import binascii
import os

router = APIRouter()
file_access = require_any_permission("acc_files", account_admin=True)

@router.get("/accounts/{account_id}/files", response_model=List[FileResponse])
def list_files(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(file_access)
):
    """List all files attached to an account"""
    if not get_policy(db).files_enabled:
        # sysPass PHP AccountFileController::listAction() gate.
        raise HTTPException(status_code=403, detail="Files management disabled")
    if not AccountService(db, get_encryption_service()).can_access_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)
    return service.get_files(account_id, current_user["id"])

@router.post("/accounts/{account_id}/files", response_model=FileUploadResponse, status_code=status.HTTP_201_CREATED)
def upload_file(
    account_id: int,
    file_data: FileCreate,
    db: Session = Depends(get_db),
    current_user = Depends(file_access)
):
    """Upload a file to an account"""
    if not AccountService(db, get_encryption_service()).can_edit_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")

    policy = get_policy(db)
    if not policy.files_enabled:
        raise HTTPException(status_code=403, detail="Files management disabled")
    # Bound the work before decoding; the decoded length is checked exactly.
    if len(file_data.content) > 4 * -(-policy.max_file_bytes // 3) + 4:
        raise HTTPException(status_code=413, detail=f"File size exceeded (maximum {policy.files_allowed_size_kb} KB)")
    try:
        content = base64.b64decode(file_data.content, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid base64 content")
    if not content:
        raise HTTPException(status_code=400, detail="Invalid file")
    if len(content) > policy.max_file_bytes:
        raise HTTPException(status_code=413, detail=f"File size exceeded (maximum {policy.files_allowed_size_kb} KB)")

    # sysPass PHP: extension = upper-cased suffix of the file name.
    extension = os.path.splitext(file_data.name)[1].lstrip(".").upper()
    if len(extension) > 10:
        raise HTTPException(status_code=422, detail="File extension too long")
    if policy.files_allowed_exts and extension not in policy.files_allowed_exts:
        raise HTTPException(status_code=415, detail="File type not allowed")
    # PHP AccountFileController::checkAllowedMimeType(): the declared type, or
    # else the type detected from the content (stored instead); an empty list
    # allows nothing.
    file_type = file_data.type
    if policy.files_allowed_mime is not None:
        if not policy.files_allowed_mime:
            raise HTTPException(status_code=415, detail="There aren't any allowed MIME types")
        if file_type.split(";")[0].strip().lower() not in policy.files_allowed_mime:
            detected = detect_mime(content)
            if detected not in policy.files_allowed_mime:
                raise HTTPException(status_code=415, detail="File type not allowed")
            file_type = detected

    service = FileService(db)

    # Create the file
    file = service.create_file(
        account_id=account_id,
        name=file_data.name,
        file_type=file_type,
        size=len(content),
        content=content,
        extension=extension
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

@router.get("/accounts/{account_id}/files/count")
def get_file_count(
    account_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(file_access)
):
    """Get the number of files attached to an account"""
    if not AccountService(db, get_encryption_service()).can_access_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)
    count = service.get_file_count(account_id, current_user["id"])

    return {"account_id": account_id, "file_count": count}

@router.get("/accounts/{account_id}/files/{file_id}")
def get_file(
    account_id: int,
    file_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(file_access)
):
    """Get a specific file and its content"""
    if not AccountService(db, get_encryption_service()).can_access_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)
    file = service.get_file(file_id, current_user["id"], account_id=account_id)

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
def get_file_metadata(
    account_id: int,
    file_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(file_access)
):
    """Get file metadata without downloading content"""
    if not AccountService(db, get_encryption_service()).can_access_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)
    file = service.get_file(file_id, current_user["id"], account_id=account_id)

    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    return file

@router.delete("/accounts/{account_id}/files/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(
    account_id: int,
    file_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(file_access)
):
    """Delete a file from an account"""
    if not AccountService(db, get_encryption_service()).can_edit_account(account_id, current_user["id"]):
        raise HTTPException(status_code=404, detail="Account not found")

    service = FileService(db)

    if not service.delete_file(file_id, current_user["id"], account_id=account_id):
        raise HTTPException(status_code=404, detail="File not found")

    return None
