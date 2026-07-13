"""Import/Export API Endpoints"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.core.security import get_encryption_service
from app.api.deps import require_permission
from app.models.account import User
from app.services.import_export_service import (
    CsvImportService,
    XmlImportService,
    KeePassImportService,
    ExportService
)

router = APIRouter(prefix="/import-export", tags=["Import/Export"])


@router.post("/import/csv")
async def import_csv(
    file: UploadFile = File(...),
    delimiter: str = Form(','),
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_import')),
):
    """Import accounts from CSV file"""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")
    content = await file.read()
    try:
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")
    service = CsvImportService(db, get_encryption_service(), user_id)
    try:
        data = service.parse_csv(content_str, delimiter=delimiter)
        stats = service.import_accounts(data)
        return {'format': 'csv', 'stats': stats, 'errors': service.errors[:10]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")


@router.post("/import/xml")
async def import_xml(
    file: UploadFile = File(...),
    user_id: int = Form(...),
    export_password: str = Form(""),
    import_master_password: str = Form(""),
    current_master_password: str = Form(""),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_import')),
):
    """Import accounts from sysPass XML format"""
    if not file.filename.endswith('.xml'):
        raise HTTPException(status_code=400, detail="File must be an XML")
    content = await file.read()
    try:
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")
    service = XmlImportService(
        db,
        get_encryption_service(),
        user_id,
        export_password=export_password,
        import_master_password=import_master_password,
        current_master_password=current_master_password,
    )
    try:
        data = service.parse_xml(content_str)
        stats = service.import_accounts(data)
        return {'format': 'xml', 'stats': stats, 'errors': service.errors[:10]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")


@router.post("/import/keepass")
async def import_keepass(
    file: UploadFile = File(...),
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_import')),
):
    """Import accounts from KeePass XML format"""
    if not file.filename.endswith('.xml'):
        raise HTTPException(status_code=400, detail="File must be a KeePass XML")
    content = await file.read()
    try:
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")
    service = KeePassImportService(db, get_encryption_service(), user_id)
    try:
        data = service.parse_keepass(content_str)
        stats = service.import_accounts(data)
        return {'format': 'keepass', 'stats': stats, 'errors': service.errors[:10]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")


@router.get("/export/csv")
async def export_csv(
    account_ids: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_import')),
):
    """Export accounts to CSV format"""
    service = ExportService(db, get_encryption_service())
    account_id_list = None
    if account_ids is not None:
        try:
            account_id_list = [int(id.strip()) for id in account_ids.split(',')]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid account IDs format")
    csv_content = service.export_to_csv(account_id_list)
    return {'format': 'csv', 'content': csv_content, 'filename': 'syspass_export.csv'}


@router.get("/export/xml")
async def export_xml(
    account_ids: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_import')),
):
    """Export accounts to sysPass XML format"""
    service = ExportService(db, get_encryption_service())
    account_id_list = None
    if account_ids is not None:
        try:
            account_id_list = [int(id.strip()) for id in account_ids.split(',')]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid account IDs format")
    try:
        xml_content = service.export_to_xml(
            account_id_list,
            username=current_user.get("username", "pySysPass"),
            user_id=current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {'format': 'xml', 'content': xml_content, 'filename': 'syspass_export.xml'}


@router.post("/export/xml/protected")
async def export_xml_protected(
    export_password: str = Form(...),
    master_password: str = Form(""),
    account_ids: str = Form(""),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_import')),
):
    """Export password-protected, PHP-native sysPass XML."""
    if not export_password:
        raise HTTPException(status_code=400, detail="Export password is required")
    try:
        account_id_list = (
            [int(value.strip()) for value in account_ids.split(",") if value.strip()]
            if account_ids
            else None
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account IDs format")

    user = db.get(User, current_user["id"])
    try:
        content = ExportService(db, get_encryption_service()).export_to_xml(
            account_id_list,
            export_password=export_password,
            master_password=master_password or None,
            username=current_user.get("username", "pySysPass"),
            user_id=current_user["id"],
            group_id=user.userGroupId if user else 0,
            group_name=user.userGroup.name if user and user.userGroup else "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "format": "xml",
        "content": content,
        "filename": "syspass_export.xml",
        "encrypted": True,
    }


@router.get("/export/keepass")
async def export_keepass(
    account_ids: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_import')),
):
    """Export accounts to KeePass XML format"""
    service = ExportService(db, get_encryption_service())
    account_id_list = None
    if account_ids is not None:
        try:
            account_id_list = [int(id.strip()) for id in account_ids.split(',')]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid account IDs format")
    keepass_content = service.export_to_keepass(account_id_list)
    return {'format': 'keepass', 'content': keepass_content, 'filename': 'syspass_export_keepass.xml'}
