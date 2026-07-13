"""LDAP API — test connection and import users."""
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.api.deps import require_permission
from app.services.config_service import ConfigService
from app.services.ldap_service import LdapService, LdapImportService

router = APIRouter()


def _ldap_from_config(db: Session) -> LdapService:
    cfg = ConfigService(db).get_ldap_settings()
    if not cfg.ldap_enabled or not cfg.ldap_server:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LDAP is not enabled or not configured.",
        )
    return LdapService(
        ldap_uri=cfg.ldap_server,
        base_dn=cfg.ldap_base or "",
        bind_dn=cfg.ldap_binduser or None,
        bind_password=cfg.ldap_bindpass or None,
        use_tls=cfg.ldap_tls_enabled or False,
    )


class LdapTestBody(BaseModel):
    ldap_uri: Optional[str] = None
    base_dn: Optional[str] = None
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None
    use_tls: bool = False


class LdapImportBody(BaseModel):
    user_filter: str = "(objectClass=person)"
    default_group_id: Optional[int] = None


@router.post("/ldap/test-connection")
async def test_ldap_connection(
    body: LdapTestBody,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
):
    """Test LDAP connectivity with the supplied (or stored) parameters."""
    if body.ldap_uri:
        svc = LdapService(
            ldap_uri=body.ldap_uri,
            base_dn=body.base_dn or "",
            bind_dn=body.bind_dn,
            bind_password=body.bind_password,
            use_tls=body.use_tls,
        )
    else:
        svc = _ldap_from_config(db)
    try:
        svc.connect()
        svc.disconnect()
        return {"success": True, "detail": "Connection successful."}
    except Exception as exc:
        return {"success": False, "detail": str(exc)}


@router.get("/ldap/users")
async def list_ldap_users(
    user_filter: str = "(objectClass=person)",
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
) -> List[Dict]:
    """Return users from the LDAP directory (preview before import)."""
    svc = _ldap_from_config(db)
    try:
        svc.connect()
        users = svc.import_users(user_filter=user_filter)
        svc.disconnect()
        return users
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.post("/ldap/import")
async def import_ldap_users(
    body: LdapImportBody,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission('config_general')),
) -> Dict:
    """Import users from LDAP into sysPass."""
    ldap_svc = _ldap_from_config(db)
    cfg = ConfigService(db).get_ldap_settings()
    group_id = body.default_group_id or cfg.ldap_defaultgroup or 1
    try:
        ldap_svc.connect()
        ldap_users = ldap_svc.import_users(user_filter=body.user_filter)
        ldap_svc.disconnect()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return LdapImportService(db, user_group_id=group_id).import_ldap_users(ldap_users)
