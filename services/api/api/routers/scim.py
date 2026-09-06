"""SCIM 2.0 provisioning endpoints (RFC 7643/7644).

These let an identity provider (Okta/Entra/Azure AD SCIM client) create,
update, list, and deactivate CryptoScan users deterministically over REST.
Authentication is an admin/provisioner principal (the IdP holds an API key
with admin role or a superadmin session). User deprovisioning is a soft
deactivation + session revocation — no rows are hard-deleted, preserving the
audit hash chain.

Routes are content-negotiated on the SCIM ``application/scim+json`` type but
also accept plain JSON.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles
from db.repositories.user_repository import UserRepository
from identity import scim as scim_logic

router = APIRouter(prefix="/scim/v2", tags=["scim"])


class _StoreAdapter:
    """Adapt UserRepository to the SCIM UserStore protocol."""

    def __init__(self, db: Session):
        self.repo = UserRepository(db)
        self.db = db

    def get_by_username(self, username):
        return self.repo.get_by_username(username)

    def create_user(self, username, password_hash, *, roles, display_name=None,
                    email=None, active=True):
        user = self.repo.create_user(username, password_hash, roles=list(roles),
                                     display_name=display_name, email=email, is_active=active)
        self.db.commit()
        return user

    def set_roles(self, username, roles):
        return self.repo.set_roles(username, list(roles))

    def set_active(self, username, active):
        return self.repo.set_active(username, active)

    def soft_delete(self, username):
        return self.repo.soft_delete_user(username)

    def list_all(self):
        return self.repo.list_users()


@router.get("/ServiceProviderConfig")
def service_provider_config(user: str = Depends(require_roles("admin", "superadmin"))):
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0},
        "filter": {"supported": True, "maxResults": 1000},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "name": "API Key / Bearer",
            "description": "Admin-tier bearer token or X-API-Key",
            "type": "httpxbearer",
        }],
    }


@router.get("/Users")
def list_users(
    startIndex: int = 1,
    count: int = 100,
    filter: str | None = None,
    user: str = Depends(require_roles("admin", "superadmin")),
    db: Session = Depends(get_db_session),
):
    return scim_logic.list_scim_users(_StoreAdapter(db), start_index=startIndex,
                                      count=count, filter_expr=filter)


@router.post("/Users", status_code=201)
def create_user(
    resource: dict,
    user: str = Depends(require_roles("admin", "superadmin")),
    db: Session = Depends(get_db_session),
):
    try:
        result = scim_logic.create_scim_user(_StoreAdapter(db), resource)
    except scim_logic.ScimError as exc:
        raise HTTPException(status_code=exc.status,
                            detail={"scimType": exc.scim_type, "detail": exc.detail})
    _audit(db, user, "scim.user_create", result["userName"])
    return result


@router.get("/Users/{username}")
def get_user(
    username: str,
    user: str = Depends(require_roles("admin", "superadmin")),
    db: Session = Depends(get_db_session),
):
    row = _StoreAdapter(db).get_by_username(username)
    if row is None:
        raise HTTPException(status_code=404, detail={"status": "404", "detail": "User not found"})
    return scim_logic.to_scim_user(row)


@router.patch("/Users/{username}")
def patch_user(
    username: str,
    body: dict,
    user: str = Depends(require_roles("admin", "superadmin")),
    db: Session = Depends(get_db_session),
):
    ops = body.get("Operations") or []
    try:
        result = scim_logic.patch_scim_user(_StoreAdapter(db), username, ops)
    except scim_logic.ScimError as exc:
        raise HTTPException(status_code=exc.status,
                            detail={"scimType": exc.scim_type, "detail": exc.detail})
    db.commit()
    _audit(db, user, "scim.user_update", username)
    return result


@router.delete("/Users/{username}", status_code=204)
def delete_user(
    username: str,
    user: str = Depends(require_roles("admin", "superadmin")),
    db: Session = Depends(get_db_session),
):
    try:
        scim_logic.deactivate_scim_user(_StoreAdapter(db), username)
    except scim_logic.ScimError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail)
    db.commit()
    _audit(db, user, "scim.user_deactivate", username)
    return None


def _audit(db: Session, actor: str, action: str, target: str) -> None:
    UserRepository(db).audit(actor, action, target_type="user", target_id=target)
    db.commit()
