"""Resource-level access grants (report 13 §2.2 — per-system permissions).

Platform roles (the 8-role catalog in ``api/security/rbac.py``) answer "what
kind of actor is this?". They cannot answer "may this developer touch THIS
payment system?" — that is a resource-level decision. This model adds
per-resource grants on top:

* a grant binds (subject, resource_type, resource_id) → resource role
  (``owner`` > ``operator`` > ``viewer``);
* **restrictive-only-when-present**: a resource with no grants behaves
  exactly as before (unrestricted for authenticated users). Once ANY grant
  exists for a resource, the resource is under grant control and a subject
  must hold a grant with a sufficient role;
* platform ``superadmin`` always passes; ``auditor`` passes read-only
  checks (its platform charter is read-everything);
* grants are tenant-scoped and audit-logged by the management endpoints.

This is deliberately a floor, not a fortress: full BLU→system→asset
inheritance and custom role definitions remain open (report 13 §2.2).
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class ResourceGrant(BaseModel, TenantScoped):
    __tablename__ = "resource_grants"
    __table_args__ = (
        UniqueConstraint("tenant_id", "subject", "resource_type", "resource_id", name="uq_resource_grant"),
    )

    subject: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(20), nullable=False, default="SYSTEM", index=True)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # owner > operator > viewer (ordering lives in ResourceGrantRepository)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    granted_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    revoke_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
