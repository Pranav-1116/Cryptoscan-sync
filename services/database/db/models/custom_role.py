"""Tenant-defined custom roles (report 13 §2.2 open item, round 30).

The built-in RBAC catalog is fixed (9 roles + legacy aliases); report 13
asked for custom role definitions — a tenant saying "we need a
`crypto-operator` that can trigger scans and read crypto state, nothing
else" without being handed `ciso`.

A custom role is a *named permission subset* of the platform's existing
permission matrix: it can never grant an action the matrix does not
know, and it can never collide with a built-in role name. Enforcement
stays in the same `require_permission` path — a custom role is not a
bypass, it is a narrower key.

The DB layer cannot import from `api` (contract noted in ``user.py``),
so the permission validation happens at the API surface where
``ALL_PERMISSIONS`` lives; the model stores the declared list as given.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import UniqueConstraint

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CustomRole(BaseModel, TenantScoped):
    __tablename__ = "custom_roles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_custom_role_per_tenant"),
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # subset of api.security.rbac.ALL_PERMISSIONS (validated at write)
    permissions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
