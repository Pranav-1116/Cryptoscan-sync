"""Human owner of a system or process."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class BusinessOwner(BaseModel, TenantScoped):
    __tablename__ = "business_owners"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, unique=True)
    role: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    escalation_contact: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
