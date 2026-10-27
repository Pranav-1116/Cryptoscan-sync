"""Persisted container / image-root scan summary."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class ContainerScan(BaseModel, TenantScoped):
    __tablename__ = "container_scans"

    scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    package_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    library_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vuln_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
