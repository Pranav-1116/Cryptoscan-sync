"""Which repositories should be scanned on webhook."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class RepoConfiguration(BaseModel, TenantScoped):
    __tablename__ = "repo_configurations"

    repo_url: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    repo_name: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_on_push: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_on_pr: Mapped[bool] = mapped_column(Boolean, default=True)
    baseline_scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    notification_emails: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    @property
    def config_id(self) -> str:
        return self.id
