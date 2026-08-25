"""Registered cloud accounts (credentials never required for IaC scans)."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class CloudAccount(BaseModel):
    __tablename__ = "cloud_accounts"

    cloud_provider: Mapped[str] = mapped_column(String(20), nullable=False)
    account_identifier: Mapped[str] = mapped_column(String(200), nullable=False)
    role_arn: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    regions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
