"""Organization/account-level settings (singleton-style key/value store).

Holds the active sector profile and other estate-wide configuration that the
universal engine reads at scan/report time. One row per setting key; values
are JSON so structures (a sector profile reference + overrides) round-trip.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class AppSetting(BaseModel):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
