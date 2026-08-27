"""Persisted network scan runs — enables drift between stored scans."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class NetworkScanRun(BaseModel):
    __tablename__ = "network_scan_runs"

    scan_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    target_kind: Mapped[str] = mapped_column(String(30), nullable=False, default="hosts")
    verdict: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    probed: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ok: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    result: Mapped[Optional[dict]] = mapped_column(JSON(), nullable=True)
