"""Runtime (production traffic / process) crypto observations."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel, utcnow


class RuntimeFinding(BaseModel):
    __tablename__ = "runtime_findings"

    scanner_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, default="session")  # session | tls-library-risk
    hostname: Mapped[Optional[str]] = mapped_column(String(300), nullable=True, index=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    tls_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cipher_suite: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    algorithm: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # registry verdict
    quantum_impact: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    weak_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    dedup_key: Mapped[str] = mapped_column(String(400), nullable=False, index=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
