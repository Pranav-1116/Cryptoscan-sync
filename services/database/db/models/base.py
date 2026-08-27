"""ORM mixins."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from db.connection.session import Base

__all__ = ["Base", "BaseModel", "utcnow", "new_id"]


def utcnow() -> datetime:
    """Aware UTC now (shared_models.chrono contract)."""
    from shared_models.chrono import utcnow as _utcnow

    return _utcnow()


def new_id() -> str:
    return str(uuid.uuid4())


class BaseModel(Base):
    __abstract__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=utcnow, default=utcnow
    )

    def to_dict(self, exclude: set[str] | None = None) -> dict:
        exclude = exclude or set()
        data = {}
        for column in self.__table__.columns:
            if column.name in exclude:
                continue
            value = getattr(self, column.name, None)
            if isinstance(value, datetime):
                value = value.isoformat()
            elif isinstance(value, uuid.UUID):
                value = str(value)
            data[column.name] = value
        return data
