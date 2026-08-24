# services/database/db/models/base.py

"""
Base ORM model and mixins for all database entities.
Provides common fields (id, created_at, updated_at) and utilities.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Column, DateTime, String, func
from sqlalchemy.orm import declarative_mixin, declared_attr
from sqlalchemy.dialects.postgresql import UUID
import uuid

from db.connection.session import Base


@declarative_mixin
class TimestampMixin:
    """
    Mixin providing created_at and updated_at timestamps.
    Automatically managed by database (uses current_timestamp).
    """
    
    @declared_attr
    def created_at(cls):
        """Created timestamp (set once, never updated)."""
        return Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
            index=True,
        )
    
    @declared_attr
    def updated_at(cls):
        """Updated timestamp (auto-updated on each modify)."""
        return Column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
            index=True,
        )


@declarative_mixin
class UUIDMixin:
    """
    Mixin providing UUID primary key.
    Uses PostgreSQL native UUID type.
    """
    
    @declared_attr
    def id(cls):
        """Primary key: UUID v4."""
        return Column(
            UUID(as_uuid=True),
            primary_key=True,
            default=uuid.uuid4,
            nullable=False,
            index=True,
        )


@declarative_mixin
class AuditMixin:
    """
    Mixin for audit trail: created_by, updated_by.
    Tracks which user/system modified the record.
    """
    
    @declared_attr
    def created_by(cls):
        """User or system that created this record."""
        return Column(
            String(255),
            nullable=True,
            index=False,
        )
    
    @declared_attr
    def updated_by(cls):
        """User or system that last updated this record."""
        return Column(
            String(255),
            nullable=True,
            index=False,
        )


class BaseModel(Base, UUIDMixin, TimestampMixin):
    """
    Abstract base class for all ORM models.
    Provides: id (UUID), created_at, updated_at
    
    Usage:
        class User(BaseModel):
            __tablename__ = 'users'
            name = Column(String(255), nullable=False)
    """
    
    __abstract__ = True
    
    def to_dict(self, exclude: Optional[set] = None) -> dict:
        """
        Convert ORM model to dictionary.
        Useful for JSON serialization.
        
        Args:
            exclude: Set of field names to exclude
        
        Returns:
            Dictionary representation
        """
        exclude = exclude or set()
        result = {}
        
        for column in self.__table__.columns:
            if column.name not in exclude:
                value = getattr(self, column.name, None)
                # Serialize datetime to ISO format
                if isinstance(value, datetime):
                    value = value.isoformat()
                # Serialize UUID
                elif isinstance(value, uuid.UUID):
                    value = str(value)
                result[column.name] = value
        
        return result
    
    def __repr__(self) -> str:
        """Pretty representation for logging."""
        class_name = self.__class__.__name__
        id_val = getattr(self, 'id', 'unknown')
        return f"<{class_name}(id={id_val})>"


class AuditedBaseModel(BaseModel, AuditMixin):
    """
    Base model with audit trail fields.
    Use for entities requiring who-did-what tracking.
    """
    
    __abstract__ = True