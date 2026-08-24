"""
Base repository with common CRUD operations.
Implements Repository pattern for data access abstraction.
"""
from typing import Generic, TypeVar, Type, List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, update, delete
from ..models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """
    Base repository with generic CRUD operations.
    
    All repositories inherit from this to get standard database operations.
    """
    
    def __init__(self, model: Type[ModelType], session: Session):
        """
        Initialize repository.
        
        Args:
            model: SQLAlchemy model class
            session: Database session
        """
        self.model = model
        self.session = session
    
    def create(self, obj: ModelType) -> ModelType:
        """
        Create new record.
        
        Args:
            obj: Model instance to create
            
        Returns:
            Created model instance with ID populated
        """
        self.session.add(obj)
        self.session.flush()
        self.session.refresh(obj)
        return obj
    
    def create_many(self, objects: List[ModelType]) -> List[ModelType]:
        """
        Bulk create multiple records.
        
        Args:
            objects: List of model instances
            
        Returns:
            List of created instances
        """
        self.session.add_all(objects)
        self.session.flush()
        for obj in objects:
            self.session.refresh(obj)
        return objects
    
    def get_by_id(self, id_value: Any) -> Optional[ModelType]:
        """
        Get record by primary key.
        
        Args:
            id_value: Primary key value
            
        Returns:
            Model instance or None if not found
        """
        return self.session.get(self.model, id_value)
    
    def get_all(self, limit: int = 100, offset: int = 0) -> List[ModelType]:
        """
        Get all records with pagination.
        
        Args:
            limit: Maximum number of records
            offset: Number of records to skip
            
        Returns:
            List of model instances
        """
        stmt = select(self.model).limit(limit).offset(offset)
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def update(self, id_value: Any, values: Dict[str, Any]) -> Optional[ModelType]:
        """
        Update record by ID.
        
        Args:
            id_value: Primary key value
            values: Dictionary of field updates
            
        Returns:
            Updated model instance or None if not found
        """
        obj = self.get_by_id(id_value)
        if obj is None:
            return None
        
        for key, value in values.items():
            if hasattr(obj, key):
                setattr(obj, key, value)
        
        self.session.flush()
        self.session.refresh(obj)
        return obj
    
    def delete(self, id_value: Any) -> bool:
        """
        Delete record by ID.
        
        Args:
            id_value: Primary key value
            
        Returns:
            True if deleted, False if not found
        """
        obj = self.get_by_id(id_value)
        if obj is None:
            return False
        
        self.session.delete(obj)
        self.session.flush()
        return True
    
    def count(self) -> int:
        """
        Count total records.
        
        Returns:
            Total number of records
        """
        stmt = select(self.model)
        result = self.session.execute(stmt)
        return len(list(result.scalars().all()))
    
    def exists(self, id_value: Any) -> bool:
        """
        Check if record exists.
        
        Args:
            id_value: Primary key value
            
        Returns:
            True if exists, False otherwise
        """
        return self.get_by_id(id_value) is not None