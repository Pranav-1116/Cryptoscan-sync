"""Generic repository."""

from __future__ import annotations

from typing import Any, Generic, Type, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.base import BaseModel

ModelType = TypeVar("ModelType", bound=BaseModel)


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], session: Session):
        self.model = model
        self.session = session

    def create(self, obj: ModelType) -> ModelType:
        self.session.add(obj)
        self.session.flush()
        self.session.refresh(obj)
        return obj

    def get_by_id(self, id_value: Any) -> ModelType | None:
        return self.session.get(self.model, id_value)

    def get_all(self, limit: int = 100, offset: int = 0) -> list[ModelType]:
        stmt = select(self.model).limit(limit).offset(offset)
        return list(self.session.execute(stmt).scalars().all())

    def update(self, id_value: Any, values: dict[str, Any]) -> ModelType | None:
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
        obj = self.get_by_id(id_value)
        if obj is None:
            return False
        self.session.delete(obj)
        self.session.flush()
        return True

    def count(self) -> int:
        from sqlalchemy import func

        return int(self.session.execute(select(func.count()).select_from(self.model)).scalar_one())
