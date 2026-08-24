"""Bulk insert helper."""

from __future__ import annotations

from typing import Iterable

from sqlalchemy.orm import Session


def bulk_insert(session: Session, objects: Iterable[object]) -> None:
    session.add_all(list(objects))
    session.flush()
