"""Shared assurance-router boundary: exact selected estate, residency, human author."""
import uuid
from typing import Annotated
from fastapi import Depends, Path
from sqlalchemy.orm import Session
from api.dependencies import TenantContext, get_db_session
from api.security.estate_history import history_context
from api.assurance import store

Key = Annotated[str, Path(min_length=1, max_length=36)]


async def estate(ctx: TenantContext = Depends(history_context), db: Session = Depends(get_db_session)):
    store.residency(db, ctx.tenant_id)
    return ctx


def author(db, request, user, permission="assurance.manage"):
    return store.actor(db, request, user, permission)


def new_id():
    return str(uuid.uuid4())
