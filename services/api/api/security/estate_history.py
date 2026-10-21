"""Trusted selected-estate context for API history, including NULL/platform.

The ORM's unscoped administrative view and readable curated NULL inventory are
not history access grants. History repositories must also receive an explicit
owner predicate. Internal dispatch/reaper repositories retain their own contract.
"""

from fastapi import Depends

from api.dependencies import TenantContext, get_tenant_context
from db.tenancy import tenant_scope


async def history_context(ctx: TenantContext = Depends(get_tenant_context)):
    # A sync generator's ContextVar changes do not propagate back to the request
    # task. Establish scope here for both sync handlers and async retry paths,
    # even when the optional HTTP tenant middleware is not installed.
    with tenant_scope(ctx.tenant_id):
        yield ctx


def assert_single_platform_estate(db):
    """Mixed-source aggregates are not partitioned. Tenant deletion is not a
    declassification: orphaned non-NULL inventory/history must also block them.
    """
    from fastapi import HTTPException
    from sqlalchemy import select
    from db.connection.session import Base
    from db.models.tenant import Tenant
    from db.tenancy import TenantScoped

    mixed = db.query(Tenant).first() is not None
    if not mixed:
        for mapper in Base.registry.mappers:
            model = mapper.class_
            if (
                issubclass(model, TenantScoped)
                and db.execute(select(model.tenant_id).where(model.tenant_id.is_not(None)).limit(1)).first() is not None
            ):
                mixed = True
                break
    if mixed:
        raise HTTPException(
            409, detail="Multi-estate aggregate exports/streams are not qualified; use estate-bound scan exports"
        )
