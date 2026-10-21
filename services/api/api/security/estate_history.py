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
