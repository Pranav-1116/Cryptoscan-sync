"""Stripe billing surface: checkout, webhook ingestion, subscription status.

All state lives in the platform key-value settings store keyed per tenant
(``billing:{tenant_id}``); the plan/quota enforcement already shipped in the
SaaS round reads the tenant's plan column — this module moves the plan
forward when Stripe says the customer paid, and flags past_due when payment
fails. Without STRIPE_API_KEY configured, checkout returns 503 honestly.
"""

from __future__ import annotations


from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.dependencies import (TenantContext, get_current_user,
                              get_db_session, get_tenant_context)

router = APIRouter(prefix="/saas/billing", tags=["billing"])

_STATE_PREFIX = "billing:"


class CheckoutBody(BaseModel):
    plan: str = Field(..., pattern="^(FREE|PRO|ENTERPRISE)$")
    success_url: str = Field(..., min_length=8, max_length=500)
    cancel_url: str = Field(..., min_length=8, max_length=500)


def _state_key(tenant_id: str) -> str:
    return f"{_STATE_PREFIX}{tenant_id}"


def _tenant_id(ctx) -> str:
    """The request's resolved tenant (or 'platform' outside tenant scope)."""
    return str(getattr(ctx, "tenant_id", None) or "platform")


@router.post("/checkout")
def create_checkout(body: CheckoutBody, user: str = Depends(get_current_user),
                    db=Depends(get_db_session),
                    ctx: TenantContext = Depends(get_tenant_context)):
    from billing.stripe_gateway import (
        StripeError,
        configured,
        create_checkout_session,
    )

    if not configured():
        raise HTTPException(status_code=503, detail={
            "error": "billing_not_configured",
            "message": "STRIPE_API_KEY is not set on this deployment",
        })
    tenant_id = _tenant_id(ctx)
    try:
        session = create_checkout_session(
            plan=body.plan, tenant_id=tenant_id, tenant_name=tenant_id,
            success_url=body.success_url, cancel_url=body.cancel_url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except StripeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)[:300])
    from db.repositories.settings_repository import SettingsRepository

    SettingsRepository(db).set(
        _state_key(tenant_id),
        {"status": "checkout_created", "plan": body.plan,
         "checkout_session": session.get("id"), "url": session.get("url")},
        updated_by=user)
    return {"checkout_url": session.get("url"), "session_id": session.get("id"),
            "plan": body.plan}


@router.post("/webhook")
async def stripe_webhook(request: Request, db=Depends(get_db_session)):
    """Stripe calls this; the signature is the only authentication."""
    from billing.stripe_gateway import verify_webhook

    payload = await request.body()
    header = request.headers.get("stripe-signature", "")
    try:
        event = verify_webhook(payload, header)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid webhook: {exc}")
    from billing.stripe_gateway import subscription_state_from_event

    state = subscription_state_from_event(event)
    if state is None:
        return {"handled": False, "type": event.get("type")}
    from db.repositories.settings_repository import SettingsRepository

    repo = SettingsRepository(db)
    key = _state_key(state["tenant_id"])
    previous = repo.get(key, {}) or {}
    merged = {**previous, **state,
              "updated_at_epoch": int(__import__("time").time())}
    repo.set(key, merged, updated_by="stripe-webhook")
    return {"handled": True, "type": event.get("type"), "status": state["status"]}


@router.get("/status")
def billing_status(user: str = Depends(get_current_user), db=Depends(get_db_session),
                   ctx: TenantContext = Depends(get_tenant_context)):
    from billing.stripe_gateway import configured
    from db.repositories.settings_repository import SettingsRepository

    tenant_id = _tenant_id(ctx)
    state = SettingsRepository(db).get(_state_key(tenant_id), None)
    return {
        "configured": configured(),
        "tenant_id": tenant_id,
        "subscription": state,
    }
