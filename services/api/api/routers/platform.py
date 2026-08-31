"""Platform scope — what CryptoScan is (and is not), served to consumers.

Read-only self-description: compliance teams can query this endpoint to
verify the tool's declared boundaries (read-only, evidence-chained,
metadata-only — never key material) without reading the source.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from api.dependencies import get_current_user
from shared_models.platform_scope import scope_manifest

router = APIRouter(prefix="/platform", tags=["platform"])


@router.get("/scope")
def platform_scope(user: str = Depends(get_current_user)):
    """Return the declared platform scope and honest boundaries."""
    return scope_manifest()
