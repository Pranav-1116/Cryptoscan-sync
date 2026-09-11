"""Cloud KMS key inventory — collect AWS KMS / Azure Key Vault metadata.

The collectors (inventory.cloud_kms) are read-only against the provider and
normalize key metadata into the SAME crypto-asset shape as file-based
discovery, so cloud keys flow into the existing CBOM, roadmap and evidence
surfaces instead of becoming a parallel silo. Persisted rows are idempotent
per provider ref (upsert), never duplicates.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.security.rbac import require_permission
from db.models.crypto_asset import CryptoAsset
from db.repositories.asset_repository import AssetRepository

router = APIRouter(prefix="/inventory/cloud", tags=["inventory-cloud"])

_CLOUD_SOURCES = ("aws-kms", "azure-keyvault")


class CollectBody(BaseModel):
    provider: str = Field(..., pattern="^(aws-kms|azure-keyvault)$")
    region: str = ""
    vault_url: str = ""
    dry_run: bool = False


@router.post("/collect")
def collect(body: CollectBody,
            user: str = Depends(require_permission("crypto.manage")),
            db: Session = Depends(get_db_session)):
    """Collect key metadata from the provider. dry_run=true normalizes and
    reports without writing; otherwise rows are upserted into the inventory."""
    from inventory import cloud_kms

    try:
        if body.provider == "aws-kms":
            result = cloud_kms.collect_aws_kms(region=body.region)
        else:
            result = cloud_kms.collect_azure_keyvault(vault_url=body.vault_url)
    except RuntimeError as exc:  # SDK missing / no vault configured
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # provider refused (credentials/network) — honest 502
        raise HTTPException(status_code=502,
                            detail=f"{body.provider} collection failed: {exc}") from exc

    upserted = created = 0
    if not body.dry_run:
        repo = AssetRepository(db)
        for asset in result["assets"]:
            _, was_created = repo.upsert_cloud_asset(asset)
            created += int(was_created)
            upserted += 1
        db.commit()
    return {**result, "dry_run": body.dry_run, "upserted": upserted, "created": created}


@router.get("/assets")
def list_cloud_assets(limit: int = Query(200, ge=1, le=1000),
                      user: str = Depends(get_current_user),
                      db: Session = Depends(get_db_session)):
    """Crypto assets collected from cloud KMS providers (newest first)."""
    rows = db.execute(
        select(CryptoAsset)
        .where(CryptoAsset.source_language.in_(_CLOUD_SOURCES))
        .order_by(CryptoAsset.created_at.desc())
        .limit(limit)
    ).scalars().all()
    return {"assets": [row.to_dict() for row in rows], "total_count": len(rows)}
