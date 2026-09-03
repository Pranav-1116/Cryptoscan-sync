"""Plugin marketplace API (P2) — deterministic, hash-pinned, signed plugins.

Endpoints (admin-gated; plugins can execute code so this is a privileged
surface):

* POST /marketplace/plugins          upload a plugin (manifest + content + sig)
* GET  /marketplace/plugins           list plugins by state
* POST /marketplace/plugins/{id}/enable   enable a verified plugin
* POST /marketplace/plugins/{id}/disable  disable
* GET  /marketplace/trusted-keys      list pinned authority key ids

A plugin that fails content pinning, platform gating, or signature trust is
QUARANTINED and can never be enabled. Never executes AI — plugins are rules /
signatures / small code bundles verified cryptographically.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from marketplace.manifest import ManifestError, PluginManifest
from marketplace.registry import (
    PluginState,
    decide_state,
    select_enable_target,
)
from marketplace.verify import verify_plugin
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/marketplace", tags=["marketplace"])

_ADMIN = ("admin", "superadmin")


def _trusted_keys(db: Session) -> list[str]:
    """Pinned authority keys from app settings (id:base64pub), env override."""
    import os

    keys: list[str] = []
    env_keys = os.environ.get("MARKETPLACE_TRUSTED_KEYS", "")
    keys.extend(k.strip() for k in env_keys.split(",") if k.strip())
    try:
        from db.models.app_setting import AppSetting

        row = db.execute(
            select(AppSetting).where(AppSetting.key == "marketplace.trusted_keys")
        ).scalar_one_or_none()
        if row and isinstance(row.value, list):
            keys.extend(str(k) for k in row.value)
    except Exception:  # noqa: BLE001
        logger.debug("trusted-keys settings lookup skipped", exc_info=True)
    return keys


class PluginUpload(BaseModel):
    manifest: dict = Field(..., description="Plugin manifest object")
    content: str = Field("", description="Plugin text payload (rules/signatures/code)")
    signature: str | None = None
    signer_key_id: str | None = None
    platform_version: str = "999.0.0"
    enable: bool = False


class PluginOut(BaseModel):
    id: str
    plugin_id: str
    version: str
    plugin_type: str
    name: str
    state: str
    trusted: bool
    signer_key_id: str | None
    content_sha256: str
    min_platform: str
    verify_errors: list | None = None


def _to_out(row) -> PluginOut:
    return PluginOut(
        id=row.id,
        plugin_id=row.plugin_id,
        version=row.version,
        plugin_type=row.plugin_type,
        name=row.name,
        state=row.state,
        trusted=row.trusted,
        signer_key_id=row.signer_key_id,
        content_sha256=row.content_sha256,
        min_platform=row.min_platform,
        verify_errors=row.verify_errors,
    )


@router.get("/trusted-keys")
def list_trusted_keys(
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMIN)),
):
    keys = _trusted_keys(db)
    return {"trusted_key_ids": [k.split(":", 1)[0] for k in keys if ":" in k], "count": len(keys)}


@router.post("/plugins", response_model=PluginOut, status_code=201)
def upload_plugin(
    body: PluginUpload,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMIN)),
):
    from db.models.p2 import PluginPackage

    try:
        manifest = PluginManifest.from_dict(body.manifest)
    except ManifestError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    content_bytes = body.content.encode("utf-8")
    result = verify_plugin(
        manifest,
        content_bytes,
        trusted_keys=_trusted_keys(db),
        signature=body.signature,
        signer_key_id=body.signer_key_id,
        platform_version=body.platform_version,
    )

    new_state = decide_state(
        manifest,
        verified_ok=result.ok,
        trusted=result.trusted,
        operator_enable=body.enable,
    )

    # refuse to downgrade / clobber an ENABLED plugin with a quarantined upload
    existing_enabled = db.execute(
        select(PluginPackage).where(
            PluginPackage.plugin_id == manifest.plugin_id,
            PluginPackage.state == PluginState.ENABLED.value,
        )
    ).scalars().all()
    if new_state == PluginState.QUARANTINED and existing_enabled:
        # keep the current enabled version; quarantine the new one separately
        pass

    row = PluginPackage(
        plugin_id=manifest.plugin_id,
        version=manifest.version,
        plugin_type=manifest.plugin_type,
        name=manifest.name,
        description=manifest.description,
        content_sha256=manifest.content_sha256,
        content=body.content,
        signature=body.signature,
        signer_key_id=body.signer_key_id,
        min_platform=manifest.min_platform,
        state=new_state.value,
        trusted=result.trusted,
        author=manifest.author,
        tags={"tags": list(manifest.tags)},
        verify_errors=result.errors,
        enabled_by=user if new_state == PluginState.ENABLED else None,
    )
    db.add(row)

    if new_state == PluginState.ENABLED:
        # disable other enabled versions of the same plugin (single active)
        for old in existing_enabled:
            old.state = PluginState.DISABLED.value

    db.commit()
    db.refresh(row)
    if new_state == PluginState.QUARANTINED:
        logger.warning("plugin_quarantined", extra={"plugin_id": manifest.plugin_id,
                                                     "version": manifest.version,
                                                     "errors": result.errors})
    return _to_out(row)


@router.get("/plugins", response_model=list[PluginOut])
def list_plugins(
    state: str | None = None,
    plugin_type: str | None = None,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
):
    from db.models.p2 import PluginPackage

    stmt = select(PluginPackage).order_by(PluginPackage.plugin_id, PluginPackage.created_at.desc())
    if state:
        stmt = stmt.where(PluginPackage.state == state.upper())
    if plugin_type:
        stmt = stmt.where(PluginPackage.plugin_type == plugin_type.lower())
    rows = list(db.execute(stmt).scalars())
    return [_to_out(r) for r in rows]


def _get_plugin_or_404(db: Session, plugin_pk: str):
    from db.models.p2 import PluginPackage

    row = db.get(PluginPackage, plugin_pk)
    if not row:
        raise HTTPException(status_code=404, detail="plugin not found")
    return row


@router.post("/plugins/{plugin_pk}/enable", response_model=PluginOut)
def enable_plugin(
    plugin_pk: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMIN)),
):
    from db.models.p2 import PluginPackage

    row = _get_plugin_or_404(db, plugin_pk)
    # fail-closed: a quarantined or untrusted executable plugin can NEVER enable
    if row.state == PluginState.QUARANTINED.value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="plugin is quarantined and cannot be enabled")
    if row.plugin_type in ("scanner", "ingestor", "integrator") and not row.trusted:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="executable plugin is not signed by a trusted authority")
    # single-active: disable siblings
    for other in db.execute(
        select(PluginPackage).where(
            PluginPackage.plugin_id == row.plugin_id,
            PluginPackage.state == PluginState.ENABLED.value,
            PluginPackage.id != row.id,
        )
    ).scalars():
        other.state = PluginState.DISABLED.value
    row.state = PluginState.ENABLED.value
    row.enabled_by = user
    db.commit()
    db.refresh(row)
    return _to_out(row)


@router.post("/plugins/{plugin_pk}/disable", response_model=PluginOut)
def disable_plugin(
    plugin_pk: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMIN)),
):

    row = _get_plugin_or_404(db, plugin_pk)
    if row.state != PluginState.QUARANTINED.value:
        row.state = PluginState.DISABLED.value
    db.commit()
    db.refresh(row)
    return _to_out(row)


def active_plugin_content(db: Session, plugin_id: str) -> str | None:
    """Return the content of the currently ENABLED plugin (used by scanners)."""
    from db.models.p2 import PluginPackage

    rows = list(db.execute(
        select(PluginPackage).where(PluginPackage.plugin_id == plugin_id)
    ).scalars())
    candidates = [
        r for r in rows
        if r.state in (PluginState.ENABLED.value, PluginState.VERIFIED.value)
    ]
    target = select_enable_target(
        [type("P", (), {
            "manifest": PluginManifest.from_dict({
                "plugin_id": r.plugin_id, "version": r.version,
                "plugin_type": r.plugin_type, "name": r.name,
                "content_sha256": r.content_sha256, "min_platform": r.min_platform,
            }),
            "state": PluginState(r.state),
        })() for r in candidates],
        plugin_id,
    ) if candidates else None
    if target is None:
        return None
    return next((r.content for r in candidates if r.version == target.manifest.version), None)
