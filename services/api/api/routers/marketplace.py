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

from db.tenancy import filtered_get

import logging

from fastapi import APIRouter, Body, Depends, HTTPException, status
from marketplace.manifest import ManifestError, PluginManifest
from marketplace.registry import (
    PluginState,
    decide_state,
)
from marketplace.verify import verify_plugin
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/marketplace", tags=["marketplace"])

_ADMIN = ("admin", "superadmin")


_TRUST_SETTING = "marketplace.trusted_keys"


def _trusted_keys(db: Session) -> list[str]:
    """Pinned authority keys (``id:base64pub``) from app settings + env override."""
    import os

    keys: list[str] = []
    env_keys = os.environ.get("MARKETPLACE_TRUSTED_KEYS", "")
    keys.extend(k.strip() for k in env_keys.split(",") if k.strip())
    try:
        from db.repositories.settings_repository import SettingsRepository

        stored = SettingsRepository(db).get(_TRUST_SETTING, default=[])
        if isinstance(stored, list):
            keys.extend(str(k) for k in stored)
    except Exception:  # noqa: BLE001
        logger.debug("trusted-keys settings lookup skipped", exc_info=True)
    return keys


class TrustedKeyBody(BaseModel):
    key_id: str = Field(..., min_length=1, max_length=128)
    public_key_b64: str = Field(..., min_length=32, description="Base64 Ed25519 public key")


@router.post("/trusted-keys", status_code=201)
def add_trusted_key(
    body: TrustedKeyBody,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMIN)),
):
    """Pin a signing authority key. Executable plugins signed by this key trust."""
    import base64

    try:
        raw = base64.b64decode(body.public_key_b64.encode("ascii"), validate=True)
        if len(raw) != 32:  # Ed25519 public keys are exactly 32 bytes
            raise ValueError("Ed25519 public key must decode to 32 bytes")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"invalid Ed25519 public key: {exc}")

    from db.repositories.settings_repository import SettingsRepository

    repo = SettingsRepository(db)
    keys = [k for k in repo.get(_TRUST_SETTING, default=[]) if isinstance(k, str)]
    entry = f"{body.key_id}:{body.public_key_b64.strip()}"
    if entry not in keys:
        keys = [k for k in keys if not k.startswith(body.key_id + ":")]
        keys.append(entry)
        repo.set(_TRUST_SETTING, keys, updated_by=user)
        db.commit()
    return {"added": body.key_id, "trusted_key_ids": [k.split(":", 1)[0] for k in keys]}


@router.delete("/trusted-keys/{key_id}")
def remove_trusted_key(
    key_id: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMIN)),
):
    from db.repositories.settings_repository import SettingsRepository

    repo = SettingsRepository(db)
    keys = [k for k in repo.get(_TRUST_SETTING, default=[]) if isinstance(k, str)]
    remaining = [k for k in keys if not k.startswith(key_id + ":")]
    if len(remaining) == len(keys):
        raise HTTPException(status_code=404, detail="trusted key not found")
    repo.set(_TRUST_SETTING, remaining, updated_by=user)
    db.commit()
    return {"removed": key_id, "trusted_key_ids": [k.split(":", 1)[0] for k in remaining]}


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
    # Human-approval gate: an executable plugin can never become ENABLED purely
    # on upload, even if signed by a trusted authority. It is held at VERIFIED
    # until a 'plugin_enable_executable' governance request is APPROVED by a
    # separate approver and /enable is called with that approval id. Data-only
    # plugins (rulesets) may auto-enable on upload as they contain no code.
    _executable_upload = manifest.plugin_type in ("scanner", "ingestor", "integrator")
    if _executable_upload and new_state == PluginState.ENABLED:
        new_state = PluginState.VERIFIED

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


class RulesetEvaluateBody(BaseModel):
    findings: list[dict] = Field(default_factory=list, max_length=20000)


@router.post("/plugins/{plugin_pk}/evaluate")
def evaluate_ruleset(
    plugin_pk: str,
    body: RulesetEvaluateBody,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
):
    """Run a ruleset plugin's deterministic rules over submitted findings.

    Returns a CI-style gate (PASS/WARN/FAIL) with every matched rule. Only an
    ENABLED or VERIFIED ruleset plugin may be evaluated — never a quarantined
    payload. The ruleset is parsed from the plugin content (JSON/YAML-less JSON).
    """
    import json as _json

    from ruleset.engine import Ruleset, RulesetEngine, RulesetError

    row = _get_plugin_or_404(db, plugin_pk)
    if row.state == PluginState.QUARANTINED.value:
        raise HTTPException(status_code=409, detail="cannot evaluate a quarantined plugin")
    if row.plugin_type != "ruleset":
        raise HTTPException(status_code=422, detail="plugin is not a ruleset")
    try:
        data = _json.loads(row.content or "{}")
        ruleset = Ruleset.from_dict(data)
    except (RulesetError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"invalid ruleset content: {exc}")

    # content pin: refuse if the stored payload does not match its hash
    import hashlib

    if hashlib.sha256((row.content or "").encode("utf-8")).hexdigest() != row.content_sha256:
        raise HTTPException(status_code=409, detail="plugin content hash mismatch (tampered)")

    summary = RulesetEngine(ruleset).evaluate_many(body.findings)
    summary["plugin_id"] = row.plugin_id
    summary["plugin_state"] = row.state
    return summary


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


class EnableBody(BaseModel):
    approval_id: str | None = None


@router.post("/plugins/{plugin_pk}/enable", response_model=PluginOut)
def enable_plugin(
    plugin_pk: str,
    body: EnableBody = Body(default_factory=EnableBody),
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMIN)),
):
    from db.models.p2 import GovernanceApproval, PluginPackage

    row = _get_plugin_or_404(db, plugin_pk)
    # fail-closed: a quarantined or untrusted executable plugin can NEVER enable
    if row.state == PluginState.QUARANTINED.value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="plugin is quarantined and cannot be enabled")
    is_executable = row.plugin_type in ("scanner", "ingestor", "integrator")
    if is_executable and not row.trusted:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="executable plugin is not signed by a trusted authority")
    # human-approval gate (policy-as-code, no AI): enabling an EXECUTABLE plugin
    # is a HIGH-risk change requiring an APPROVED governance request whose
    # request_ref pins this exact plugin id. Segregation of duties is enforced
    # at the governance decide endpoint (requester cannot self-approve).
    if is_executable:
        approval_id = (body.approval_id if body else None)
        if not approval_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=("enabling an executable plugin is HIGH risk: submit a "
                        "'plugin_enable_executable' governance request referencing "
                        f"plugin {row.plugin_id}, obtain a separate approver's approval, "
                        "then re-call /enable with {\"approval_id\": <id>}"))
        appr = filtered_get(db, GovernanceApproval, approval_id)
        if appr is None or appr.status != "APPROVED":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="governance approval not found or not APPROVED")
        if appr.request_type != "plugin_enable_executable":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="approval is not of type plugin_enable_executable")
        refs = {row.plugin_id, row.id}
        if appr.request_ref not in refs and (appr.payload or {}).get("plugin_id") != row.plugin_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="approval does not reference this plugin id")
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


def _active_row(db: Session, plugin_id: str):
    """Return the highest-version ENABLED plugin row for an id (single active)."""
    from db.models.p2 import PluginPackage

    rows = list(db.execute(
        select(PluginPackage).where(
            PluginPackage.plugin_id == plugin_id,
            PluginPackage.state == PluginState.ENABLED.value,
        )
    ).scalars())
    if not rows:
        return None

    def _v(r):
        try:
            return tuple(int(p) for p in (r.version.split("+")[0].split("-")[0].split(".")))
        except ValueError:
            return (0, 0, 0)

    return max(rows, key=_v)


@router.get("/active/{plugin_id:path}")
def active_plugin(
    plugin_id: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles("admin", "superadmin", "scanner", "developer",
                                      "security_analyst", "ciso", "auditor")),
):
    """Scanner-facing: fetch the active (ENABLED) plugin payload + integrity pins.

    Scanners/worker call this to load a ruleset/signature bundle. Only ENABLED
    packages are served — never QUARANTINED/DISABLED — and the content hash is
    returned so the caller can re-verify the payload.
    """
    row = _active_row(db, plugin_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no enabled plugin for that id")
    return {
        "plugin_id": row.plugin_id,
        "version": row.version,
        "plugin_type": row.plugin_type,
        "state": row.state,
        "content_sha256": row.content_sha256,
        "signer_key_id": row.signer_key_id,
        "trusted": row.trusted,
        "content": row.content or "",
    }
