"""Site security operations: offline license, external secrets, zero-trust PDP.

Round 31 surfaces for three standing deployment-scoped opens:

- ``GET /license/status`` (advanced/73 P0#1) — offline license state,
  never the signing key or raw document.
- ``GET /security/secrets/status`` (advanced/75 P0#1) — which
  credential settings are external references, through which provider,
  and whether they currently resolve. No values, ever.
- ``GET /security/zero-trust/policies`` + ``POST /security/zero-trust/
  evaluate`` (advanced/82) — the active policy-as-code document and a
  dry-run decision for any (principal, roles, method, path) input.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.dependencies import get_current_user, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["site-security"])


# ── offline license (advanced/73 P0#1) ───────────────────────────────


@router.get("/license/status")
def license_status_view(user: str = Depends(get_current_user)):
    from api.config.settings import get_settings
    from api.security.license import license_status

    settings = get_settings()
    status = license_status(
        signing_key=settings.LICENSE_SIGNING_KEY,
        raw_license=settings.LICENSE_DOCUMENT,
        site_id=settings.LICENSE_SITE_ID or None,
    )
    # never echo the signing key or the raw document
    return status | {"enforced": bool(settings.LICENSE_REQUIRED)}


class TrialLicenseRequest(BaseModel):
    days: int = 30


@router.post("/license/trial")
def issue_trial_license(
    body: TrialLicenseRequest,
    admin: str = Depends(require_admin),
):
    """Issue a signed evaluation license for THIS site (offline issuer)."""
    from api.security.license import LicenseError, trial_license

    if not 1 <= body.days <= 365:
        raise HTTPException(status_code=422, detail="days must be 1..365")
    try:
        return trial_license(days=body.days)
    except LicenseError as exc:
        raise HTTPException(status_code=409, detail={"code": exc.code,
                                                     "message": str(exc)}) from exc


# ── external secrets (advanced/75 P0#1) ──────────────────────────────


@router.get("/security/secrets/status")
def secrets_status_view(admin: str = Depends(require_admin)):
    from api.security.vault import secret_status

    return secret_status()


# ── serving-TLS posture (deployment set, round 36) ───────────────────


@router.get("/security/tls/posture")
def tls_posture_view(admin: str = Depends(require_admin)):
    """Inspect the configured serving certificate and trust bundle.

    Never returns key material — only posture checks and certificate
    metadata. mTLS enforcement and TDE stay deployment-scoped; an
    unconfigured app boundary is reported as such (reverse-proxy
    termination is legitimate and invisible from inside the process).
    """
    from api.config.settings import get_settings
    from api.security.tls_posture import inspect_tls_posture

    settings = get_settings()
    return inspect_tls_posture(
        settings.TLS_CERT_FILE, settings.TLS_KEY_FILE, settings.TLS_CA_BUNDLE,
        min_version=settings.TLS_MIN_VERSION,
    )


# ── zero-trust PDP (advanced/82) ─────────────────────────────────────


@router.get("/security/zero-trust/policies")
def zero_trust_policies(admin: str = Depends(require_admin)):
    """The active embedded policy document (OPA policies live in OPA)."""
    from api.config.settings import get_settings
    from api.security.pdp import load_policies

    settings = get_settings()
    if not (settings.ZERO_TRUST_POLICY_FILE or "").strip():
        return {
            "format": "zelnx-zero-trust/v1",
            "rules": [],
            "source": None,
            "enforced": bool(settings.ZERO_TRUST_ENFORCED),
            "opa": {"configured": bool((settings.OPA_URL or "").strip()),
                    "policy_path": settings.OPA_POLICY_PATH},
        }
    try:
        doc = load_policies(settings.ZERO_TRUST_POLICY_FILE)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return doc | {
        "source": settings.ZERO_TRUST_POLICY_FILE,
        "enforced": bool(settings.ZERO_TRUST_ENFORCED),
        "opa": {"configured": bool((settings.OPA_URL or "").strip()),
                "policy_path": settings.OPA_POLICY_PATH},
    }


class ZeroTrustEvalRequest(BaseModel):
    principal: str = ""
    roles: list[str] = []
    method: str = "GET"
    path: str = "/api/v1/systems"


@router.post("/security/zero-trust/evaluate")
def zero_trust_evaluate(body: ZeroTrustEvalRequest,
                        admin: str = Depends(require_admin)):
    """Dry-run the composed PDP decision for one request shape.

    In enforcement mode an unreachable engine denies — here the same
    call reports the failure instead, so operators can test policies
    before turning ZERO_TRUST_ENFORCED on.
    """
    from api.config.settings import get_settings
    from api.security.pdp import zero_trust_decision

    settings = get_settings()
    decision = zero_trust_decision(
        principal=body.principal, roles=body.roles,
        method=body.method, path=body.path,
        policy_file=settings.ZERO_TRUST_POLICY_FILE,
        opa_url=settings.OPA_URL,
        opa_policy_path=settings.OPA_POLICY_PATH,
        enforced=False,
    )
    return decision | {
        "enforced": bool(settings.ZERO_TRUST_ENFORCED),
        "composition": "PDP deny blocks RBAC allow; PDP allow never bypasses RBAC",
    }
