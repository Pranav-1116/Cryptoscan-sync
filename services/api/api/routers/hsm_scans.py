"""Spec-named HSM/KMS key-residence scan endpoints (`/hsm-scans`).

The key-residence core (connectivity, HSM-origin attributes, non-exportable
sign challenge) lives in ``keyassure.hsm_connectivity`` and is already
served as an assurance check at ``/crypto-assurance/hsm-check``. This router
puts the SAME core behind the specialized-scan contract (round 44/§4.8):
central admission, a tenant-bound durable ``ScanJob`` row (status, admission
decision, bounded coverage) readable at ``GET /jobs/{id}``, and honest
``verification_mode`` labeling — SUBMITTED attests collector-reported
attributes, LIVE is what the provider itself answered (opt-in, requires
``CRYPTOSCAN_HSM_LIVE`` and provider credentials).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import TenantContext, get_db_session, get_tenant_context
from api.routers.crypto_assurance import _DictBackend, _live_backend, hsm_live_enabled
from api.security.scan_admission import admit_scan
from api.security.scan_runs import DurableScanRun, coverage_from_result

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hsm-scans", tags=["hsm-scans"])


class HsmKeySpec(BaseModel):
    key_ref: str
    provider: str
    #: SUBMITTED mode: attributes a collector reported for the key
    describe: dict | None = None
    sign_challenge_ok: bool = True
    #: LIVE mode: provider connection options (endpoint, credentials ref…)
    options: dict | None = None


class HsmScanRequest(BaseModel):
    keys: list[HsmKeySpec] = Field(..., min_length=1, max_length=50)
    live: bool = False


@router.post("")
@router.post("/")
@router.post("/scan")
def trigger_hsm_scan(
    body: HsmScanRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db_session),
):
    """Run HSM/KMS key-residence checks as a durable, admitted scan run.

    Admission is the same central safe-scan decision as every other scan
    (emergency stop, queue depth, policy); LIVE mode reaches out to provider
    endpoints and is therefore admitted as active probing, SUBMITTED mode
    attests collector-reported attributes and touches no network.
    """
    if body.live and not hsm_live_enabled():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="live HSM verification is disabled; set CRYPTOSCAN_HSM_LIVE=true "
                   "on an API instance that holds provider credentials",
        )
    decision = admit_scan(active_probing_requested=body.live)
    target = ", ".join(f"{k.provider}:{k.key_ref}" for k in body.keys)[:500]
    with DurableScanRun(
        db, job_type="HSM_KEY_CHECK", target=target,
        user=ctx.username, admission=decision, tenant_id=ctx.tenant_id,
        metadata={"live": body.live, "keys": len(body.keys)},
    ) as run:
        from keyassure.hsm_connectivity import HsmCheckError, check_key

        results = []
        for spec in body.keys:
            try:
                if body.live:
                    backend = _live_backend(spec.provider, spec.options or {})
                else:
                    backend = _DictBackend(spec.describe or {},
                                           sign_ok=spec.sign_challenge_ok)
                result = check_key(spec.key_ref, provider=spec.provider,
                                   backend=backend)
            except HsmCheckError as exc:
                results.append({"key_ref": spec.key_ref,
                                "provider": spec.provider, "error": str(exc)})
                continue
            # how the verdict was obtained travels with every result —
            # downstream evidence must never conflate the two modes
            result["verification_mode"] = "LIVE" if body.live else "SUBMITTED"
            results.append(result)
        summary = {
            "total": len(results),
            "verification_mode": "LIVE" if body.live else "SUBMITTED",
            "hardware_backed": sum(1 for r in results if r.get("hardware_backed")),
            "software_keys": sum(1 for r in results
                                 if r.get("key_residence") == "SOFTWARE"),
            "connectivity_failures": sum(1 for r in results
                                         if r.get("connectivity") == "FAIL"
                                         or "error" in r),
        }
        run.succeed(coverage=coverage_from_result(summary))
    return {"job_id": run.job_id, "admission": decision,
            "summary": summary, "results": results}
