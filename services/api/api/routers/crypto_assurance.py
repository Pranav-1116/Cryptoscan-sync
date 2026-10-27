"""Key/crypto assurance API: active TLS audit, CT monitoring, expiry alerts,
HSM/KMS residence, trust-store inventory, hybrid-PQC downgrade, and weak-
primitive code rules. All engines are deterministic (no AI).

Active outbound TLS audits are gated behind an admin/auditor principal and are
read-only network handshakes. The target-validation / SSRF guard from the
platform is applied before any outbound connection.
"""

from __future__ import annotations

import base64
import os

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles
from db.repositories.user_repository import UserRepository

router = APIRouter(prefix="/crypto-assurance", tags=["crypto-assurance"])


# ------------------------------- 6. TLS audit ------------------------------ #
class TlsAuditRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(443, ge=1, le=65535)
    sni: str | None = None


@router.post("/tls-audit")
def tls_audit(body: TlsAuditRequest,
              user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from api.security.target_validation import TargetValidationError, validate_probe_target

    try:
        validate_probe_target(body.host)  # SSRF guard; fail-closed
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=f"target rejected: {exc}")
    from keyassure.tls_audit import TlsAuditError, audit_tls_endpoint

    try:
        return audit_tls_endpoint(body.host, body.port, sni=body.sni)
    except TlsAuditError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ----------------------------- 7. CT monitoring ---------------------------- #
class CtMonitorRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=200)
    known_serials: list[str] = Field(default_factory=list)
    allowed_issuers: list[str] = Field(default_factory=list)


@router.post("/ct-monitor")
def ct_monitor(body: CtMonitorRequest,
               user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from keyassure.ct_monitor import CtMonitorError, monitor_domain, summarize

    reports = []
    for domain in body.domains:
        try:
            reports.append(monitor_domain(
                domain, known_serials=body.known_serials,
                allowed_issuers=body.allowed_issuers))
        except CtMonitorError as exc:
            reports.append({"domain": domain, "error": str(exc),
                            "observed": [], "new_certs": [], "rogue_certs": []})
    return {"reports": [r if isinstance(r, dict) else r.__dict__ for r in reports],
            "summary": summarize([r for r in reports if not isinstance(r, dict) or "error" not in r])}


# ---------------------------- 8. Expiry alerts ----------------------------- #
class ExpiryAsset(BaseModel):
    id: str | None = None
    subject: str | None = None
    type: str = "certificate"
    not_after: str
    owner: str | None = None
    sla_tier: str = "tier2"
    sla_lead_days: int | None = None
    renewed: bool = False


class ExpiryRequest(BaseModel):
    assets: list[ExpiryAsset] = Field(..., min_length=1)


@router.post("/expiry-alerts")
def expiry_alerts(body: ExpiryRequest,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from keyassure.expiry_alerts import run_expiry_campaign

    result = run_expiry_campaign([a.model_dump() for a in body.assets])
    UserRepository(db).audit(user, "crypto.expiry_campaign", target_type="campaign",
                             target_id="expiry-alerts",
                             detail={"assets": result["total_assets"],
                                     "sla_breached": result["sla_breached"],
                                     "actionable": result["actionable_alerts"]})
    db.commit()
    return result


# --------------------------- 9. HSM/KMS residence -------------------------- #
class HsmKeySpec(BaseModel):
    key_ref: str
    provider: str


class HsmRequest(BaseModel):
    """Two modes, and the distinction matters for what the result proves.

    *Submitted* (default): a trusted collector that ran inside the cloud/HSM
    environment posts the provider's ``describe`` output and the API verifies
    residence deterministically from it. The verdict is only ever as good as
    the attributes the caller supplied -- it attests to what was reported, not
    to what the HSM actually holds.

    *Live* (``live: true``): the API talks to the provider itself through a
    real adapter (``keyassure.hsm_backends``), reads the key's attributes and
    performs the non-exportable sign challenge. This is the mode that actually
    verifies key residence. It needs outbound credentials, so it is gated on
    ``CRYPTOSCAN_HSM_LIVE`` the way live cloud scanning is gated on
    ``CRYPTOSCAN_CLOUD_LIVE``.
    """
    keys: list[dict] = Field(..., min_length=1,
                             description="Each: {key_ref, provider, describe:{...}} "
                                         "or, with live=true, {key_ref, provider, options:{...}}")
    live: bool = Field(False, description="Query the provider directly instead of "
                                          "trusting a submitted describe payload.")


def hsm_live_enabled() -> bool:
    """Live HSM/KMS queries are opt-in: they need real outbound credentials."""
    return os.environ.get("CRYPTOSCAN_HSM_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


def _live_backend(provider: str, options: dict):
    """Build a real provider adapter, or fail with an actionable message."""
    from keyassure.hsm_backends import BACKENDS, BackendUnavailable

    factory = BACKENDS.get((provider or "").lower())
    if factory is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"no live adapter for provider {provider!r}; "
                   f"supported: {sorted(BACKENDS)}",
        )
    try:
        return factory(**(options or {}))
    except BackendUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    except TypeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"bad options for {provider}: {exc}") from exc


class _DictBackend:
    def __init__(self, describe: dict, sign_ok: bool = True):
        self._describe = describe
        self._sign_ok = sign_ok

    def describe(self, key_ref):
        if isinstance(self._describe, dict) and self._describe.get("__connect_fail__"):
            raise RuntimeError("connectivity failed")
        return self._describe

    def sign_challenge(self, key_ref, nonce):
        if not self._sign_ok:
            raise RuntimeError("signing not available")
        return {"signature": b"\x30" + b"\x00" * 64}


@router.post("/hsm-check")
def hsm_check(body: HsmRequest,
              db: Session = Depends(get_db_session),
              user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from keyassure.hsm_connectivity import HsmCheckError, check_key

    if body.live and not hsm_live_enabled():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="live HSM verification is disabled; set CRYPTOSCAN_HSM_LIVE=true "
                   "on an API instance that holds provider credentials",
        )

    results = []
    for spec in body.keys:
        key_ref = spec.get("key_ref")
        provider = spec.get("provider", "")
        if body.live:
            backend = _live_backend(provider, spec.get("options") or {})
        else:
            describe = spec.get("describe") or {}
            sign_ok = bool(spec.get("sign_challenge_ok", True))
            backend = _DictBackend(describe, sign_ok=sign_ok)
        try:
            result = check_key(key_ref, provider=provider, backend=backend)
        except HsmCheckError as exc:
            results.append({"key_ref": key_ref, "provider": provider, "error": str(exc)})
            continue
        # Record how the verdict was obtained: a submitted-attribute result
        # attests to what a collector reported, a live one to what the
        # provider itself answered. Downstream evidence must not conflate them.
        result["verification_mode"] = "LIVE" if body.live else "SUBMITTED"
        results.append(result)
    summary = {
        "total": len(results),
        "verification_mode": "LIVE" if body.live else "SUBMITTED",
        "hardware_backed": sum(1 for r in results if r.get("hardware_backed")),
        "software_keys": sum(1 for r in results if r.get("key_residence") == "SOFTWARE"),
        "connectivity_failures": sum(1 for r in results if r.get("connectivity") == "FAIL"),
    }
    UserRepository(db).audit(user, "crypto.hsm_check", target_type="hsm",
                             target_id="hsm-check", detail=summary)
    db.commit()
    return {"summary": summary, "results": results}


# -------------------------- 10. Trust-store audit -------------------------- #
class TrustStoreRequest(BaseModel):
    """PEM bundle content (base64), or a server-local absolute path."""
    pem_bundle_b64: str | None = None
    path: str | None = None
    approved_fingerprints: list[str] = Field(default_factory=list)
    approved_subjects: list[str] = Field(default_factory=list)


@router.post("/trust-store")
def trust_store(body: TrustStoreRequest,
                user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from keyassure.trust_store import TrustStoreError, audit, parse_pem_bundle

    anchors = []
    baseline = set(body.approved_fingerprints)
    if body.pem_bundle_b64:
        try:
            raw = base64.b64decode(body.pem_bundle_b64)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"invalid base64 bundle: {exc}")
        anchors = parse_pem_bundle(raw, source="uploaded-bundle")
    elif body.path:
        import os

        if not os.path.isfile(body.path):
            raise HTTPException(status_code=404, detail=f"trust store not found: {body.path}")
        try:
            from keyassure.trust_store import inventory_path

            anchors = inventory_path(body.path)
        except TrustStoreError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    else:
        raise HTTPException(status_code=400, detail="provide pem_bundle_b64 or path")
    return audit(anchors, approved_fingerprints=baseline or None,
                 approved_subjects=set(body.approved_subjects) or None)


# ------------------------ 11. Hybrid-PQC downgrade ------------------------- #
class PqcAuditRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(443, ge=1, le=65535)
    sni: str | None = None


@router.post("/pqc-downgrade-audit")
def pqc_downgrade(body: PqcAuditRequest,
                  user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from api.security.target_validation import TargetValidationError, validate_probe_target

    try:
        validate_probe_target(body.host)
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=f"target rejected: {exc}")
    from keyassure.pqc_downgrade import audit_endpoint

    # Live PQC requires an oqs/OpenSSL-3.5 build; the default handshaker reports
    # LOCAL_UNSUPPORTED honestly. The pure policy is exercised via tests.
    return audit_endpoint(body.host, body.port, sni=body.sni)


# -------------------------- 12. Code weak-primitive ------------------------ #
class CodeScanRequest(BaseModel):
    filename: str = "snippet.py"
    source: str = Field(..., min_length=1)


@router.post("/code-rules/scan")
def code_scan(body: CodeScanRequest,
              user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from keyassure.code_rules import scan_python, _regex_scan

    if body.filename.endswith(".py"):
        findings = [f.__dict__ for f in scan_python(body.source, body.filename)]
    else:
        findings = [f.__dict__ for f in _regex_scan(body.source, body.filename)]
    by_rule: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {"file": body.filename, "total_findings": len(findings),
            "by_rule": by_rule, "by_severity": by_sev, "findings": findings}
