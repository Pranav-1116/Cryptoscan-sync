"""Offline license verification (advanced/73 P0#1, round 31).

An air-gapped site cannot phone home, so entitlement is a SIGNED
DOCUMENT carried in by the operator: licensee, plan, feature flags,
expiry, and the site binding. Verification is fully offline — canonical
JSON + SHA-256 content hash + HMAC-SHA256 signature, exactly the
platform's existing signed-transfer convention (control_plane
integrations, report signing). An attacker without the issuer key
cannot mint or alter a license; a leaked license is bound to one site
id, so it is useless elsewhere.

Composition rule: ``require_license`` composes with RBAC (never
replaces it). An expired or invalid license denies licensed routes even
for admins; a valid license never grants anything RBAC would deny.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException

logger = logging.getLogger(__name__)

LICENSE_FORMAT = "zelnx-license/v1"

#: features the platform knows how to gate (validated at issue AND verify
#: time so a bogus license cannot smuggle in an arbitrary feature name)
KNOWN_FEATURES = {
    "scanning", "cbom", "hbom", "vbom", "compliance", "migration",
    "threat_intel", "airgap", "integrations", "api",
}

PLANS = {"COMMUNITY", "PROFESSIONAL", "ENTERPRISE", "AIRGAP"}


class LicenseError(ValueError):
    """Structured license failure — code is machine-readable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def issue_license(
    *,
    licensee: str,
    plan: str,
    features: list[str],
    expires_at: datetime,
    site_id: str,
    issuer: str,
    signing_key: str,
    issued_at: Optional[datetime] = None,
) -> dict[str, Any]:
    """Issuer side — build a signed license package (offline CLI use).

    The signing key never leaves the issuer; sites only hold the same
    key for HMAC verification (symmetric, like every other signed
    transfer in this platform).
    """
    if not (licensee or "").strip():
        raise LicenseError("INVALID", "licensee is required")
    plan_n = str(plan or "").upper()
    if plan_n not in PLANS:
        raise LicenseError("INVALID", f"unknown plan '{plan}' (one of {sorted(PLANS)})")
    unknown = [f for f in features or [] if f not in KNOWN_FEATURES]
    if unknown:
        raise LicenseError("INVALID", f"unknown features: {', '.join(sorted(unknown))}")
    if not (site_id or "").strip():
        raise LicenseError("INVALID", "site_id is required")
    expires = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
    issued = issued_at or _now()
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if expires <= issued:
        raise LicenseError("INVALID", "expires_at must be after issued_at")
    doc = {
        "format": LICENSE_FORMAT,
        "licensee": licensee.strip(),
        "plan": plan_n,
        "features": sorted(set(features or [])),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "site_id": site_id.strip(),
        "issuer": (issuer or "zelinx").strip(),
    }
    canonical = _canonical(doc)
    return {
        "license": doc,
        "content_hash": hashlib.sha256(canonical).hexdigest(),
        "signature": hmac.new(signing_key.encode(), canonical, hashlib.sha256).hexdigest(),
    }


def verify_license(
    package: dict[str, Any],
    *,
    signing_key: str,
    site_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Verify a license package. Raises LicenseError with a code.

    Never raises on license *content* problems alone — tamper checks
    come first, then expiry, then site binding, so the operator always
    learns the most specific cause.
    """
    if not isinstance(package, dict) or not isinstance(package.get("license"), dict):
        raise LicenseError("MALFORMED", "package must carry a license document")
    doc = package["license"]
    if doc.get("format") != LICENSE_FORMAT:
        raise LicenseError("MALFORMED", f"unsupported license format {doc.get('format')!r}")
    if not (signing_key or "").strip():
        raise LicenseError("MISSING_KEY", "no license signing key configured on this site")
    canonical = _canonical(doc)
    if hashlib.sha256(canonical).hexdigest() != package.get("content_hash"):
        raise LicenseError("TAMPERED", "content hash mismatch — license altered or corrupt")
    if not hmac.compare_digest(
        hmac.new(signing_key.encode(), canonical, hashlib.sha256).hexdigest(),
        str(package.get("signature") or ""),
    ):
        raise LicenseError("TAMPERED", "signature mismatch — untrusted license")
    if doc.get("plan") not in PLANS:
        raise LicenseError("TAMPERED", f"unknown plan '{doc.get('plan')}'")
    unknown = [f for f in doc.get("features") or [] if f not in KNOWN_FEATURES]
    if unknown:
        raise LicenseError("TAMPERED", f"unknown features: {', '.join(sorted(unknown))}")
    moment = now or _now()
    try:
        issued = datetime.fromisoformat(str(doc.get("issued_at")))
        expires = datetime.fromisoformat(str(doc.get("expires_at")))
    except (TypeError, ValueError) as exc:
        raise LicenseError("MALFORMED", "unparseable issued_at/expires_at") from exc
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if moment < issued:
        raise LicenseError("NOT_YET_VALID", f"license becomes valid {doc.get('issued_at')}")
    if moment >= expires:
        raise LicenseError("EXPIRED", f"license expired {doc.get('expires_at')}")
    if site_id is not None and str(doc.get("site_id") or "") != site_id:
        raise LicenseError("SITE_MISMATCH",
                           f"license is bound to site '{doc.get('site_id')}', this site is '{site_id}'")
    return {
        "valid": True,
        "licensee": doc.get("licensee"),
        "plan": doc.get("plan"),
        "features": list(doc.get("features") or []),
        "expires_at": doc.get("expires_at"),
        "days_remaining": max(0, (expires - moment).days),
        "site_id": doc.get("site_id"),
        "issuer": doc.get("issuer"),
    }


def load_license_payload(raw: str) -> dict[str, Any]:
    """Parse the license package from settings (inline JSON or a file path)."""
    text = (raw or "").strip()
    if not text:
        raise LicenseError("MALFORMED", "empty license configuration")
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise LicenseError("MALFORMED", f"license JSON unparseable: {exc}") from exc
    try:
        with open(text, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise LicenseError("MALFORMED", f"license file unreadable: {exc}") from exc


def license_status(
    *,
    signing_key: str,
    raw_license: str,
    site_id: Optional[str] = None,
) -> dict[str, Any]:
    """Non-raising verification for the status endpoint."""
    try:
        package = load_license_payload(raw_license)
    except LicenseError as exc:
        return {"valid": False, "code": exc.code, "detail": str(exc)}
    try:
        result = verify_license(package, signing_key=signing_key, site_id=site_id)
    except LicenseError as exc:
        return {"valid": False, "code": exc.code, "detail": str(exc)}
    return result


def require_license(feature: Optional[str] = None):
    """FastAPI dependency: deny when the site's license is invalid or
    lacks ``feature``. Composes with RBAC (runs in addition, never
    instead)."""

    def dependency() -> dict[str, Any]:
        from api.config.settings import get_settings

        settings = get_settings()
        if not settings.LICENSE_REQUIRED:
            return {"enforced": False}
        result = license_status(
            signing_key=settings.LICENSE_SIGNING_KEY,
            raw_license=settings.LICENSE_DOCUMENT,
            site_id=settings.LICENSE_SITE_ID or None,
        )
        if not result.get("valid"):
            logger.warning("license_denied", extra={"code": result.get("code")})
            raise HTTPException(
                status_code=403,
                detail={"message": "license invalid on this site",
                        "code": result.get("code")},
            )
        if feature is not None and feature not in result.get("features", []):
            raise HTTPException(
                status_code=403,
                detail={"message": f"feature '{feature}' is not licensed on this site",
                        "code": "FEATURE_NOT_LICENSED",
                        "plan": result.get("plan")},
            )
        return {"enforced": True, "plan": result.get("plan"),
                "features": result.get("features")}

    return dependency


def trial_license(days: int = 30) -> dict[str, Any]:
    """Convenience issuer for evaluation sites (documented, audited by use)."""
    from api.config.settings import get_settings

    settings = get_settings()
    if not (settings.LICENSE_SIGNING_KEY or "").strip():
        raise LicenseError("MISSING_KEY", "LICENSE_SIGNING_KEY not configured")
    return issue_license(
        licensee="evaluation",
        plan="PROFESSIONAL",
        features=sorted(KNOWN_FEATURES),
        expires_at=_now() + timedelta(days=days),
        site_id=settings.LICENSE_SITE_ID or "evaluation",
        issuer="trial",
        signing_key=settings.LICENSE_SIGNING_KEY,
    )
