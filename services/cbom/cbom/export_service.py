"""Technology BOM Export Service (spec: validate -> filter -> generate -> sign/hash -> audit).

The pure engine (``technology_bom``) knows how to *materialize and render* a BOM
state. This service is the operational pipeline the customer actually invokes
when they download an export:

1. ``validate``   — reject unsupported formats/layers up front with a clear error.
2. ``filter``     — project the state onto a sub-set (layer / risk / key-size / search).
3. ``generate``   — render JSON / CSV / CycloneDX / CycloneDX-XML / SPDX / PDF.
4. ``sign/hash``  — bind an HMAC-SHA256 signature + content hash to the artifact.
5. ``audit``      — hand a manifest to the caller so an audit event is recorded.

The service is pure (no DB, no I/O, no FastAPI): it takes a materialized state
and returns a verifiable export manifest. The router supplies the signing secret
(env/SEK) and the ``on_audit`` callback that emits the platform event.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from typing import Any

from cbom.technology_bom import (
    export_technology_bom,
    filter_technology_bom,
)

VALID_FORMATS = {"json", "csv", "cyclonedx", "cyclonedx-xml", "spdx", "pdf", "xml"}
VALID_LAYERS = {"all", "sbom", "cbom", "hbom", "vendor", "certificates"}


class ExportValidationError(ValueError):
    """Raised for an unsupported format / layer / malformed filter."""


def validate_export_request(fmt: str, layer: str, filters: dict[str, Any] | None) -> None:
    fmt = (fmt or "json").strip().lower()
    layer = (layer or "all").strip().lower()
    if fmt not in VALID_FORMATS:
        raise ExportValidationError(
            f"unsupported format '{fmt}'. Supported: {sorted(VALID_FORMATS)}")
    if layer not in VALID_LAYERS:
        raise ExportValidationError(
            f"unsupported layer '{layer}'. Supported: {sorted(VALID_LAYERS)}")
    fl = (filters or {})
    if fl.get("layer") not in (None, "") and str(fl["layer"]).lower() not in VALID_LAYERS:
        raise ExportValidationError(f"unsupported filter layer '{fl['layer']}'")


def canonical_export_payload(state: dict[str, Any], body: Any) -> bytes:
    """The exact bytes both signatures cover (content hash + JWS + legacy HMAC)."""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return json.dumps({"snapshot_id": state.get("snapshot_id"), "body": body},
                      sort_keys=True, default=str).encode("utf-8")


def sign_manifest(state: dict[str, Any], body: Any, *, secret: str) -> str:
    """Legacy raw HMAC-SHA256 hex (kept for verifiers predating JWS support)."""
    payload = canonical_export_payload(state, body)
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def sign_manifest_jws(state: dict[str, Any], body: Any, *, secret: str,
                      alg: str = "HS256") -> str:
    """RFC 7515 compact JWS over the same canonical bytes as the content hash.

    Standards-conformant signature for export manifests (HS256 shared secret
    by default; asymmetric algs supported via ``cbom.signing.jws_signer``).
    """
    from cbom.signing.jws_signer import sign_compact

    payload = canonical_export_payload(state, body)
    return sign_compact(payload, secret, alg)


def export_bom(
    state: dict[str, Any],
    *,
    fmt: str = "json",
    layer: str = "all",
    filters: dict[str, Any] | None = None,
    signature: str | None = None,
    on_audit: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    """Run the full export pipeline and return a verifiable manifest.

    ``signature`` is the optional pre-computed signature (so a caller that has a
    historical manifest can sign it); when omitted the service signs it with the
    provided ``signing_secret``. ``on_audit`` receives the manifest and should
    return an audit event id (persisted by the caller).
    """
    fmt = (fmt or "json").strip().lower()
    layer = (layer or "all").strip().lower()
    validate_export_request(fmt, layer, filters)

    # scope = the layer being exported; filters may narrow it further
    scope = str((filters or {}).get("layer") or layer).lower()
    filtered = filter_technology_bom(state, filters) if filters else state

    block = export_technology_bom(filtered, fmt=fmt, layer=scope)
    secret = signing_secret()
    sig = signature or sign_manifest(filtered, block["data"], secret=secret)
    manifest: dict[str, Any] = {
        **block,
        # canonical signature: RFC 7515 compact JWS over the hashed bytes
        "signature_jws": sign_manifest_jws(filtered, block["data"], secret=secret),
        # legacy raw HMAC hex retained for older verifiers
        "signature_hmac": sig,
        "signature_alg": "HS256",
        "audit_event_id": None,
    }
    if on_audit is not None:
        manifest["audit_event_id"] = on_audit(manifest)
    return manifest


def signing_secret() -> str:
    """Best-effort HMAC secret for export signatures (never fails)."""
    import os

    for var in ("EXPORT_SIGNING_SECRET", "GOVERNANCE_SIGNING_SECRET", "SECRET_KEY"):
        val = os.environ.get(var)
        if val:
            return val
    return "zelnx-export-secret-change-me"
