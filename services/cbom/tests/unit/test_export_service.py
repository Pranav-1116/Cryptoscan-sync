"""Technology BOM Export Service tests (validate -> filter -> generate -> sign -> audit)."""

from __future__ import annotations

from cbom.export_service import (
    ExportValidationError,
    export_bom,
    signing_secret,
    validate_export_request,
)
from cbom.technology_bom import materialize_technology_bom


def _inventory():
    return {
        "applications": [{"id": "app-1", "name": "web", "version": "1.0"}],
        "crypto": [{"id": "c-1", "algorithm": "RSA-2048", "key_size": 2048,
                    "purpose": "TLS", "asset": "Server-1"}],
        "hardware": [{"id": "h-1", "asset_id": "HSM-1", "manufacturer": "ZELNX",
                      "model": "KMS", "device_type": "hsm", "risk_level": "HIGH"}],
        "vendors": [{"name": "ZELNX", "risk_level": "HIGH"}],
        "certificates": [],
        "dependencies": [],
    }


def _state():
    return materialize_technology_bom(_inventory(), environment="prod", state_version=1)


def test_validate_rejects_bad_format():
    try:
        validate_export_request("yaml", "all", None)
        assert False, "should have raised"
    except ExportValidationError:
        pass


def test_validate_rejects_bad_layer():
    try:
        validate_export_request("json", "nope", None)
        assert False, "should have raised"
    except ExportValidationError:
        pass


def test_export_service_signs_and_audits():
    seen = {}

    def on_audit(manifest):
        seen["manifest"] = manifest
        return "audit-1"

    manifest = export_bom(_state(), fmt="json", layer="all", on_audit=on_audit)
    assert manifest["format"] == "json"
    assert len(manifest["integrity_sha256"]) == 64
    assert len(manifest["signature_hmac"]) == 64
    assert manifest["audit_event_id"] == "audit-1"
    assert seen["manifest"]["integrity_sha256"] == manifest["integrity_sha256"]


def test_export_service_filters_and_generates_pdf():
    manifest = export_bom(_state(), fmt="pdf", layer="hbom", filters={"risk_level": "HIGH"})
    assert manifest["mime_type"] == "application/pdf"
    assert isinstance(manifest["data"], bytes)
    assert manifest["data"].startswith(b"%PDF-")
    assert manifest["layer"] == "hbom"
    assert len(manifest["signature_hmac"]) == 64


def test_export_service_deterministic_signature():
    a = export_bom(_state(), fmt="json", layer="sbom")
    b = export_bom(_state(), fmt="json", layer="sbom")
    # deterministic materialization -> identical integrity + signature
    assert a["integrity_sha256"] == b["integrity_sha256"]
    assert a["signature_hmac"] == b["signature_hmac"]


def test_signing_secret_never_empty():
    assert len(signing_secret()) >= 8


def test_export_manifest_carries_rfc7515_jws():
    """A2 conformance: the export manifest's canonical signature is a compact
    JWS over the same bytes as the content hash; legacy HMAC hex retained."""
    from cbom.export_service import (
        canonical_export_payload,
        signing_secret,
    )
    from cbom.signing.jws_signer import verify_compact

    manifest = export_bom(_state(), fmt="json", layer="all")
    jws = manifest["signature_jws"]
    assert jws.count(".") == 2
    # the JWS payload claim IS the canonical export payload (full coverage)
    import base64
    import json as _json

    claim = _json.loads(base64.urlsafe_b64decode(
        jws.split(".")[1] + "=" * (-len(jws.split(".")[1]) % 4)))
    assert claim == _json.loads(canonical_export_payload(_state(), manifest["data"]))
    ok, err = verify_compact(jws, signing_secret(), "HS256")
    assert ok, err

    # tamper -> verification fails
    head, _, sig = jws.rpartition(".")
    ok2, _ = verify_compact(f"{head}.{sig[:-2]}aa", signing_secret(), "HS256")
    assert ok2 is False


def test_export_jws_covers_bytes_bodies():
    """Binary formats (pdf) sign the raw bytes inside the JWS payload claim."""
    from cbom.export_service import sign_manifest_jws, signing_secret
    from cbom.signing.jws_signer import verify_compact

    state = _state()
    manifest = export_bom(state, fmt="pdf", layer="hbom")
    ok, err = verify_compact(manifest["signature_jws"], signing_secret(), "HS256")
    assert ok, err
    # deterministic: same input, same JWS
    again = sign_manifest_jws(state, manifest["data"], secret=signing_secret())
    assert again == manifest["signature_jws"]
