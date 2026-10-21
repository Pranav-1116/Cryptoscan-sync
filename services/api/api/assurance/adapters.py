"""Signed supplier quarantine and deeply bounded OFFLINE profile qualification."""
import base64
import hashlib
from datetime import datetime, timedelta
from fastapi import HTTPException
from db.models.assurance import AssuranceBlob
from db.models.base import utcnow
from db.models.software_supply_chain import SoftwareArtifact
from db.repositories.execution_control import aware
from shared_models.qualified_export import collect_export, engine_fingerprint
from shared_models.software_identity import scope_key
from . import store


def save_signer(db, owner, identifier, body, actor):
    previous = store.latest(db, owner, "supplier_signer", identifier, required=False)
    if previous and previous.payload["public_key_base64"] != body.public_key_base64:
        raise HTTPException(409, "Key rotation requires a new signer identity; never replace a historical key")
    if body.expires_at <= utcnow() and not body.revoked:
        raise HTTPException(422, "Trusted signer expiry must be in the future")
    return store.append(db, owner, "supplier_signer", identifier, body.expected_revision,
                        body.model_dump(mode="json", exclude={"expected_revision"}), actor)


def check(db, owner, payload):
    manifest = payload["manifest"]
    b = store.blob(db, owner, payload["blob_id"])
    problems = []
    artifact = store.exact(db, SoftwareArtifact, owner, payload["artifact_id"])
    if manifest["customer_id"] != (owner or "platform") or manifest["estate_scope"] != scope_key(owner):
        problems.append("WRONG_CUSTOMER")
    if manifest["build_digest"] != artifact.digest:
        problems.append("WRONG_BUILD")
    if manifest["payload_sha256"] != b.sha256:
        problems.append("DIGEST_MISMATCH")
    collected, expiry = (aware(datetime.fromisoformat(manifest[k])) for k in ("collected_at", "expires_at"))
    if not collected <= utcnow() < expiry or collected >= expiry:
        problems.append("STALE")
    signer = store.latest(db, owner, "supplier_signer", payload["signer_id"], required=False)
    if not signer or signer.payload["revoked"] or aware(datetime.fromisoformat(signer.payload["expires_at"])) <= utcnow():
        problems.append("UNTRUSTED_SIGNER")
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        try:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(signer.payload["public_key_base64"], validate=True))
            public.verify(base64.b64decode(payload["signature_base64"], validate=True), store.encoded(manifest))
        except (ValueError, InvalidSignature):
            problems.append("UNTRUSTED_SIGNER")
    return problems


def upload(db, owner, body, actor):
    store.exact(db, SoftwareArtifact, owner, body.artifact_id)
    # A foreign signer is never adopted via the ORM's curated NULL visibility.
    store.latest(db, owner, "supplier_signer", body.signer_id)
    try:
        data = base64.b64decode(body.payload_base64, validate=True)
    except ValueError:
        raise HTTPException(422, "Invalid base64 evidence payload") from None
    if not 0 < len(data) <= 1048576:
        raise HTTPException(413, "Supplier quarantine payload must be 1..1048576 bytes")
    b = AssuranceBlob(tenant_id=owner, scope_key=scope_key(owner), data=data,
                      byte_count=len(data), sha256=hashlib.sha256(data).hexdigest(), created_by=actor)
    db.add(b)
    db.flush()
    value = {"artifact_id": body.artifact_id, "signer_id": body.signer_id, "blob_id": b.id,
             "manifest": body.manifest.model_dump(mode="json"), "signature_base64": body.signature_base64,
             "state": "QUARANTINED", "origin_verified": False, "independent_truth_verified": False}
    problems = check(db, owner, value)
    # No supplier payload is parsed at intake, even if its signer is trusted.
    value["problems"] = problems
    value["origin_verified"] = "UNTRUSTED_SIGNER" not in problems and "DIGEST_MISMATCH" not in problems
    return store.append(db, owner, "supplier_evidence", b.id, 0, value, actor)


def disposition(db, owner, identifier, body, actor, approve):
    row = store.latest(db, owner, "supplier_evidence", identifier)
    if row.payload["state"] == "APPROVED_OFFLINE_JSON" and approve:
        raise HTTPException(409, "Supplier approval is already recorded")
    if approve and actor == row.created_by:
        raise HTTPException(409, "Supplier uploader cannot approve its own evidence")
    value = dict(row.payload)
    problems = check(db, owner, value)
    if approve and not problems:
        try:
            result = collect_export(store.blob(db, owner, value["blob_id"]).data, value["manifest"])
            value["parsed_output_sha256"] = store.digest(result)
            value["parsed_summary"] = {k: v for k, v in result.items() if k != "facts"}
        except (ValueError, TypeError, RecursionError, UnicodeError):
            problems.append("MALFORMED")
    value.update(state="APPROVED_OFFLINE_JSON" if approve and not problems else "QUARANTINED",
                 problems=problems, review_evidence_ref=body.evidence_ref, review_reason=body.reason,
                 reviewed_by=actor, independent_truth_verified=False)
    return store.append(db, owner, "supplier_evidence", identifier, body.expected_revision, value, actor)


def save_adapter(db, owner, identifier, body, actor):
    value = body.model_dump(mode="json", exclude={"expected_revision"})
    value.update(qualification_scope="BOUNDED_OFFLINE_EXPORT_ONLY", live_vendor_supported=False,
                 permission_validation="DECLARED_NOT_LIVE_VERIFIED", rate_retry_validation="DECLARED_NOT_LIVE_EXERCISED")
    return store.append(db, owner, "adapter_manifest", identifier, body.expected_revision, value, actor)


def qualify(db, owner, identifier, body, actor):
    profile = store.latest(db, owner, "adapter_manifest", identifier)
    manifest = profile.payload
    outcomes = {case.expected_outcome for case in body.cases}
    needed = {"COMPLETE", "PARTIAL", "WRONG_CUSTOMER", "WRONG_BUILD", "STALE", "UNTRUSTED_SIGNER", "MALFORMED"}
    if outcomes != needed or len({c.supplier_evidence_id for c in body.cases}) != len(body.cases):
        raise HTTPException(422, "Exercise unique positive/partial and all quarantine cases; a class name is not qualification")
    cases = []
    for case in body.cases:
        evidence = store.latest(db, owner, "supplier_evidence", case.supplier_evidence_id)
        signed = evidence.payload["manifest"]
        if any(signed[k] != manifest[k] for k in ("vendor", "product", "version", "profile", "format")):
            raise HTTPException(409, "Qualification case is for a different vendor/product/version/profile")
        problems = check(db, owner, evidence.payload)
        result = None
        actual = problems[0] if problems else None
        if not actual:
            try:
                result = collect_export(store.blob(db, owner, evidence.payload["blob_id"]).data, signed)
                actual = "COMPLETE" if result["collection_complete"] else "PARTIAL"
            except (ValueError, TypeError, RecursionError, UnicodeError):
                actual = "MALFORMED"
        actual_sha = store.digest(result) if result else None
        fields = sorted({f["kind"] for f in result["facts"]}) if result else []
        positive = actual in {"COMPLETE", "PARTIAL"}
        passed = (actual == case.expected_outcome and (not positive or (
            evidence.payload["state"] == "APPROVED_OFFLINE_JSON" and case.expected_output_sha256 == actual_sha
            and set(fields) <= set(manifest["collected_fields"]))))
        cases.append({"supplier_evidence_id": evidence.subject_id, "evidence_sha256": evidence.payload_sha256,
                      "input_sha256": signed["payload_sha256"], "expected": case.expected_outcome,
                      "actual": actual, "expected_output_sha256": case.expected_output_sha256,
                      "actual_output_sha256": actual_sha, "collected_fields": fields, "passed": passed})
    old = store.latest(db, owner, "adapter_qualification", identifier, required=False)
    return store.append(db, owner, "adapter_qualification", identifier, old.revision if old else 0,
        {"manifest_sha256": profile.payload_sha256, "manifest_revision": profile.revision, "engine_sha256": engine_fingerprint(),
         "qualified_at": utcnow().isoformat(), "expires_at": (utcnow() + timedelta(days=30)).isoformat(),
         "scope": "BOUNDED_OFFLINE_EXPORT_ONLY", "passed": all(c["passed"] for c in cases),
         "live_vendor_supported": False, "cases": cases, "evidence_ref": body.evidence_ref,
         "not_qualified": ["live authentication/permissions", "vendor API pagination", "429/retry/load behavior", "named vendor product integration"]}, actor)


def adapter_status(db, owner, identifier):
    manifest = store.latest(db, owner, "adapter_manifest", identifier)
    qualification = store.latest(db, owner, "adapter_qualification", identifier, required=False)
    valid = bool(qualification and qualification.payload["passed"]
        and qualification.payload.get("engine_sha256") == engine_fingerprint()
        and qualification.payload["manifest_sha256"] == manifest.payload_sha256
        and aware(datetime.fromisoformat(qualification.payload["expires_at"])) > utcnow())
    if valid:
        # Revocation/expiry after qualification cannot leave a stale support flag.
        for case in qualification.payload["cases"]:
            if case["actual"] in {"COMPLETE", "PARTIAL"}:
                current = store.latest(db, owner, "supplier_evidence", case["supplier_evidence_id"])
                if current.payload["state"] != "APPROVED_OFFLINE_JSON" or check(db, owner, current.payload):
                    valid = False
                    break
    return {"manifest": store.public(manifest), "qualification": store.public(qualification) if qualification else None,
            "offline_profile_exercised": valid, "live_vendor_supported": False,
            "support_status": "OFFLINE_PROFILE_EXERCISED" if valid else "NOT_QUALIFIED"}


def observations(db, owner, adapter_id, evidence_id):
    status = adapter_status(db, owner, adapter_id)
    if not status["offline_profile_exercised"]:
        raise HTTPException(409, "Exact offline profile has no current exercised qualification")
    evidence = store.latest(db, owner, "supplier_evidence", evidence_id)
    profile = status["manifest"]["payload"]
    signed = evidence.payload["manifest"]
    if any(profile[k] != signed[k] for k in ("vendor", "product", "version", "profile", "format")):
        raise HTTPException(409, "Supplier evidence does not match this exact exercised profile")
    if evidence.payload["state"] != "APPROVED_OFFLINE_JSON" or check(db, owner, evidence.payload):
        raise HTTPException(409, "Supplier evidence is quarantined, stale, revoked or untrusted")
    result = collect_export(store.blob(db, owner, evidence.payload["blob_id"]).data, signed)
    if not {f["kind"] for f in result["facts"]} <= set(profile["collected_fields"]):
        raise HTTPException(409, "Export fields exceed the exercised manifest")
    return {**result, "source_evidence_id": evidence_id, "source_sha256": evidence.payload_sha256,
            "artifact_id": evidence.payload["artifact_id"], "build_digest": signed["build_digest"],
            "qualification_id": status["qualification"]["id"], "automatic_identity_joins": False,
            "live_vendor_supported": False, "independent_truth_verified": False}
