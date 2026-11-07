"""Report/export manifest contract (gap analysis §B).

"Export manifests include schema version, report_id, tenant_id, filters,
generated_at and totals."

Every generated report archive carries a manifest with those six fields.
``tenant_id: null`` is the honest value for a platform-estate export (NULL
tenant = platform estate in the tenancy model) and always travels with an
explicit ``scope``. Filters describe exactly what the export selected —
an export with no narrowing filters says so with an explicit ``{}`` plus the
fixed selection it applied; nothing is implied or invented.
"""

from __future__ import annotations

from datetime import datetime, timezone

MANIFEST_SCHEMA = "cryptoscan.report-manifest/1"

REQUIRED_FIELDS = ("schema_version", "report_id", "tenant_id", "filters",
                   "generated_at", "totals")


def build_manifest(*, schema_version: str, report_id: str, tenant_id,
                   filters: dict, totals: dict, scope: str,
                   generated_at: str | None = None,
                   extra: dict | None = None) -> dict:
    """Build a manifest carrying every §B field. Anything missing is refused."""
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise ValueError("schema_version is required and must be non-empty")
    if not isinstance(report_id, str) or not report_id.strip():
        raise ValueError("report_id is required and must be non-empty")
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("scope is required (platform-estate or tenant id)")
    if tenant_id is not None and not isinstance(tenant_id, str):
        raise ValueError("tenant_id must be a string or null (= platform estate)")
    if not isinstance(filters, dict):
        raise ValueError("filters must be a dict (use {} to state 'no narrowing')")
    if not isinstance(totals, dict) or not totals:
        raise ValueError("totals must be a non-empty dict of counted values")
    for key, value in totals.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"total {key!r} must be a non-negative int; got {value!r}")
    if generated_at is not None and not isinstance(generated_at, str):
        raise ValueError("generated_at must be an ISO string when given")
    stamp = generated_at or datetime.now(timezone.utc).isoformat()
    manifest = {
        "schema_version": schema_version.strip(),
        "report_id": report_id.strip(),
        "tenant_id": tenant_id,
        "scope": scope.strip(),
        "filters": dict(filters),
        "generated_at": stamp,
        "totals": dict(totals),
    }
    if extra:
        for key in REQUIRED_FIELDS:
            if key in extra:
                raise ValueError(f"extra may not redefine required field {key!r}")
        manifest.update(extra)
    return manifest


def verify_manifest(manifest: dict) -> None:
    """Examiner-side check: every §B field is present and shaped. Raises."""
    missing = [field for field in REQUIRED_FIELDS if field not in manifest]
    if missing:
        raise ValueError(f"manifest missing required fields: {missing}")
    build_manifest(
        schema_version=manifest["schema_version"],
        report_id=manifest["report_id"],
        tenant_id=manifest["tenant_id"],
        filters=manifest["filters"],
        totals=manifest["totals"],
        scope=manifest.get("scope", ""),
        generated_at=manifest["generated_at"],
    )


#: File-level verification verdicts (P0-2): a hashed file that is present
#: and matches is VALID; a hash that does not match is DIGEST_MISMATCH; a
#: file the manifest covers but that is not present is ARTIFACT_UNVERIFIABLE
#: — unverifiable, never valid.
VALID = "VALID"
DIGEST_MISMATCH = "DIGEST_MISMATCH"
ARTIFACT_UNVERIFIABLE = "ARTIFACT_UNVERIFIABLE"


def verify_manifest_files(manifest: dict, files: dict) -> dict:
    """Check the manifest's recorded file digests against the actual files.

    ``files`` maps name -> bytes. Every file the manifest records must be
    present and hash to its recorded sha256: a missing artifact is
    unverifiable, not valid. Returns {"verified", "files", "problems"}.
    """
    import hashlib
    verify_manifest(manifest)
    recorded = manifest.get("files") or {}
    if not isinstance(recorded, dict) or not recorded:
        raise ValueError("manifest records no file digests: nothing to verify")
    verdicts: dict[str, str] = {}
    problems: list[dict[str, str]] = []
    for name, meta in sorted(recorded.items()):
        expected = str((meta or {}).get("sha256") or "")
        payload = files.get(name)
        if payload is None:
            verdicts[name] = ARTIFACT_UNVERIFIABLE
            problems.append({"code": "ARTIFACT_UNVERIFIABLE", "file": name,
                             "detail": "the manifest covers this artifact but it "
                                       "is not present: unverifiable, not valid"})
        elif not hmac_compare(expected, hashlib.sha256(payload).hexdigest()):
            verdicts[name] = DIGEST_MISMATCH
            problems.append({"code": "DIGEST_MISMATCH", "file": name,
                             "detail": "the artifact does not hash to its "
                                       "recorded digest"})
        else:
            verdicts[name] = VALID
    verified = not problems
    return {"verified": verified, "files": verdicts, "problems": problems}


def hmac_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(str(a), str(b))
