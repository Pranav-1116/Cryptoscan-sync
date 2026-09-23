"""Turn a binary scan into a stored SBOM artifact, once, for every caller.

There are three ways a binary scan can run: synchronously in the API
(``POST /devsecops/binary/scan``), inline in the API process when no queue is
configured (the development fallback), and in a worker process consuming the job
queue. All three must produce the *same* artifact — same manifest fields, same
signature story, same storage layout — or the platform would have three
definitions of "what the report says" and would eventually act on the wrong one.

So the manifest assembly and the storage live here, in the devsecops package both
sides already depend on, and the API router keeps only HTTP concerns (validation,
status codes, response shape). Heavy imports stay inside the functions, matching
the rest of this package, so importing it costs nothing.

Idempotency: pass ``artifact_id`` and the artifact is rewritten under that id
instead of a fresh one. A retried job therefore replaces its own artifact; it
never multiplies it.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: how many scanner findings a manifest carries for the report; the counts in
#: ``findings_by_severity`` are always complete, this is the readable excerpt
MAX_REPORT_FINDINGS = 60
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

#: how many groups/pairs the manifest's fingerprint block carries


# --------------------------------------------------------------------------- #
# manifest fragments
# --------------------------------------------------------------------------- #

def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        counts[severity] = counts.get(severity, 0) + 1
    return dict(sorted(counts.items()))


def finding_excerpt(findings: list[dict], limit: int = MAX_REPORT_FINDINGS) -> list[dict]:
    """The findings a stored report can list, worst first and bounded.

    A manifest that says "1 HIGH" and cannot say which one is not evidence, so the
    scan's findings travel with the artifact. The list is capped and the cap is
    stated, so "12 findings" never silently becomes "12 findings shown".
    """
    rows = sorted(findings, key=lambda row: (
        _SEVERITY_ORDER.get(str(row.get("severity") or "INFO").upper(), 9),
        str(row.get("code") or ""), str(row.get("path") or "")))
    return [{"code": row.get("code"), "severity": str(row.get("severity") or "INFO").upper(),
             "title": row.get("title"), "path": row.get("path"),
             "detail": (str(row.get("detail") or "")[:240] or None)} for row in rows[:limit]]


def fingerprint_summary(result: dict) -> dict | None:
    """The scan's fleet comparison, in a manifest-sized form.

    Counts are complete; the group and pair lists are bounded by
    :data:`devsecops.fingerprints.MAX_GROUPS_IN_SUMMARY`, and the bound is
    reported, so "2 duplicate groups" never hides a third.
    """
    from devsecops.fingerprints import summarise

    clusters = result.get("fingerprints")
    if not clusters:
        return None
    return summarise(clusters)


def yara_summary(result: dict) -> dict | None:
    """What the ruleset was and what it matched, in a manifest-sized form.

    The rule list is bounded but the counts are not, and the ruleset digest is
    always present: a match without the digest of the rules that produced it is
    not reproducible, so the manifest would be asking to be taken on trust.
    """
    summary = result.get("yara") or {}
    if not summary:
        return None
    return {
        "rules": summary.get("rules", 0),
        "private_rules": summary.get("private_rules", 0),
        "digest": summary.get("digest"),
        "sources": (summary.get("sources") or [])[:20],
        "matches": summary.get("matches", 0),
        "files_matched": summary.get("files_matched", 0),
        "by_rule": dict(list((summary.get("by_rule") or {}).items())[:20]),
        "by_severity": summary.get("by_severity") or {},
        "truncated_scans": summary.get("truncated_scans", 0),
        "rule_files_skipped": summary.get("rule_files_skipped", 0),
        "error_count": summary.get("error_count", 0),
        "errors": (summary.get("errors") or [])[:10],
        "note": ("a rule the loader refused did not run; rule errors are findings, so "
                 "an empty match list next to an error is not a clean result"),
    }


def binary_posture(result: dict) -> dict:
    """How the scanned binaries are signed, encrypted, and how much was searched.

    A manifest that says "3 unsigned, 1 encrypted" is actionable; one that only
    lists formats is not. Only formats that *have* a signature story are counted
    as signed/unsigned — an ELF has no signature field and is not "unsigned".
    The constant coverage is reported alongside, because "no AES constants" means
    something different when only 16 bytes of a file were searched — and so is the
    table set that was searched: which tables a scan used, and where the ones an
    installed pack contributed came from.
    """
    signature_formats = {"pe", "macho"}
    signed = unsigned = encrypted = 0
    keys = {"private_keys": 0, "unencrypted_private_keys": 0, "certificates": 0,
            "keystores": 0, "artefacts_with_keys": 0, "test_vectors": 0}
    coverage = {"artefacts_searched": 0, "searched_bytes": 0, "tables_matched": 0,
                "complete_tables": 0, "algorithms": set()}
    for row in result.get("binaries") or []:
        signature = row.get("signature") or {}
        if str(row.get("format")) in signature_formats:
            if signature.get("present"):
                signed += 1
            else:
                unsigned += 1
        if row.get("encrypted"):
            encrypted += 1
        embedded = row.get("embedded_keys") or {}
        if embedded:
            keys["artefacts_with_keys"] += 1
            keys["private_keys"] += int(embedded.get("private_keys") or 0)
            keys["unencrypted_private_keys"] += int(embedded.get("unencrypted_private_keys") or 0)
            keys["certificates"] += int(embedded.get("certificates") or 0)
            keys["keystores"] += int(embedded.get("keystores") or 0)
            keys["test_vectors"] += len(embedded.get("test_vectors") or [])
        summary = row.get("constants") or {}
        if summary:
            if int(summary.get("searched_bytes") or 0):
                coverage["artefacts_searched"] += 1
            coverage["searched_bytes"] += int(summary.get("searched_bytes") or 0)
            coverage["tables_matched"] += int(summary.get("tables_matched") or 0)
            for name in summary.get("named_algorithms") or []:
                coverage["algorithms"].add(str(name))
        coverage["complete_tables"] += int(summary.get("complete_tables") or 0)
    tables = result.get("constant_tables") or {}
    constants = {**coverage, "algorithms": sorted(coverage["algorithms"])}
    if tables:
        # provenance of the search itself: a report that names an algorithm from a
        # pack's table has to say so, and a table that failed to load is a reason
        # the search was narrower than it looks
        constants["tables"] = {
            "builtin": tables.get("builtin", 0),
            "installed": tables.get("installed", 0),
            "total": tables.get("total", 0),
            "digest": tables.get("digest"),
            "sources": tables.get("sources") or [],
            "error_count": len(tables.get("errors") or []),
            "errors": (tables.get("errors") or [])[:5],
        }
    return {"signature_posture": {"signed": signed, "unsigned": unsigned},
            "encrypted_binaries": encrypted, "key_material": keys,
            "constants": constants}


def build_binary_manifest(*, scan: dict[str, Any], result: dict[str, Any], bom: dict[str, Any],
                          cbom: dict[str, Any], fmt: str, target: str, created_by: str,
                          artifact_id: str, payload_sha256: str, compliance: dict[str, Any],
                          pinning: dict[str, Any], feed_supplied: bool = False,
                          recursive: bool = True, include_raw: bool = False,
                          job_id: str | None = None, ruleset_digest: str | None = None) -> dict:
    """Assemble the manifest both the API response and the stored report read.

    ``job_id``/``ruleset_digest`` are recorded when the scan came from the queue
    or ran with rules, so a stored artifact can be traced back to the job that
    produced it and the exact rule text that was applied.
    """
    packages = result.get("packages") or []
    findings = result.get("findings") or []
    artifact_key = f"{artifact_id}.{'cdx.json' if fmt == 'cyclonedx' else 'spdx.json'}"
    # the fleet comparison is reported exactly when it ran; ``None`` here means
    # "this scan was not a fleet scan", not "no duplicates were found"
    fingerprints = fingerprint_summary(result)
    manifest: dict[str, Any] = {
        "artifact_id": artifact_id,
        "kind": "binary",
        "target": target,
        "format": fmt,
        "sha256": payload_sha256,
        "component_count": len(packages) + len(result.get("binaries") or []),
        "binary_count": len(result.get("binaries") or []),
        "crypto_components": len(result.get("libraries") or []),
        "dependency_edges": len(result.get("dependencies") or []),
        "minimum_elements": compliance["score"],
        "compliant": compliance["compliant"],
        "pinned": pinning["pinned"],
        "unpinned": pinning["unpinned"],
        "vulnerability_count": len(result.get("vulnerabilities") or []),
        "feed_supplied": bool(feed_supplied),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": created_by,
        "storage_key": artifact_key,
        "cbom_storage_key": f"{artifact_id}.cbom.json",
        "job_id": job_id,
        "ruleset_digest": ruleset_digest,
        "scan_options": {"kind": "binary", "target": target, "as_image": False,
                         "include_vendored": False, "use_lockfiles": False,
                         "recursive": bool(recursive), "include_raw": bool(include_raw),
                         "format": fmt, "feed_supplied": bool(feed_supplied),
                         "ruleset_digest": ruleset_digest},
        "binary_summary": {
            "files_walked": result.get("files_walked", 0),
            "binaries_scanned": result.get("binaries_scanned", 0),
            "by_format": result.get("by_format") or {},
            "by_arch": result.get("by_arch") or {},
            "crypto_libraries": len(result.get("libraries") or []),
            "algorithms": (result.get("crypto") or {}).get("algorithms") or [],
            "pqc_markers": (result.get("crypto") or {}).get("pqc_markers") or [],
            "ecc_markers": (result.get("crypto") or {}).get("ecc_markers") or [],
            "findings": len(findings),
            "findings_by_severity": severity_counts(findings),
            "findings_excerpt": finding_excerpt(findings),
            "findings_excerpt_limit": MAX_REPORT_FINDINGS,
            "cbom_components": len(cbom.get("components") or []),
            "truncated": bool((result.get("limits") or {}).get("truncated")),
            "embedded_binaries": result.get("embedded_binaries", 0),
            "containers_followed": result.get("containers_followed", 0),
            "containers_refused": result.get("containers_refused", 0),
            "packed_binaries": result.get("packed_binaries", 0),
            "key_material": (result.get("embedded_keys") or {}),
            "fingerprints": fingerprints,
            "yara": yara_summary(result),
            **binary_posture(result),
            "extraction_limits": result.get("extraction_limits") or {},
        },
    }
    return manifest


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #

def artifact_storage():
    """Persistent on-disk SBOM artifact store (survives restarts).

    Shared by the API and the worker: both read ``SBOM_STORAGE_DIR``, so a job
    scanned by a worker is downloadable from the API's endpoints unchanged.
    """
    import tempfile

    from governance.backup_jobs import DiskBackupStorage

    root = os.environ.get("SBOM_STORAGE_DIR", "/var/lib/cryptoscan/sboms")
    try:
        return DiskBackupStorage(root)
    except Exception:  # noqa: BLE001 — an unwritable default root must not lose the artifact
        return DiskBackupStorage(os.path.join(tempfile.gettempdir(), "cryptoscan-sboms"))


def resolve_signing_secret(db: Any = None, *, fallback_secret: str | None = None,
                           settings_repo: Any = None) -> tuple[str | None, str]:
    """(secret, key_id) for signing SBOM manifests.

    Preference order matches the rest of the platform: vault ref > persisted
    settings key > HKDF from the platform master > the process's configured
    ``SECRET_KEY``. The last one is *stable across restarts* — unlike a
    process-random fallback — so ``/verify`` keeps agreeing with artifacts signed
    earlier in the same deployment. Returns ``(None, "unsigned")`` when nothing is
    available, which ``/verify`` reports honestly rather than as a failure.
    """
    import logging

    logger = logging.getLogger(__name__)
    try:
        from governance.keys import signing_secret

        if settings_repo is None and db is not None:
            from db.repositories.settings_repository import SettingsRepository

            settings_repo = SettingsRepository(db)
        return signing_secret(settings_repo=settings_repo), "platform"
    except Exception as exc:  # noqa: BLE001 — signing must never break a scan
        logger.warning("sbom_platform_signing_key_unavailable: %s", exc)
    if fallback_secret and str(fallback_secret).strip():
        return str(fallback_secret).strip(), "settings"
    return None, "unsigned"


def store_binary_artifact(*, scan: dict[str, Any], result: dict[str, Any], bom: dict[str, Any],
                          cbom: dict[str, Any], fmt: str = "cyclonedx", created_by: str,
                          db: Any = None, artifact_id: str | None = None, job_id: str | None = None,
                          feed_supplied: bool = False, recursive: bool = True,
                          include_raw: bool = False,
                          secret: tuple[str | None, str] | None = None) -> dict[str, Any]:
    """Build the manifest for a finished scan and store it, signed.

    This is the one place a binary artifact is written. The synchronous endpoint
    and the worker job both call it, so scanning the same target produces the
    same artifact — same keys, same manifest shape, same signature — whether the
    work happened inside a request or inside a job.

    The artifact id is the caller's choice: a job passes its own id, so a retry
    rewrites its artifact instead of adding a duplicate.

    ``secret`` is the caller's resolved signing material; when it is not given the
    platform order is used (vault ref > persisted settings key > HKDF from the
    master). A caller that also has a configured ``SECRET_KEY`` should pass
    :func:`resolve_signing_secret` with it as the fallback, so the worker signs
    with the key the API verifies with.
    """
    from devsecops.sbom import check_pinning
    from devsecops.sbom_assurance import check_minimum_elements

    payload = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha256 = hashlib.sha256(payload).hexdigest()
    artifact_id = str(artifact_id or uuid.uuid4())
    compliance = check_minimum_elements(bom)
    components = [{"name": row.get("name"),
                   "version": row.get("version") or row.get("declared_spec"),
                   "ecosystem": row.get("manager")} for row in (result.get("packages") or [])]
    pinning = check_pinning(components)
    manifest = build_binary_manifest(
        scan=scan, result=result, bom=bom, cbom=cbom, fmt=fmt,
        target=str(scan.get("target") or ""), created_by=created_by, artifact_id=artifact_id,
        payload_sha256=sha256, compliance=compliance, pinning=pinning,
        feed_supplied=feed_supplied, recursive=recursive, include_raw=include_raw,
        job_id=job_id, ruleset_digest=(result.get("yara") or {}).get("digest"))
    written = write_binary_artifact(
        manifest=manifest, payload=payload, cbom=cbom,
        secret=resolve_signing_secret(db) if secret is None else secret)
    return {"artifact_id": artifact_id, "manifest": manifest, "compliance": compliance,
            "pinning": pinning, "payload_sha256": sha256, "components": components, **written}


def write_binary_artifact(*, manifest: dict[str, Any], payload: bytes, cbom: dict[str, Any],
                          secret: tuple[str | None, str] = (None, "unsigned")) -> dict[str, Any]:
    """Write the SBOM, the CBOM and the manifest under the manifest's own key.

    Signing is applied here, once, so both callers produce the same signature for
    the same manifest. Returns the storage keys for the caller's response.
    """
    key = str(manifest["storage_key"])
    cbom_key = str(manifest["cbom_storage_key"])
    store = artifact_storage()
    store.put(key, payload)
    store.put(cbom_key, json.dumps(cbom, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signing_secret_value, key_id = secret
    if signing_secret_value:
        from devsecops import sbom_scan as sb

        manifest["signature_alg"] = "HMAC-SHA256"
        manifest["signature_key"] = key_id
        manifest["signature"] = sb.sign_manifest(manifest, signing_secret_value)
    store.put_manifest(key, manifest)
    return {"artifact_key": key, "cbom_key": cbom_key, "signed": bool(signing_secret_value),
            "signature_key": key_id}


def audit_artifact(db: Any, actor: str, *, artifact_id: str, target: str, binaries: int,
                   findings: int, sha256: str, job_id: str | None = None) -> None:
    """Record who produced an artifact — a request user or the worker process."""
    if db is None or not actor:
        return
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(actor, "devsecops.binary_scan", target_type="sbom_artifact",
                                 target_id=artifact_id,
                                 detail={"target": target, "binaries": binaries,
                                         "findings": findings, "sha256": sha256[:16],
                                         "job_id": job_id})
    except Exception:  # noqa: BLE001 — an audit failure is logged by the repository, not fatal
        import logging

        logging.getLogger(__name__).warning("binary_scan_audit_failed", exc_info=True)


def scan_target_label(target: str) -> str:
    """A short, stable label for a target path (used for CBOM system names)."""
    return Path(str(target)).expanduser().name or str(target)
