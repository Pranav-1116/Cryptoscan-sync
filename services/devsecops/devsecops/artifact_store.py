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

Tenancy: an artifact belongs to the tenant that asked for it. Its objects are
written under that tenant's own prefix and sealed with that tenant's own key
(:mod:`devsecops.artifact_crypto`), so a backup of one organization's storage
prefix is not readable with another's key — and reading an artifact back checks
the bucket before the bytes. An install with no tenant context uses the platform
estate (``platform``), which is also where artifacts written before this existed
live, so nothing on disk became unreadable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from devsecops import artifact_crypto

logger = logging.getLogger(__name__)

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


def artifact_tenant_bucket(tenant_id: Any) -> str:
    """The storage/int-key scope for a tenant (blank -> the platform estate)."""
    return artifact_crypto.normalize_tenant(tenant_id)


def build_binary_manifest(*, scan: dict[str, Any], result: dict[str, Any], bom: dict[str, Any],
                          cbom: dict[str, Any], fmt: str, target: str, created_by: str,
                          artifact_id: str, payload_sha256: str, compliance: dict[str, Any],
                          pinning: dict[str, Any], feed_supplied: bool = False,
                          recursive: bool = True, include_raw: bool = False,
                          job_id: str | None = None, ruleset_digest: str | None = None,
                          tenant_id: str | None = None, at_rest: dict[str, Any] | None = None,
                          bom_documents: dict[str, dict[str, Any]] | None = None) -> dict:
    """Assemble the manifest both the API response and the stored report read.

    ``job_id``/``ruleset_digest`` are recorded when the scan came from the queue
    or ran with rules, so a stored artifact can be traced back to the job that
    produced it and the exact rule text that was applied.

    ``tenant_id`` scopes the storage keys and is recorded on the manifest, and
    ``at_rest`` records how the payload was sealed (algorithm, key id, key
    source) so the answer to "is this encrypted?" travels with the artifact
    rather than living in a runbook.
    """
    packages = result.get("packages") or []
    findings = result.get("findings") or []
    bucket = artifact_tenant_bucket(tenant_id)
    artifact_key = f"tenants/{bucket}/{artifact_id}.{'cdx.json' if fmt == 'cyclonedx' else 'spdx.json'}"
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
        # PARTIAL is a first-class result, not a storage failure.  Consumers can
        # gate on this field without mistaking an incomplete static walk for a
        # clean release.
        "result_state": str(scan.get("result_state") or "COMPLETE"),
        "feed_supplied": bool(feed_supplied),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": created_by,
        "tenant_id": str(tenant_id) if tenant_id else None,
        "tenant_bucket": bucket,
        "at_rest": at_rest or {"algorithm": "none", "encrypted": False,
                               "note": "sealing was not recorded for this artifact"},
        "storage_key": artifact_key,
        "cbom_storage_key": f"tenants/{bucket}/{artifact_id}.cbom.json",
        # where the evidence lives, and whether that was allowed to be ephemeral:
        # a manifest that cannot answer this cannot support a restore or an audit
        "storage": storage_status(),
        # Additional binary projections (HBOM/NBOM/VBOM/vulnerability BOM and
        # the unified technology view) are sidecars, not silently folded into
        # the SBOM document. Each carries its own digest and storage key.
        "bom_documents": bom_documents or {},
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
            "result_state": str(scan.get("result_state") or "COMPLETE"),
            "truncated": bool((result.get("limits") or {}).get("truncated")),
            "limits": result.get("limits") or {},
            "parser_states": {
                state: sum(1 for row in (result.get("binaries") or [])
                           if str(row.get("parser_state") or "UNKNOWN") == state)
                for state in ("COMPLETE", "PARTIAL", "MALFORMED", "UNSUPPORTED", "REFUSED_BY_LIMIT", "UNKNOWN")
            },
            "evidence_model_version": next(
                (row.get("evidence_model_version") for row in (result.get("binaries") or [])
                 if row.get("evidence_model_version")), None),
            "provenance_graph": {
                "nodes": len((result.get("provenance_graph") or {}).get("nodes") or []),
                "edges": len((result.get("provenance_graph") or {}).get("edges") or []),
                "truncated": bool((result.get("provenance_graph") or {}).get("truncated")),
            },
            "embedded_binaries": result.get("embedded_binaries", 0),
            "containers_followed": result.get("containers_followed", 0),
            "containers_refused": result.get("containers_refused", 0),
            "packed_binaries": result.get("packed_binaries", 0),
            "key_material": (result.get("embedded_keys") or {}),
            "fingerprints": fingerprints,
            "yara": yara_summary(result),
            **binary_posture(result),
            "extraction_limits": result.get("extraction_limits") or {},
            "bom_types": ["SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "VULNERABILITY_BOM", "TECHNOLOGY_BOM"],
            "bom_documents": bom_documents or {},
        },
    }
    return manifest


# --------------------------------------------------------------------------- #
# database read model
# --------------------------------------------------------------------------- #

MAX_INDEXED_BINARY_OBSERVATIONS = 5000
MAX_INDEXED_LIST_ITEMS = 120
MAX_INDEXED_STRING = 2000
_REDACTED_INDEX_KEYS = {"private_key", "private_keys", "secret", "secrets", "key_material",
                        "material", "raw_bytes", "payload", "certificate_der", "signature_blob"}


def _bounded_index_json(value: Any, depth: int = 0) -> Any:
    """Bound nested parser JSON before it enters a query/read model."""
    if depth > 5:
        return "[truncated]"
    if isinstance(value, str):
        return value[:MAX_INDEXED_STRING]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        output = {}
        for key, item in list(value.items())[:MAX_INDEXED_LIST_ITEMS]:
            key_text = str(key)
            normalized_key = "".join(char for char in key_text.lower() if char.isalnum() or char == "_")
            if key_text.lower() in _REDACTED_INDEX_KEYS or normalized_key in {
                    "privatekey", "privatekeys", "keymaterial", "secretmaterial"}:
                continue
            output[key_text[:200]] = _bounded_index_json(item, depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [_bounded_index_json(item, depth + 1) for item in value[:MAX_INDEXED_LIST_ITEMS]]
    return str(value)[:MAX_INDEXED_STRING]


def _indexed_signature(value: Any) -> dict[str, Any] | None:
    """Keep signature posture metadata, never a certificate/signature blob."""
    if not isinstance(value, dict):
        return None
    allowed = ("present", "type", "entries", "size", "hash_type", "flags",
               "team_id", "identifier", "signing_identifier", "verification",
               "note", "hardened_runtime", "ad_hoc")
    return _bounded_index_json({key: value[key] for key in allowed if key in value})


def _indexed_observation(row: dict[str, Any], *, artifact_id: str,
                         scan_record_id: str, tenant_id: str | None) -> dict[str, Any]:
    """Project one parser record into a bounded, redacted database row."""
    parsed = row.get("parsed")
    parser_note = str(row.get("parse_error") or row.get("parse_note") or "").lower()
    if parsed is False:
        if row.get("unsupported") or row.get("refused") or any(
                token in parser_note for token in ("unrecognised", "unsupported", "refused")):
            state = "unsupported"
        else:
            state = "partial" if parser_note else "unknown"
    elif parsed is True:
        state = "observed"
    else:
        state = "unknown"
    # The normalized model is more precise than the legacy projection, but keep
    # the API's lower-case states stable for existing clients.
    explicit_state = str(row.get("parser_state") or "").upper()
    state = {"COMPLETE": "observed", "PARTIAL": "partial", "MALFORMED": "partial",
             "UNSUPPORTED": "unsupported", "REFUSED_BY_LIMIT": "refused",
             "UNKNOWN": "unknown"}.get(explicit_state, state)
    metadata_keys = ("type", "machine", "bits", "endianness", "subsystem", "libraries",
                     "imports", "import_symbols", "delay_imports", "delay_import_symbols",
                     "exports", "sections", "section_count", "library_count", "parse_note",
                     "parse_error", "strings_sampled", "packer", "encrypted", "encryption_id",
                     "minimum_os", "platform", "framework", "name", "file_name", "size",
                     "android", "ios", "java", "python", "dotnet", "packages_inside",
                     "containers_followed", "containers_refused", "go_build_info", "build_info",
                     "parser_state", "evidence_model_version", "runtime_behavior_proven",
                     "runtime_behavior_caveat", "identity", "evidence", "member_offset")
    metadata = {key: row[key] for key in metadata_keys if key in row}
    for key in ("libraries", "imports", "import_symbols", "delay_imports",
                "delay_import_symbols", "exports", "sections"):
        if isinstance(metadata.get(key), list):
            metadata[key] = metadata[key][:MAX_INDEXED_LIST_ITEMS]
    crypto = row.get("crypto")
    if isinstance(crypto, dict):
        crypto = {key: crypto.get(key) for key in (
            "libraries", "algorithms", "algorithm_evidence", "suppressed_libraries",
            "pqc_markers", "ecc_markers", "quantum_vulnerable", "weak_primitives",
            "string_evidence", "constants_summary") if key in crypto}
    coverage = {
        key: row[key] for key in ("crypto_constants", "strings_sampled", "fingerprints",
                                  "identity", "parser_state", "evidence_model_version")
        if key in row
    }
    if isinstance(coverage.get("fingerprints"), dict):
        coverage["fingerprints"] = {
            key: coverage["fingerprints"].get(key) for key in (
                "build_id", "build_fingerprint", "code_sha256", "imports_sha256")
            if key in coverage["fingerprints"]
        }
    findings = row.get("findings") or []
    return {
        "tenant_id": tenant_id,
        "scan_record_id": scan_record_id,
        "artifact_id": artifact_id,
        "path": str(row.get("path") or row.get("name") or "")[:MAX_INDEXED_STRING],
        "format": str(row.get("format") or "raw")[:32],
        "arch": str(row.get("arch") or row.get("machine") or "")[:100] or None,
        "sha256": str(row.get("sha256"))[:64] if row.get("sha256") else None,
        "parsed": parsed,
        "evidence_state": state,
        "derived_from": str(row.get("derived_from"))[:MAX_INDEXED_STRING] if row.get("derived_from") else None,
        "depth": row.get("depth"),
        "crypto": _bounded_index_json(crypto),
        "hardening": _bounded_index_json(row.get("hardening")) if isinstance(row.get("hardening"), dict) else None,
        "signature": _indexed_signature(row.get("signature")),
        "coverage": _bounded_index_json(coverage),
        "findings": _bounded_index_json(findings[:40]),
        "parser_metadata": _bounded_index_json(metadata),
    }


def persist_binary_scan_index(*, db: Any, artifact_id: str, scan: dict[str, Any],
                              result: dict[str, Any], manifest: dict[str, Any],
                              created_by: str, tenant_id: str | None = None) -> bool:
    """Upsert the queryable binary read model inside a savepoint.

    Artifact storage is authoritative and must not fail because an optional
    index is unavailable during a rolling migration. A savepoint isolates an
    index failure from the caller's audit/CBOM transaction; the returned boolean
    is surfaced to operators rather than pretending the database was updated.
    """
    if db is None:
        return False
    try:
        from db.models.binary_scan import BinaryScanObservation, BinaryScanRecord

        with db.begin_nested():
            record_query = db.query(BinaryScanRecord).filter(
                BinaryScanRecord.artifact_id == str(artifact_id))
            record_query = record_query.filter(
                BinaryScanRecord.tenant_id.is_(None) if tenant_id is None
                else BinaryScanRecord.tenant_id == str(tenant_id))
            record = record_query.first()
            if record is None:
                record = BinaryScanRecord(artifact_id=str(artifact_id))
                db.add(record)
            record.tenant_id = tenant_id
            record.job_id = manifest.get("job_id")
            record.target = str(manifest.get("target") or scan.get("target") or "")
            record.format = str(manifest.get("format") or "cyclonedx")
            record.sha256 = str(manifest.get("sha256") or "")
            record.status = str(scan.get("result_state") or "COMPLETE").upper()
            record.created_by = str(created_by or "system")
            record.files_walked = int(result.get("files_walked") or 0)
            record.binaries_scanned = int(result.get("binaries_scanned") or 0)
            record.findings_count = len(result.get("findings") or [])
            record.summary = _bounded_index_json(manifest.get("binary_summary") or {})
            summary = manifest.get("binary_summary") or {}
            record.coverage = _bounded_index_json({
                "result_state": scan.get("result_state") or "COMPLETE",
                "parser_states": summary.get("parser_states") or {},
                "provenance_graph": summary.get("provenance_graph") or {},
                "constants": summary.get("constants") or {},
                "evidence_model_version": summary.get("evidence_model_version"),
            })
            record.limits = _bounded_index_json(result.get("limits") or result.get("extraction_limits") or {})
            # BaseModel generates the UUID at flush time; observations reference it.
            db.flush()

            observation_query = db.query(BinaryScanObservation).filter(
                BinaryScanObservation.artifact_id == str(artifact_id))
            observation_query = observation_query.filter(
                BinaryScanObservation.tenant_id.is_(None) if tenant_id is None
                else BinaryScanObservation.tenant_id == str(tenant_id))
            observation_query.delete(synchronize_session=False)
            rows = (result.get("binaries") or [])[:MAX_INDEXED_BINARY_OBSERVATIONS]
            for row in rows:
                db.add(BinaryScanObservation(**_indexed_observation(
                    row, artifact_id=str(artifact_id), scan_record_id=record.id,
                    tenant_id=tenant_id)))
            record.observations_count = len(rows)
            record.observations_truncated = len(result.get("binaries") or []) > len(rows)
            db.flush()
        return True
    except Exception as exc:  # noqa: BLE001 — optional read model must not lose an artifact
        logger.warning("binary_scan_index_persist_failed: %s", exc, extra={
            "error_type": type(exc).__name__, "error": str(exc)[:300],
            "artifact_id": str(artifact_id)[:64]})
        return False


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #

#: Where an unconfigured install writes. Node-local, so it is durable only when
#: the operator makes it so (a mounted volume) and says nothing about backups.
DEFAULT_SBOM_ROOT = "/var/lib/cryptoscan/sboms"

#: Environments where the store's own durability is the operator's problem.
_EPHEMERAL_ENVIRONMENTS = frozenset({"test", "dev", "development", "local", "ci"})


class StorageRefused(RuntimeError):
    """This environment may not hold evidence in the store that is available.

    Raised instead of silently writing to a temporary directory: the review's
    blocker is precisely that a fallback turns "we have the evidence" into "we
    had it until the container restarted".
    """


def _storage_environment(environment: str | None = None) -> str:
    env = environment or os.environ.get("ENVIRONMENT") or os.environ.get("CRYPTOSCAN_ENV")
    return str(env or "development").strip().lower()


def _store_probe(root: Path) -> tuple[bool, bool, str | None]:
    """Write, read back and hash a probe object: ``(writable, integrity, error)``.

    "Integrity verified on write" is a claim, so it is tested rather than assumed:
    a store that returns different bytes than it was given is not a store this
    platform will put production evidence into.
    """
    probe = root / ".cryptoscan-store-probe"
    try:
        root.mkdir(parents=True, exist_ok=True)
        payload = b"cryptoscan-store-probe"
        probe.write_bytes(payload)
        returned = probe.read_bytes()
        probe.unlink(missing_ok=True)
        return True, returned == payload, None
    except Exception as exc:  # noqa: BLE001 — an unusable root is reported, not raised here
        return False, False, f"{type(exc).__name__}: {exc}"


def storage_status(environment: str | None = None) -> dict[str, Any]:
    """What the store is, and whether this environment may use it.

    The manifest records this, so an auditor can see *where* an artifact was
    written and whether that was allowed, rather than inferring it from a path.
    """
    from devsecops.sbom_evidence import storage_policy

    env = _storage_environment(environment)
    configured = str(os.environ.get("SBOM_STORAGE_DIR") or "").strip()
    root = Path(configured or DEFAULT_SBOM_ROOT)
    writable, integrity, error = _store_probe(root)
    backup = str(os.environ.get("SBOM_STORAGE_BACKUP_DIR") or "").strip() or None
    retention_raw = str(os.environ.get("SBOM_RETENTION_DAYS") or "").strip()
    retention = int(retention_raw) if retention_raw.isdigit() and int(retention_raw) > 0 else None
    durable = bool(configured)
    policy = storage_policy(
        environment=env, configured_store=configured or None, writable=writable,
        durable=durable, backup=backup, retention_days=retention,
        integrity_verified=integrity)
    return {
        "environment": env,
        "root": str(root),
        "configured": bool(configured),
        "writable": writable,
        "durable": durable,
        "integrity_verified": integrity,
        "backup": bool(backup),
        "retention_days": retention,
        "verdict": policy["verdict"] if env not in _EPHEMERAL_ENVIRONMENTS
        else ("ALLOW" if writable else "ALLOW_EPHEMERAL"),
        "mode": policy["mode"],
        "reasons": policy["reasons"],
        "error": error,
    }


def artifact_storage(environment: str | None = None):
    """Persistent on-disk SBOM artifact store (survives restarts).

    Shared by the API and the worker: both read ``SBOM_STORAGE_DIR``, so a job
    scanned by a worker is downloadable from the API's endpoints unchanged.

    **A temporary fallback is a production refusal.** Outside dev/test/CI, an
    unwritable or unconfigured store raises :class:`StorageRefused` naming what
    is missing — backup target (``SBOM_STORAGE_BACKUP_DIR``), retention
    (``SBOM_RETENTION_DAYS``) and integrity — instead of writing evidence to a
    directory that disappears with the container. Development keeps the old
    convenience, and :func:`storage_status` records which of the two happened.
    """
    import tempfile

    from governance.backup_jobs import DiskBackupStorage

    status = storage_status(environment)
    if status["verdict"] == "REFUSE":
        raise StorageRefused(
            "refusing to store SBOM evidence in "
            f"{status['environment']}: " + "; ".join(status["reasons"]))
    if status["writable"]:
        return DiskBackupStorage(status["root"])
    if status["environment"] not in _EPHEMERAL_ENVIRONMENTS:
        raise StorageRefused(
            f"the artifact store at {status['root']} is not usable: {status['error']}")
    logger.warning("sbom_artifact_store_ephemeral: %s", status["error"])
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
                          secret: tuple[str | None, str] | None = None,
                          tenant_id: str | None = None,
                          encryption_secret: str | None = None,
                          bom_bundle: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
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

    ``tenant_id`` is the artifact's owner: the payload and the CBOM are sealed
    with that tenant's key and written under its prefix, and the manifest records
    the tenant and the sealing, before it is signed — so the signature covers the
    statement about how the artifact was protected, not just its content. With no
    key material configured the objects are written plain and the manifest says
    ``algorithm: none``: a downgrade that is recorded is one an auditor can find,
    an unrecorded one is not.
    """
    from devsecops.sbom import check_pinning
    from devsecops.sbom_assurance import check_minimum_elements

    payload = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # the digest and the signature stay over the *plaintext*: verification, gating
    # and diffing must not change because the bytes at rest are sealed
    sha256 = hashlib.sha256(payload).hexdigest()
    artifact_id = str(artifact_id or uuid.uuid4())
    scope = artifact_tenant_bucket(tenant_id)
    sealed_payload, at_rest = artifact_crypto.encrypt_blob(
        payload, tenant_id=scope, secret=encryption_secret)
    cbom_bytes = json.dumps(cbom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sealed_cbom, _ = artifact_crypto.encrypt_blob(cbom_bytes, tenant_id=scope,
                                                 secret=encryption_secret)
    # Every projection is sealed with the same tenant key as the SBOM/CBOM. The
    # manifest exposes only metadata and digests; readers must pass through the
    # tenant-scoped sidecar endpoint.
    sidecar_blobs: dict[str, bytes] = {}
    sidecar_documents: dict[str, dict[str, Any]] = {}
    for bom_name, document in (bom_bundle or {}).items():
        if bom_name in {"sbom", "cbom", "vendor_bom", "vulbom"} or not isinstance(document, dict) or not document:
            continue
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sealed, sidecar_rest = artifact_crypto.encrypt_blob(raw, tenant_id=scope,
                                                            secret=encryption_secret)
        key_name = str(bom_name).replace("_", "-")
        sidecar_key = f"tenants/{scope}/{artifact_id}.{key_name}.json"
        sidecar_blobs[sidecar_key] = sealed
        sidecar_documents[bom_name] = {
            "storage_key": sidecar_key,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "encrypted": bool(sidecar_rest.get("encrypted")),
            "format": document.get("bomFormat", "json"),
            "component_count": len(document.get("components") or []),
            "vulnerability_count": len(document.get("vulnerabilities") or []),
        }
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
        job_id=job_id, ruleset_digest=(result.get("yara") or {}).get("digest"),
        tenant_id=tenant_id, at_rest=at_rest, bom_documents=sidecar_documents)
    written = write_binary_artifact(
        manifest=manifest, payload=sealed_payload, cbom_blob=sealed_cbom,
        bom_blobs=sidecar_blobs,
        secret=resolve_signing_secret(db) if secret is None else secret)
    database_indexed = persist_binary_scan_index(
        db=db, artifact_id=artifact_id, scan=scan, result=result, manifest=manifest,
        created_by=created_by, tenant_id=str(tenant_id) if tenant_id else None)
    return {"artifact_id": artifact_id, "manifest": manifest, "compliance": compliance,
            "pinning": pinning, "payload_sha256": sha256, "components": components,
            "database_indexed": database_indexed, **written}


def write_binary_artifact(*, manifest: dict[str, Any], payload: bytes, cbom_blob: bytes,
                          bom_blobs: dict[str, bytes] | None = None,
                          secret: tuple[str | None, str] = (None, "unsigned")) -> dict[str, Any]:
    """Write the SBOM, the CBOM and the manifest under the manifest's own key.

    ``payload``/``cbom_blob`` arrive already sealed (see
    :func:`store_binary_artifact`), so this function never decides the protection
    story — it writes what the manifest it is given says was written. Signing is
    applied here, once, so both callers produce the same signature for the same
    manifest. The manifest itself stays readable on disk on purpose: it is the
    artifact's index (it is what a listing, a gate and a diff read without a
    key), which is why it carries counts, labels and an excerpt rather than the
    whole document.
    """
    key = str(manifest["storage_key"])
    cbom_key = str(manifest["cbom_storage_key"])
    store = artifact_storage()
    store.put(key, payload)
    store.put(cbom_key, cbom_blob)
    for sidecar_key, sidecar_blob in (bom_blobs or {}).items():
        store.put(str(sidecar_key), sidecar_blob)
    signing_secret_value, key_id = secret
    if signing_secret_value:
        from devsecops import sbom_scan as sb

        manifest["signature_alg"] = "HMAC-SHA256"
        manifest["signature_key"] = key_id
        manifest["signature"] = sb.sign_manifest(manifest, signing_secret_value)
    store.put_manifest(key, manifest)
    return {"artifact_key": key, "cbom_key": cbom_key, "signed": bool(signing_secret_value),
            "signature_key": key_id}


# --------------------------------------------------------------------------- #
# reading back: one tenant at a time
# --------------------------------------------------------------------------- #

def manifest_tenant(manifest: dict[str, Any]) -> str:
    """Which bucket an artifact belongs to.

    A manifest written before tenancy recorded nothing, and lands in the platform
    estate — the same bucket an install without tenants uses, so a single-tenant
    deployment's history stays readable after the upgrade.
    """
    raw = manifest.get("tenant_bucket") or manifest.get("tenant_id")
    try:
        return artifact_tenant_bucket(raw)
    except artifact_crypto.ArtifactCryptoError:  # noqa: PERF203 — a bad stored value is not a scope
        return artifact_crypto.PLATFORM_TENANT


def visible_manifests(store: Any, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Every manifest this tenant may see (its own bucket, nothing else)."""
    scope = artifact_tenant_bucket(tenant_id)
    return [row for row in store.list_manifests() if manifest_tenant(row) == scope]


def find_manifest(store: Any, artifact_id: str, *, tenant_id: str | None = None,
                  ) -> dict[str, Any] | None:
    """The tenant's manifest for an id — another tenant's artifact is *absent*.

    Not "forbidden": an id that exists elsewhere is not something this caller
    needs to learn, and a 403 would say it exists.
    """
    scope = artifact_tenant_bucket(tenant_id)
    for row in store.list_manifests():
        if str(row.get("artifact_id")) == artifact_id and manifest_tenant(row) == scope:
            return row
    return None


def read_artifact_blob(store: Any, manifest: dict[str, Any], *, tenant_id: str | None = None,
                       encryption_secret: str | None = None,
                       label: str = "stored SBOM") -> tuple[bytes, dict[str, Any]]:
    """The plaintext bytes of a stored artifact, for its tenant.

    Raises :class:`devsecops.artifact_crypto.ArtifactCryptoError` when the object
    cannot be opened with this tenant's key (``wrong_tenant``/``no_key``/
    ``tampered``/``malformed``), so a caller can answer with the reason instead of
    an empty document.
    """
    scope = artifact_tenant_bucket(tenant_id)
    owner = manifest_tenant(manifest)
    if owner != scope:
        raise artifact_crypto.ArtifactCryptoError(
            "wrong_tenant",
            f"{label} belongs to tenant {owner!r}, not {scope!r} — tenants read their own artifacts")
    key = manifest.get("storage_key")
    if not key:
        raise artifact_crypto.ArtifactCryptoError("malformed", f"{label} has no storage key")
    blob = store.get(str(key))
    return artifact_crypto.decrypt_blob(blob, tenant_id=scope, secret=encryption_secret, label=label)


def read_artifact_cbom(store: Any, manifest: dict[str, Any], *, tenant_id: str | None = None,
                       encryption_secret: str | None = None) -> tuple[bytes, dict[str, Any]]:
    """The plaintext CBOM of a stored artifact, for its tenant."""
    key = manifest.get("cbom_storage_key")
    if not key:
        raise artifact_crypto.ArtifactCryptoError("malformed", "the artifact has no CBOM key")
    scoped = dict(manifest, storage_key=key)
    return read_artifact_blob(store, scoped, tenant_id=tenant_id,
                              encryption_secret=encryption_secret, label="stored CBOM")


def at_rest_status(tenant_id: str | None = None, *, secret: str | None = None) -> dict[str, Any]:
    """What a store would do for this tenant — for a status/health answer."""
    return artifact_crypto.at_rest_report(tenant_id, secret)


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
