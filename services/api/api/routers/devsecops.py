"""DevSecOps pipeline API: container CVE scan, K8s/IaC misconfig, cloud CIS
posture, SBOM import/export + pinning, and outbound integrations
(ITSM/SIEM/message-bus/chat). All checks are deterministic (no AI).

The active outbound connectors (Splunk HEC, Elastic, ServiceNow, Jira, Slack,
Teams, Kafka/RabbitMQ) are driven from stored integration credentials but the
HTTP/producer transport is injected at runtime; destinations are validated by
the existing SSRF-safe webhook guard. In this reference surface the tests
exercise the payload builders with an injected transport.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles
from db.repositories.user_repository import UserRepository

# the manifest/store half of a binary artifact lives in the devsecops package:
# the same functions serve this router (synchronous scan) and the worker process
# (queued job), so both produce one artifact, not two dialects of one
from devsecops.artifact_store import (
    MAX_REPORT_FINDINGS,
    audit_artifact,
    binary_posture as _binary_posture,
    build_binary_manifest,
    finding_excerpt as _finding_excerpt,
    resolve_signing_secret,
    severity_counts as _severity_counts,
    store_binary_artifact,
)

router = APIRouter(prefix="/devsecops", tags=["devsecops"])


def _enforce_airgap_writable(operation: str) -> None:
    """Block mutating/networked operations when AIRGAP_MODE is on (fail-closed)."""
    import os

    if os.environ.get("AIRGAP_MODE", "false").lower() not in ("1", "true", "yes", "on"):
        return
    from governance import airgap

    allow = tuple(a.strip() for a in os.environ.get("AIRGAP_ALLOWLIST", "").split(",") if a.strip())
    try:
        airgap.enforce_operation(operation, airgap.AirgapPolicy(airgap=True, allowlist=allow))
    except airgap.AirgapReadOnlyError as exc:
        raise HTTPException(status_code=423, detail=str(exc))  # 423 Locked


# ------------------------------------------------------------- 13. image --- #
class ContainerScanRequest(BaseModel):
    packages: list[dict] = Field(default_factory=list)
    feed: list[dict] = Field(default_factory=list)
    dockerfile: str | None = None


@router.post("/container-scan")
def container_scan(body: ContainerScanRequest,
                   user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.container_scan import scan_image

    return scan_image(packages=body.packages, feed=body.feed, dockerfile=body.dockerfile)


# --------------------------------------------------------------- 14. k8s --- #
class K8sScanRequest(BaseModel):
    manifests_yaml: str = Field(..., min_length=1)


@router.post("/k8s-manifest-scan")
def k8s_scan(body: K8sScanRequest,
             user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.k8s_rules import scan_manifests

    try:
        return scan_manifests(body.manifests_yaml)
    except Exception as exc:  # YAML parse failure is a client error
        raise HTTPException(status_code=400, detail=f"manifest parse failed: {exc}")


# ----------------------------------------------------------- 15. posture --- #
class PostureRequest(BaseModel):
    resources: list[dict]


@router.post("/cloud-posture")
def cloud_posture(body: PostureRequest,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.cloud_posture import evaluate

    result = evaluate(body.resources)
    if result["total_findings"]:
        UserRepository(db).audit(user, "devsecops.cloud_posture", target_type="posture",
                                 target_id="cis-scan",
                                 detail={"resources": result["resources_scanned"],
                                         "findings": result["total_findings"],
                                         "by_severity": result["by_severity"]})
        db.commit()
    return result


# ---------------------------------------------------------------- 16. SBOM -- #
class SbomImportRequest(BaseModel):
    doc: dict
    format: str | None = None  # cyclonedx | spdx | auto


@router.post("/sbom/import")
def sbom_import(body: SbomImportRequest,
                user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.sbom import check_pinning, dependency_graph, import_sbom

    try:
        comps = import_sbom(body.doc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"component_count": len(comps), "components": comps,
            "pinning": check_pinning(comps), "graph": dependency_graph(comps)}


class SbomExportRequest(BaseModel):
    components: list[dict]
    format: str = "cyclonedx"  # cyclonedx | spdx


@router.post("/sbom/export")
def sbom_export(body: SbomExportRequest,
                user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from devsecops.sbom import export_cyclonedx, export_spdx

    if body.format.lower() in ("cyclonedx", "cdx"):
        return {"format": "cyclonedx", "bom": export_cyclonedx(body.components)}
    if body.format.lower() == "spdx":
        return {"format": "spdx", "bom": export_spdx(body.components)}
    raise HTTPException(status_code=422, detail="format must be cyclonedx or spdx")


# ------------------------------------------- 16b. SBOM scanner (E2E) ---- #
_SBOM_OPERATORS = ("admin", "auditor", "security_analyst", "superadmin")
# reading an SBOM (list/download/report/diff/validate/gate) is an auditor task —
# the read-only role may do those; mutating operations stay restricted.
_SBOM_READERS = (*_SBOM_OPERATORS, "readonly")


def _require_sbom_operator(user: str, db: "Session | None") -> None:
    """Issuing a VEX statement is a judgement call, not a read.

    Read-only accounts may *derive* statements (they come straight from the
    document), but authoring one asserts something about exploitability that
    ends up in a compliance artefact, so it needs an operator role. Tokens with
    no roles at all keep the platform's legacy admin fallback.
    """
    from api.dependencies import _user_roles
    from api.security.rbac import normalize_roles

    roles = normalize_roles(_user_roles(user, None, db))
    if roles and not (set(roles) & set(normalize_roles(list(_SBOM_OPERATORS)))):
        raise HTTPException(status_code=403, detail=(
            "issuing VEX statements requires one of roles: "
            + ", ".join(_SBOM_OPERATORS)))
_SBOM_STORE = None
_ARTIFACT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _sbom_storage():
    """Persistent on-disk SBOM artifact store (survives restarts).

    The store itself lives in :mod:`devsecops.artifact_store`, so a worker process
    writing the same job produces an artifact these endpoints serve unchanged.
    """
    from devsecops.artifact_store import artifact_storage

    global _SBOM_STORE
    if _SBOM_STORE is None:
        _SBOM_STORE = artifact_storage()
    return _SBOM_STORE


def _sbom_signing_secret(db: Session | None) -> tuple[str | None, str]:
    """(secret, key_id) for signing SBOM manifests — the platform-wide order.

    Vault ref > persisted settings key > HKDF from the platform master > this
    process's configured ``SECRET_KEY``. The last one is stable across restarts
    (unlike a process-random fallback), so ``/verify`` keeps agreeing with
    artifacts signed earlier in the same deployment.
    """
    try:
        from api.config.settings import get_settings

        configured = (get_settings().SECRET_KEY or "").strip() or None
    except Exception:  # noqa: BLE001 — settings must never break a scan
        configured = None
    return resolve_signing_secret(db, fallback_secret=configured)


class SbomScanRequest(BaseModel):
    kind: str = Field(..., description="source | container | binary")
    target: str = Field(..., min_length=1, max_length=512,
                        description="source tree path, filesystem root, docker-save .tar, or registry image")
    format: str = Field("cyclonedx", description="cyclonedx | spdx")
    as_image: bool = Field(False, description="treat the target as a registry image even if a path exists")
    include_vendored: bool = Field(False, description="source kind: also parse manifests under vendor/")
    use_lockfiles: bool = Field(True, description="source kind: merge resolved dependency lockfiles")
    feed: list[dict] | None = Field(None, description=("optional NVD-style advisory feed; matched "
                                                        "deterministically offline (no network)"))
    recursive: bool = Field(True, description="binary kind: descend into subdirectories")
    include_raw: bool = Field(False, description=("binary kind: also record files with no recognised "
                                                  "container format but crypto-library evidence"))


@router.post("/sbom/scan", status_code=status.HTTP_201_CREATED)
def sbom_scan(body: SbomScanRequest, db: Session = Depends(get_db_session),
              user: str = Depends(require_roles(*_SBOM_OPERATORS))):
    """End-to-end SBOM generation: scan a source tree or container target and
    produce a deterministic CycloneDX 1.5 / SPDX 2.3 bill of materials with
    crypto-relevance enrichment, pinning summary, and a signed-by-hash
    persistent artifact (download via GET /sbom/{artifact_id}/download)."""

    from datetime import datetime, timezone

    import hashlib
    import uuid

    from devsecops import binary_scan as binary
    from devsecops import sbom_scan as sb
    from devsecops.sbom import check_pinning
    from api.security.target_validation import TargetValidationError, validate_source_target

    kind = body.kind.lower()
    if kind not in ("source", "container", "binary"):
        raise HTTPException(status_code=422, detail="kind must be source, container or binary")
    if body.format.lower() not in ("cyclonedx", "cdx", "spdx"):
        raise HTTPException(status_code=422, detail="format must be cyclonedx or spdx")
    fmt = "spdx" if body.format.lower() == "spdx" else "cyclonedx"

    if kind == "source":
        try:
            resolved = validate_source_target(body.target, label="target")
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if resolved.startswith(("http://", "https://", "git@")):
            raise HTTPException(400, "remote git URLs are not supported by the SBOM scanner — point it at a local source tree")
        try:
            result = sb.scan_source(resolved, include_vendored=body.include_vendored,
                                    use_lockfiles=body.use_lockfiles)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    elif kind == "binary":
        try:
            resolved = validate_source_target(body.target, label="target")
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        target_path = Path(resolved).expanduser()
        if not target_path.exists():
            raise HTTPException(status_code=404, detail=f"scan target not found: {resolved}")
        try:
            binary_result = binary.scan_path(target_path, recursive=body.recursive,
                                             include_raw=body.include_raw)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        result = binary.sbom_result(binary_result)
    else:
        raw = str(body.target).strip()
        raw_path = Path(raw).expanduser()
        looks_path = body.as_image is False and (
            raw_path.exists() or raw.startswith(("/", "~", ".")))
        if looks_path:
            try:
                raw = validate_source_target(raw, label="target")
            except TargetValidationError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        elif not (sb.is_image_ref(raw) and (":" in raw or "/" in raw)):
            raise HTTPException(400, detail=("target must be a local path, docker-save .tar, "
                                             "or a registry image reference (e.g. nginx:1.27)"))
        if not looks_path:
            # a registry pull is a networked operation — fail closed in airgap
            _enforce_airgap_writable("scan.sbom.container")
        try:
            result = sb.scan_container(raw, as_image=body.as_image)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"container target not found: {exc}")
        except Exception as exc:  # noqa: BLE001 — docker/pull unavailability: report honestly
            raise HTTPException(status_code=503, detail=f"container scan unavailable: {exc}")

    if body.feed:
        try:
            sb.enrich_vulnerabilities(result, body.feed)
        except Exception as exc:  # noqa: BLE001 — a bad feed must not yield a fake-clean SBOM
            raise HTTPException(status_code=422, detail=f"advisory feed could not be applied: {exc}")
    else:
        result.setdefault("vulnerabilities", [])
    try:
        bom = sb.render_sbom(result, fmt=fmt, created_by=user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    packages = result.get("packages") or []
    payload = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha256 = hashlib.sha256(payload).hexdigest()
    artifact_id = str(uuid.uuid4())
    ext = "cdx.json" if fmt == "cyclonedx" else "spdx.json"
    key = f"{artifact_id}.{ext}"

    components = [{"name": p.get("name"),
                   "version": p.get("declared_spec") or p.get("raw_spec") or p.get("version"),
                   "ecosystem": p.get("manager")} for p in packages]
    pinning = check_pinning(components)
    component_count = len(packages) + len(result.get("binaries") or [])
    from devsecops.sbom_assurance import check_minimum_elements

    compliance = check_minimum_elements(bom)
    manifest = {
        "artifact_id": artifact_id,
        "kind": kind,
        "target": str(result.get("target") or body.target),
        "format": fmt,
        "sha256": sha256,
        "component_count": component_count,
        "binary_count": len(result.get("binaries") or []),
        "crypto_components": len(result.get("libraries") or []),
        "manifest_count": result.get("manifest_count", 0),
        "lockfile_count": result.get("lockfile_count", 0),
        "direct_count": sum(1 for p in packages if p.get("direct") is True),
        "transitive_count": sum(1 for p in packages if p.get("direct") is False),
        "dependency_edges": len(result.get("dependencies") or []),
        "minimum_elements": compliance["score"],
        "compliant": compliance["compliant"],
        "pinned": pinning["pinned"],
        "unpinned": pinning["unpinned"],
        "vulnerability_count": len(result.get("vulnerabilities") or []),
        # provenance of a binary scan: what was walked, what was parsed, and what
        # the parser refused to claim (so "0 findings" reads honestly)
        "binary_summary": ({
            "files_walked": result.get("files_walked", 0),
            "binaries_scanned": result.get("binaries_scanned", 0),
            "by_format": result.get("by_format") or {},
            "by_arch": result.get("by_arch") or {},
            "crypto_libraries": len(result.get("libraries") or []),
            "algorithms": (result.get("crypto") or {}).get("algorithms") or [],
            "pqc_markers": (result.get("crypto") or {}).get("pqc_markers") or [],
            "findings": len(result.get("findings") or []),
            "findings_by_severity": _severity_counts(result.get("findings") or []),
            "findings_excerpt": _finding_excerpt(result.get("findings") or []),
            "findings_excerpt_limit": MAX_REPORT_FINDINGS,
            "truncated": bool((result.get("limits") or {}).get("truncated")),
            **_binary_posture(result),
        } if kind == "binary" else None),
        # whether an advisory feed was actually applied — an SBOM with zero
        # advisories because nothing was checked reads differently from one
        # that was checked against a feed and came back clean
        "feed_supplied": bool(body.feed),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": user,
        "storage_key": key,
        # what it takes to re-scan the very same target with the same options
        "scan_options": {"kind": kind, "target": str(result.get("target") or body.target),
                         "as_image": bool(body.as_image),
                         "include_vendored": bool(body.include_vendored),
                         "use_lockfiles": bool(body.use_lockfiles),
                         "recursive": bool(body.recursive),
                         "include_raw": bool(body.include_raw),
                         "format": fmt, "feed_supplied": bool(body.feed)},
    }
    secret, key_id = _sbom_signing_secret(db)
    if secret:
        manifest["signature_alg"] = "HMAC-SHA256"
        manifest["signature_key"] = key_id
        manifest["signature"] = sb.sign_manifest(manifest, secret)
    store = _sbom_storage()
    store.put(key, payload)
    store.put_manifest(key, manifest)
    UserRepository(db).audit(user, "devsecops.sbom_scan", target_type="sbom_artifact",
                             target_id=artifact_id,
                             detail={"kind": kind, "target": manifest["target"], "format": fmt,
                                     "components": component_count, "sha256": sha256[:16]})
    db.commit()
    return {"artifact_id": artifact_id, "manifest": manifest, "compliance": compliance,
            "download_url": f"/api/v1/devsecops/sbom/{artifact_id}/download",
            "report_url": f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown",
            "verify_url": f"/api/v1/devsecops/sbom/{artifact_id}/verify", "bom": bom}


def _scanner_findings(manifest: dict) -> dict[str, int] | None:
    """Findings a scan recorded about the artifact, for the gate to weigh.

    The gate reads CVEs out of the SBOM document; a binary scan's own findings (a
    private key shipped inside the binary) are not in that document, so they are
    handed to the gate explicitly — otherwise a leaked key gates PASS.
    """
    summary = manifest.get("binary_summary") or {}
    counts = summary.get("findings_by_severity")
    return counts if isinstance(counts, dict) and counts else None


class BinaryScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512,
                        description="file or directory to scan for binaries and firmware")
    recursive: bool = Field(True, description="descend into subdirectories")
    include_raw: bool = Field(False, description="record unrecognised files that carry crypto evidence")
    yara_rules: list[str] | None = Field(None, description=(
        "rule files or directories (YARA subset, see /devsecops/yara/validate); the "
        "built-in rules always run, these are added to them"))
    format: str = Field("cyclonedx", description="cyclonedx | spdx for the SBOM half")
    feed: list[dict] | None = Field(None, description="optional NVD-style advisory feed")
    ingest_cbom: bool = Field(False, description=("also load the CBOM into the platform crypto "
                                                  "inventory (POST /cbom/ingest does the same)"))
    system_name: str | None = Field(None, max_length=200, description="CBOM: system the assets belong to")
    artifact_id: str | None = Field(None, max_length=64, description=(
        "reuse an existing artifact id instead of minting one — a retried job then rewrites "
        "its own artifact instead of adding a duplicate"))
    job_id: str | None = Field(None, max_length=64, description=(
        "the queued job this scan belongs to, recorded in the manifest and the audit trail"))


@router.post("/binary/scan", status_code=status.HTTP_201_CREATED)
def binary_scan(body: BinaryScanRequest, db: Session = Depends(get_db_session),
                user: str = Depends(require_roles(*_SBOM_OPERATORS))):
    """Scan binaries, shared libraries, archives and firmware images end to end.

    Deterministic and offline: magic-byte format identification, real parsing
    (ELF dynamic/static/symbol/Go-buildinfo/program-headers/hardening, PE
    imports/delay-imports/resources/version-info/debug/CLR/Authenticode presence,
    Mach-O load commands, ``ar``/zip/RPM/deb members, Java class constant pools,
    WASM imports, firmware container chains and device-tree identity), graded
    crypto evidence, then the same artefact pipeline as every other scan —
    CycloneDX/SPDX SBOM, NTIA score, signing, licence policy, gate, VEX, diff —
    plus a CycloneDX CBOM of the cryptographic assets.

    Archive and compression members are followed (gzip/xz/bzip2/tar/cpio/zip/ar
    as well as RPM/deb payloads) within a bounded budget; an embedded file that
    parses is reported with the container it came from, and a compression format
    this scanner cannot open (zstd/lz4, filesystem images) is reported as refused
    with the reason rather than silently skipped.
    """

    import hashlib
    import uuid

    from devsecops import binary_scan as bs
    from devsecops import sbom_scan as sb
    from devsecops.sbom import check_pinning
    from devsecops.sbom_assurance import check_minimum_elements
    from api.security.target_validation import TargetValidationError, validate_source_target

    if body.format.lower() not in ("cyclonedx", "cdx", "spdx"):
        raise HTTPException(status_code=422, detail="format must be cyclonedx or spdx")
    fmt = "spdx" if body.format.lower() == "spdx" else "cyclonedx"
    try:
        resolved = validate_source_target(body.target, label="target")
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    target_path = Path(resolved).expanduser()
    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"scan target not found: {resolved}")

    rule_paths: list[str] = []
    for entry in body.yara_rules or []:
        try:
            rule_paths.append(validate_source_target(entry, label="rule path"))
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for entry in rule_paths:
        if not Path(entry).expanduser().exists():
            raise HTTPException(status_code=404, detail=f"rule path not found: {entry}")
    try:
        scan = bs.scan_path(target_path, recursive=body.recursive, include_raw=body.include_raw,
                            yara_rules=rule_paths)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    result = bs.sbom_result(scan)
    if body.feed:
        try:
            sb.enrich_vulnerabilities(result, body.feed)
        except Exception as exc:  # noqa: BLE001 — a bad feed must not yield a fake-clean SBOM
            raise HTTPException(status_code=422, detail=f"advisory feed could not be applied: {exc}")
    else:
        result.setdefault("vulnerabilities", [])
    try:
        bom = sb.render_sbom(result, fmt=fmt, created_by=user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    cbom = bs.cbom_document(scan, target=str(scan.get("target")), created_by=user)

    packages = result.get("packages") or []
    payload = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha256 = hashlib.sha256(payload).hexdigest()
    artifact_id = body.artifact_id or str(uuid.uuid4())
    compliance = check_minimum_elements(bom)
    components = [{"name": p.get("name"), "version": p.get("version") or p.get("declared_spec"),
                   "ecosystem": p.get("manager")} for p in packages]
    pinning = check_pinning(components)
    findings = result.get("findings") or []
    manifest = build_binary_manifest(
        scan=scan, result=result, bom=bom, cbom=cbom, fmt=fmt,
        target=str(scan.get("target") or body.target), created_by=user, artifact_id=artifact_id,
        payload_sha256=sha256, compliance=compliance, pinning=pinning,
        feed_supplied=bool(body.feed), recursive=body.recursive, include_raw=body.include_raw,
        job_id=body.job_id, ruleset_digest=(result.get("yara") or {}).get("digest"))
    store_binary_artifact(manifest=manifest, payload=payload, cbom=cbom, secret=_sbom_signing_secret(db))

    cbom_result: dict = {"components": len(cbom.get("components") or []), "ingested": False}
    if body.ingest_cbom:
        # ingest through the same path POST /cbom/ingest uses, so "ingested" means
        # the assets really are in the inventory (and not merely well-formed)
        from api.routers.cbom import ingest_document

        try:
            loaded = ingest_document(bom=cbom, db=db,
                                     system_name=body.system_name or f"binaries:{Path(resolved).name}",
                                     owner=user)
            cbom_result = {"components": len(cbom.get("components") or []),
                           "records": loaded["imported"], "ingested": True,
                           "system": loaded["system"].get("name"),
                           "ingest_endpoint": "/api/v1/cbom/ingest"}
            db.commit()
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001 — inventory unavailable is reported, never faked
            cbom_result = {"components": len(cbom.get("components") or []), "ingested": False,
                           "error": f"CBOM inventory unavailable: {exc}"}
    audit_artifact(db, user, artifact_id=artifact_id, target=manifest["target"],
                   binaries=manifest["binary_count"], findings=len(result.get("findings") or []),
                   sha256=sha256, job_id=body.job_id)
    db.commit()
    return {
        "artifact_id": artifact_id, "manifest": manifest, "compliance": compliance,
        "summary": manifest["binary_summary"],
        "findings": findings[:200],
        "crypto_libraries": result.get("libraries") or [],
        "binaries": result.get("binaries") or [],
        "cbom": cbom,
        "cbom_result": cbom_result,
        "download_url": f"/api/v1/devsecops/sbom/{artifact_id}/download",
        "report_url": f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown",
        "verify_url": f"/api/v1/devsecops/sbom/{artifact_id}/verify",
        "bom": bom,
    }


class FingerprintMatchRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512,
                        description="file or directory to fingerprint and search")
    reference: str | None = Field(None, max_length=512, description=(
        "a file whose fingerprint is the query (typically the suspect binary)"))
    build_fingerprint: str | None = Field(None, max_length=128,
                                          description="explicit build fingerprint to look for")
    code_sha256: str | None = Field(None, max_length=128,
                                    description="explicit code-section digest to look for")
    ssdeep: str | None = Field(None, max_length=512,
                               description="explicit fuzzy fingerprint (ssdeep) to compare against")
    similarity: int = Field(85, ge=0, le=100,
                            description="fuzzy score at or above which a pair is reported")
    recursive: bool = Field(True, description="descend into subdirectories")
    fuzzy_bytes: int | None = Field(None, ge=1024, le=8 * 1024 * 1024, description=(
        "how much code the fuzzy pass reads, up to 8 MiB (a full scan reads 512 KiB)"))


@router.post("/fingerprints/match")
def fingerprint_match(body: FingerprintMatchRequest,
                      user: str = Depends(require_roles(*_SBOM_READERS))):
    """Find whether a build appears elsewhere, or whether anything resembles it.

    Deterministic and offline: every file under ``target`` is fingerprinted (exact
    code/ABI digests plus an ssdeep similarity score) and compared with the query,
    which is either a reference file inside the same allowed roots or an explicit
    fingerprint. The answer says *which* of the two things it is — an identical
    build, the same code with a different import surface, a resemblance with the
    score, or nothing — and never reports a resemblance as identity.
    """
    from api.security.target_validation import TargetValidationError, validate_source_target
    from devsecops import binary_scan as bs
    from devsecops.fingerprints import match as match_fingerprints

    try:
        target = validate_source_target(body.target, label="target")
        reference = (validate_source_target(body.reference, label="reference")
                     if body.reference else None)
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    query: dict = {"build_fingerprint": body.build_fingerprint,
                   "code_sha256": body.code_sha256, "ssdeep": body.ssdeep,
                   "source": None}
    if reference:
        walked = bs.fingerprint_path(reference, recursive=False,
                                     fuzzy_bytes=body.fuzzy_bytes, max_files=1)
        if not walked["artefacts"]:
            raise HTTPException(status_code=400,
                                detail=f"reference could not be fingerprinted: {reference}")
        row = walked["artefacts"][0]["fingerprints"]
        query.update({"build_fingerprint": row.get("build_fingerprint"),
                      "code_sha256": row.get("code_sha256"), "ssdeep": row.get("ssdeep"),
                      "source": {"path": reference, "format": walked["artefacts"][0]["format"],
                                 "fingerprints": row}})
    if not any(query.get(key) for key in ("build_fingerprint", "code_sha256", "ssdeep")):
        raise HTTPException(status_code=400, detail=(
            "a query needs a reference file or at least one of build_fingerprint, "
            "code_sha256 or ssdeep"))

    walked = bs.fingerprint_path(target, recursive=body.recursive,
                                 fuzzy_bytes=body.fuzzy_bytes)
    matches = []
    for artefact in walked["artefacts"]:
        verdict = match_fingerprints(query, {"fingerprints": artefact.get("fingerprints") or {}},
                                     similarity=body.similarity)
        if verdict["verdict"] == "different":
            continue
        matches.append({**verdict, "path": artefact["path"], "format": artefact.get("format"),
                        "size": artefact.get("size")})
    order = {"identical": 0, "same-code": 1, "similar": 2, "different": 3}
    matches.sort(key=lambda row: (order[row["verdict"]], -int(row["score"]), str(row["path"])))
    return {
        "query": {key: query.get(key) for key in
                  ("build_fingerprint", "code_sha256", "ssdeep", "source")},
        "matches": matches,
        "identical": sum(1 for row in matches if row["verdict"] == "identical"),
        "same_code": sum(1 for row in matches if row["verdict"] == "same-code"),
        "similar": sum(1 for row in matches if row["verdict"] == "similar"),
        "compared": walked["fingerprinted"],
        "similarity_threshold": body.similarity,
        "fuzzy_bytes": walked["fuzzy_bytes"],
        "limits": {"files_read": walked["files_read"], "skipped": walked["skipped"],
                   "truncated": walked["truncated"]},
        "note": ("an identical verdict means the same build fingerprint (code plus import "
                 "surface); same-code means the code matched but the imports differ; similar "
                 f"is an ssdeep score at or above {body.similarity} and is a resemblance, "
                 "not identity. A similar match at 100 says the fuzzy sample could not see "
                 "the difference the exact digests found"),
    }


class YaraValidateRequest(BaseModel):
    rules: list[str] | None = Field(None, description=(
        "rule files or directories to load, on top of the built-in rules"))
    text: str | None = Field(None, max_length=200_000, description=(
        "rule text to parse without reading a file (for a pasted or downloaded rule)"))


@router.post("/yara/validate")
def yara_validate(body: YaraValidateRequest,
                  user: str = Depends(require_roles(*_SBOM_OPERATORS))):
    """Load a ruleset and report exactly what it will do, rule by rule.

    An operator who ships rules needs two answers before trusting a scan: which
    rules are loaded, and which were refused and why. This returns both, plus the
    bundle digest a match will cite. Nothing is scanned here — this is the check
    that the ruleset itself is what it claims to be.
    """
    from devsecops.yara_rules import YaraError, load_rules, parse_rules
    from api.security.target_validation import TargetValidationError, validate_source_target

    paths: list[str] = []
    for entry in body.rules or []:
        try:
            paths.append(validate_source_target(entry, label="rule path"))
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    for entry in paths:
        if not Path(entry).expanduser().exists():
            raise HTTPException(status_code=404, detail=f"rule path not found: {entry}")

    extra: list[dict] = []
    if body.text:
        try:
            parsed = parse_rules(body.text, "request:text")
        except YaraError as exc:
            raise HTTPException(status_code=422, detail=f"rule text does not parse: {exc}")
        extra = [{"name": rule.name, "tags": rule.tags, "severity": rule.severity(),
                  "private": rule.private, "strings": len(rule.patterns),
                  "source": rule.source, "meta": rule.meta} for rule in parsed]

    ruleset = load_rules(paths)
    return {
        "rules": [{"name": rule.name, "tags": rule.tags, "severity": rule.severity(),
                   "private": rule.private, "strings": sorted(rule.patterns),
                   "condition_refers_to": sorted(rule.references()),
                   "source": rule.source, "meta": rule.meta} for rule in ruleset.rules],
        "summary": ruleset.summary(),
        "text_rules": extra,
        "note": ("a rule that did not load is reported under summary.errors and will not "
                 "run — the scan's findings will say so too, so a ruleset error cannot be "
                 "mistaken for a clean scan"),
    }


@router.get("/binary/artifacts/{artifact_id}/cbom")
def binary_cbom(artifact_id: str, user: str = Depends(require_roles(*_SBOM_READERS))):
    """The CBOM stored alongside a binary-scan artifact."""
    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    key = f"{artifact_id}.cbom.json"
    try:
        blob = store.get(key)
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=404, detail="no CBOM stored for this artifact")
    return json.loads(blob.decode("utf-8"))


@router.get("/sbom/artifacts")
def sbom_artifacts(kind: str | None = None, fmt: str | None = None,
                  q: str | None = None, limit: int = 50,
                  user: str = Depends(require_roles(*_SBOM_READERS))):
    """List generated SBOM artifacts (newest first, capped at 50)."""
    items = _sbom_storage().list_manifests()
    items.sort(key=lambda m: str(m.get("created_at") or ""), reverse=True)
    if kind:
        wanted = kind.strip().lower()
        items = [i for i in items if str(i.get("kind") or "").lower() == wanted]
    if fmt:
        wanted = "cyclonedx" if fmt.strip().lower() in ("cyclonedx", "cdx") else fmt.strip().lower()
        items = [i for i in items if str(i.get("format") or "").lower() == wanted]
    if q:
        needle = q.strip().lower()
        items = [i for i in items if needle in str(i.get("target") or "").lower()]
    bounded = items[:max(1, min(limit, 200))]
    for item in bounded:
        aid = item.get("artifact_id")
        item["download_url"] = f"/api/v1/devsecops/sbom/{aid}/download" if aid else None
        item["verify_url"] = f"/api/v1/devsecops/sbom/{aid}/verify" if aid else None
        item["report_url"] = f"/api/v1/devsecops/sbom/{aid}/report" if aid else None
    return {"total": len(items), "returned": len(bounded), "artifacts": bounded}


class SbomValidateRequest(BaseModel):
    doc: dict = Field(..., description="CycloneDX or SPDX JSON document")


@router.post("/sbom/validate")
def sbom_validate(body: SbomValidateRequest,
                  user: str = Depends(require_roles(*_SBOM_READERS))):
    """NTIA minimum-elements check for a CycloneDX/SPDX document: supplier,
    component name, version, unique identifiers, dependency relationships,
    SBOM author and timestamp — per-element coverage plus the exact gaps.
    Use it on a supplier's SBOM before accepting it, or on our own output."""
    from devsecops.sbom_assurance import check_minimum_elements

    return check_minimum_elements(body.doc)


class SbomDiffRequest(BaseModel):
    from_artifact: str | None = Field(None, description="artifact id (baseline)")
    to_artifact: str | None = Field(None, description="artifact id (current)")
    from_doc: dict | None = Field(None, description="or an inline cyclonedx/spdx document")
    to_doc: dict | None = Field(None, description="or an inline cyclonedx/spdx document")


@router.post("/sbom/diff")
def sbom_diff(body: SbomDiffRequest,
              user: str = Depends(require_roles(*_SBOM_READERS))):
    """Diff two SBOMs (stored artifacts or inline docs): components added,
    removed, version-changed (upgrade/downgrade), license changes, crypto
    deltas and a review verdict."""
    from devsecops.sbom_assurance import diff_boms

    store = _sbom_storage()

    def _load(artifact_id: str) -> tuple[dict, dict]:
        if not _ARTIFACT_ID_RE.match(artifact_id):
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        man = next((m for m in store.list_manifests() if m.get("artifact_id") == artifact_id), None)
        if man is None or not man.get("storage_key"):
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        try:
            doc = json.loads(store.get(man["storage_key"]))
        except Exception:  # noqa: BLE001 — manifest without a readable blob
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        return doc, man

    meta: dict = {}
    if body.from_artifact and body.to_artifact:
        old, old_man = _load(body.from_artifact)
        new, new_man = _load(body.to_artifact)
        meta = {"from": {k: old_man.get(k) for k in ("artifact_id", "target", "format", "created_at")},
                "to": {k: new_man.get(k) for k in ("artifact_id", "target", "format", "created_at")}}
    elif body.from_doc is not None and body.to_doc is not None:
        old, new = body.from_doc, body.to_doc
    else:
        raise HTTPException(status_code=422, detail=("pass from_artifact+to_artifact, "
                                                     "or from_doc+to_doc"))
    result = diff_boms(old, new)
    result["sources"] = meta
    return result


@router.get("/sbom/{artifact_id}/verify")
def sbom_verify(artifact_id: str, db: Session = Depends(get_db_session),
                user: str = Depends(require_roles(*_SBOM_READERS))):
    """Re-verify a stored artifact: recompute the blob digest and the manifest
    HMAC signature. Returns OK only when both match."""
    from devsecops.sbom_scan import verify_artifact

    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = next((m for m in store.list_manifests() if m.get("artifact_id") == artifact_id), None)
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        blob = store.get(man["storage_key"])
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=404, detail="artifact not found")
    secret, key_id = _sbom_signing_secret(db)
    result = verify_artifact(man, blob, secret)
    result["key_id"] = key_id
    failed = {c["check"] for c in result["checks"] if not c["ok"]}
    notes = []
    if "blob_sha256" in failed:
        notes.append("the stored BOM bytes no longer match the recorded sha256 — "
                     "the artifact was modified or corrupted after generation")
    if "manifest_signature" in failed:
        notes.append("the stored manifest does not match its HMAC signature — it was "
                     "modified after signing, or the signing key changed since "
                     f"(signed with: {man.get('signature_key') or 'unknown'})")
    if notes:
        result["note"] = "; ".join(notes)
    if result["verdict"] != "OK":
        UserRepository(db).audit(user, "devsecops.sbom_verify_failed", target_type="sbom_artifact",
                                 target_id=artifact_id,
                                 detail={"checks": result["checks"]}, outcome="FAILURE")
        db.commit()
    return {"artifact_id": artifact_id, **result, "manifest": {
        "format": man.get("format"), "kind": man.get("kind"), "target": man.get("target"),
        "sha256": man.get("sha256"), "created_at": man.get("created_at"),
        "signature_alg": man.get("signature_alg")}}


@router.get("/sbom/{artifact_id}/report")
def sbom_report(artifact_id: str, fmt: str = "markdown",
                user: str = Depends(require_roles(*_SBOM_READERS))):
    """Auditor-friendly summary of a stored SBOM: components, crypto inventory,
    pinning, minimum-elements status and provenance (markdown or json)."""
    from devsecops.sbom_assurance import check_minimum_elements
    from devsecops.sbom import check_pinning

    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = next((m for m in store.list_manifests() if m.get("artifact_id") == artifact_id), None)
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        bom = json.loads(store.get(man["storage_key"]))
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=404, detail="artifact not found")

    compliance = check_minimum_elements(bom)
    components = _bom_components(bom)
    pinning = check_pinning(components)
    crypto = [c for c in components if _is_crypto_component(c, bom)]
    payload = {
        "artifact": {k: man.get(k) for k in ("artifact_id", "kind", "target", "format", "sha256",
                                             "component_count", "crypto_components", "pinned",
                                             "unpinned", "manifest_count", "created_at", "created_by",
                                             "signature_alg")},
        "compliance": compliance,
        "pinning": pinning,
        "crypto_components": crypto,
        "binary": man.get("binary_summary"),
    }
    if fmt.lower() in ("json", "raw"):
        return payload
    lines = [
        f"# SBOM report — {man.get('target')}",
        "",
        f"- Artifact: `{man.get('artifact_id')}` ({man.get('kind')}, {man.get('format')})",
        f"- Generated: {man.get('created_at')} by {man.get('created_by')}",
        f"- SHA-256: `{man.get('sha256')}`",
        f"- Signature: {man.get('signature_alg') or 'none'}",
        f"- Components: {man.get('component_count')} ({man.get('crypto_components')} crypto-relevant)",
        f"- Pinning: {man.get('pinned')} pinned / {man.get('unpinned')} unpinned",
        f"- Minimum elements: {compliance['score']} — {'COMPLIANT' if compliance['compliant'] else 'GAPS'}",
        "",
        "## Minimum elements (NTIA)",
        "",
        "| Element | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for element in compliance["elements"]:
        lines.append(f"| {element['label']} | {element['status']} | {element['detail']} |")
    lines += ["", "## Crypto-relevant components", "",
              "| Component | Version | Vendor | Source |", "| --- | --- | --- | --- |"]
    if crypto:
        for comp in sorted(crypto, key=lambda c: str(c.get("name"))):
            lines.append(f"| {comp.get('name')} | {comp.get('version') or '-'} | "
                         f"{comp.get('vendor') or '-'} | {comp.get('ecosystem') or '-'} |")
    else:
        lines.append("| _none_ | | | |")
    if pinning["findings"]:
        lines += ["", "## Pinning findings", "", "| Coordinate | Code | Severity | Detail |",
                  "| --- | --- | --- | --- |"]
        for finding in pinning["findings"]:
            lines.append(f"| {finding['coordinate']} | {finding['code']} | {finding['severity']} | "
                         f"{finding['detail']} |")
    binary = man.get("binary_summary") or {}
    if binary:
        lines += ["", "## Binary scan", "",
                  f"- Files walked: {binary.get('files_walked', 0)}, "
                  f"binaries scanned: {binary.get('binaries_scanned', 0)}",
                  f"- Formats: {json.dumps(binary.get('by_format') or {}, sort_keys=True)}",
                  f"- Crypto libraries: {binary.get('crypto_libraries', 0)}",
                  f"- Signed/unsigned: {json.dumps(binary.get('signature_posture') or {})}, "
                  f"encrypted: {binary.get('encrypted_binaries', 0)}"]
        constants = binary.get("constants") or {}
        if constants:
            searched = constants.get("searched_bytes", 0)
            lines.append(
                f"- Constant tables: {constants.get('tables_matched', 0)} matched "
                f"({constants.get('complete_tables', 0)} complete) in "
                f"{searched} byte(s) searched across "
                f"{constants.get('artefacts_searched', 0)} artefact(s)")
            named = constants.get("algorithms") or []
            lines.append(f"- Confirmed by constant table: {', '.join(named) if named else '_none_'}")
        keys = binary.get("key_material") or {}
        if keys.get("artefacts_with_keys"):
            lines.append(f"- Embedded key material: {keys.get('private_keys', 0)} private key(s) "
                         f"({keys.get('unencrypted_private_keys', 0)} unencrypted), "
                         f"{keys.get('certificates', 0)} certificate(s) in "
                         f"{keys.get('artefacts_with_keys')} artefact(s)")
        excerpt = binary.get("findings_excerpt") or []
        counts = binary.get("findings_by_severity") or {}
        if excerpt:
            lines += ["", f"## Scan findings ({binary.get('findings', len(excerpt))} total)", "",
                      "| Severity | Code | Finding | Path |", "| --- | --- | --- | --- |"]
            for row in excerpt:
                lines.append(f"| {row.get('severity')} | {row.get('code')} | "
                             f"{row.get('title')} | {row.get('path') or '-'} |")
            limit = int(binary.get("findings_excerpt_limit") or len(excerpt))
            if sum(counts.values()) > len(excerpt):
                lines += ["", f"_Showing {len(excerpt)} of {sum(counts.values())} findings "
                              f"(limit {limit}); severity counts above are complete._"]
    if compliance["gaps"]:
        lines += ["", "## Gaps", ""] + [f"- {gap}" for gap in compliance["gaps"]]
    body = "\n".join(lines) + "\n"
    ext = "md" if fmt.lower() in ("markdown", "md") else "txt"
    return Response(content=body.encode("utf-8"), media_type="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="cryptoscan-sbom-{artifact_id[:8]}.{ext}"'})


class SbomGateRequest(BaseModel):
    policy: dict | None = Field(None, description="gate policy overrides (see DEFAULT_GATE_POLICY)")


class SbomRescanRequest(BaseModel):
    policy: dict | None = Field(None, description="gate policy for the fresh artifact")
    include_vendored: bool | None = Field(None, description="override the stored scan option")
    use_lockfiles: bool | None = Field(None, description="override the stored scan option")


def _load_sbom_artifact(artifact_id: str) -> tuple[dict, bytes]:
    """(manifest, blob) for a stored artifact, or 404."""
    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = next((m for m in store.list_manifests() if m.get("artifact_id") == artifact_id), None)
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        return man, store.get(man["storage_key"])
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=404, detail="artifact not found")


@router.post("/sbom/{artifact_id}/gate")
def sbom_gate(artifact_id: str, body: SbomGateRequest | None = None,
              user: str = Depends(require_roles(*_SBOM_READERS))):
    """Evaluate a stored artifact against a supply-chain gate policy.

    Deterministic and offline: counts critical/high advisories recorded in the
    document, checks declared licenses against the deny list, checks the NTIA
    minimum-elements score, the pinning summary and the signature. A FAIL
    verdict means the policy's blocker thresholds were crossed — the caller
    should stop the pipeline; warnings are advisory.
    """
    from devsecops.sbom_assurance import evaluate_gate

    man, blob = _load_sbom_artifact(artifact_id)
    try:
        bom = json.loads(blob.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — a corrupt blob is a real failure, not a pass
        raise HTTPException(status_code=422, detail=f"stored SBOM could not be parsed: {exc}")
    result = evaluate_gate(bom, policy=(body.policy if body else None),
                           unpinned=man.get("unpinned"),
                           signed=bool(man.get("signature")),
                           scanner_findings=_scanner_findings(man))
    return {"artifact_id": artifact_id, "target": man.get("target"), "format": man.get("format"),
            "generated_at": man.get("created_at"), **result}


@router.post("/sbom/{artifact_id}/rescan")
def sbom_rescan(artifact_id: str, body: SbomRescanRequest | None = None,
                db: Session = Depends(get_db_session),
                user: str = Depends(require_roles(*_SBOM_OPERATORS))):
    """Re-scan the stored target with the stored options and diff old -> new.

    This is the "did anything change under me?" control: it re-runs the same
    scan (source kind, lockfile preference, format), stores the fresh artifact,
    diffs it against the previous one (added/removed/upgrade/downgrade/license/
    crypto deltas) and gates the result. Advisory feeds are not persisted (they
    can be large and are supplied per scan), so a rescan of a fed artifact runs
    without one and says so in ``notes`` rather than silently reporting zero
    advisories.
    """
    from devsecops.sbom_assurance import diff_boms, evaluate_gate

    man, blob = _load_sbom_artifact(artifact_id)
    opts = man.get("scan_options") or {}
    if not opts.get("target"):
        raise HTTPException(status_code=409, detail=(
            "this artifact predates recorded scan options — scan the target again "
            "to enable re-scan"))
    overrides = body or SbomRescanRequest()
    request = {"kind": opts.get("kind") or "source", "target": opts["target"],
               "format": opts.get("format") or "cyclonedx",
               "as_image": bool(opts.get("as_image")),
               "include_vendored": (overrides.include_vendored if overrides.include_vendored is not None
                                    else bool(opts.get("include_vendored"))),
               "use_lockfiles": (overrides.use_lockfiles if overrides.use_lockfiles is not None
                                 else bool(opts.get("use_lockfiles"))),
               "recursive": bool(opts.get("recursive", True)),
               "include_raw": bool(opts.get("include_raw", False))}
    try:
        fresh = sbom_scan(SbomScanRequest(**request), db=db, user=user)
    except HTTPException as exc:
        raise HTTPException(status_code=exc.status_code,
                            detail=f"re-scan of {opts['target']} failed: {exc.detail}")

    old_bom: dict = {}
    try:
        old_bom = json.loads(blob.decode("utf-8"))
    except Exception:  # noqa: BLE001 — the fresh artifact is still valid evidence
        old_bom = {}
    try:
        delta = diff_boms(old_bom, fresh["bom"]) if old_bom else None
        diff_error = "" if delta is not None else "the previous document could not be read"
    except Exception as exc:  # noqa: BLE001 — the fresh artifact still stands on its own
        delta = None
        diff_error = str(exc)
    notes = []
    if opts.get("feed_supplied"):
        recorded = [str(v.get("id")) for v in (old_bom.get("vulnerabilities") or [])
                    if isinstance(v, dict) and v.get("id")]
        note = ("the previous artifact was generated with an advisory feed, which is not persisted — "
                "the fresh artifact reports no advisories")
        if recorded:
            shown = ", ".join(recorded[:5]) + ("…" if len(recorded) > 5 else "")
            note += (f"; it recorded {len(recorded)} ({shown}), so re-run the scan with a feed "
                     "before trusting a clean gate verdict on this build")
        notes.append(note)
    if delta is None:
        notes.append(f"diff unavailable: {diff_error}")
    new_man = fresh["manifest"]
    gate = evaluate_gate(fresh["bom"], policy=(overrides.policy),
                         unpinned=new_man.get("unpinned"), signed=bool(new_man.get("signature")),
                         scanner_findings=_scanner_findings(new_man))
    return {"artifact_id": fresh["artifact_id"], "previous_artifact_id": artifact_id,
            "target": new_man.get("target"), "scan_options": new_man.get("scan_options"),
            "diff": delta, "gate": gate, "manifest": new_man, "notes": notes,
            "verify_url": fresh["verify_url"], "download_url": fresh["download_url"]}


# ------------------------------------------------- SBOM license / VEX / index --- #
# Artifact manifests are cheap to scan but the listing is I/O bound; a short
# in-process cache keeps the index and license endpoints snappy without ever
# serving a stale body (bodies are always read from the store).
_INDEX_CACHE: dict[str, object] = {"signature": None, "rows": []}
_INDEX_CACHE_TTL_SECONDS = 10.0


class SbomLicenseRequest(BaseModel):
    doc: dict | None = Field(None, description="CycloneDX or SPDX JSON document")
    artifact_id: str | None = Field(None, description="stored artifact instead of an inline document")
    policy: dict | None = Field(None, description=("forbidden/restricted/require_declared/"
                                                   "review_copyleft — see DEFAULT_LICENSE_POLICY"))
    fmt: str = Field("json", description="json, or markdown for a renderable section")


class SbomVexRequest(BaseModel):
    doc: dict | None = Field(None, description="CycloneDX or SPDX JSON document")
    artifact_id: str | None = Field(None, description="stored artifact instead of an inline document")
    analyses: dict | None = Field(None, description=("operator statements, keyed by CVE: "
                                                     "{state, justification, detail, response}"))
    fmt: str = Field("json", description="json (CycloneDX VEX) or markdown")


def _resolve_sbom_doc(doc: dict | None, artifact_id: str | None) -> dict:
    """Exactly one of an inline document or a stored artifact id."""
    if bool(doc) == bool(artifact_id):
        raise HTTPException(status_code=422,
                            detail="provide exactly one of `doc` or `artifact_id`")
    if doc:
        return doc
    _man, blob = _load_sbom_artifact(str(artifact_id))
    try:
        return json.loads(blob.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — corrupt storage is a real error
        raise HTTPException(status_code=422, detail=f"stored SBOM could not be parsed: {exc}")


@router.post("/sbom/license")
def sbom_license(body: SbomLicenseRequest,
                 user: str = Depends(require_roles(*_SBOM_READERS))):
    """License inventory and policy evaluation for a document or stored artifact.

    Reports declared licenses grouped by SPDX identifier with the components
    carrying them, the components that declare nothing, and policy violations.
    The copyleft review trigger is a policy flag, not a compatibility ruling:
    the engine never claims two licenses are or are not compatible.
    """
    from devsecops.sbom_license import check_license_policy, render_license_report

    doc = _resolve_sbom_doc(body.doc, body.artifact_id)
    report = check_license_policy(doc, policy=body.policy)
    payload: dict = {"artifact_id": body.artifact_id, "verdict": report["verdict"], **report}
    if str(body.fmt).lower() == "markdown":
        payload["markdown"] = render_license_report(report)
    return payload


@router.post("/sbom/vex")
def sbom_vex(body: SbomVexRequest, db: Session = Depends(get_db_session),
             user: str = Depends(require_roles(*_SBOM_READERS))):
    """Deterministic VEX statements for a document or stored artifact.

    Advisory matches the platform found are reported ``exploitable`` (that is
    what the advisory asserts for the version range it matched). ``not_affected``
    is only ever produced by an operator statement with a valid justification,
    or when the affected component is provably absent — the platform does not
    invent reachability analysis.
    """
    from devsecops import sbom_vex as vx

    if body.analyses:
        _require_sbom_operator(user, db)
    doc = _resolve_sbom_doc(body.doc, body.artifact_id)
    try:
        rows = vx.statements(doc, analyses=body.analyses)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if str(body.fmt).lower() == "markdown":
        return {"artifact_id": body.artifact_id, "statement_count": len(rows),
                "summary": vx.counts(rows), "statements": rows,
                "markdown": vx.render_markdown(rows, target=manifest_target(doc))}
    return {"artifact_id": body.artifact_id, "statement_count": len(rows),
            "summary": vx.counts(rows), "statements": rows,
            "vex_document": vx.build_vex_document(doc, analyses=body.analyses, author=user)}


@router.get("/sbom/{artifact_id}/vex")
def sbom_vex_for_artifact(artifact_id: str, dl: bool = False,
                          user: str = Depends(require_roles(*_SBOM_READERS))):
    """VEX document for a stored artifact (download as .vex.json with ?dl=true)."""
    from devsecops import sbom_vex as vx

    doc = _resolve_sbom_doc(None, artifact_id)
    rows = vx.statements(doc)
    document = vx.build_vex_document(doc, author=user)
    if dl:
        from fastapi.responses import Response

        body = json.dumps(document, indent=2).encode("utf-8")
        return Response(content=body, media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="cryptoscan-vex-{artifact_id[:8]}.json"'})
    return {"artifact_id": artifact_id, "statement_count": len(rows),
            "summary": vx.counts(rows), "statements": rows, "vex_document": document}


def manifest_target(doc: dict) -> str | None:
    component = ((doc.get("metadata") or {}).get("component") or {}) if isinstance(doc, dict) else {}
    if isinstance(component, dict) and component.get("name"):
        return str(component["name"])
    name = doc.get("name") if isinstance(doc, dict) else None
    return str(name) if name else None


def _artifact_rows() -> list[dict]:
    """Cached listing of stored artifacts (manifests only — bodies are not read)."""
    import time

    store = _sbom_storage()
    rows = store.list_manifests()
    signature = (len(rows), max((str(r.get("created_at") or "") for r in rows), default=""))
    cached_at = _INDEX_CACHE.get("at")
    if (_INDEX_CACHE["signature"] == signature
            and isinstance(cached_at, float)
            and time.monotonic() - cached_at < _INDEX_CACHE_TTL_SECONDS):
        return _INDEX_CACHE["rows"]  # type: ignore[return-value]
    for row in rows:
        base = str(row.get("storage_key") or "").split("/")[-1]
        row["artifact_id"] = base.split(".")[0] or None
    _INDEX_CACHE.update({"signature": signature, "rows": rows, "at": time.monotonic()})
    return rows


@router.get("/sbom/components")
def sbom_components(q: str | None = None, crypto: bool | None = None, limit: int = 100,
                    artifact_id: str | None = None,
                    user: str = Depends(require_roles(*_SBOM_READERS))):
    """Cross-artifact component index: which artifact carries which component.

    Reads each artifact body once (metadata is not stored per component in the
    manifest), so the response is bounded by ``limit`` and says how many rows it
    saw. ``crypto=true`` narrows to crypto-relevant components, ``q`` matches
    name/purl substrings.
    """
    bounded = max(1, min(limit, 500))
    needle = (q or "").strip().lower()
    rows = []
    scanned = 0
    for man in sorted(_artifact_rows(), key=lambda m: str(m.get("created_at") or ""), reverse=True):
        if artifact_id and man.get("artifact_id") != artifact_id:
            continue
        if not man.get("artifact_id"):
            continue
        scanned += 1
        try:
            doc = json.loads(_sbom_storage().get(str(man.get("storage_key"))).decode("utf-8"))
        except Exception:  # noqa: BLE001 — a corrupt artifact must not break the index
            continue
        for comp in _bom_components(doc):
            is_crypto = bool(comp.get("crypto")) or _is_crypto_component(comp, doc)
            if crypto is True and not is_crypto:
                continue
            if crypto is False and is_crypto:
                continue
            name = str(comp.get("name") or "")
            if needle and needle not in name.lower() and needle not in str(comp.get("purl") or "").lower():
                continue
            rows.append({"name": name, "version": comp.get("version"),
                         "purl": comp.get("purl"), "crypto": is_crypto,
                         "artifact_id": man.get("artifact_id"),
                         "target": man.get("target"), "format": man.get("format"),
                         "created_at": man.get("created_at")})
            if len(rows) >= bounded:
                return {"total": len(rows), "returned": len(rows), "truncated": True,
                        "artifacts_scanned": scanned, "components": rows}
    return {"total": len(rows), "returned": len(rows), "truncated": False,
            "artifacts_scanned": scanned, "components": rows}


@router.get("/sbom/advisories")
def sbom_advisories(severity: str | None = None, cve: str | None = None,
                    user: str = Depends(require_roles(*_SBOM_READERS))):
    """Advisories recorded across stored artifacts (matched scans only).

    Only artifacts whose manifests record ``feed_supplied`` are counted — an
    artifact scanned without a feed contributes nothing here, and the response
    states how many artifacts were actually checked.
    """
    wanted = str(severity or "").strip().upper()
    needle = str(cve or "").strip().upper()
    index: dict[str, dict] = {}
    checked = 0
    unchecked = 0
    for man in _artifact_rows():
        if not man.get("artifact_id"):
            continue
        if not man.get("feed_supplied"):
            unchecked += 1
            continue
        checked += 1
        try:
            doc = json.loads(_sbom_storage().get(str(man.get("storage_key"))).decode("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        for vuln in doc.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            cve_id = str(vuln.get("id") or "")
            if not cve_id or (needle and needle != cve_id.upper()):
                continue
            ratings = vuln.get("ratings") or [{}]
            level = str(ratings[0].get("severity") or "unknown").upper()
            if wanted and level != wanted:
                continue
            entry = index.setdefault(cve_id, {"cve": cve_id, "severity": level,
                                              "recommendation": vuln.get("recommendation"),
                                              "affected": []})
            for affect in vuln.get("affects") or []:
                ref = affect.get("ref") if isinstance(affect, dict) else None
                entry["affected"].append({"ref": ref, "artifact_id": man.get("artifact_id"),
                                          "target": man.get("target")})
    count = sum(len(v["affected"]) for v in index.values())
    return {"total": len(index), "affected_components": count,
            "artifacts_checked": checked, "artifacts_without_feed": unchecked,
            "advisories": sorted(index.values(), key=lambda v: (v["severity"], v["cve"]))}


@router.delete("/sbom/artifacts")
def sbom_prune(older_than_days: int = 90, db: Session = Depends(get_db_session),
               user: str = Depends(require_roles("admin", "superadmin"))):
    """Retention: delete artifacts older than N days (default 90, min 1)."""
    from datetime import datetime, timedelta, timezone

    if older_than_days < 1:
        raise HTTPException(status_code=422, detail="older_than_days must be >= 1")
    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    store = _sbom_storage()
    deleted, kept = [], 0
    for man in store.list_manifests():
        created = str(man.get("created_at") or "")
        try:
            stamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
        except ValueError:
            kept += 1
            continue
        if stamp < cutoff and man.get("storage_key"):
            store.delete(man["storage_key"])
            deleted.append({"artifact_id": man.get("artifact_id"), "created_at": created,
                            "target": man.get("target")})
        else:
            kept += 1
    if deleted:
        UserRepository(db).audit(user, "devsecops.sbom_prune", target_type="sbom_artifact",
                                 target_id="retention",
                                 detail={"older_than_days": older_than_days,
                                         "deleted": len(deleted)})
        db.commit()
    return {"deleted": len(deleted), "kept": kept, "older_than_days": older_than_days,
            "artifacts": deleted[:20]}


def _bom_components(bom: dict) -> list[dict]:
    """Components of either BOM format in the scanner's component shape.

    SPDX documents describe their own subject as a package, which is not a
    component — counting it would add a phantom unpinned component to reports.
    """
    from devsecops.sbom_assurance import spdx_components

    out = []
    if str(bom.get("bomFormat") or "").lower() == "cyclonedx":
        for comp in bom.get("components") or []:
            out.append({"name": comp.get("name"), "version": comp.get("version"),
                        "ecosystem": (comp.get("purl") or "").split(":")[1].split("/")[0]
                        if comp.get("purl") else None})
        return out
    for pkg in spdx_components(bom):
        purl = None
        for ref in pkg.get("externalRefs") or []:
            if str(ref.get("referenceType") or "").lower() == "purl":
                purl = str(ref.get("referenceLocator") or "")
        version = str(pkg.get("versionInfo") or "")
        out.append({"name": pkg.get("name"),
                    "version": None if version == "NOASSERTION" else version,
                    "ecosystem": purl.split(":")[1].split("/")[0] if purl else None})
    return out


def _is_crypto_component(component: dict, bom: dict) -> bool:
    if str(bom.get("bomFormat") or "").lower() != "cyclonedx":
        return False
    for comp in bom.get("components") or []:
        if comp.get("name") == component.get("name"):
            return any(isinstance(p, dict) and p.get("name") == "cryptoscan:crypto-library"
                       and str(p.get("value")) == "true" for p in (comp.get("properties") or []))
    return False


@router.get("/sbom/{artifact_id}/download")
def sbom_download(artifact_id: str, user: str = Depends(require_roles(*_SBOM_READERS))):
    """Download a persisted SBOM artifact (JSON) with its provenance header."""
    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = next((m for m in store.list_manifests() if m.get("artifact_id") == artifact_id), None)
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        blob = store.get(man["storage_key"])
    except Exception:  # noqa: BLE001 — manifest without a readable blob
        raise HTTPException(status_code=404, detail="artifact not found")
    ext = "cdx.json" if man.get("format") == "cyclonedx" else "spdx.json"
    return Response(
        content=blob, media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="cryptoscan-sbom-{artifact_id[:8]}.{ext}"',
            "X-SBOM-SHA256": str(man.get("sha256") or ""),
        })


# ------------------------------------------------- 17-20. connector previews #
# These endpoints build the outbound payload (and, for a configured live
# transport, deliver it). They always return the constructed payload + dedup
# key so an operator can preview/audit before enabling a target.
class ConnectorRequest(BaseModel):
    provider: str
    finding: dict
    target: dict = Field(default_factory=dict)
    deliver_live: bool = False


@router.post("/connectors/preview")
def connector_preview(body: ConnectorRequest,
                      db: Session = Depends(get_db_session),
                      user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    """Build (and optionally send) a connector payload for one finding.

    Deterministic preview: returns provider, dedup key, and the exact body that
    would be sent. With deliver_live=true and a configured target, it performs
    the real HTTP delivery using the SSRF-validated URL.
    """
    import json as _json

    from devsecops import connectors

    # Air-gap read-only mode must block live delivery BEFORE any network attempt
    # or payload build (fail-closed, 423 Locked).
    if body.deliver_live:
        _enforce_airgap_writable("connector.deliver")

    f = body.finding
    target = body.target
    captured: dict = {}

    def capture(url, *, content, headers, timeout=10):
        from control_plane.delivery import validate_webhook_url

        validate_webhook_url(url)  # raises on SSRF/unsafe target
        captured["url"] = url
        captured["headers"] = {k: ("***" if "auth" in k.lower() else v) for k, v in headers.items()}
        try:
            captured["body"] = _json.loads(content.decode())
        except Exception:
            captured["body_raw"] = content.decode()[:4000]
        if body.deliver_live:
            post = connectors.default_http_post()
            return post(url, content=content, headers=headers, timeout=timeout)
        from devsecops.connectors import HttpResult

        return HttpResult(ok=True, status=200, body="{}")

    provider = body.provider.lower()
    try:
        if provider == "servicenow":
            res = connectors.servicenow_ticket(
                f, instance=target.get("instance", "example.service-now.com"),
                auth=target.get("auth", "preview"), table=target.get("table", "incident"), post=capture)
        elif provider == "jira":
            res = connectors.jira_issue(
                f, base_url=target.get("base_url", "https://jira.example.com"),
                auth=target.get("auth", "preview"), project=target.get("project", "SEC"), post=capture)
        elif provider == "splunk":
            res = connectors.splunk_hec(
                [f], hec_url=target.get("hec_url", "https://splunk.example.com:8088"),
                token=target.get("token", "preview"), post=capture)
        elif provider == "elastic":
            res = connectors.elastic_bulk(
                [f], base_url=target.get("base_url", "https://es.example.com:9200"),
                index=target.get("index", "findings"), auth=target.get("auth", "preview"), post=capture)
        elif provider == "slack":
            res = connectors.slack_message(f, webhook_url=target.get("webhook_url", "https://hooks.slack.com/x"), post=capture)
        elif provider == "teams":
            res = connectors.teams_adaptive_card(f, webhook_url=target.get("webhook_url", "https://teams.example.com/x"), post=capture)
        elif provider == "kafka":
            produced = []
            res = connectors.kafka_stream(
                [f], topic=target.get("topic", "findings"),
                bootstrap=target.get("bootstrap", ""),
                producer=(lambda t, v, h: produced.append({"topic": t, "value": _json.loads(v.decode()), "headers": h})))
            captured["messages"] = produced
        elif provider == "rabbitmq":
            published = []
            res = connectors.rabbit_stream(
                [f], exchange=target.get("exchange", "security"), routing_key=target.get("routing_key", "findings"),
                publisher=(lambda ex, rk, b, p: published.append({"exchange": ex, "routing_key": rk, "properties": p})))
            captured["messages"] = published
        else:
            raise HTTPException(status_code=422,
                                detail=f"unknown provider {provider!r}; supported: servicenow, jira, splunk, elastic, slack, teams, kafka, rabbitmq")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"connector error: {exc}")

    if body.deliver_live:
        UserRepository(db).audit(user, "devsecops.connector_delivery", target_type="integration",
                                 target_id=provider, detail={"ok": res.get("ok"), "dedup_key": res.get("dedup_key")})
        db.commit()
    return {"provider": provider, "result": res, "delivered_live": body.deliver_live,
            "preview": captured}


# ------------------------------------------------- 20. inbound chat actions -- #
class ChatActionRequest(BaseModel):
    platform: str = Field(..., description="slack | teams")
    action: str = Field(..., description="ack | assign | ticket")
    key: str
    finding_id: str
    actor: str
    # Slack signature verification (v0 HMAC) — optional in preview; required live
    timestamp: str | None = None
    signature: str | None = None
    raw_body: str | None = None
    signing_secret: str | None = None


@router.post("/chat/action")
def chat_action(body: ChatActionRequest, db: Session = Depends(get_db_session),
                user: str = Depends(require_roles("admin", "security_analyst", "auditor", "superadmin"))):
    """Deterministic inbound ack/assign/ticket handler for Slack/Teams buttons.

    Verifies the platform request signature (Slack v0 HMAC) when provided, then
    applies the state transition idempotently and writes an audit entry. Fails
    closed on bad signature / unknown action / mismatched dedup key.
    """
    from devsecops import sync as dsync

    # Signature verification (fail-closed when a secret+signature are supplied)
    if body.platform == "slack" and body.signing_secret:
        raw = (body.raw_body or "").encode()
        if not body.signature or not body.timestamp or not dsync.verify_slack_request(
                signing_secret=body.signing_secret, timestamp=body.timestamp,
                body=raw, signature=body.signature):
            UserRepository(db).audit(user, "devsecops.chat_action_rejected", target_type="finding",
                                     target_id=body.finding_id, detail={"reason": "bad signature"},
                                     outcome="FAILURE")
            db.commit()
            raise HTTPException(status_code=401, detail="invalid Slack request signature")

    # Persist finding lifecycle state in the settings-backed store so ack/assign
    # survives restarts and is shared with bidirectional ITSM sync.
    from db.repositories.settings_repository import SettingsRepository
    from devsecops.finding_state import FindingStateStore

    store = FindingStateStore(SettingsRepository(db))
    state = store.get_or_create(body.finding_id)
    result = dsync.apply_chat_action(state, action=body.action, key=body.key,
                                     actor=body.actor, finding=body.finding_id)
    if result.get("ok"):
        store.save(state, by=user)
    if not result.get("ok"):
        UserRepository(db).audit(user, "devsecops.chat_action_rejected", target_type="finding",
                                 target_id=body.finding_id, detail={"reason": result.get("error")},
                                 outcome="FAILURE")
        db.commit()
        raise HTTPException(status_code=400, detail=result.get("error") or "action rejected")

    UserRepository(db).audit(user, f"devsecops.chat_{body.action}", target_type="finding",
                             target_id=body.finding_id,
                             detail={"platform": body.platform, "actor": body.actor,
                                     "idempotent": result.get("idempotent", False),
                                     "new_status": result["state"]["status"]})
    db.commit()
    return {"ok": True, "platform": body.platform, "action": body.action,
            "finding_id": body.finding_id, "state": result["state"],
            "idempotent": result.get("idempotent", False),
            "audit": result.get("audit")}


# ------------------------------------------- 17. bidirectional ticket sync -- #
class TicketPullRequest(BaseModel):
    provider: str = Field(..., description="servicenow | jira")
    # Injected remote state (deterministic reconciliation). Ignored when
    # live=true, which performs real HTTPS GET against a configured instance.
    remote_rows: list[dict] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    live: bool = False
    instance: str | None = None     # ServiceNow host (e.g. acme.service-now.com)
    base_url: str | None = None     # Jira base URL
    auth: str | None = None         # Basic auth token (base64 user:pass)
    jql: str | None = None


@router.post("/tickets/sync-pull")
def ticket_sync_pull(body: TicketPullRequest, db: Session = Depends(get_db_session),
                     user: str = Depends(require_roles("admin", "security_analyst", "auditor", "superadmin"))):
    """Reconcile remote ITSM ticket state (status/assignee/comments) back onto
    local findings by de-dup key. Persists reconciled state and audits changes.

    Two modes:
    - live=false (default): remote_rows supplied in the request (deterministic).
    - live=true: performs a REAL HTTPS GET against the ServiceNow/Jira instance
      using provided/vault credentials; the destination is SSRF-validated and a
      reachable-but-failed poll is reported honestly (never faked)."""
    from devsecops import sync as dsync
    from devsecops.finding_state import FindingStateStore
    from db.repositories.settings_repository import SettingsRepository

    state_store = FindingStateStore(SettingsRepository(db))
    states = {fid: state_store.get_or_create(fid) for fid in body.finding_ids}

    synced = set()
    for st in states.values():
        synced.update(st.synced_comment_ids)

    transport_errors: list[dict] = []
    if body.live:
        # REAL HTTP transport against a live ITSM (SSRF-validated).
        from devsecops import runtime_adapters as rt
        from control_plane.delivery import validate_webhook_url
        auth = body.auth or os.environ.get("ITSM_BASIC_AUTH", "")
        if not auth:
            raise HTTPException(400, "live sync requires ITSM credentials (auth or ITSM_BASIC_AUTH)")
        base = body.instance or body.base_url
        if not base:
            raise HTTPException(400, "live sync requires instance (ServiceNow) or base_url (Jira)")
        host = base if base.startswith("http") else f"https://{base}"
        try:
            validate_webhook_url(f"{host}/api/now/table/incident") if body.provider == "servicenow" \
                else validate_webhook_url(f"{host}/rest/api/3/search/jql")
        except Exception as exc:  # noqa: BLE001 - SSRF rejection
            raise HTTPException(421, f"destination rejected (SSRF/unsafe): {exc}")
        raw_get = rt.urllib_get()

        def live_get(url, headers=None):
            h = {"Accept": "application/json", "Authorization": f"Basic {auth}", **(headers or {})}
            return raw_get(url, headers=h)
        ts = dsync.TicketSync(get=live_get, synced_comments=synced)
        if body.provider == "servicenow":
            outcomes = ts.pull_servicenow(states, instance=host, auth=auth)
        elif body.provider == "jira":
            outcomes = ts.pull_jira(states, base_url=host, auth=auth, jql=body.jql or "labels = cryptoscan")
        else:
            raise HTTPException(422, "provider must be servicenow or jira")
        # surface any poll failure honestly
        for o in outcomes:
            if not o.get("ok"):
                transport_errors.append({"provider": o.get("provider"), "error": o.get("error")})
    else:
        # Deterministic injected mode.
        remote_json = {"result": body.remote_rows} if body.provider == "servicenow" \
            else {"issues": body.remote_rows}
        import json as _json

        def fake_get(url, headers=None):
            from devsecops.connectors import HttpResult
            return HttpResult(ok=True, status=200, body=_json.dumps(remote_json))

        ts = dsync.TicketSync(get=fake_get, synced_comments=synced)
        if body.provider == "servicenow":
            outcomes = ts.pull_servicenow(states, instance="injected", auth="injected")
        elif body.provider == "jira":
            outcomes = ts.pull_jira(states, base_url="https://injected", auth="x")
        else:
            raise HTTPException(422, "provider must be servicenow or jira")

    # persist reconciled states (including synced comment ids for idempotency)
    for fid, st in states.items():
        st.synced_comment_ids = sorted(ts._synced_comments)
        state_store.save(st, by=user)

    reconciled = [o for o in outcomes if o.get("action") == "RECONCILED"]
    for o in reconciled:
        UserRepository(db).audit(user, f"devsecops.ticket_sync_{body.provider}",
                                 target_type="finding", target_id=o.get("finding_id", ""),
                                 detail={"ticket_id": o.get("ticket_id"), "changes": o.get("changes")})
    db.commit()
    return {"provider": body.provider, "mode": "live" if body.live else "injected",
            "reconciled": len(reconciled),
            "no_match": sum(1 for o in outcomes if o.get("action") == "NO_MATCH"),
            "transport_errors": transport_errors,
            "ok": not transport_errors,
            "outcomes": outcomes,
            "states": {fid: st.to_dict() for fid, st in states.items()}}
