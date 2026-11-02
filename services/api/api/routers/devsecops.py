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

import logging

logger = logging.getLogger(__name__)


import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, get_job_repository, require_roles
from db.repositories.job_repository import JobRepository
from db.repositories.user_repository import UserRepository

# the manifest/store half of a binary artifact lives in the devsecops package:
# the same functions serve this router (synchronous scan) and the worker process
# (queued job), so both produce one artifact, not two dialects of one
from devsecops.artifact_crypto import ArtifactCryptoError
from devsecops.artifact_store import (
    MAX_REPORT_FINDINGS,
    at_rest_status as _at_rest_status,
    audit_artifact,
    binary_posture as _binary_posture,
    finding_excerpt as _finding_excerpt,
    find_manifest as _find_manifest,
    read_artifact_blob as _read_artifact_blob,
    read_artifact_cbom as _read_artifact_cbom,
    severity_counts as _severity_counts,
    store_binary_artifact,
    visible_manifests as _visible_manifests,
)

router = APIRouter(prefix="/devsecops", tags=["devsecops"])

#: how many recent jobs a batch status looks at (the batch lives on the jobs)
_BATCH_WINDOW = 500


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
    from devsecops.sbom import (check_pinning, dependency_graph, guard_import,
                                import_sbom, mark_imported)

    # An imported document is untrusted input: it is measured against the parser
    # budget and screened for attempts to overwrite an observed fact *before* a
    # component is read out of it, and every row it contributes is labelled.
    try:
        screening = guard_import(body.doc, source=f"api:/sbom/import:{user}")
        comps = mark_imported(import_sbom(body.doc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"component_count": len(comps), "components": comps,
            "trust": screening["trust"], "may_override": screening["may_override"],
            "content_hash": screening["content_hash"],
            "import_budget": screening["budget"],
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
    A production install whose store is unconfigured or unbacked raises
    :class:`StorageRefused` there rather than degrading to a temporary directory;
    the API turns that into a 503 that names what is missing, because an artifact
    the bank cannot find tomorrow is not evidence.
    """
    from devsecops.artifact_store import StorageRefused, artifact_storage

    global _SBOM_STORE
    if _SBOM_STORE is None:
        try:
            _SBOM_STORE = artifact_storage()
        except StorageRefused as exc:
            raise HTTPException(status_code=503,
                                detail=f"SBOM artifact storage unavailable: {exc}")
    return _SBOM_STORE


def _artifact_tenant(request: Request, db: Session | None = None,
                     user: str | None = None) -> str | None:
    """Which tenant's artifacts this request may read and write.

    Three cases, in order: an API key minted inside a tenant is hard-bound to it
    (the auth middleware puts the binding on the request, and a mismatched
    ``X-Tenant-ID`` was already refused) — that is the path scanners use; a
    session caller uses the middleware's membership-validated selected tenant
    (or an explicitly membership-validated ``X-Tenant-ID``); only a caller with
    no selected tenant uses the **platform estate** (``None``), which is where
    artifacts written before tenancy live. So nothing on disk became unreadable,
    and a tenant-bound key can never reach another tenant's bucket by accident.
    """
    binding = getattr(request.state, "tenant_id", None)
    if binding:
        return str(binding)
    header = (request.headers.get("x-tenant-id") or "").strip()
    # Session principals with one/default tenant need no explicit header.
    # TenantScopeMiddleware already validated that selection. Using only the
    # header here would write their files into the platform bucket while the
    # ORM stamps their database rows into a tenant, splitting the identity join.
    from db.tenancy import current_tenant
    active = current_tenant()
    if active is not None:
        if header and header != active:
            raise HTTPException(status_code=403, detail="artifact tenant differs from the active request scope")
        return active
    if not header:
        return None
    if db is None or not user:
        raise HTTPException(status_code=403, detail="X-Tenant-ID needs a tenant-scoped principal")
    from db.repositories.tenant_repository import TenantRepository

    if TenantRepository(db).membership(header, user) is None:
        raise HTTPException(status_code=403, detail=f"not a member of tenant {header}")
    return header


def _sealed_error(exc: ArtifactCryptoError) -> HTTPException:
    """Map a sealing failure to an answer that names the reason.

    A cross-tenant object is *absent* (the manifest lookup already filtered it);
    an object this tenant owns but cannot open — no key on this host, a rotated
    master, an edited object — is a 422 carrying the reason, never an empty
    document that would read as "the artifact says nothing".
    """
    if exc.reason == "wrong_tenant":
        return HTTPException(status_code=404, detail="artifact not found")
    return HTTPException(status_code=422, detail={"message": str(exc), "reason": exc.reason})


def _artifact_blob(store, manifest: dict, tenant_id: str | None,
                   *, label: str = "stored SBOM"):
    """(plaintext, at_rest) for an artifact of this tenant, or a 404/422."""
    try:
        return _read_artifact_blob(store, manifest, tenant_id=tenant_id, label=label)
    except ArtifactCryptoError as exc:
        raise _sealed_error(exc) from exc


def _artifact_cbom_blob(store, manifest: dict, tenant_id: str | None):
    try:
        return _read_artifact_cbom(store, manifest, tenant_id=tenant_id)
    except ArtifactCryptoError as exc:
        raise _sealed_error(exc) from exc


@router.get("/binary/at-rest")
def binary_at_rest(request: Request, db: Session = Depends(get_db_session),
                   user: str = Depends(require_roles(*_SBOM_READERS))):
    """How this tenant's artifacts are protected on disk — and what is on the disk.

    An auditor asks two questions this endpoint answers together: is the payload
    encrypted, with which key (id only), and are there artifacts in my bucket that
    are *not*? Counting by algorithm is what turns "encryption is configured" into
    "every artifact but the three from before the upgrade".
    """
    tenant = _artifact_tenant(request, db, user)
    store = _sbom_storage()
    rows = _visible_manifests(store, tenant_id=tenant)
    counts: dict[str, int] = {}
    key_ids: dict[str, int] = {}
    for row in rows:
        at_rest = row.get("at_rest") or {}
        algorithm = str(at_rest.get("algorithm") or "unrecorded")
        counts[algorithm] = counts.get(algorithm, 0) + 1
        if at_rest.get("key_id"):
            key_ids[str(at_rest["key_id"])] = key_ids.get(str(at_rest["key_id"]), 0) + 1
    return {"tenant": tenant or "platform",
            "at_rest": _at_rest_status(tenant),
            "artifacts": len(rows),
            "by_algorithm": counts,
            "by_key_id": key_ids,
            "plaintext_artifacts": counts.get("none", 0) + counts.get("unrecorded", 0)}


def _sbom_signing_secret(db: Session | None) -> tuple[str | None, str]:
    """(secret, key_id) for signing SBOM manifests — the platform-wide order.

    Vault ref > persisted settings key > HKDF from the platform master > this
    process's configured ``SECRET_KEY``. The last one is stable across restarts
    (unlike a process-random fallback), so ``/verify`` keeps agreeing with
    artifacts signed earlier in the same deployment.
    """
    from devsecops.artifact_store import resolve_signing_secret

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
def sbom_scan(body: SbomScanRequest, request: Request,
              db: Session = Depends(get_db_session),
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

    binary_bundle: dict[str, dict] = {}
    if kind == "binary":
        cbom = binary.cbom_document(binary_result, target=str(binary_result.get("target") or resolved),
                                    created_by=user)
        from devsecops.binary_boms import build_binary_bom_bundle

        binary_bundle = build_binary_bom_bundle(
            binary_result, result, sbom=bom, cbom=cbom,
            target=str(binary_result.get("target") or resolved), created_by=user)
        # The generic scanner predates tenant-aware binary storage. Route binary
        # scans through the same sealed artifact writer as the dedicated endpoint
        # and worker so a caller cannot receive an unencrypted, platform-scoped
        # sidecar by choosing /sbom/scan.
        stored = store_binary_artifact(
            scan=binary_result, result=result, bom=bom, cbom=cbom, fmt=fmt,
            created_by=user, db=db, artifact_id=None, feed_supplied=bool(body.feed),
            recursive=body.recursive, include_raw=body.include_raw,
            secret=_sbom_signing_secret(db),
            tenant_id=_artifact_tenant(request, db, user), bom_bundle=binary_bundle)
        manifest = stored["manifest"]
        artifact_id = stored["artifact_id"]
        UserRepository(db).audit(
            user, "devsecops.sbom_scan", target_type="sbom_artifact", target_id=artifact_id,
            detail={"kind": kind, "target": manifest["target"], "format": fmt,
                    "components": manifest.get("component_count", 0),
                    "sha256": manifest.get("sha256", "")[:16]},
        )
        db.commit()
        return {
            "artifact_id": artifact_id, "manifest": manifest,
            "database_indexed": bool(stored.get("database_indexed")),
            "compliance": stored["compliance"], "download_url":
            f"/api/v1/devsecops/sbom/{artifact_id}/download",
            "report_url": f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown",
            "verify_url": f"/api/v1/devsecops/sbom/{artifact_id}/verify", "bom": bom,
            "cbom": cbom, "bom_documents": manifest.get("bom_documents") or {},
            "bom_types": ["SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "VULNERABILITY_BOM", "TECHNOLOGY_BOM"],
        }
    packages = result.get("packages") or []
    payload = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha256 = hashlib.sha256(payload).hexdigest()
    artifact_id = str(uuid.uuid4())
    ext = "cdx.json" if fmt == "cyclonedx" else "spdx.json"
    from devsecops.artifact_store import artifact_tenant_bucket, storage_status
    tenant = _artifact_tenant(request, db, user)
    key = f"tenants/{artifact_tenant_bucket(tenant)}/{artifact_id}.{ext}"

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
        "tenant_id": tenant,
        "tenant_bucket": artifact_tenant_bucket(tenant),
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
        # the graph as the parser budget measured it: depth, cycle count and what
        # was withheld, so "0 edges" is never mistaken for "no dependencies"
        "parser_budget": result.get("parser_budget") or None,
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
        "storage": storage_status(),
        "cbom_storage_key": f"{artifact_id}.cbom.json" if kind == "binary" else None,
        "bom_documents": ({
            name: {"storage_key": f"{artifact_id}.{name.replace('_', '-')}.json",
                   "sha256": hashlib.sha256(json.dumps(document, sort_keys=True,
                                                        separators=(",", ":")).encode("utf-8")).hexdigest(),
                   "encrypted": False, "format": document.get("bomFormat", "json"),
                   "component_count": len(document.get("components") or []),
                   "vulnerability_count": len(document.get("vulnerabilities") or [])}
            for name, document in binary_bundle.items()
            if name not in {"sbom", "cbom", "vendor_bom", "vulbom"} and isinstance(document, dict) and document
        } if kind == "binary" else {}),
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
    if kind == "binary" and binary_bundle:
        cbom_payload = json.dumps(binary_bundle.get("cbom") or {}, sort_keys=True,
                                  separators=(",", ":")).encode("utf-8")
        store.put(str(manifest["cbom_storage_key"]), cbom_payload)
        for name, document in binary_bundle.items():
            if name in {"sbom", "cbom", "vendor_bom", "vulbom"} or not isinstance(document, dict) or not document:
                continue
            side_key = str((manifest.get("bom_documents") or {}).get(name, {}).get("storage_key") or "")
            if side_key:
                store.put(side_key, json.dumps(document, sort_keys=True,
                                                separators=(",", ":")).encode("utf-8"))
    store.put_manifest(key, manifest)
    UserRepository(db).audit(user, "devsecops.sbom_scan", target_type="sbom_artifact",
                             target_id=artifact_id,
                             detail={"kind": kind, "target": manifest["target"], "format": fmt,
                                     "components": component_count, "sha256": sha256[:16]})
    db.commit()
    return {"artifact_id": artifact_id, "manifest": manifest, "compliance": compliance,
            "parser_budget": manifest.get("parser_budget"),
            "download_url": f"/api/v1/devsecops/sbom/{artifact_id}/download",
            "report_url": f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown",
            "verify_url": f"/api/v1/devsecops/sbom/{artifact_id}/verify",
            "bom": bom,
            "bom_documents": manifest.get("bom_documents") or {},
            "bom_types": (["SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "VULNERABILITY_BOM", "TECHNOLOGY_BOM"]
                          if kind == "binary" else ["SBOM"])}


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
    max_total_bytes: int = Field(2 * 1024 * 1024 * 1024, ge=1, le=8 * 1024 * 1024 * 1024,
                                 description="walk-wide input byte budget")
    max_seconds: float = Field(15 * 60, ge=0.1, le=2 * 60 * 60,
                               description="walk-wide wall-clock budget")


class BinaryScanJobRequest(BaseModel):
    """Queue a binary scan instead of waiting for it in the request."""

    target: str = Field(..., min_length=1, max_length=4096)
    yara_rules: list[str] | None = Field(None, description=(
        "rule files or directories; the built-in rules always run"))
    format: str = Field("cyclonedx", description="cyclonedx | spdx for the SBOM half")
    recursive: bool = True
    include_raw: bool = Field(False, description="keep raw hex context in findings")
    ingest_cbom: bool = Field(False, description="load the CBOM into the crypto inventory")
    system_name: str | None = Field(None, max_length=200, description="CBOM: system the assets belong to")
    system_id: str | None = Field(None, max_length=64, description="stamp this system when the job finishes")
    artifact_id: str | None = Field(None, max_length=64, description=(
        "the artifact id to write; minted here when omitted, so the caller can poll the "
        "artifact before the scan has finished"))
    batch_id: str | None = Field(None, max_length=64, description=(
        "record this job as part of an intake batch, so "
        "GET /devsecops/binary/batches/{batch_id} reports on the whole pass"))
    max_total_bytes: int = Field(2 * 1024 * 1024 * 1024, ge=1, le=8 * 1024 * 1024 * 1024,
                                 description="walk-wide input byte budget")
    max_seconds: float = Field(15 * 60, ge=0.1, le=2 * 60 * 60,
                               description="walk-wide wall-clock budget")


class BinaryScanJobResponse(BaseModel):
    job_id: str
    artifact_id: str
    status: str
    queued_options: dict
    message: str
    report_url: str
    verify_url: str
    poll_url: str


def _binary_options(*, target: str, artifact_id: str, rules: list[str] | None = None,
                     fmt: str = "cyclonedx", recursive: bool = True, include_raw: bool = False,
                     ingest_cbom: bool = False, system_name: str | None = None,
                     batch_id: str | None = None, tenant_id: str | None = None,
                     max_total_bytes: int = 2 * 1024 * 1024 * 1024,
                     max_seconds: float = 15 * 60) -> dict:
    """The options a queued binary scan runs with — one builder for both entry points.

    A single queued scan and a fleet pass have to produce the same artifact, so
    the options are assembled here instead of at each call site. ``tenant_id``
    travels with them because a worker process has no request to ask: without it
    the job would store the artifact in the platform estate and its tenant would
    then have no way to read back its own scan.
    """
    options: dict = {
        "kind": "binary",
        "target": target,
        "yara_rules": list(rules or []),
        "format": "spdx" if str(fmt).lower() == "spdx" else "cyclonedx",
        "recursive": bool(recursive),
        "include_raw": bool(include_raw),
        "ingest_cbom": bool(ingest_cbom),
        "max_total_bytes": int(max_total_bytes),
        "max_seconds": float(max_seconds),
        "system_name": system_name,
        "artifact_id": artifact_id,
        "tenant_id": tenant_id,
    }
    if batch_id:
        options["batch_id"] = batch_id
    return options


@router.post("/binary/jobs", status_code=status.HTTP_202_ACCEPTED,
             response_model=BinaryScanJobResponse)
def binary_scan_job(
    body: BinaryScanJobRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    job_repo: JobRepository = Depends(get_job_repository),
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_SBOM_OPERATORS)),
):
    """Queue a binary/firmware scan; poll the job, then read the artifact.

    The synchronous endpoint above is the right call for a directory a request
    can afford to wait for. A firmware image, a release bundle, or a fleet of
    artefacts is not that: this queues the same scan as a job, so it can be
    retried, followed in the console, and failed visibly.

    The artifact id is chosen *now* and returned with the job id, which means the
    report URL is pollable from the moment of acceptance — a scan that has not
    finished has no artifact to read, and the endpoints say so rather than
    inventing one.
    """
    import uuid as _uuid

    from api.security.target_validation import TargetValidationError, validate_source_target
    from api.routers.trigger import enqueue_scan_job

    _enforce_airgap_writable("devsecops.binary_scan_job")
    if body.format.lower() not in ("cyclonedx", "cdx", "spdx"):
        raise HTTPException(status_code=422, detail="format must be cyclonedx or spdx")
    try:
        resolved = validate_source_target(body.target, label="target")
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not Path(resolved).expanduser().exists():
        raise HTTPException(status_code=404, detail=f"scan target not found: {resolved}")

    rule_paths: list[str] = []
    for entry in body.yara_rules or []:
        try:
            rule_paths.append(validate_source_target(entry, label="rule path"))
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not Path(rule_paths[-1]).expanduser().exists():
            raise HTTPException(status_code=404, detail=f"rule path not found: {rule_paths[-1]}")

    artifact_id = body.artifact_id or str(_uuid.uuid4())
    options = _binary_options(
        target=resolved, artifact_id=artifact_id, rules=rule_paths, fmt=body.format,
        recursive=bool(body.recursive), include_raw=bool(body.include_raw),
        ingest_cbom=bool(body.ingest_cbom), system_name=body.system_name,
        batch_id=body.batch_id, tenant_id=_artifact_tenant(request, db, user),
        max_total_bytes=body.max_total_bytes, max_seconds=body.max_seconds,
    )
    queued = enqueue_scan_job(
        job_repo, background_tasks,
        repo_url=f"binary://{resolved}",
        branch="main",
        triggered_by=user,
        job_type="BINARY",
        system_id=body.system_id,
        scan_options=options,
    )
    job_id = str(getattr(queued, "job_id", "") or "")
    return BinaryScanJobResponse(
        job_id=job_id,
        artifact_id=artifact_id,
        status=str(getattr(queued, "status", "") or "QUEUED"),
        queued_options=options,
        message=(f"Binary scan queued. Poll /api/v1/jobs/{job_id} for status; the "
                 f"artifact appears at the report URL when it exists."),
        report_url=f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown",
        verify_url=f"/api/v1/devsecops/sbom/{artifact_id}/verify",
        poll_url=f"/api/v1/jobs/{job_id}",
    )


class BinaryBatchRequest(BaseModel):
    """Take a directory of binaries and queue what actually needs scanning."""

    spool: str = Field(..., min_length=1, max_length=4096,
                       description="directory the binaries are dropped into")
    dry_run: bool = Field(True, description="plan the pass and queue nothing (the default)")
    patterns: list[str] | None = Field(None, description=(
        "glob patterns to take; defaults to the usual binary/archive names, plus "
        "extension-less files with the execute bit"))
    min_size: int | None = Field(None, ge=0, description="skip files smaller than this (default 64)")
    max_size: int | None = Field(None, ge=1, description="skip files larger than this (default 512 MiB)")
    limit: int = Field(50, ge=1, le=500, description=(
        "queue at most this many files in one pass — a fleet arrives faster than it is "
        "worth queueing blindly, and the rest is reported rather than dropped"))
    force: bool = Field(False, description="re-queue content that was scanned in an earlier pass")
    recursive: bool = True
    format: str = Field("cyclonedx", description="cyclonedx | spdx for the SBOM half")
    include_raw: bool = Field(False, description="keep raw hex context in findings")
    ingest_cbom: bool = Field(False, description="load each CBOM into the crypto inventory")
    system_name: str | None = Field(None, max_length=200, description="CBOM: system the assets belong to")
    system_id: str | None = Field(None, max_length=64, description="stamp this system on every queued job")
    yara_rules: list[str] | None = Field(None, description="rule files/directories for every file in the pass")
    batch_id: str | None = Field(None, max_length=64, description="reuse a batch id (a retry of the pass)")


@router.post("/binary/batch")
def binary_batch(
    body: BinaryBatchRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    job_repo: JobRepository = Depends(get_job_repository),
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_SBOM_OPERATORS)),
):
    """Queue a pass over a spool directory — once per *distinct* binary.

    Identity here is content, not path: the same library shipped at eleven paths
    is one scan, and a file whose content changed is a new scan even at the path
    that was scanned yesterday. Every file that is not queued comes back with the
    reason and, where one exists, the artifact that already covers it — because
    "0 queued" and "everything was already scanned" must not look the same.

    ``dry_run`` (the default) returns the plan and starts nothing, so an operator
    can see exactly what a pass would do before it does it. The memory of what was
    scanned lives beside the spool (``<spool>/.cryptoscan-intake.json``); if that
    file cannot be written the pass says so rather than re-scanning the fleet in
    silence next time.
    """
    import uuid as _uuid

    from api.security.target_validation import TargetValidationError, validate_source_target
    from api.routers.trigger import enqueue_scan_job
    from devsecops.intake import load_state, plan_intake, record_outcome, save_state, state_path_for

    if not body.dry_run:
        _enforce_airgap_writable("devsecops.binary_batch")

    try:
        spool = validate_source_target(body.spool, label="spool")
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not Path(spool).expanduser().is_dir():
        raise HTTPException(status_code=404, detail=f"spool directory not found: {spool}")

    rule_paths: list[str] = []
    for entry in body.yara_rules or []:
        try:
            rule_paths.append(validate_source_target(entry, label="rule path"))
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    batch_id = body.batch_id or str(_uuid.uuid4())
    state_file = state_path_for(spool)
    plan_kwargs: dict = {"limit": body.limit, "force": bool(body.force), "recursive": bool(body.recursive)}
    if body.patterns:
        plan_kwargs["patterns"] = tuple(body.patterns)
    if body.min_size is not None:
        plan_kwargs["min_size"] = body.min_size
    if body.max_size is not None:
        plan_kwargs["max_size"] = body.max_size
    plan = plan_intake(spool, state_file=state_file, **plan_kwargs)

    # the plan's own answer, filled in with job/artifact ids once anything is queued:
    # a dry run must report what it *would* do, not an empty list plus a message
    queued_files: list[dict] = [
        {"path": candidate.path, "sha256": candidate.sha256, "size": candidate.size,
         "reason": candidate.reason, "job_id": None, "artifact_id": None}
        for candidate in plan.queued
    ]
    artifact_ids: dict[str, str] = {}
    job_ids: dict[str, str] = {}
    tenant_id = _artifact_tenant(request, db, user)
    if not body.dry_run:
        for row, candidate in zip(queued_files, plan.queued):
            artifact_id = str(_uuid.uuid4())
            options = _binary_options(
                target=candidate.path, artifact_id=artifact_id, rules=rule_paths, fmt=body.format,
                recursive=bool(body.recursive), include_raw=bool(body.include_raw),
                ingest_cbom=bool(body.ingest_cbom), system_name=body.system_name,
                batch_id=batch_id, tenant_id=tenant_id,
            )
            queued = enqueue_scan_job(
                job_repo, background_tasks, repo_url=f"binary://{candidate.path}", branch="main",
                triggered_by=user, job_type="BINARY", system_id=body.system_id, scan_options=options,
            )
            candidate.job_id = str(getattr(queued, "job_id", "") or "") or None
            candidate.artifact_id = artifact_id
            artifact_ids[candidate.path] = artifact_id
            job_ids[candidate.path] = candidate.job_id or ""
            row.update({"job_id": candidate.job_id, "artifact_id": artifact_id})

    state_saved, state_note = True, None
    if not body.dry_run and plan.queued:
        try:
            state = record_outcome(load_state(state_file), plan,
                                   artifact_ids=artifact_ids, job_ids=job_ids)
            state["batch_id"] = batch_id
            save_state(state_file, state)
        except OSError as exc:
            # the queue is already fed; the memory is what failed. Say it loudly:
            # a lost memory means every pass re-scans the fleet.
            state_saved, state_note = False, (
                f"the intake state could not be written ({type(exc).__name__}: {exc}); "
                "the next pass will re-scan this content unless the spool is writable")
    elif queued_files:
        state_saved = False

    UserRepository(db).audit(
        user, "devsecops.binary_batch", target_type="binary_spool", target_id=spool,
        detail={"batch_id": batch_id, "dry_run": bool(body.dry_run), "considered": plan.considered,
                "planned": len(plan.queued),
                "queued": 0 if body.dry_run else len(queued_files),
                "skipped": len(plan.skipped), "state_saved": state_saved, "limit": body.limit},
    )
    db.commit()
    payload = plan.as_dict()
    payload.update({
        "batch_id": batch_id,
        "dry_run": bool(body.dry_run),
        "queued": len(plan.queued) if body.dry_run else len(queued_files),
        "planned": len(plan.queued),
        "queued_files": queued_files,
        "state_path": str(state_file),
        "state_saved": state_saved,
        "state_note": state_note,
        "poll_url": f"/api/v1/devsecops/binary/batches/{batch_id}",
        "ops": {"kind": "binary", "yara_rules": rule_paths, "format": body.format,
                "recursive": bool(body.recursive), "include_raw": bool(body.include_raw),
                "ingest_cbom": bool(body.ingest_cbom), "system_name": body.system_name},
        "message": ("Dry run: nothing was queued. POST the same body with dry_run=false to queue "
                    "these files." if body.dry_run else
                    f"{len(queued_files)} scan(s) queued; poll /api/v1/devsecops/binary/batches/{batch_id}."),
    })
    return payload


@router.get("/binary/batches/{batch_id}")
def binary_batch_status(
    batch_id: str,
    job_repo: JobRepository = Depends(get_job_repository),
    user: str = Depends(require_roles(*_SBOM_READERS)),
):
    """How a fleet pass is going: counts by state, and what each job has produced.

    The batch lives on the jobs themselves (``progress.scan_options.batch_id``),
    so there is no second source of truth to drift. Jobs are looked up over a
    bounded window of the most recent rows, and the answer says when that window
    was exhausted rather than reporting "0 jobs" for a pass that did happen.
    """
    jobs = job_repo.list_by_scan_option("batch_id", batch_id, limit=_BATCH_WINDOW)
    by_status: dict[str, int] = {}
    files: list[dict] = []
    artifacts: list[str] = []
    binaries = findings = matches = 0
    for job in jobs:
        options = ((job.progress or {}).get("scan_options") or {})
        progress = job.progress or {}
        binary = progress.get("binary") or {}
        status = str(getattr(job, "status", "") or "")
        by_status[status] = by_status.get(status, 0) + 1
        binaries += int(binary.get("binaries_scanned") or 0)
        findings += int(binary.get("findings") or 0)
        matches += int(binary.get("yara_matches") or 0)
        artifact_id = binary.get("artifact_id") or options.get("artifact_id")
        if artifact_id:
            artifacts.append(str(artifact_id))
        files.append({
            "job_id": str(getattr(job, "job_id", "") or ""),
            "target": options.get("target") or getattr(job, "target_repo", None),
            "status": status,
            "stage": binary.get("stage") or progress.get("current_stage"),
            "percent": progress.get("percent"),
            "error": getattr(job, "error_message", None),
            "artifact_id": artifact_id,
            "report_url": binary.get("report_url") or (f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown"
                                                      if artifact_id else None),
            "binaries_scanned": binary.get("binaries_scanned"),
            "findings": binary.get("findings"),
            "yara_matches": binary.get("yara_matches"),
        })
    return {
        "batch_id": batch_id,
        "jobs": len(files),
        "by_status": by_status,
        "artifacts": artifacts,
        "totals": {"binaries_scanned": binaries, "findings": findings, "yara_matches": matches},
        "files": files,
        "window": {"looked_at": len(jobs), "limit": _BATCH_WINDOW,
                   "truncated": len(jobs) >= _BATCH_WINDOW,
                   "note": ("the batch is stored on the jobs themselves; only the most recent "
                            f"{_BATCH_WINDOW} jobs are searched — an older batch may report 0 here")},
    }


class BinaryDynamicRequest(BaseModel):
    """Run a sample under the ADR-012 LD_PRELOAD tracer — or only preflight it."""

    target: str = Field(..., min_length=1, max_length=4096, description="the sample to analyse")
    args: list[str] = Field(default_factory=list, max_length=32,
                            description="argv handed to the sample (bounded: count and length)")
    cwd: str | None = Field(None, max_length=512,
                            description="working directory for the run (default: a scratch dir, removed after)")
    timeout: int | None = Field(None, ge=1, le=60,
                                description="wall-clock seconds; killed (whole process group) on expiry")
    execute: bool = Field(False, description=(
        "actually run the sample. Off by default; refused unless the host sets "
        "BINARY_EXECUTION_ENABLED=true (ADR-012: opt-in, never a default)"))
    submit: bool = Field(False, description=(
        "ingest the observations as runtime findings, so dynamic evidence sits beside the "
        "eBPF/mesh agent rows in the same inventory"))
    hostname: str | None = Field(None, max_length=255,
                                 description="host to attribute the observations to")
    scanner_id: str = Field("ld-preload-agent-v1.0", max_length=100,
                            description="scanner id recorded on every ingested finding")


@router.post("/binary/dynamic")
def binary_dynamic(
    body: BinaryDynamicRequest,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_SBOM_OPERATORS)),
):
    """Dynamic analysis of one sample under the LD_PRELOAD tracer (ADR-012).

    Without ``execute`` this is the preflight: it says exactly what would happen
    ("this host allows execution", "the sample is statically linked, the tracer
    cannot load", "the run budget is spent") and starts no process — which is the
    answer most callers want, because the static scan already covered the file.

    With ``execute`` the sample runs only if the host opted in *and* the sample
    passed the preflight. A refusal is a 403 with every reason, not a quiet
    "no dynamic findings": an empty dynamic result must never be readable as
    "the sample was clean".

    ``submit`` hands the observations to the runtime-findings ingest, so a
    binary's runtime crypto behaviour lands in the same inventory, verdicts and
    SSE stream as the always-on agents.
    """
    from api.security.target_validation import TargetValidationError, validate_source_target
    from devsecops import dynamic_scan as dyn

    try:
        resolved = validate_source_target(body.target, label="target")
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not Path(resolved).expanduser().exists():
        raise HTTPException(status_code=404, detail=f"sample not found: {resolved}")

    policy = dyn.ExecutionPolicy.from_env()
    result = dyn.dynamic_scan(
        resolved, args=body.args, timeout=body.timeout, policy=policy,
        cwd=body.cwd, execute=body.execute,
    )
    if body.execute and not result["executed"]:
        # asked to run, did not run: the caller must not have to read the body to notice
        raise HTTPException(status_code=403, detail={
            "message": "the sample was not executed",
            "refusals": result["refusals"],
            "checks": result["checks"],
            "limits": result["limits"],
        })
    if result["executed"]:
        _enforce_airgap_writable("devsecops.binary_dynamic")

    ingested = None
    if body.submit and result["executed"]:
        from api.routers.runtime import RuntimeFindingsBody, ingest_runtime_findings

        payload = dyn.to_runtime_findings(result, hostname=body.hostname, scanner_id=body.scanner_id)
        ingested = ingest_runtime_findings(RuntimeFindingsBody(**payload), user=user, db=db)

    UserRepository(db).audit(
        user, "devsecops.binary_dynamic", target_type="binary", target_id=str(result["target"]),
        detail={"executed": result["executed"], "refusals": result["refusals"],
                "observations": len(result["observations"]),
                "findings": len(result["findings"]), "timed_out": result["timed_out"],
                "runtime_findings_ingested": (ingested or {}).get("accepted"),
                "sha256": (result.get("sha256_before") or "")[:16]},
    )
    db.commit()
    return {**result, "runtime_ingest": ingested}


@router.post("/binary/scan", status_code=status.HTTP_201_CREATED)
def binary_scan(body: BinaryScanRequest, request: Request,
                db: Session = Depends(get_db_session),
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

    from devsecops import binary_scan as bs
    from devsecops import sbom_scan as sb
    from api.security.target_validation import TargetValidationError, validate_source_target

    # air-gap read-only mode blocks starting work, exactly as it does for the
    # queued path; reading what is already stored stays available
    _enforce_airgap_writable("devsecops.binary_scan")

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
                            max_total_bytes=body.max_total_bytes, max_seconds=body.max_seconds,
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
    from devsecops.binary_boms import build_binary_bom_bundle

    bom_bundle = build_binary_bom_bundle(
        scan, result, sbom=bom, cbom=cbom,
        target=str(scan.get("target") or resolved), created_by=user)

    findings = result.get("findings") or []
    stored = store_binary_artifact(
        scan=scan, result=result, bom=bom, cbom=cbom, fmt=fmt, created_by=user, db=db,
        artifact_id=body.artifact_id, job_id=body.job_id, feed_supplied=bool(body.feed),
        recursive=body.recursive, include_raw=body.include_raw,
        secret=_sbom_signing_secret(db),
        tenant_id=_artifact_tenant(request, db, user), bom_bundle=bom_bundle)
    artifact_id = stored["artifact_id"]
    manifest = stored["manifest"]
    compliance = stored["compliance"]
    sha256 = stored["payload_sha256"]

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
        # "is this scan encrypted at rest, and under whose key" is part of the
        # answer, not something to go and read off the disk afterwards
        "at_rest": manifest.get("at_rest") or {},
        "database_indexed": bool(stored.get("database_indexed")),
        "tenant": manifest.get("tenant_id"),
        "summary": manifest["binary_summary"],
        "findings": findings[:200],
        "crypto_libraries": result.get("libraries") or [],
        "binaries": result.get("binaries") or [],
        "cbom": cbom,
        "cbom_result": cbom_result,
        "bom_documents": manifest.get("bom_documents") or {},
        "bom_types": ["SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "VULNERABILITY_BOM", "TECHNOLOGY_BOM"],
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


# ------------------------------------------------------- knowledge packs --- #
class KnowledgeInstallRequest(BaseModel):
    pack: str = Field(..., description=(
        "a pack directory (built by devsecops.knowledge) or a .tar.gz bundle on this host"))
    dry_run: bool = Field(False, description=(
        "verify and report what would happen, without installing anything"))
    secret: str | None = Field(None, max_length=512, description=(
        "signing secret to verify the pack; omit to use CRYPTOSCAN_BUNDLE_SECRET/SECRET_KEY"))
    allow_unsigned: bool = Field(False, description=(
        "accept a pack with no signature (recorded as unsigned in the registry)"))


class KnowledgeUninstallRequest(BaseModel):
    name: str = Field(..., max_length=128, description="installed pack name")


def _knowledge_result(report: dict) -> dict:
    """Report shape the API returns: the ruleset object is summarised, not serialised."""
    ruleset = report.pop("ruleset", None)
    report["loaded_rules"] = ({"rules": len(ruleset.rules),
                               "digest": ruleset.digest,
                               "names": sorted(rule.name for rule in ruleset.rules)}
                              if ruleset is not None else None)
    return report


@router.get("/knowledge")
def knowledge_list(user: str = Depends(require_roles(*_SBOM_READERS))):
    """Which detection rules this host will load: the built-ins plus installed packs.

    This is the answer to "what does the scanner actually match?" — and in a
    disconnected install it is the answer to "did the update pack take?": the packs
    and their digests are listed, next to the digest of the set a scan will use.
    """
    from devsecops.knowledge import knowledge_state

    return knowledge_state()


@router.post("/knowledge/install")
def knowledge_install(body: KnowledgeInstallRequest,
                      user: str = Depends(require_roles(*_SBOM_OPERATORS)),
                      db: Session = Depends(get_db_session)):
    """Verify a signed rule pack, then install it so every scan loads it.

    The pack is verified — signature, per-file digests, and that its rules actually
    load in this platform's engine — before anything is written; a pack that fails
    comes back with the reasons and nothing changes on disk. Air-gap mode does not
    block this: an offline update arriving on media *is* how a disconnected install
    is updated.
    """
    from devsecops.knowledge import KnowledgeError, extract_bundle, install_pack, resolve_secret

    if not body.dry_run:
        _enforce_airgap_writable("knowledge.install")
    target = str(body.pack)
    extracted: dict | None = None
    try:
        if target.endswith((".tar.gz", ".tgz")):
            extracted = extract_bundle(target, tempfile.mkdtemp(prefix="cryptoscan-knowledge-"))
            entries = sorted(Path(extracted["dest"]).iterdir())
            target = str(entries[0]) if len(entries) == 1 and entries[0].is_dir() else extracted["dest"]
        secret, key_id = resolve_secret(body.secret)
        if body.allow_unsigned:
            secret = None
        report = install_pack(target, secret=secret, dry_run=body.dry_run,
                              require_signature=not body.allow_unsigned)
    except (KnowledgeError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result = _knowledge_result({**report, "extracted": extracted, "verified_with": key_id})
    if report.get("action") == "refused":
        UserRepository(db).audit(
            user, "devsecops.knowledge_refused", target_type="knowledge_pack",
            target_id=str((report.get("manifest") or {}).get("name") or body.pack),
            detail={"reasons": report["reasons"]}, outcome="FAILURE")
        db.commit()
        raise HTTPException(status_code=400, detail={
            "message": "the pack was refused and nothing was installed",
            "reasons": report["reasons"]})
    if not body.dry_run:
        manifest = report.get("manifest") or {}
        UserRepository(db).audit(
            user, f"devsecops.knowledge_{report['action'].replace('-', '_')}",
            target_type="knowledge_pack", target_id=str(manifest.get("name") or body.pack),
            detail={"version": manifest.get("version"), "digest": manifest.get("digest"),
                    "verified_with": key_id, "replaced": (report.get("replaced") or {}).get("version"),
                    "rules": [row["name"] for row in report.get("files") or []]})
        db.commit()
    result["note"] = ("a pack is refused or it is installed — never half-applied: the rules load "
                      "only when every file verifies and the rule text loads in this engine")
    return result


@router.post("/knowledge/uninstall")
def knowledge_uninstall(body: KnowledgeUninstallRequest,
                        user: str = Depends(require_roles(*_SBOM_OPERATORS)),
                        db: Session = Depends(get_db_session)):
    """Remove an installed pack so its rules stop being loaded."""
    from devsecops.knowledge import uninstall_pack

    _enforce_airgap_writable("knowledge.uninstall")
    report = uninstall_pack(body.name)
    if report.get("removed"):
        UserRepository(db).audit(user, "devsecops.knowledge_uninstalled",
                                 target_type="knowledge_pack", target_id=body.name,
                                 detail={"version": (report.get("removed_entry") or {}).get("version")})
        db.commit()
    return report


def _binary_tenant_clause(model: Any, tenant: str | None):
    """Keep the DB read model aligned with file-artifact visibility."""
    # A tenant-bound principal must never see legacy/platform rows with a NULL
    # owner. Only an unbound platform request can read the unowned estate.
    if tenant:
        return model.tenant_id == tenant
    return model.tenant_id.is_(None)


def _binary_record_json(record: Any) -> dict[str, Any]:
    data = record.to_dict()
    data.pop("tenant_id", None)
    # SQLAlchemy reserves the attribute name `metadata`; the model stores this
    # JSON projection as `parser_metadata`, while the API keeps the evidence
    # vocabulary stable for the console and clients.
    if "parser_metadata" in data:
        data["metadata"] = data.pop("parser_metadata")
    return data


@router.get("/binary/scans")
def binary_scans(request: Request, limit: int = 50, status_filter: str | None = None,
                 format_filter: str | None = None, q: str | None = None,
                 db: Session = Depends(get_db_session),
                 user: str = Depends(require_roles(*_SBOM_READERS))):
    """List the tenant-scoped binary read model, newest first.

    The signed manifest remains authoritative. This endpoint is intentionally a
    queryable index, so the console can show scan history and coverage without
    opening every potentially large artifact document.
    """
    from db.models.binary_scan import BinaryScanRecord

    try:
        tenant = _artifact_tenant(request, db, user)
        query = db.query(BinaryScanRecord).filter(_binary_tenant_clause(BinaryScanRecord, tenant))
        if status_filter:
            query = query.filter(BinaryScanRecord.status == status_filter.strip().upper())
        if format_filter:
            query = query.filter(BinaryScanRecord.format == format_filter.strip().lower())
        if q:
            needle = f"%{q.strip()}%"
            query = query.filter(BinaryScanRecord.target.ilike(needle))
        total = query.count()
        rows = query.order_by(BinaryScanRecord.created_at.desc()).limit(max(1, min(limit, 200))).all()
        return {"total": total, "returned": len(rows),
                "records": [_binary_record_json(row) for row in rows],
                "source": "database-read-model",
                "note": "signed artifact manifests remain the authoritative export"}
    except SQLAlchemyError as exc:
        logger.warning("binary_scan_index_unavailable", extra={"error_type": type(exc).__name__})
        raise HTTPException(status_code=503,
                            detail="binary scan index is unavailable; apply migration 0063") from exc


def _binary_scan_row(db: Session, scan_id: str, tenant: str | None):
    """Load one scan using the same exact tenant predicate for every read path."""
    from db.models.binary_scan import BinaryScanRecord

    return db.query(BinaryScanRecord).filter(
        BinaryScanRecord.id == scan_id,
        _binary_tenant_clause(BinaryScanRecord, tenant)).first()


def _binary_scan_observation_query(db: Session, scan_id: str, tenant: str | None):
    """Build the bounded observation query after the parent scan is authorized."""
    from db.models.binary_scan import BinaryScanObservation

    return db.query(BinaryScanObservation).filter(
        BinaryScanObservation.scan_record_id == scan_id,
        _binary_tenant_clause(BinaryScanObservation, tenant))


def _binary_finding_rows(record: Any, observations: list[Any]) -> list[dict[str, Any]]:
    """Project scan and observation findings into a bounded, deduplicated list."""
    rows: list[dict[str, Any]] = []
    summary = record.summary if isinstance(record.summary, dict) else {}
    binary_summary = summary.get("binary_summary") if isinstance(summary.get("binary_summary"), dict) else summary
    for finding in (binary_summary or {}).get("findings_excerpt") or []:
        if isinstance(finding, dict):
            rows.append({**finding, "source": "scan-summary"})
    for observation in observations:
        for finding in observation.findings or []:
            if not isinstance(finding, dict):
                continue
            rows.append({
                **finding,
                "path": finding.get("path") or observation.path,
                "observation_id": observation.id,
                "evidence_state": observation.evidence_state,
                "source": "parser-observation",
            })
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in rows:
        # Scan-summary excerpts and observation findings often describe the
        # same issue. Identity is the stable finding location, not its wording.
        key = (str(row.get("code") or ""), str(row.get("severity") or "").upper(),
               str(row.get("path") or ""), "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique


@router.get("/binary/scans/{scan_id}/observations")
def binary_scan_observations(
    scan_id: str,
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=100000),
    format_filter: str | None = Query(None, max_length=32),
    evidence_state: str | None = Query(None, max_length=32),
    q: str | None = Query(None, max_length=300),
    crypto_only: bool = False,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_SBOM_READERS)),
):
    """Page bounded parser observations for one authorized scan."""
    from db.models.binary_scan import BinaryScanObservation

    try:
        tenant = _artifact_tenant(request, db, user)
        record = _binary_scan_row(db, scan_id, tenant)
        if record is None:
            raise HTTPException(status_code=404, detail="binary scan not found")
        query = _binary_scan_observation_query(db, record.id, tenant)
        if format_filter:
            query = query.filter(BinaryScanObservation.format == format_filter.strip().lower())
        if evidence_state:
            query = query.filter(BinaryScanObservation.evidence_state == evidence_state.strip().lower())
        if q:
            query = query.filter(BinaryScanObservation.path.ilike(f"%{q.strip()}%"))
        if crypto_only:
            query = query.filter(BinaryScanObservation.crypto.is_not(None))
        total = query.count()
        rows = query.order_by(BinaryScanObservation.path.asc()).offset(offset).limit(limit).all()
        return {
            "scan_id": record.id,
            "artifact_id": record.artifact_id,
            "total": total,
            "offset": offset,
            "limit": limit,
            "returned": len(rows),
            "observations_truncated": bool(record.observations_truncated),
            "observations": [_binary_record_json(row) for row in rows],
            "source": "database-read-model",
            "note": "observations are bounded projections; signed artifacts remain authoritative",
        }
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.warning("binary_scan_observations_unavailable", extra={"error_type": type(exc).__name__})
        raise HTTPException(status_code=503,
                            detail="binary scan index is unavailable; apply migration 0063") from exc


@router.get("/binary/scans/{scan_id}/findings")
def binary_scan_findings(
    scan_id: str,
    request: Request,
    severity: str | None = Query(None, max_length=20),
    code: str | None = Query(None, max_length=100),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=100000),
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_SBOM_READERS)),
):
    """Read finding/evidence drill-down without opening the signed artifact."""
    try:
        from db.models.binary_scan import BinaryScanObservation

        tenant = _artifact_tenant(request, db, user)
        record = _binary_scan_row(db, scan_id, tenant)
        if record is None:
            raise HTTPException(status_code=404, detail="binary scan not found")
        observations = _binary_scan_observation_query(db, record.id, tenant).order_by(
            # The database projection is bounded to 5,000 rows by the writer.
            # Ordering keeps pagination deterministic across retries.
            BinaryScanObservation.path.asc()
        ).limit(5000).all()
        findings = _binary_finding_rows(record, observations)
        if severity:
            wanted = severity.strip().upper()
            findings = [row for row in findings if str(row.get("severity") or "INFO").upper() == wanted]
        if code:
            wanted = code.strip().lower()
            findings = [row for row in findings if str(row.get("code") or "").lower() == wanted]
        page = findings[offset:offset + limit]
        return {
            "scan_id": record.id,
            "artifact_id": record.artifact_id,
            # `total` is the available bounded projection, while the record count
            # is the authoritative scanner count. They can differ when the
            # manifest excerpt or observation index cap was reached.
            "total": len(findings),
            "authoritative_count": record.findings_count,
            "findings_truncated": len(findings) < record.findings_count,
            "offset": offset,
            "limit": limit,
            "returned": len(page),
            "findings": page,
            "source": "database-read-model",
            "note": "finding excerpts are bounded; use the signed artifact/report for the authoritative export",
        }
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.warning("binary_scan_findings_unavailable", extra={"error_type": type(exc).__name__})
        raise HTTPException(status_code=503,
                            detail="binary scan index is unavailable; apply migration 0063") from exc


@router.get("/binary/scans/{scan_id}/coverage")
def binary_scan_coverage(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_SBOM_READERS)),
):
    """Return parser coverage and evidence-state counts for one scan."""
    from db.models.binary_scan import BinaryScanObservation

    try:
        tenant = _artifact_tenant(request, db, user)
        record = _binary_scan_row(db, scan_id, tenant)
        if record is None:
            raise HTTPException(status_code=404, detail="binary scan not found")
        states = db.query(BinaryScanObservation.evidence_state, func.count(BinaryScanObservation.id)).filter(
            BinaryScanObservation.scan_record_id == record.id,
            _binary_tenant_clause(BinaryScanObservation, tenant)).group_by(
                BinaryScanObservation.evidence_state).all()
        formats = db.query(BinaryScanObservation.format, func.count(BinaryScanObservation.id)).filter(
            BinaryScanObservation.scan_record_id == record.id,
            _binary_tenant_clause(BinaryScanObservation, tenant)).group_by(
                BinaryScanObservation.format).all()
        summary = record.summary if isinstance(record.summary, dict) else {}
        return {
            "scan_id": record.id,
            "artifact_id": record.artifact_id,
            "status": record.status,
            "files_walked": record.files_walked,
            "binaries_scanned": record.binaries_scanned,
            "findings_count": record.findings_count,
            "observations_count": record.observations_count,
            "observations_truncated": bool(record.observations_truncated),
            "coverage": record.coverage or {},
            "limits": record.limits or {},
            "summary": summary,
            "evidence_states": {str(key): int(value) for key, value in states},
            "formats": {str(key): int(value) for key, value in formats},
            "source": "database-read-model",
        }
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.warning("binary_scan_coverage_unavailable", extra={"error_type": type(exc).__name__})
        raise HTTPException(status_code=503,
                            detail="binary scan index is unavailable; apply migration 0063") from exc


class BinaryScanCompareRequest(BaseModel):
    from_scan_id: str = Field(..., min_length=1, max_length=36)
    to_scan_id: str = Field(..., min_length=1, max_length=36)


@router.post("/binary/scans/compare")
def binary_scan_compare(
    body: BinaryScanCompareRequest,
    request: Request,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_SBOM_READERS)),
):
    """Compare two tenant-owned read-model scans by path/hash/evidence state."""
    try:
        tenant = _artifact_tenant(request, db, user)
        before = _binary_scan_row(db, body.from_scan_id, tenant)
        after = _binary_scan_row(db, body.to_scan_id, tenant)
        if before is None or after is None:
            raise HTTPException(status_code=404, detail="one or both binary scans not found")
        from db.models.binary_scan import BinaryScanObservation

        def load(record: Any) -> dict[str, dict[str, Any]]:
            rows = _binary_scan_observation_query(db, record.id, tenant).order_by(
                BinaryScanObservation.path.asc()).limit(5000).all()
            return {row.path: {
                "path": row.path, "format": row.format, "arch": row.arch,
                "sha256": row.sha256, "evidence_state": row.evidence_state,
                "derived_from": row.derived_from, "depth": row.depth,
                "crypto": row.crypto or {}, "hardening": row.hardening or {},
                "signature": row.signature or {}, "findings_count": len(row.findings or []),
            } for row in rows}

        left, right = load(before), load(after)
        added = [right[path] for path in sorted(set(right) - set(left))]
        removed = [left[path] for path in sorted(set(left) - set(right))]
        changed = [{"before": left[path], "after": right[path]} for path in sorted(set(left) & set(right))
                   if left[path] != right[path]]
        max_rows = 1000
        return {
            "from_scan_id": before.id, "to_scan_id": after.id,
            "from_artifact_id": before.artifact_id, "to_artifact_id": after.artifact_id,
            "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)},
            "added": added[:max_rows], "removed": removed[:max_rows], "changed": changed[:max_rows],
            "truncated": any(len(rows) > max_rows for rows in (added, removed, changed)),
            "observations_truncated": bool(before.observations_truncated or after.observations_truncated),
            "source": "database-read-model",
            "note": "This is a bounded observation diff; use signed BOM diff for the authoritative export",
        }
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.warning("binary_scan_compare_unavailable", extra={"error_type": type(exc).__name__})
        raise HTTPException(status_code=503,
                            detail="binary scan index is unavailable; apply migration 0063") from exc


@router.get("/binary/scans/{scan_id}")
def binary_scan_detail(scan_id: str, request: Request,
                       db: Session = Depends(get_db_session),
                       user: str = Depends(require_roles(*_SBOM_READERS))):
    """Read one bounded scan record and its parser observations."""
    from db.models.binary_scan import BinaryScanObservation, BinaryScanRecord

    try:
        tenant = _artifact_tenant(request, db, user)
        row = db.query(BinaryScanRecord).filter(
            BinaryScanRecord.id == scan_id,
            _binary_tenant_clause(BinaryScanRecord, tenant)).first()
        if row is None:
            raise HTTPException(status_code=404, detail="binary scan not found")
        observations = db.query(BinaryScanObservation).filter(
            BinaryScanObservation.scan_record_id == row.id,
            _binary_tenant_clause(BinaryScanObservation, tenant)).order_by(
                BinaryScanObservation.path.asc()).limit(5000).all()
        return {"record": _binary_record_json(row),
                "observations": [_binary_record_json(item) for item in observations],
                "observation_limit": 5000}
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.warning("binary_scan_detail_unavailable", extra={"error_type": type(exc).__name__})
        raise HTTPException(status_code=503,
                            detail="binary scan index is unavailable; apply migration 0063") from exc


@router.get("/binary/artifacts/{artifact_id}/cbom")
def binary_cbom(artifact_id: str, request: Request, db: Session = Depends(get_db_session),
                user: str = Depends(require_roles(*_SBOM_READERS))):
    """The CBOM stored alongside a binary-scan artifact (this tenant's only)."""
    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = _find_manifest(store, artifact_id, tenant_id=_artifact_tenant(request, db, user))
    if man is None:
        raise HTTPException(status_code=404, detail="no CBOM stored for this artifact")
    blob, _at_rest = _artifact_cbom_blob(store, man, _artifact_tenant(request, db, user))
    return json.loads(blob.decode("utf-8"))


@router.get("/binary/artifacts/{artifact_id}/bom/{bom_type}")
def binary_bom(artifact_id: str, bom_type: str, request: Request,
               db: Session = Depends(get_db_session),
               user: str = Depends(require_roles(*_SBOM_READERS))):
    """Read a tenant-scoped BOM projection produced by a binary scan.

    ``bom_type`` is one of ``sbom``, ``cbom``, ``hbom``, ``nbom``, ``vbom``,
    ``vulnerability-bom`` or ``technology-bom``. SBOM/CBOM retain their existing
    download paths; this endpoint makes every additional projection discoverable
    without exposing storage keys or another tenant's artifact.
    """
    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    requested = str(bom_type).strip().lower()
    aliases = {
        "hbom": "hbom", "nbom": "nbom", "vbom": "vbom", "vendor-bom": "vbom",
        "vulnerability-bom": "vulnerability_bom", "vulbom": "vulnerability_bom",
        "technology-bom": "technology_bom", "technology": "technology_bom",
    }
    key = aliases.get(requested)
    if requested not in {"sbom", "cbom"} and key is None:
        raise HTTPException(status_code=404, detail="unsupported binary BOM type")
    tenant = _artifact_tenant(request, db, user)
    store = _sbom_storage()
    man = _find_manifest(store, artifact_id, tenant_id=tenant)
    if man is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    if requested == "sbom":
        document = {"storage_key": man.get("storage_key")}
        key = "sbom"
    elif requested == "cbom":
        document = {"storage_key": man.get("cbom_storage_key")}
        key = "cbom"
    else:
        document = (man.get("bom_documents") or {}).get(key)
    if not document or not document.get("storage_key"):
        raise HTTPException(status_code=404, detail="BOM projection was not stored")
    scoped = dict(man, storage_key=document["storage_key"])
    try:
        blob, _ = _read_artifact_blob(store, scoped, tenant_id=tenant,
                                      label=f"stored {key}")
    except ArtifactCryptoError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return json.loads(blob.decode("utf-8"))


@router.get("/sbom/artifacts")
def sbom_artifacts(request: Request, kind: str | None = None, fmt: str | None = None,
                  q: str | None = None, limit: int = 50,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(require_roles(*_SBOM_READERS))):
    """List generated SBOM artifacts (newest first, capped at 50).

    Only this caller's tenant: an artifact written by another organization is not
    in this list at all, which is the point of listing it here.
    """
    items = _visible_manifests(_sbom_storage(), tenant_id=_artifact_tenant(request, db, user))
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
        item["bom_urls"] = ({name: f"/api/v1/devsecops/binary/artifacts/{aid}/bom/{name.replace('_', '-')}"
                             for name in (item.get("bom_documents") or {})}
                            if str(item.get("kind") or "").lower() == "binary" else {})
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
def sbom_diff(body: SbomDiffRequest, request: Request, db: Session = Depends(get_db_session),
              user: str = Depends(require_roles(*_SBOM_READERS))):
    """Diff two SBOMs (stored artifacts or inline docs): components added,
    removed, version-changed (upgrade/downgrade), license changes, crypto
    deltas and a review verdict."""
    from devsecops.sbom_assurance import diff_boms

    store = _sbom_storage()

    tenant = _artifact_tenant(request, db, user)

    def _load(artifact_id: str) -> tuple[dict, dict]:
        if not _ARTIFACT_ID_RE.match(artifact_id):
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        man = _find_manifest(store, artifact_id, tenant_id=tenant)
        if man is None or not man.get("storage_key"):
            raise HTTPException(status_code=404, detail=f"artifact not found: {artifact_id}")
        try:
            blob, _at_rest = _artifact_blob(store, man, tenant)
            doc = json.loads(blob)
        except HTTPException:
            raise
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
    if body.from_artifact and body.to_artifact and \
            str(old_man.get("kind") or "").lower() == "binary" and \
            str(new_man.get("kind") or "").lower() == "binary":
        from devsecops.binary_boms import diff_binary_bom_bundles

        def _binary_views(document: dict, manifest: dict) -> dict[str, dict]:
            views: dict[str, dict] = {"sbom": document}
            try:
                cbom_blob, _ = _artifact_cbom_blob(store, manifest, tenant)
                views["cbom"] = json.loads(cbom_blob)
            except (ArtifactCryptoError, FileNotFoundError, ValueError, TypeError, KeyError):
                pass
            for name, descriptor in (manifest.get("bom_documents") or {}).items():
                if not isinstance(descriptor, dict) or not descriptor.get("storage_key"):
                    continue
                try:
                    scoped = dict(manifest, storage_key=descriptor["storage_key"])
                    sidecar, _ = _artifact_blob(store, scoped, tenant, label=f"stored {name}")
                    views[name] = json.loads(sidecar)
                except (ArtifactCryptoError, FileNotFoundError, ValueError, TypeError, KeyError):
                    continue
            return views

        result["binary_bom_diff"] = diff_binary_bom_bundles(
            _binary_views(old, old_man), _binary_views(new, new_man))
    return result


@router.get("/sbom/{artifact_id}/verify")
def sbom_verify(artifact_id: str, request: Request, db: Session = Depends(get_db_session),
                user: str = Depends(require_roles(*_SBOM_READERS))):
    """Re-verify a stored artifact: recompute the blob digest and the manifest
    HMAC signature. Returns OK only when both match."""
    from devsecops.sbom_scan import verify_artifact

    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = _find_manifest(store, artifact_id, tenant_id=_artifact_tenant(request, db, user))
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    blob, at_rest = _artifact_blob(store, man, _artifact_tenant(request, db, user))
    secret, key_id = _sbom_signing_secret(db)
    # verification is over the *plaintext* envelope contents: sealing an artifact
    # changes where it sits, not what it says or whether its signature holds
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
def sbom_report(artifact_id: str, request: Request, fmt: str = "markdown",
                db: Session = Depends(get_db_session),
                user: str = Depends(require_roles(*_SBOM_READERS))):
    """Auditor-friendly summary of a stored SBOM: components, crypto inventory,
    pinning, minimum-elements status and provenance (markdown or json)."""
    from devsecops.sbom_assurance import check_minimum_elements
    from devsecops.sbom import check_pinning

    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = _find_manifest(store, artifact_id, tenant_id=_artifact_tenant(request, db, user))
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        blob, _at_rest = _artifact_blob(store, man, _artifact_tenant(request, db, user))
        bom = json.loads(blob)
    except HTTPException:
        raise
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


def _load_sbom_artifact(artifact_id: str, tenant_id: str | None = None) -> tuple[dict, bytes]:
    """(manifest, plaintext blob) for a stored artifact of this tenant, or 404.

    Both halves are tenanted: the manifest lookup filters by bucket, and the
    bytes are unsealed with the tenant's key, so neither "which artifacts exist"
    nor "what an artifact says" crosses a tenant boundary here.
    """
    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = _find_manifest(store, artifact_id, tenant_id=tenant_id)
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        blob, _at_rest = _artifact_blob(store, man, tenant_id)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=404, detail="artifact not found")
    return man, blob


@router.post("/sbom/{artifact_id}/gate")
def sbom_gate(artifact_id: str, request: Request, body: SbomGateRequest | None = None,
              db: Session = Depends(get_db_session),
              user: str = Depends(require_roles(*_SBOM_READERS))):
    """Evaluate a stored artifact against a supply-chain gate policy.

    Deterministic and offline: counts critical/high advisories recorded in the
    document, checks declared licenses against the deny list, checks the NTIA
    minimum-elements score, the pinning summary and the signature. A FAIL
    verdict means the policy's blocker thresholds were crossed — the caller
    should stop the pipeline; warnings are advisory.
    """
    from devsecops.sbom_assurance import evaluate_gate

    man, blob = _load_sbom_artifact(artifact_id, _artifact_tenant(request, db, user))
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
def sbom_rescan(artifact_id: str, request: Request, body: SbomRescanRequest | None = None,
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

    man, blob = _load_sbom_artifact(artifact_id, _artifact_tenant(request, db, user))
    opts = man.get("scan_options") or {}
    if not opts.get("target"):
        raise HTTPException(status_code=409, detail=(
            "this artifact predates recorded scan options — scan the target again "
            "to enable re-scan"))
    overrides = body or SbomRescanRequest()
    scan_request = {"kind": opts.get("kind") or "source", "target": opts["target"],
                    "format": opts.get("format") or "cyclonedx",
                    "as_image": bool(opts.get("as_image")),
                    "include_vendored": (overrides.include_vendored if overrides.include_vendored is not None
                                         else bool(opts.get("include_vendored"))),
                    "use_lockfiles": (overrides.use_lockfiles if overrides.use_lockfiles is not None
                                      else bool(opts.get("use_lockfiles"))),
                    "recursive": bool(opts.get("recursive", True)),
                    "include_raw": bool(opts.get("include_raw", False))}
    try:
        fresh = sbom_scan(SbomScanRequest(**scan_request), request=request, db=db, user=user)
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


def _resolve_sbom_doc(doc: dict | None, artifact_id: str | None,
                      tenant_id: str | None = None) -> dict:
    """Exactly one of an inline document or a stored artifact id (this tenant's)."""
    if bool(doc) == bool(artifact_id):
        raise HTTPException(status_code=422,
                            detail="provide exactly one of `doc` or `artifact_id`")
    if doc:
        return doc
    _man, blob = _load_sbom_artifact(str(artifact_id), tenant_id)
    try:
        return json.loads(blob.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — corrupt storage is a real error
        raise HTTPException(status_code=422, detail=f"stored SBOM could not be parsed: {exc}")


@router.post("/sbom/license")
def sbom_license(body: SbomLicenseRequest, request: Request,
                 db: Session = Depends(get_db_session),
                 user: str = Depends(require_roles(*_SBOM_READERS))):
    """License inventory and policy evaluation for a document or stored artifact.

    Reports declared licenses grouped by SPDX identifier with the components
    carrying them, the components that declare nothing, and policy violations.
    The copyleft review trigger is a policy flag, not a compatibility ruling:
    the engine never claims two licenses are or are not compatible.
    """
    from devsecops.sbom_license import check_license_policy, render_license_report

    doc = _resolve_sbom_doc(body.doc, body.artifact_id, _artifact_tenant(request, db, user))
    report = check_license_policy(doc, policy=body.policy)
    payload: dict = {"artifact_id": body.artifact_id, "verdict": report["verdict"], **report}
    if str(body.fmt).lower() == "markdown":
        payload["markdown"] = render_license_report(report)
    return payload


@router.post("/sbom/vex")
def sbom_vex(body: SbomVexRequest, request: Request, db: Session = Depends(get_db_session),
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
    doc = _resolve_sbom_doc(body.doc, body.artifact_id, _artifact_tenant(request, db, user))
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
def sbom_vex_for_artifact(artifact_id: str, request: Request, dl: bool = False,
                          db: Session = Depends(get_db_session),
                          user: str = Depends(require_roles(*_SBOM_READERS))):
    """VEX document for a stored artifact (download as .vex.json with ?dl=true)."""
    from devsecops import sbom_vex as vx

    doc = _resolve_sbom_doc(None, artifact_id, _artifact_tenant(request, db, user))
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


def _artifact_rows(tenant_id: str | None = None) -> list[dict]:
    """Cached listing of this tenant's stored artifacts (bodies are not read)."""
    import time

    store = _sbom_storage()
    rows = _visible_manifests(store, tenant_id=tenant_id)
    # the tenant is part of the cache signature: one tenant's listing must never
    # be served for another from a warm cache
    signature = (tenant_id, len(rows), max((str(r.get("created_at") or "") for r in rows), default=""))
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
def sbom_components(request: Request, q: str | None = None, crypto: bool | None = None,
                    limit: int = 100, artifact_id: str | None = None,
                    db: Session = Depends(get_db_session),
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
    tenant = _artifact_tenant(request, db, user)
    for man in sorted(_artifact_rows(tenant), key=lambda m: str(m.get("created_at") or ""),
                      reverse=True):
        if artifact_id and man.get("artifact_id") != artifact_id:
            continue
        if not man.get("artifact_id"):
            continue
        scanned += 1
        try:
            doc = json.loads(_sbom_storage().get(str(man.get("storage_key"))).decode("utf-8"))
        except Exception as _handler_exc:  # noqa: BLE001 — a corrupt artifact must not break the index
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
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
def sbom_advisories(request: Request, severity: str | None = None, cve: str | None = None,
                    db: Session = Depends(get_db_session),
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
    for man in _artifact_rows(_artifact_tenant(request, db, user)):
        if not man.get("artifact_id"):
            continue
        if not man.get("feed_supplied"):
            unchecked += 1
            continue
        checked += 1
        try:
            doc = json.loads(_sbom_storage().get(str(man.get("storage_key"))).decode("utf-8"))
        except Exception as _handler_exc:  # noqa: BLE001
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
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
def sbom_prune(request: Request, older_than_days: int = 90,
               db: Session = Depends(get_db_session),
               user: str = Depends(require_roles("admin", "superadmin"))):
    """Retention: delete artifacts older than N days (default 90, min 1)."""
    from datetime import datetime, timedelta, timezone

    if older_than_days < 1:
        raise HTTPException(status_code=422, detail="older_than_days must be >= 1")
    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    store = _sbom_storage()
    deleted, kept = [], 0
    # retention deletes this tenant's artifacts; another tenant's are not this
    # endpoint's to expire, and a platform-wide sweep would have to say so
    for man in _visible_manifests(store, tenant_id=_artifact_tenant(request, db, user)):
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
            if man.get("cbom_storage_key"):
                store.delete(man["cbom_storage_key"])
            for document in (man.get("bom_documents") or {}).values():
                if document.get("storage_key"):
                    store.delete(document["storage_key"])
            deleted.append({"artifact_id": man.get("artifact_id"), "created_at": created,
                            "target": man.get("target"),
                            "bom_documents_deleted": len(man.get("bom_documents") or {})})
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
def sbom_download(artifact_id: str, request: Request, db: Session = Depends(get_db_session),
                  user: str = Depends(require_roles(*_SBOM_READERS))):
    """Download a persisted SBOM artifact (JSON) with its provenance header."""
    if not _ARTIFACT_ID_RE.match(artifact_id):
        raise HTTPException(status_code=404, detail="artifact not found")
    store = _sbom_storage()
    man = _find_manifest(store, artifact_id, tenant_id=_artifact_tenant(request, db, user))
    if man is None or not man.get("storage_key"):
        raise HTTPException(status_code=404, detail="artifact not found")
    try:
        blob, _at_rest = _artifact_blob(store, man, _artifact_tenant(request, db, user))
    except HTTPException:
        raise
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
