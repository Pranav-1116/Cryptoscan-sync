"""Evidence chain, ownership mapping and relationship provenance for CBOM exports.

The estate CBOM used to export every crypto asset with only a file path, put
every unlinked asset in a ``system:unassigned`` bucket without saying why, and
emit system→system edges with no basis. This module assembles, from rows that
already exist, what a reviewer needs to trust (or distrust) each component:

* **evidence** — the linked ``EvidenceRecord``/``Scan`` rows: evidence id,
  content hash (recomputed and compared, so the hash is *verified*, not just
  copied), chain hash, source type, repository, commit, collector + version,
  collection time, detection method. Fields the store does not hold are
  listed as not recorded instead of being invented.
* **verification** — kept separate from confidence. Confidence is the
  scanner's certainty about the match; verification is whether a human moved
  the asset past ``DISCOVERED`` or a collector observed it at runtime.
* **ownership mapping** — status, basis and confidence of each asset→system
  link, and for unmapped assets the concrete reason. Candidate systems are
  proposed only from evidence (the scan target or a claimed network
  endpoint), never from name resemblance, and they stay ``PENDING_REVIEW``.
* **relationships** — every system→system edge with id, type, basis
  (observed / declared), confidence, verification status, evidence ref and
  first/last seen. No edge is presented as runtime-verified: the store holds
  no runtime proof for them.

Nothing here raises on missing data; absent facts are reported as absent.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

EXPORT_PROFILE_VERSION = "cryptoscan-cbom-export/2.0.0"
_CHUNK = 500
_MAX_EVIDENCE_DETAIL = 5  # occurrences listed per asset; the count covers all

#: Mapping statuses (audit item 7). ``HUMAN_APPROVED`` is part of the
#: vocabulary but the link table stores no approver, so it is not emitted.
MAPPED_EVIDENCE = "EVIDENCE_BACKED"
MAPPED_DECLARED = "DECLARED"
MAPPED_RECORDED = "RECORDED_BASIS_UNKNOWN"
PENDING = "PENDING_REVIEW"
UNMAPPED = "UNMAPPED"


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _chunks(values: list[str]) -> Iterable[list[str]]:
    for start in range(0, len(values), _CHUNK):
        yield values[start:start + _CHUNK]


_USERINFO = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.\-]*://)[^/@\s]+@", re.IGNORECASE)


def safe_location(value: Any) -> str | None:
    """A repository/target location without embedded credentials or query."""
    if not value:
        return None
    text = _USERINFO.sub(lambda m: m.group("scheme"), str(value).strip())
    return text.split("?", 1)[0].split("#", 1)[0][:500] or None


def _target_key(value: Any) -> str:
    text = (safe_location(value) or "").lower().rstrip("/")
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text)
    text = re.sub(r"^git@([^:]+):", r"\1/", text)
    return text.removesuffix(".git")


def _endpoint(location: Any) -> str | None:
    text = str(location or "")
    for scheme in ("tls://", "dtls://", "ssh://"):
        if text.startswith(scheme):
            return text[len(scheme):]
    return None


def _prop(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "value": value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)}


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #


def _load(db: Session, asset_ids: list[str]) -> tuple[dict[str, list[Any]], dict[str, Any]]:
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan

    links: dict[str, list[str]] = {}
    for chunk in _chunks(asset_ids):
        for link in db.execute(select(CryptoAssetEvidence).where(CryptoAssetEvidence.asset_id.in_(chunk))).scalars():
            links.setdefault(link.asset_id, []).append(link.evidence_id)
    evidence_ids = sorted({eid for ids in links.values() for eid in ids})
    records: dict[str, Any] = {}
    for chunk in _chunks(evidence_ids):
        for row in db.execute(select(EvidenceRecord).where(EvidenceRecord.id.in_(chunk))).scalars():
            if getattr(row, "deleted_at", None) is None:
                records[row.id] = row
    scan_ids = sorted({row.scan_id for row in records.values() if row.scan_id})
    scans: dict[str, Any] = {}
    for chunk in _chunks(scan_ids):
        for scan in db.execute(select(Scan).where(Scan.id.in_(chunk))).scalars():
            scans[scan.id] = scan
    by_asset = {aid: sorted((records[e] for e in ids if e in records),
                            key=lambda r: (_iso(r.created_at) or "", r.id))
                for aid, ids in links.items()}
    return by_asset, scans


def _endpoint_claims(db: Session) -> dict[str, str]:
    try:
        from db.models.network_scan_target import NetworkScanTarget
    except ImportError:  # pragma: no cover - optional model
        return {}
    return {row.endpoint: row.system_id for row in db.execute(select(NetworkScanTarget)).scalars() if row.system_id}


# --------------------------------------------------------------------------- #
# evidence
# --------------------------------------------------------------------------- #


def _hash_status(row: Any) -> str:
    from db.loader.chain import content_hash

    try:
        return ("CONTENT_HASH_RECOMPUTED_MATCH" if content_hash(row.finding_data or {}) == row.content_hash
                else "CONTENT_HASH_MISMATCH")
    except Exception:  # noqa: BLE001 - an unhashable payload is reported, not raised
        return "CONTENT_HASH_NOT_RECOMPUTABLE"


def _finding_field(row: Any, *paths: tuple[str, ...]) -> Any:
    data = row.finding_data if isinstance(row.finding_data, dict) else {}
    for path in paths:
        node: Any = data
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if node not in (None, ""):
            return node
    return None


def evidence_block(asset: dict[str, Any], rows: list[Any], scans: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    """``(occurrences, properties)`` for one asset row."""
    props: list[dict[str, str]] = []
    lifecycle = str(asset.get("lifecycle_state") or "DISCOVERED").upper()
    location = str(asset.get("file_path") or "")
    if lifecycle in {"VERIFIED", "ACTIVE"}:
        verification = "HUMAN_VERIFIED_LIFECYCLE"
    elif _endpoint(location):
        verification = "COLLECTOR_OBSERVED_NOT_HUMAN_VERIFIED"
    else:
        verification = "UNVERIFIED_DETECTION"
    props += [_prop("cryptoscan:verification_status", verification),
              _prop("cryptoscan:lifecycle_state", lifecycle)]
    if asset.get("occurrence_count"):
        props.append(_prop("cryptoscan:occurrence_count", str(asset["occurrence_count"])))
    for owner in ("technical_owner", "security_owner"):
        if asset.get(owner):
            props.append(_prop(f"cryptoscan:{owner}", str(asset[owner])))
    if not rows:
        props += [_prop("cryptoscan:evidence_link_status", "NOT_LINKED"),
                  _prop("cryptoscan:evidence_count", "0"),
                  _prop("cryptoscan:evidence:basis",
                        "asset row only (location recorded by the scanner); no content-addressed evidence record linked")]
        return [], props
    primary = rows[-1]  # most recent observation
    scan = scans.get(primary.scan_id)
    props += [_prop("cryptoscan:evidence_link_status", "LINKED"),
              _prop("cryptoscan:evidence_count", str(len(rows))),
              _prop("cryptoscan:evidence:id", primary.id),
              _prop("cryptoscan:evidence:content_hash", f"sha256:{primary.content_hash}"),
              _prop("cryptoscan:evidence:hash_verification", _hash_status(primary)),
              _prop("cryptoscan:evidence:chain_hash", f"sha256:{primary.chain_hash}"),
              _prop("cryptoscan:evidence:chain_position", str(primary.chain_position)),
              _prop("cryptoscan:evidence:confidence", str(primary.confidence or "NOT_RECORDED").upper())]
    if len(rows) > 1:
        props.append(_prop("cryptoscan:evidence:ids", [r.id for r in rows[-_MAX_EVIDENCE_DETAIL:]]))
    source_type = _finding_field(primary, ("source", "type")) or (scan.target_type if scan else None)
    method = _finding_field(primary, ("metadata", "scan_method"), ("metadata", "detection_method"),
                            ("detection", "method"), ("metadata", "rule_id"))
    digest = _finding_field(primary, ("artifact", "sha256"), ("binary", "sha256"), ("metadata", "artifact_sha256"),
                            ("metadata", "image_digest"), ("source", "artifact_sha256"))
    facts = {
        "cryptoscan:evidence:source_type": source_type,
        "cryptoscan:evidence:detection_method": method,
        "cryptoscan:evidence:file": primary.file_path,
        "cryptoscan:evidence:line": str(primary.line_number) if primary.line_number else None,
        "cryptoscan:evidence:build_digest": digest,
        "cryptoscan:evidence:scan_id": primary.scan_id,
        "cryptoscan:evidence:collector": scan.scanner_id if scan else None,
        "cryptoscan:evidence:collector_version": scan.scanner_version if scan else None,
        "cryptoscan:evidence:source_repository": safe_location(scan.target_location) if scan else None,
        "cryptoscan:evidence:commit": scan.target_commit if scan else None,
        "cryptoscan:evidence:branch": scan.target_branch if scan else None,
        "cryptoscan:evidence:scan_manifest_hash": scan.manifest_hash if scan else None,
        "cryptoscan:evidence:collected_at": _iso(scan.scan_start if scan and scan.scan_start else primary.created_at),
    }
    missing = []
    for name, value in facts.items():
        if value in (None, ""):
            missing.append(name.removeprefix("cryptoscan:evidence:"))
        else:
            props.append(_prop(name, str(value)))
    if missing:
        props.append(_prop("cryptoscan:evidence:fields_not_recorded", sorted(missing)))
    seen = sorted(t for t in (_iso(scans[r.scan_id].scan_start if r.scan_id in scans and scans[r.scan_id].scan_start
                                   else r.created_at) for r in rows) if t)
    if seen:
        props += [_prop("cryptoscan:evidence:first_seen", seen[0]), _prop("cryptoscan:evidence:last_seen", seen[-1])]
    occurrences = []
    for row in rows[-_MAX_EVIDENCE_DETAIL:]:
        if not row.file_path or row.file_path == "unknown":
            continue
        item: dict[str, Any] = {"location": str(row.file_path)}
        if row.line_number and row.line_number > 0:
            item["line"] = int(row.line_number)
        symbol = ".".join(p for p in (row.class_name, row.method_name) if p)
        if symbol:
            item["symbol"] = symbol
        item["additionalContext"] = f"evidence:{row.id} sha256:{row.content_hash}"
        occurrences.append(item)
    return occurrences, props


# --------------------------------------------------------------------------- #
# ownership mapping
# --------------------------------------------------------------------------- #


def mapping_block(asset: dict[str, Any], rows: list[Any], scans: dict[str, Any], systems: dict[str, Any],
                  targets: dict[str, list[str]], claims: dict[str, str]) -> list[dict[str, str]]:
    system_id = asset.get("system_id")
    scan_targets = {_target_key(scans[r.scan_id].target_location) for r in rows
                    if r.scan_id in scans and scans[r.scan_id].target_location}
    scan_ids = {r.scan_id for r in rows}
    endpoint = _endpoint(asset.get("file_path"))
    imported = str(asset.get("source_basis") or "").startswith(("IMPORT", "LEGACY_IMPORT"))
    if system_id:
        system = systems.get(system_id)
        system_target = _target_key(getattr(system, "scan_target", None)) if system else ""
        if system is not None and ((system_target and system_target in scan_targets)
                                   or (system.last_scan_id and system.last_scan_id in scan_ids)):
            status, basis, confidence = MAPPED_EVIDENCE, "SCAN_OF_THE_SYSTEMS_REGISTERED_TARGET", "HIGH"
        elif endpoint and claims.get(endpoint) == system_id:
            status, basis, confidence = MAPPED_EVIDENCE, "NETWORK_ENDPOINT_CLAIMED_BY_SYSTEM", "MEDIUM"
        elif imported:
            status, basis, confidence = MAPPED_DECLARED, "IMPORTED_DECLARATION", "LOW"
        else:
            status, basis, confidence = (MAPPED_RECORDED, "LINK_RECORDED_WITHOUT_PROVENANCE", "UNKNOWN")
        props = [_prop("cryptoscan:mapping_status", status), _prop("cryptoscan:mapping_basis", basis),
                 _prop("cryptoscan:mapping_confidence", confidence)]
        if status == MAPPED_RECORDED:
            props.append(_prop("cryptoscan:mapping_note", "the system link exists but neither the scan target nor a "
                               "claimed endpoint corroborates it; the link table stores no approver"))
        return props
    # unmapped: explain, and propose only evidence-derived candidates
    candidates: list[tuple[str, str]] = []
    for key in scan_targets:
        candidates += [(sid, "SCAN_TARGET_MATCHES_REGISTERED_SYSTEM") for sid in targets.get(key, [])]
    if endpoint and claims.get(endpoint) in systems:
        candidates.append((claims[endpoint], "NETWORK_ENDPOINT_CLAIMED_BY_SYSTEM"))
    if candidates:
        sid, basis = sorted(set(candidates))[0]
        return [_prop("cryptoscan:mapping_status", PENDING), _prop("cryptoscan:mapping_basis", basis),
                _prop("cryptoscan:mapping_confidence", "HIGH" if basis.startswith("SCAN") else "MEDIUM"),
                _prop("cryptoscan:mapping_candidate_system", f"system:{systems[sid].name}"),
                _prop("cryptoscan:mapping_reason", "evidence points at a registered system but the link has not "
                                                   "been recorded or approved")]
    if endpoint:
        reason = "NETWORK_ENDPOINT_NOT_CLAIMED_BY_ANY_SYSTEM"
    elif not rows:
        reason = "NO_EVIDENCE_LINK_AND_NO_SYSTEM_LINK"
    elif scan_targets:
        reason = "SCAN_TARGET_NOT_REGISTERED_TO_ANY_SYSTEM"
    else:
        reason = "EVIDENCE_HAS_NO_SCAN_TARGET"
    return [_prop("cryptoscan:mapping_status", UNMAPPED), _prop("cryptoscan:mapping_basis", "NONE"),
            _prop("cryptoscan:mapping_confidence", "NONE"), _prop("cryptoscan:mapping_reason", reason)]


# --------------------------------------------------------------------------- #
# assembly
# --------------------------------------------------------------------------- #


def enrich_records(db: Session, records: list[dict[str, Any]], systems: list[Any]) -> dict[str, Any]:
    """Attach evidence + mapping to each located asset row (in place) and return
    an export-level summary. Placeholder rows are removed from ``records`` and
    reported in the summary instead of becoming components."""
    from cbom.crypto_normalization import is_placeholder

    excluded = [r for r in records if is_placeholder(r.get("algorithm"), r.get("purpose"))]
    if excluded:
        records[:] = [r for r in records if not is_placeholder(r.get("algorithm"), r.get("purpose"))]
    asset_ids = sorted({str(r["id"]) for r in records if r.get("id")})
    evidence, scans = _load(db, asset_ids) if asset_ids else ({}, {})
    by_id = {s.id: s for s in systems}
    targets: dict[str, list[str]] = {}
    for system in systems:
        key = _target_key(getattr(system, "scan_target", None))
        if key:
            targets.setdefault(key, []).append(system.id)
    claims = _endpoint_claims(db)
    mapping_counts: dict[str, int] = {}
    reasons: dict[str, int] = {}
    linked = 0
    for record in records:
        rows = evidence.get(str(record.get("id")), [])
        occurrences, props = evidence_block(record, rows, scans)
        mapping = mapping_block(record, rows, scans, by_id, targets, claims)
        status = next(p["value"] for p in mapping if p["name"] == "cryptoscan:mapping_status")
        mapping_counts[status] = mapping_counts.get(status, 0) + 1
        for p in mapping:
            if p["name"] == "cryptoscan:mapping_reason" and status == UNMAPPED:
                reasons[p["value"]] = reasons.get(p["value"], 0) + 1
        linked += bool(rows)
        extra = record.get("extra") if isinstance(record.get("extra"), dict) else {}
        for key, name in (("cipher_suite", "cryptoscan:evidence:cipher_suite"),
                          ("tls_version", "cryptoscan:evidence:negotiated_protocol")):
            if extra.get(key):
                props.append(_prop(name, str(extra[key])))
        if isinstance(extra.get("curve"), str) and extra["curve"]:
            record["curve"] = extra["curve"]
        record["cbom_properties"] = props + mapping
        if occurrences:
            record["cbom_occurrences"] = occurrences
    sources = sorted({(safe_location(s.target_location) or "", s.target_commit or "NOT_RECORDED")
                      for s in scans.values() if s.target_location})
    collectors = sorted({f"{s.scanner_id}/{s.scanner_version}" for s in scans.values() if s.scanner_id})
    return {
        "excluded": [{"ref": str(r.get("id")), "recorded_algorithm": str(r.get("algorithm")),
                      "reason": "placeholder or bookkeeping value, not cryptography"} for r in excluded],
        "mapping_counts": dict(sorted(mapping_counts.items())),
        "unmapped_reasons": dict(sorted(reasons.items())),
        "evidence_linked_assets": linked,
        "evidence_unlinked_assets": len({str(r.get("id")) for r in records}) - len(
            {str(r.get("id")) for r in records if evidence.get(str(r.get("id")))}),
        "source_revisions": [{"repository": repo, "commit": commit} for repo, commit in sources[:100]],
        "collectors": collectors,
    }


# --------------------------------------------------------------------------- #
# relationships
# --------------------------------------------------------------------------- #

_EDGE_BASIS = {"discovered": "OBSERVED", "imported": "DECLARED", "manual": "DECLARED"}


def edge_record(edge: Any, parent_ref: str, child_ref: str) -> dict[str, Any]:
    """One system→system relationship with its provenance. Never claims
    runtime verification: the store holds no runtime proof for these edges."""
    source = str(edge.source or "manual").lower()
    basis = _EDGE_BASIS.get(source, "DECLARED")
    confirmed = edge.last_verified or getattr(edge, "last_confirmed_at", None)
    now = datetime.now(timezone.utc)
    valid_until = getattr(edge, "valid_until", None)
    if valid_until is not None and valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=timezone.utc)
    lifecycle = str(getattr(edge, "lifecycle_state", "ACTIVE") or "ACTIVE")
    if valid_until is not None and valid_until < now:
        lifecycle = "EXPIRED"
    record = {
        "id": f"edge:{edge.id}",
        "source": parent_ref,
        "target": child_ref,
        "type": edge.relation or "DEPENDS_ON",
        "basis": basis,
        "declared_by": f"{source}:{edge.created_by}" if edge.created_by else source,
        "confidence": edge.confidence,
        "confidence_meaning": edge.confidence_meaning or ("NOT_RECORDED" if edge.confidence is None else
                                                          "source-supplied score, not a verification result"),
        "verification_status": "RECONFIRMED_BY_SOURCE_NOT_RUNTIME_VERIFIED" if confirmed else "NOT_VERIFIED",
        "evidence_ref": edge.evidence_ref or getattr(edge, "lifecycle_evidence_ref", None) or "NOT_RECORDED",
        "first_seen": _iso(edge.created_at),
        "last_seen": _iso(confirmed or edge.updated_at or edge.created_at),
        "lifecycle_state": lifecycle,
    }
    if isinstance(edge.operational_dependency, dict) and edge.operational_dependency.get("mode"):
        record["operational_mode"] = edge.operational_dependency["mode"]
    return record


def failed_collections(db: Session, limit: int = 20) -> dict[str, Any]:
    from db.models.scan import Scan

    rows = list(db.execute(select(Scan).where(Scan.status == "FAILED").order_by(Scan.scan_start.desc()).limit(limit)).scalars())
    return {"failed_scans_listed": len(rows), "limit": limit,
            "items": [{"scan_id": s.id, "target": safe_location(s.target_location), "at": _iso(s.scan_start),
                       "error": (s.error_message or "")[:200]} for s in rows]}


def organization(db: Session) -> dict[str, str] | None:
    from db.tenancy import current_tenant

    tenant_id = current_tenant()
    if not tenant_id:
        return None
    from db.models.tenant import Tenant

    tenant = db.get(Tenant, tenant_id)
    return {"id": tenant_id, "name": tenant.name if tenant is not None else "NOT_RECORDED"}
