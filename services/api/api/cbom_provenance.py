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


def _load(db: Session, records: list[dict[str, Any]]) -> tuple[dict[str, list[Any]], dict[str, Any], dict[str, str]]:
    """``(evidence rows per asset, scans, link basis per asset)``.

    Recorded asset→evidence links are used first. Assets with no link (stores
    seeded or migrated before links were written) are resolved against the
    scan findings themselves: an evidence record with the *same file path,
    algorithm and key size* is the observation the asset was deduplicated
    from. That basis is stated per asset (``MATCHED_BY_LOCATION_AND_ALGORITHM``)
    so a resolved link is never presented as a recorded one.
    """
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan

    asset_ids = sorted({str(r["id"]) for r in records if r.get("id")})
    links: dict[str, list[str]] = {}
    for chunk in _chunks(asset_ids):
        for link in db.execute(select(CryptoAssetEvidence).where(CryptoAssetEvidence.asset_id.in_(chunk))).scalars():
            links.setdefault(link.asset_id, []).append(link.evidence_id)
    evidence_ids = sorted({eid for ids in links.values() for eid in ids})
    records_by_id: dict[str, Any] = {}
    for chunk in _chunks(evidence_ids):
        for row in db.execute(select(EvidenceRecord).where(EvidenceRecord.id.in_(chunk))).scalars():
            if getattr(row, "deleted_at", None) is None:
                records_by_id[row.id] = row
    by_asset = {aid: [records_by_id[e] for e in ids if e in records_by_id] for aid, ids in links.items()}
    basis = {aid: "RECORDED_LINK" for aid, rows in by_asset.items() if rows}
    # fallback: same location + algorithm + key size in the scan findings
    unlinked: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        aid = str(record.get("id") or "")
        path = str(record.get("file_path") or "")
        if aid and aid not in basis and path and not _endpoint(path) and path != "unknown":
            unlinked.setdefault(path, []).append(record)
    if unlinked:
        for chunk in _chunks(sorted(unlinked)):
            for row in db.execute(select(EvidenceRecord).where(EvidenceRecord.file_path.in_(chunk))).scalars():
                if getattr(row, "deleted_at", None) is not None:
                    continue
                for record in unlinked.get(row.file_path, []):
                    same_alg = str(row.algorithm or "").upper() == str(record.get("algorithm") or "").upper()
                    same_size = (row.key_size or None) == (record.get("key_size") or None)
                    same_purpose = not (row.purpose and record.get("purpose")) or \
                        str(row.purpose).upper() == str(record.get("purpose")).upper()
                    # never resolve across owners (a tenant can read platform rows)
                    same_owner = "tenant_id" not in record or getattr(row, "tenant_id", None) == record["tenant_id"]
                    if same_alg and same_size and same_purpose and same_owner:
                        aid = str(record["id"])
                        by_asset.setdefault(aid, []).append(row)
                        basis[aid] = "MATCHED_BY_LOCATION_AND_ALGORITHM"
    scan_ids = sorted({row.scan_id for rows in by_asset.values() for row in rows if row.scan_id})
    scans: dict[str, Any] = {}
    for chunk in _chunks(scan_ids):
        for scan in db.execute(select(Scan).where(Scan.id.in_(chunk))).scalars():
            scans[scan.id] = scan
    ordered = {aid: sorted({r.id: r for r in rows}.values(), key=lambda r: (_iso(r.created_at) or "", r.id))
               for aid, rows in by_asset.items() if rows}
    return ordered, scans, basis


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


_NR = "NOT_RECORDED"


def _source_record(row: Any, scan: Any, link_basis: str, verification: str) -> dict[str, Any]:
    """One first-class evidence record for a static finding."""
    end_line = _finding_field(row, ("end_line",), ("line_end",), ("source", "end_line"), ("location", "end_line"))
    record = {
        "evidence_id": row.id,
        "evidence_type": "SOURCE_FINDING",
        "link_basis": link_basis,
        "repository": (safe_location(scan.target_location) if scan else None) or _NR,
        "commit": (scan.target_commit if scan else None) or _NR,
        "branch": (scan.target_branch if scan else None) or _NR,
        "file": row.file_path if row.file_path and row.file_path != "unknown" else _NR,
        "line_start": int(row.line_number) if row.line_number and row.line_number > 0 else _NR,
        "line_end": int(end_line) if isinstance(end_line, int) else _NR,
        "symbol": ".".join(p for p in (row.class_name, row.method_name) if p) or _NR,
        "detection_method": _finding_field(row, ("metadata", "scan_method"), ("metadata", "detection_method"),
                                           ("detection", "method"), ("metadata", "rule_id"))
        or ((row.policy_evaluation or {}).get("rule_id") if isinstance(row.policy_evaluation, dict) else None) or _NR,
        "collector": (scan.scanner_id if scan else None)
        or ((row.provenance or {}).get("collector") if isinstance(row.provenance, dict) else None) or _NR,
        "collector_version": (scan.scanner_version if scan else None) or _NR,
        "captured_at": _iso(scan.scan_start if scan and scan.scan_start else row.created_at) or _NR,
        "sha256": row.content_hash,
        "sha256_basis": _hash_status(row),
        "chain_hash": row.chain_hash,
        "chain_position": row.chain_position,
        "scan_id": row.scan_id,
        "scan_status": (scan.status if scan else None) or _NR,
        "scan_manifest_sha256": (scan.manifest_hash if scan else None) or _NR,
        "confidence": str(row.confidence or _NR).upper(),
        "verification_status": verification,
        "build_digest": _finding_field(row, ("artifact", "sha256"), ("binary", "sha256"), ("metadata", "artifact_sha256"),
                                       ("metadata", "image_digest"), ("source", "artifact_sha256")) or _NR,
    }
    record["fields_not_recorded"] = sorted(k for k, v in record.items() if v == _NR)
    return record


def observation_record(obs: dict[str, Any], verification: str) -> dict[str, Any]:
    """One first-class evidence record for a live network observation."""
    evidence = obs.get("evidence") or {}
    record = {
        "evidence_id": evidence.get("evidence_id") or _NR,
        "evidence_type": evidence.get("evidence_type") or "NETWORK_OBSERVATION",
        "link_basis": "ENDPOINT_OBSERVATION",
        "endpoint": obs.get("endpoint") or _NR,
        "repository": _NR, "commit": _NR, "file": _NR, "line_start": _NR, "line_end": _NR,
        "detection_method": evidence.get("detection_method") or _NR,
        "collector": evidence.get("collector") or _NR,
        "collector_version": evidence.get("collector_version") or _NR,
        "captured_at": evidence.get("captured_at") or _NR,
        "sha256": evidence.get("sha256") or _NR,
        "sha256_basis": evidence.get("sha256_basis") or _NR,
        "confidence": evidence.get("confidence") or _NR,
        "verification_status": verification,
        "build_digest": _NR,
        "source_store": evidence.get("source") or _NR,
    }
    record["fields_not_recorded"] = sorted(k for k, v in record.items()
                                           if v == _NR and k not in {"repository", "commit", "file", "line_start",
                                                                     "line_end", "build_digest"})
    record["not_applicable"] = ["repository", "commit", "file", "line_start", "line_end", "build_digest"]
    return record


def evidence_block(asset: dict[str, Any], rows: list[Any], scans: dict[str, Any], *,
                   link_basis: str | None = None, observation: dict[str, Any] | None = None
                   ) -> tuple[list[dict], list[dict], list[dict]]:
    """``(occurrences, properties, evidence records)`` for one asset row."""
    props: list[dict[str, str]] = []
    lifecycle = str(asset.get("lifecycle_state") or "DISCOVERED").upper()
    location = str(asset.get("file_path") or "")
    is_network = bool(_endpoint(location)) or (isinstance(asset.get("extra"), dict)
                                               and asset["extra"].get("observation") == "live TLS handshake")
    if lifecycle in {"VERIFIED", "ACTIVE"}:
        verification = "HUMAN_VERIFIED_LIFECYCLE"
    elif is_network:
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
    if not rows and observation and observation.get("evidence"):
        record = observation_record(observation, verification)
        props += [_prop("cryptoscan:evidence_link_status", "OBSERVATION"),
                  _prop("cryptoscan:evidence_count", "1"),
                  _prop("cryptoscan:evidence:id", record["evidence_id"]),
                  _prop("cryptoscan:evidence:type", record["evidence_type"]),
                  _prop("cryptoscan:evidence:sha256", f"sha256:{record['sha256']}"),
                  _prop("cryptoscan:evidence:sha256_basis", record["sha256_basis"]),
                  _prop("cryptoscan:evidence:collector", record["collector"]),
                  _prop("cryptoscan:evidence:collector_version", record["collector_version"]),
                  _prop("cryptoscan:evidence:captured_at", record["captured_at"]),
                  _prop("cryptoscan:evidence:records", [record])]
        occurrence = {"location": location or record["endpoint"],
                      "additionalContext": f"evidence:{record['evidence_id']} sha256:{record['sha256']}"}
        return [occurrence], props, [record]
    if not rows:
        props += [_prop("cryptoscan:evidence_link_status", "NO_EVIDENCE_RECORD"),
                  _prop("cryptoscan:evidence_count", "0"),
                  _prop("cryptoscan:evidence:basis",
                        "asset row only: no linked evidence record, no scan finding at the same location/algorithm "
                        "and no network observation — the location is a scanner claim, not an evidence record")]
        return [], props, []
    basis = link_basis or "RECORDED_LINK"
    evidence_records = [_source_record(r, scans.get(r.scan_id), basis, verification) for r in rows]
    primary = evidence_records[-1]  # most recent observation
    props += [_prop("cryptoscan:evidence_link_status", "LINKED" if basis == "RECORDED_LINK" else "RESOLVED"),
              _prop("cryptoscan:evidence:link_basis", basis),
              _prop("cryptoscan:evidence_count", str(len(rows))),
              _prop("cryptoscan:evidence:id", primary["evidence_id"]),
              _prop("cryptoscan:evidence:content_hash", f"sha256:{primary['sha256']}"),
              _prop("cryptoscan:evidence:hash_verification", primary["sha256_basis"]),
              _prop("cryptoscan:evidence:chain_hash", f"sha256:{primary['chain_hash']}"),
              _prop("cryptoscan:evidence:chain_position", str(primary["chain_position"])),
              _prop("cryptoscan:evidence:confidence", primary["confidence"])]
    if len(rows) > 1:
        props.append(_prop("cryptoscan:evidence:ids", [r["evidence_id"] for r in evidence_records[-_MAX_EVIDENCE_DETAIL:]]))
    for key in ("repository", "commit", "branch", "file", "line_start", "detection_method", "collector",
                "collector_version", "captured_at", "build_digest", "scan_id", "scan_status"):
        value = primary.get(key)
        if value not in (None, "", _NR):
            name = "source_repository" if key == "repository" else key
            props.append(_prop(f"cryptoscan:evidence:{name}", str(value)))
    if primary["fields_not_recorded"]:
        props.append(_prop("cryptoscan:evidence:fields_not_recorded", primary["fields_not_recorded"]))
    seen = sorted(r["captured_at"] for r in evidence_records if r["captured_at"] != _NR)
    if seen:
        props += [_prop("cryptoscan:evidence:first_seen", seen[0]), _prop("cryptoscan:evidence:last_seen", seen[-1])]
    props.append(_prop("cryptoscan:evidence:records", evidence_records[-_MAX_EVIDENCE_DETAIL:]))
    occurrences = []
    for row, rec in zip(rows[-_MAX_EVIDENCE_DETAIL:], evidence_records[-_MAX_EVIDENCE_DETAIL:]):
        if not row.file_path or row.file_path == "unknown":
            continue
        item: dict[str, Any] = {"location": str(row.file_path)}
        if row.line_number and row.line_number > 0:
            item["line"] = int(row.line_number)
        if rec["symbol"] != _NR:
            item["symbol"] = rec["symbol"]
        item["additionalContext"] = f"evidence:{row.id} sha256:{row.content_hash}"
        occurrences.append(item)
    return occurrences, props, evidence_records


# --------------------------------------------------------------------------- #
# ownership mapping
# --------------------------------------------------------------------------- #


#: mapping status → relationship basis (review P1 vocabulary)
_MAPPING_BASIS = {MAPPED_EVIDENCE: "OBSERVED", MAPPED_DECLARED: "DECLARED", MAPPED_RECORDED: "DECLARED"}


def mapping_block(asset: dict[str, Any], rows: list[Any], scans: dict[str, Any], systems: dict[str, Any],
                  targets: dict[str, list[str]], claims: dict[str, str], *,
                  system_targets: dict[str, set[str]] | None = None,
                  observation: dict[str, Any] | None = None, link_basis: str | None = None
                  ) -> tuple[list[dict[str, str]], dict[str, Any] | None]:
    """``(mapping properties, membership relationship record or None)``.

    Every mapped asset states: status, basis, the evidence id that supports
    the link, confidence, verification status, the scope of what the link
    proves, and ``runtime_dependency_verified`` — always ``false`` here: a scan
    of the system's repository shows the algorithm is *in its code*, and an
    endpoint the system claims shows what that *listener* negotiated; neither
    proves the system's internal runtime use of the algorithm.
    """
    from api.cbom_collection import relationship

    system_id = asset.get("system_id")
    endpoint = _endpoint(asset.get("file_path")) or (
        asset.get("extra", {}).get("endpoint") if isinstance(asset.get("extra"), dict)
        and asset["extra"].get("observation") == "live TLS handshake" else None)
    scan_targets = {_target_key(scans[r.scan_id].target_location) for r in rows
                    if r.scan_id in scans and scans[r.scan_id].target_location}
    imported = str(asset.get("source_basis") or "").startswith(("IMPORT", "LEGACY_IMPORT"))
    asset_ref = str(asset.get("id"))
    if system_id:
        system = systems.get(system_id)
        known = set((system_targets or {}).get(system_id, set()))
        if system is not None and getattr(system, "scan_target", None):
            known.add(_target_key(system.scan_target))
        corroborating = [r for r in rows if r.scan_id in scans and (
            _target_key(scans[r.scan_id].target_location) in known
            or (system is not None and system.last_scan_id and r.scan_id == system.last_scan_id))]
        obs_evidence = (observation or {}).get("evidence") or {}
        if system is not None and corroborating:
            status, basis, confidence = MAPPED_EVIDENCE, "SCAN_OF_THE_SYSTEMS_REGISTERED_TARGET", "HIGH"
            if link_basis == "MATCHED_BY_LOCATION_AND_ALGORITHM":
                confidence = "MEDIUM"
            evidence_id = corroborating[-1].id
            scope = "SYSTEM_SOURCE_REPOSITORY"
            scope_note = ("the algorithm appears in the system's scanned repository; presence in code is not proof "
                          "of runtime use")
            verification = "EVIDENCE_CORROBORATED_NOT_HUMAN_APPROVED"
            first = _iso(scans[corroborating[0].scan_id].scan_start) if corroborating[0].scan_id in scans else None
            last = _iso(scans[corroborating[-1].scan_id].scan_start) if corroborating[-1].scan_id in scans else None
        elif endpoint and claims.get(endpoint) == system_id:
            status, basis, confidence = MAPPED_EVIDENCE, "NETWORK_ENDPOINT_CLAIMED_BY_SYSTEM", "MEDIUM"
            evidence_id = obs_evidence.get("evidence_id") or f"network-target:{endpoint}"
            scope = "SYSTEM_CLAIMED_ENDPOINT"
            scope_note = ("the system claims this endpoint and the collector observed what the listener negotiated; "
                          "a load balancer or proxy may terminate TLS, and the observation says nothing about "
                          "algorithms the system uses internally")
            verification = "ENDPOINT_OWNERSHIP_DECLARED_OBSERVATION_RUNTIME"
            first, last = obs_evidence.get("first_seen") or obs_evidence.get("captured_at"), obs_evidence.get("captured_at")
        elif imported:
            status, basis, confidence = MAPPED_DECLARED, "IMPORTED_DECLARATION", "LOW"
            evidence_id, scope, verification = None, "DECLARATION_ONLY", "UNVERIFIED_DECLARATION"
            scope_note = "declared by an imported document; not observed by a collector"
            first = last = None
        else:
            status, basis, confidence = (MAPPED_RECORDED, "LINK_RECORDED_WITHOUT_PROVENANCE", "UNKNOWN")
            evidence_id, scope, verification = None, "LINK_ONLY", "UNVERIFIED_LINK_WITHOUT_PROVENANCE"
            scope_note = ("the system link exists but neither a scan of the system's target nor a claimed endpoint "
                          "corroborates it; the link table stores no approver")
            first = last = None
        rel_basis = "INFERRED" if basis == "NETWORK_ENDPOINT_CLAIMED_BY_SYSTEM" else _MAPPING_BASIS[status]
        props = [_prop("cryptoscan:mapping_status", status), _prop("cryptoscan:mapping_basis", basis),
                 _prop("cryptoscan:mapping_evidence_id", evidence_id or _NR),
                 _prop("cryptoscan:mapping_confidence", confidence),
                 _prop("cryptoscan:mapping_verification_status", verification),
                 _prop("cryptoscan:mapping_scope", scope),
                 _prop("cryptoscan:mapping_note", scope_note),
                 _prop("cryptoscan:runtime_dependency_verified", "false")]
        rel = relationship(f"system:{system.name}" if system is not None else f"system:{system_id}", asset_ref,
                           "SYSTEM_CONTAINS_CRYPTO_ASSET", basis=rel_basis, evidence_id=evidence_id,
                           confidence=confidence, verification_status=verification, first_seen=first, last_seen=last,
                           scope=scope)
        props.append(_prop("cryptoscan:relationship:membership", rel))
        return props, rel
    # unmapped: explain, and propose only evidence-derived candidates
    candidates: list[tuple[str, str]] = []
    for key in scan_targets:
        candidates += [(sid, "SCAN_TARGET_MATCHES_REGISTERED_SYSTEM") for sid in targets.get(key, [])]
    if endpoint and claims.get(endpoint) in systems:
        candidates.append((claims[endpoint], "NETWORK_ENDPOINT_CLAIMED_BY_SYSTEM"))
    if candidates:
        sid, basis = sorted(set(candidates))[0]
        evidence_id = (rows[-1].id if rows and basis.startswith("SCAN") else
                       ((observation or {}).get("evidence") or {}).get("evidence_id")) or _NR
        return [_prop("cryptoscan:mapping_status", PENDING), _prop("cryptoscan:mapping_basis", basis),
                _prop("cryptoscan:mapping_evidence_id", evidence_id),
                _prop("cryptoscan:mapping_confidence", "HIGH" if basis.startswith("SCAN") else "MEDIUM"),
                _prop("cryptoscan:mapping_verification_status", "PENDING_REVIEW"),
                _prop("cryptoscan:runtime_dependency_verified", "false"),
                _prop("cryptoscan:mapping_candidate_system", f"system:{systems[sid].name}"),
                _prop("cryptoscan:mapping_reason", "evidence points at a registered system but the link has not "
                                                   "been recorded or approved")], None
    if endpoint:
        reason = "NETWORK_ENDPOINT_NOT_CLAIMED_BY_ANY_SYSTEM"
    elif not rows:
        reason = "NO_EVIDENCE_LINK_AND_NO_SYSTEM_LINK"
    elif scan_targets:
        reason = "SCAN_TARGET_NOT_REGISTERED_TO_ANY_SYSTEM"
    else:
        reason = "EVIDENCE_HAS_NO_SCAN_TARGET"
    return [_prop("cryptoscan:mapping_status", UNMAPPED), _prop("cryptoscan:mapping_basis", "NONE"),
            _prop("cryptoscan:mapping_evidence_id", _NR), _prop("cryptoscan:mapping_confidence", "NONE"),
            _prop("cryptoscan:mapping_verification_status", "NOT_APPLICABLE"),
            _prop("cryptoscan:runtime_dependency_verified", "false"),
            _prop("cryptoscan:mapping_reason", reason)], None


# --------------------------------------------------------------------------- #
# assembly
# --------------------------------------------------------------------------- #


def _system_targets(db: Session, systems: list[Any]) -> dict[str, set[str]]:
    """Target keys a system is known to own: its registered target and the
    repository of the last job recorded against it."""
    from db.models.scan import Scan

    ids = sorted({s.last_scan_id for s in systems if s.last_scan_id})
    locations: dict[str, str] = {}
    for chunk in _chunks(ids):
        for scan_id, location in db.execute(select(Scan.id, Scan.target_location).where(Scan.id.in_(chunk))).all():
            locations[scan_id] = location
    out: dict[str, set[str]] = {}
    for system in systems:
        keys = {_target_key(system.scan_target)} if getattr(system, "scan_target", None) else set()
        if system.last_scan_id in locations:
            keys.add(_target_key(locations[system.last_scan_id]))
        out[system.id] = {k for k in keys if k}
    return out


def enrich_records(db: Session, records: list[dict[str, Any]], systems: list[Any],
                   observations: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Attach evidence + mapping to each located asset row (in place) and return
    an export-level summary. Placeholder rows are removed from ``records`` and
    reported in the summary instead of becoming components."""
    from cbom.crypto_normalization import is_placeholder

    observations = observations or {}
    excluded = [r for r in records if is_placeholder(r.get("algorithm"), r.get("purpose"))]
    if excluded:
        records[:] = [r for r in records if not is_placeholder(r.get("algorithm"), r.get("purpose"))]
    evidence, scans, link_basis = _load(db, records) if records else ({}, {}, {})
    by_id = {s.id: s for s in systems}
    targets: dict[str, list[str]] = {}
    for system in systems:
        key = _target_key(getattr(system, "scan_target", None))
        if key:
            targets.setdefault(key, []).append(system.id)
    claims = {ep: sid for ep, sid in _endpoint_claims(db).items() if sid in by_id}
    system_targets = _system_targets(db, systems)
    mapping_counts: dict[str, int] = {}
    mapping_basis_counts: dict[str, int] = {}
    reasons: dict[str, int] = {}
    link_status: dict[str, int] = {}
    hash_status: dict[str, int] = {}
    relationships: list[dict[str, Any]] = []
    scans_by_system: dict[str, set[str]] = {}
    seen_assets: set[str] = set()
    for record in records:
        aid = str(record.get("id"))
        rows = evidence.get(aid, [])
        extra = record.get("extra") if isinstance(record.get("extra"), dict) else {}
        endpoint = _endpoint(record.get("file_path")) or (extra.get("endpoint") if extra.get("observation") else None)
        observation = observations.get(endpoint) if endpoint else None
        occurrences, props, ev_records = evidence_block(record, rows, scans, link_basis=link_basis.get(aid),
                                                        observation=observation)
        mapping, rel = mapping_block(record, rows, scans, by_id, targets, claims, system_targets=system_targets,
                                     observation=observation, link_basis=link_basis.get(aid))
        if rel is not None:
            relationships.append(rel)
        values = {p["name"]: p["value"] for p in mapping}
        status = values["cryptoscan:mapping_status"]
        mapping_counts[status] = mapping_counts.get(status, 0) + 1
        mapping_basis_counts[values["cryptoscan:mapping_basis"]] = \
            mapping_basis_counts.get(values["cryptoscan:mapping_basis"], 0) + 1
        if status == UNMAPPED:
            reasons[values["cryptoscan:mapping_reason"]] = reasons.get(values["cryptoscan:mapping_reason"], 0) + 1
        if record.get("system_id"):
            scans_by_system.setdefault(record["system_id"], set()).update(r.scan_id for r in rows if r.scan_id)
        if aid not in seen_assets:
            seen_assets.add(aid)
            state = next(p["value"] for p in props if p["name"] == "cryptoscan:evidence_link_status")
            link_status[state] = link_status.get(state, 0) + 1
            for item in ev_records:
                hash_status[item["sha256_basis"]] = hash_status.get(item["sha256_basis"], 0) + 1
        for key, name in (("cipher_suite", "cryptoscan:evidence:cipher_suite"),
                          ("tls_version", "cryptoscan:evidence:negotiated_protocol")):
            if extra.get(key):
                props.append(_prop(name, str(extra[key])))
        if isinstance(extra.get("curve"), str) and extra["curve"]:
            record["curve"] = extra["curve"]
        record["cbom_properties"] = props + mapping
        if occurrences:
            record["cbom_occurrences"] = occurrences
    with_evidence = sum(v for k, v in link_status.items() if k != "NO_EVIDENCE_RECORD")
    return {
        "excluded": [{"ref": str(r.get("id")), "recorded_algorithm": str(r.get("algorithm")),
                      "reason": "placeholder or bookkeeping value, not cryptography"} for r in excluded],
        "mapping_counts": dict(sorted(mapping_counts.items())),
        "mapping_basis_counts": dict(sorted(mapping_basis_counts.items())),
        "unmapped_reasons": dict(sorted(reasons.items())),
        "evidence_linked_assets": link_status.get("LINKED", 0),
        "evidence_summary": {
            "assets": len(seen_assets),
            "assets_with_evidence_record": with_evidence,
            "assets_without_evidence_record": link_status.get("NO_EVIDENCE_RECORD", 0),
            "by_link_status": dict(sorted(link_status.items())),
            "by_hash_verification": dict(sorted(hash_status.items())),
            "link_status_meaning": {
                "LINKED": "recorded asset→evidence link",
                "RESOLVED": "no recorded link; matched to a scan finding with the same file, algorithm and key size",
                "OBSERVATION": "live network observation of the endpoint (no source evidence applies)",
                "NO_EVIDENCE_RECORD": "asset row only — the location is a scanner claim, not an evidence record"},
            "confidence_is_not_verification": True},
        "evidence_unlinked_assets": link_status.get("NO_EVIDENCE_RECORD", 0),
        "relationships": relationships,
        "scans_by_system": scans_by_system,
        "claims": claims,
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


def failed_collections(db: Session, limit: int = 20, scans: list[Any] | None = None) -> dict[str, Any]:
    """Failed jobs; with ``scans`` only those the export may cite."""
    from db.models.scan import Scan

    if scans is not None:
        rows = [s for s in scans if str(s.status or "").upper() == "FAILED"][:limit]
    else:
        rows = list(db.execute(select(Scan).where(Scan.status == "FAILED")
                               .order_by(Scan.scan_start.desc()).limit(limit)).scalars())
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
