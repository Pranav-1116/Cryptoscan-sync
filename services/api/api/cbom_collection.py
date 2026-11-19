"""Collection facts for the estate CBOM: coverage dimensions, TLS observations,
relationship records and collector provenance.

The estate export used to state coverage from each system's *stored* status —
so an estate with a failed warehouse collection, a queued portal rescan and two
infrastructure systems that no collector ever reached printed
``coverage_pct=100, completeness=COMPLETE``. This module derives coverage from
the collection facts themselves (scan jobs, network probe runs, runtime
observations) and reports each dimension separately:

* registered-system coverage — which systems any collector actually reached;
* successful-target coverage — per source repository / network endpoint, the
  latest job's outcome;
* repository/file coverage — repositories and files read by successful scans;
* crypto-discovery completeness — always ``NOT_PROVEN``;
* runtime-observation coverage — endpoints with a live handshake observation;
* failed / partial / pending jobs — listed, never folded into a percentage.

It also turns each live TLS observation into first-class CBOM content: the
negotiated protocol, its cipher, the certificate, the certificate's public key
and signature algorithm become separate components linked by relationships
that cite the observation's evidence id. Facts a collector did not record
(SNI, key-exchange group, chain trust …) are reported as not recorded.

Nothing here raises on missing data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

COLLECTION_PROFILE = "cryptoscan-cbom-collection/1.0.0"
NOT_RECORDED = "NOT_RECORDED"
_RUN_LIMIT = 200
_SCAN_LIMIT = 5000

#: Relationship basis vocabulary (review P1).
BASIS = ("DECLARED", "OBSERVED", "INFERRED", "RUNTIME_VERIFIED", "HUMAN_APPROVED")
#: Declared system classes that hold key material behind an API.
_KEY_CUSTODY_CLASSES = {"HSM", "KMS", "PAYMENT_HSM", "CLOUD_KMS", "KEY_MANAGER"}
_SUCCESS = {"COMPLETED", "SUCCESS", "SUCCEEDED", "DONE", "OK"}
_FAILED = {"FAILED", "ERROR", "ABORTED", "TIMEOUT", "CANCELLED"}
_PARTIAL = {"PARTIAL", "COMPLETED_WITH_ERRORS", "PARTIALLY_COMPLETED"}
_PENDING = {"QUEUED", "PENDING", "RUNNING", "IN_PROGRESS", "SCHEDULED"}


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def canonical_sha256(payload: Any) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode()).hexdigest()


def _job_state(status: Any, statistics: Any = None) -> str:
    text = str(status or "").upper()
    if text in _SUCCESS:
        errors = (statistics or {}).get("errors") if isinstance(statistics, dict) else None
        skipped = (statistics or {}).get("files_skipped") if isinstance(statistics, dict) else None
        return "PARTIAL" if errors or skipped else "SUCCEEDED"
    if text in _FAILED:
        return "FAILED"
    if text in _PARTIAL:
        return "PARTIAL"
    if text in _PENDING:
        return "PENDING"
    return "UNKNOWN"


def _target_key(value: Any) -> str:
    from api.cbom_provenance import _target_key as key

    return key(value)


def _version_from_scanner_id(scanner_id: Any) -> str | None:
    match = re.search(r"-v(\d+(?:\.\d+)*)$", str(scanner_id or ""))
    return match.group(1) if match else None


# --------------------------------------------------------------------------- #
# live network observations
# --------------------------------------------------------------------------- #


def _observation_from_finding(finding: dict[str, Any], run: Any, evidence_by_endpoint: dict[str, dict]) -> dict:
    from cbom.tls_analysis import PQC_GROUPS

    endpoint = str(finding.get("endpoint") or "")
    crypto = finding.get("crypto") if isinstance(finding.get("crypto"), dict) else {}
    certs = [c for c in (finding.get("certificates") or []) if isinstance(c, dict)]
    leaf = certs[0] if certs else {}
    chain = finding.get("chain_validation") if isinstance(finding.get("chain_validation"), dict) else {}
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    group = crypto.get("key_exchange_group") or crypto.get("negotiated_group") or finding.get("negotiated_group")
    facts = {
        "endpoint": endpoint,
        "version": crypto.get("tls_version"),
        "cipher_suite": crypto.get("cipher_suite"),
        "key_exchange": crypto.get("key_exchange_algorithm"),
        "key_exchange_group": group,
        "authentication": crypto.get("authentication_algorithm"),
        "bulk_cipher": crypto.get("encryption_algorithm"),
        "bulk_cipher_mode": crypto.get("encryption_mode") or crypto.get("mode"),
        "bulk_cipher_bits": crypto.get("key_size"),
        "alpn": crypto.get("alpn"),
        "sni": finding.get("sni") or meta.get("sni"),
        "verification_hostname": meta.get("certificate_hostname"),
        "certificate_fingerprint_sha256": leaf.get("fingerprint_sha256"),
        "certificate_subject": leaf.get("subject"),
        "certificate_issuer": leaf.get("issuer"),
        "certificate_serial": leaf.get("serial_number"),
        "certificate_public_key_algorithm": leaf.get("public_key_algorithm"),
        "certificate_public_key_bits": leaf.get("public_key_size") or leaf.get("public_key_bits"),
        "certificate_curve": leaf.get("curve"),
        "certificate_signature_algorithm": leaf.get("signature_algorithm"),
        "certificate_not_before": leaf.get("not_before"),
        "certificate_not_after": leaf.get("not_after"),
        "certificate_self_signed": leaf.get("is_self_signed"),
        "chain_length": len(certs) if certs else None,
        "chain_status": chain.get("chain_completeness") if chain.get("chain_completeness") not in (None, "NOT_EVALUATED")
        else None,
        "trust_status": chain.get("trust_status") if chain.get("trust_status") not in (None, "NOT_VERIFIED") else None,
        "chain_errors": list(chain.get("errors") or []) or None,
        "pqc_group_negotiated": bool(group) and str(group).upper().replace("-", "").replace("_", "") in PQC_GROUPS,
    }
    chained = evidence_by_endpoint.get(endpoint) or {}
    scanner = finding.get("scanner_id") or chained.get("scanner_version")
    evidence = {
        "evidence_id": chained.get("evidence_id") or finding.get("finding_id") or f"netobs:{run.id}:{endpoint}",
        "evidence_type": "NETWORK_HANDSHAKE_OBSERVATION",
        "captured_at": chained.get("observed_at") or _iso(run.created_at),
        "collector": scanner or NOT_RECORDED,
        "collector_version": _version_from_scanner_id(scanner) or NOT_RECORDED,
        "detection_method": meta.get("scan_method") or "ACTIVE_PROBE",
        "confidence": str(meta.get("confidence") or NOT_RECORDED).upper(),
        "sha256": canonical_sha256(finding),
        "sha256_basis": "COMPUTED_AT_EXPORT_OVER_STORED_COLLECTOR_FINDING",
        "run_id": run.id,
        "source": "NETWORK_SCAN_RUN",
        "chained": bool(chained),
    }
    return {"endpoint": endpoint, "state": "OBSERVED", "facts": facts, "evidence": evidence}


def network_observations(db: Session, *, endpoints: set[str] | None = None,
                         run_limit: int = _RUN_LIMIT) -> dict[str, dict[str, Any]]:
    """Latest live observation per endpoint: ``{endpoint: {state, facts, evidence, last_attempt}}``.

    Sources, strongest first: stored network scan runs (full collector
    finding), runtime session rows, then the network asset rows' own
    observation fields. A failed latest attempt is kept as ``last_attempt``.
    """
    out: dict[str, dict[str, Any]] = {}
    try:
        from db.models.network_scan_run import NetworkScanRun

        runs = list(db.execute(select(NetworkScanRun).order_by(NetworkScanRun.created_at.desc())
                               .limit(run_limit)).scalars())
    except Exception:  # noqa: BLE001 - optional store
        runs = []
    for run in runs:
        result = run.result if isinstance(run.result, dict) else {}
        evidence_by_endpoint = {}
        for item in result.get("network_evidence") or []:
            if isinstance(item, dict):
                ep = (item.get("target") or {}).get("endpoint") if isinstance(item.get("target"), dict) else None
                if ep:
                    evidence_by_endpoint.setdefault(ep, item)
        for finding in result.get("findings") or []:
            if not isinstance(finding, dict) or not finding.get("endpoint"):
                continue
            endpoint = str(finding["endpoint"])
            status = str(finding.get("status") or "").upper()
            slot = out.setdefault(endpoint, {"endpoint": endpoint})
            slot.setdefault("last_attempt", {"status": status or "UNKNOWN", "at": _iso(run.created_at),
                                             "run_id": run.id, "error": (str(finding.get("error") or "")[:200]
                                                                         or None)})
            if status == "OK" and "facts" not in slot:
                crypto = finding.get("crypto") if isinstance(finding.get("crypto"), dict) else {}
                if crypto.get("tls_version") or crypto.get("cipher_suite"):
                    slot.update(_observation_from_finding(finding, run, evidence_by_endpoint))
    # runtime session rows (materialized by every TLS collection path)
    try:
        from db.models.runtime_finding import RuntimeFinding

        rows = list(db.execute(select(RuntimeFinding).where(RuntimeFinding.kind == "session")
                               .order_by(RuntimeFinding.last_seen_at.desc()).limit(5000)).scalars())
    except Exception:  # noqa: BLE001
        rows = []
    for row in rows:
        endpoint = str(row.hostname or "")
        if not endpoint or "facts" in out.get(endpoint, {}):
            continue
        extra = row.extra if isinstance(row.extra, dict) else {}
        payload = {"scanner_id": row.scanner_id, "hostname": endpoint, "tls_version": row.tls_version,
                   "cipher_suite": row.cipher_suite, "algorithm": row.algorithm, "key_size": row.key_size,
                   "extra": extra}
        slot = out.setdefault(endpoint, {"endpoint": endpoint})
        slot.update({
            "state": "OBSERVED",
            "facts": {"endpoint": endpoint, "version": row.tls_version, "cipher_suite": row.cipher_suite,
                      "key_exchange": extra.get("key_exchange"), "authentication": extra.get("authentication"),
                      "bulk_cipher": row.algorithm, "bulk_cipher_bits": row.key_size,
                      "bulk_cipher_mode": extra.get("mode"), "pqc_group_negotiated": False},
            "evidence": {"evidence_id": f"runtime:{row.id}", "evidence_type": "RUNTIME_SESSION_OBSERVATION",
                         "captured_at": _iso(row.last_seen_at), "first_seen": _iso(row.created_at),
                         "collector": row.scanner_id or NOT_RECORDED,
                         "collector_version": _version_from_scanner_id(row.scanner_id) or NOT_RECORDED,
                         "detection_method": "ACTIVE_PROBE", "confidence": NOT_RECORDED,
                         "observation_count": row.observation_count,
                         "sha256": canonical_sha256(payload),
                         "sha256_basis": "COMPUTED_AT_EXPORT_OVER_STORED_RUNTIME_ROW",
                         "source": "RUNTIME_FINDING"},
        })
    if endpoints is not None:
        # only endpoints this export covers (its systems' targets, its asset rows)
        out = {ep: obs for ep, obs in out.items() if ep in endpoints}
    return out


def export_endpoints(db: Session, systems: list[Any], records: list[dict[str, Any]]) -> set[str]:
    """Endpoints in scope: claimed by an exported system, or the location of an exported asset row."""
    ids = {s.id for s in systems}
    out: set[str] = set()
    try:
        from db.models.network_scan_target import NetworkScanTarget

        for target in db.execute(select(NetworkScanTarget)).scalars():
            if target.system_id in ids and target.endpoint:
                out.add(str(target.endpoint))
    except Exception:  # noqa: BLE001 - optional store
        pass
    for record in records:
        location = str(record.get("file_path") or "")
        extra = record.get("extra") if isinstance(record.get("extra"), dict) else {}
        if location.startswith(("tls://", "dtls://")):
            out.add(location.split("://", 1)[1])
        if extra.get("observation") == "live TLS handshake" and extra.get("endpoint"):
            out.add(str(extra["endpoint"]))
    return out


def enrich_observations_from_assets(observations: dict[str, dict], records: list[dict[str, Any]], db: Session) -> None:
    """Fill certificate facts the runtime rows do not carry from the network
    asset rows (``host:port`` certificate key) and the certificate store."""
    certs_by_fp: dict[str, Any] = {}
    fingerprints = {str((r.get("extra") or {}).get("fingerprint_sha256")) for r in records
                    if isinstance(r.get("extra"), dict) and (r.get("extra") or {}).get("fingerprint_sha256")}
    if fingerprints:
        try:
            from db.models.certificate import Certificate

            for cert in db.execute(select(Certificate).where(Certificate.fingerprint_sha256.in_(sorted(fingerprints)))
                                   ).scalars():
                certs_by_fp[cert.fingerprint_sha256] = cert
        except Exception:  # noqa: BLE001
            pass
    for record in records:
        extra = record.get("extra") if isinstance(record.get("extra"), dict) else {}
        location = str(record.get("file_path") or "")
        endpoint = extra.get("endpoint") or (location[len("tls://"):] if location.startswith("tls://") else None)
        if not endpoint or extra.get("observation") != "live TLS handshake":
            continue
        slot = observations.setdefault(endpoint, {"endpoint": endpoint})
        facts = slot.setdefault("facts", {"endpoint": endpoint, "pqc_group_negotiated": False})
        if location.startswith("tls://"):
            for key, src in (("version", "tls_version"), ("cipher_suite", "cipher_suite"),
                             ("key_exchange", "key_exchange"), ("authentication", "authentication")):
                if facts.get(key) is None and extra.get(src):
                    facts[key] = extra[src]
        else:
            fp = extra.get("fingerprint_sha256")
            cert = certs_by_fp.get(fp)
            fill = {
                "certificate_fingerprint_sha256": fp,
                "certificate_subject": extra.get("subject") or (cert.subject if cert else None),
                "certificate_issuer": cert.issuer if cert else None,
                "certificate_serial": cert.serial_number if cert else None,
                "certificate_public_key_algorithm": record.get("algorithm"),
                "certificate_public_key_bits": record.get("key_size"),
                "certificate_curve": extra.get("curve"),
                "certificate_signature_algorithm": extra.get("signature_algorithm"),
                "certificate_not_before": _iso(cert.not_before) if cert else None,
                "certificate_not_after": _iso(cert.not_after) if cert else None,
                "certificate_self_signed": cert.is_self_signed if cert else None,
            }
            for key, value in fill.items():
                if facts.get(key) in (None, "") and value not in (None, ""):
                    facts[key] = value
            facts["certificate_asset_ref"] = str(record.get("id"))
        if "evidence" not in slot:
            payload = {"asset": str(record.get("id")), "location": location, "extra": extra}
            slot["state"] = "OBSERVED"
            slot["evidence"] = {"evidence_id": f"asset-observation:{record.get('id')}",
                                "evidence_type": "NETWORK_ASSET_OBSERVATION_FIELDS",
                                "captured_at": extra.get("last_seen_at") or NOT_RECORDED,
                                "first_seen": extra.get("first_seen_at"),
                                "collector": ",".join(record.get("scanner_ids") or []) or NOT_RECORDED,
                                "collector_version": NOT_RECORDED, "detection_method": "ACTIVE_PROBE",
                                "confidence": str(record.get("confidence") or NOT_RECORDED).upper(),
                                "sha256": canonical_sha256(payload),
                                "sha256_basis": "COMPUTED_AT_EXPORT_OVER_STORED_ASSET_OBSERVATION_FIELDS",
                                "source": "CRYPTO_ASSET_ROW"}


# --------------------------------------------------------------------------- #
# relationships
# --------------------------------------------------------------------------- #


def relationship(source: str, target: str, rtype: str, *, basis: str, evidence_id: str | None,
                 confidence: str, verification_status: str, first_seen: str | None, last_seen: str | None,
                 scope: str | None = None) -> dict[str, Any]:
    if basis not in BASIS:
        raise ValueError(f"unknown relationship basis {basis}")
    rid = "rel:" + hashlib.sha256(f"{rtype}|{source}|{target}".encode()).hexdigest()[:20]
    record = {"relationship_id": rid, "source": source, "target": target, "type": rtype, "basis": basis,
              "evidence_id": evidence_id or NOT_RECORDED, "confidence": confidence,
              "verification_status": verification_status, "first_seen": first_seen or NOT_RECORDED,
              "last_seen": last_seen or NOT_RECORDED}
    if scope:
        record["scope"] = scope
    return record


# --------------------------------------------------------------------------- #
# TLS observations → components
# --------------------------------------------------------------------------- #


def _prop(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "value": value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)}


def _alg_component(ref: str, algorithm: str, *, key_size: Any = None, mode: Any = None, curve: Any = None,
                   purpose: str, location: str, evidence: dict[str, Any], system: dict[str, Any] | None,
                   role: str, basis_note: str) -> dict[str, Any]:
    props = [_prop("cryptoscan:purpose", purpose), _prop("cryptoscan:confidence", evidence.get("confidence") or "HIGH"),
             _prop("cryptoscan:component_role", role), _prop("cryptoscan:deployment_stage", "RUNTIME_OBSERVED"),
             _prop("cryptoscan:evidence:id", evidence["evidence_id"]),
             _prop("cryptoscan:evidence_link_status", "OBSERVATION"),
             _prop("cryptoscan:evidence:sha256", f"sha256:{evidence['sha256']}"),
             _prop("cryptoscan:evidence:sha256_basis", evidence["sha256_basis"]),
             _prop("cryptoscan:evidence:collector", evidence.get("collector") or NOT_RECORDED),
             _prop("cryptoscan:evidence:captured_at", evidence.get("captured_at") or NOT_RECORDED),
             _prop("cryptoscan:evidence:basis", basis_note),
             _prop("cryptoscan:verification_status", "COLLECTOR_OBSERVED_NOT_HUMAN_VERIFIED")]
    if curve:
        props.append(_prop("cryptoscan:curve", str(curve)))
    if system:
        props += [_prop("cryptoscan:system", system["name"]), _prop("cryptoscan:system_id", system["id"])]
        if system.get("criticality"):
            props.append(_prop("cryptoscan:criticality", system["criticality"]))
    algorithm_props: dict[str, Any] = {"primitive": "unknown", "algorithm": algorithm}
    if key_size:
        algorithm_props["parameterSetIdentifier"] = str(key_size)
    if mode:
        algorithm_props["mode"] = str(mode)
    if curve:
        algorithm_props["curve"] = str(curve)
    return {"type": "cryptographic-asset", "name": algorithm, "bom-ref": ref,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algorithm_props},
            "evidence": {"occurrences": [{"location": location,
                                          "additionalContext": f"evidence:{evidence['evidence_id']} "
                                                               f"sha256:{evidence['sha256']}"}]},
            "properties": props}


def _bulk_cipher(facts: dict[str, Any]) -> tuple[str | None, Any, Any]:
    from cbom.tls_analysis import parse_suite

    suite = parse_suite(facts.get("cipher_suite"))
    if suite["recognized"] and suite["cipher"] not in {None, "NULL"}:
        cipher = suite["cipher"]
        if cipher == "AES" and suite["mode"] in {"GCM", "CCM", "CCM_8"}:
            return f"AES-{suite['mode'][:3]}", suite["cipher_bits"], suite["mode"][:3]
        if cipher == "CHACHA20":
            return "ChaCha20-Poly1305", 256, None
        return cipher, suite["cipher_bits"], suite["mode"] if suite["mode"] in {"CBC"} else None
    return None, None, None


def tls_components(records: list[dict[str, Any]], observations: dict[str, dict[str, Any]],
                   systems_by_id: dict[str, Any], claims: dict[str, str]) -> dict[str, Any]:
    """Turn each live TLS observation into separate, linked components.

    Returns ``{"components", "provides", "depends", "relationships",
    "record_properties", "summary"}``: new components (bulk cipher, key
    exchange — only when the group/method is recorded —, certificate, its
    public key and its signature algorithm), protocol→algorithm ``provides``
    edges, protocol→certificate ``dependsOn``, relationship records citing the
    observation evidence id, and the ``cryptoscan:tls:observation`` property
    to attach to each endpoint's protocol record.
    """
    from cbom.tls_analysis import parse_suite

    components: list[dict[str, Any]] = []
    provides: dict[str, list[str]] = {}
    depends: dict[str, list[str]] = {}
    relationships: list[dict[str, Any]] = []
    record_props: dict[str, list[dict[str, str]]] = {}
    summary = {"tls_observations": 0, "versions": {}, "missing_facts": {}, "components_added": 0}
    # the network materializer stores the negotiated bulk cipher at tls://endpoint
    cipher_records: dict[str, dict[str, Any]] = {}
    for record in records:
        location = str(record.get("file_path") or "")
        if location.startswith("tls://") and str(record.get("purpose") or "").upper() == "NETWORK_ENCRYPTION":
            cipher_records.setdefault(location[len("tls://"):], record)
    members: dict[str, list[str]] = {}
    seen: set[str] = set()
    for endpoint, obs in sorted(observations.items()):
        facts, evidence = obs.get("facts"), obs.get("evidence")
        if not facts or not evidence or not (facts.get("version") or facts.get("cipher_suite")):
            continue
        key = re.sub(r"[^A-Za-z0-9_.:-]", "_", endpoint)
        proto_ref = f"tls-protocol:{key}"
        if proto_ref in seen:
            continue
        seen.add(proto_ref)
        location = f"tls://{endpoint}"
        cipher_record = cipher_records.get(endpoint)
        sid = (cipher_record or {}).get("system_id") or claims.get(endpoint)
        system = systems_by_id.get(sid)
        sys_info = ({"id": system.id, "name": system.name, "criticality": system.criticality} if system else None)
        evid, captured = evidence["evidence_id"], evidence.get("captured_at")
        first = evidence.get("first_seen") or captured
        summary["tls_observations"] += 1
        version = str(facts.get("version") or NOT_RECORDED)
        summary["versions"][version] = summary["versions"].get(version, 0) + 1
        observation = {k: v for k, v in facts.items() if v not in (None, "", [])}
        not_recorded = sorted(k for k in ("version", "cipher_suite", "key_exchange_group", "sni",
                                          "certificate_public_key_algorithm", "certificate_signature_algorithm",
                                          "certificate_not_after", "chain_status", "trust_status")
                              if facts.get(k) in (None, "", []))
        for k in not_recorded:
            summary["missing_facts"][k] = summary["missing_facts"].get(k, 0) + 1
        observation["facts_not_recorded"] = not_recorded
        observation["evidence"] = {k: evidence[k] for k in ("evidence_id", "evidence_type", "captured_at", "collector",
                                                            "collector_version", "detection_method", "sha256",
                                                            "sha256_basis", "source") if k in evidence}
        # the protocol itself: one component per observed endpoint
        proto = _alg_component(proto_ref, str(facts.get("version") or "TLS"), purpose="TRANSPORT_SECURITY",
                               location=location, evidence=evidence, system=sys_info, role="TLS_OBSERVED_PROTOCOL",
                               basis_note="protocol version negotiated in a live handshake with this endpoint")
        proto["properties"] += [_prop("cryptoscan:tls:observation", observation),
                                _prop("cryptoscan:tls:endpoint", endpoint)]
        if facts.get("cipher_suite"):
            proto["properties"].append(_prop("cryptoscan:evidence:cipher_suite", str(facts["cipher_suite"])))
        components.append(proto)
        if sid:
            members.setdefault(sid, []).append(proto_ref)
            relationships.append(relationship(
                f"system:{system.name}" if system else f"system:{sid}", proto_ref, "SYSTEM_EXPOSES_PROTOCOL",
                basis="INFERRED", evidence_id=evid, confidence="MEDIUM",
                verification_status="ENDPOINT_OWNERSHIP_DECLARED_OBSERVATION_RUNTIME", first_seen=first,
                last_seen=captured, scope="the system claims this endpoint; a proxy or load balancer may terminate TLS"))
        verified = dict(basis="RUNTIME_VERIFIED", evidence_id=evid, confidence="HIGH",
                        verification_status="VERIFIED_BY_HANDSHAKE_OBSERVATION", first_seen=first, last_seen=captured,
                        scope="endpoint-level: what this listener negotiated; not proof of internal use by its owner")
        # bulk cipher: reuse the materialized asset row; add a component only when none exists
        bulk, bits, mode = _bulk_cipher(facts)
        if cipher_record is not None:
            ref = str(cipher_record.get("id"))
            if mode and not cipher_record.get("mode"):
                cipher_record["mode"] = mode  # the suite names the mode; the asset row lost it
            provides.setdefault(proto_ref, []).append(ref)
            relationships.append(relationship(proto_ref, ref, "PROTOCOL_PROVIDES_ALGORITHM", **verified))
        elif bulk:
            ref = f"tls-cipher:{key}"
            components.append(_alg_component(ref, bulk, key_size=bits, mode=mode, purpose="NETWORK_ENCRYPTION",
                                             location=location, evidence=evidence, system=sys_info,
                                             role="TLS_NEGOTIATED_BULK_CIPHER",
                                             basis_note="bulk cipher of the negotiated cipher suite"))
            provides.setdefault(proto_ref, []).append(ref)
            relationships.append(relationship(proto_ref, ref, "PROTOCOL_PROVIDES_ALGORITHM", **verified))
        # key exchange — only when the method (TLS 1.2 suite) or the group is recorded
        suite = parse_suite(facts.get("cipher_suite"))
        group = facts.get("key_exchange_group")
        kx_name = None
        if group:
            from cbom.tls_analysis import normalize_group

            g = normalize_group(group)
            kx_name = ("ML-KEM-768" if g["pqc_hybrid"] and "768" in str(group) else
                       "X25519" if str(group).upper() == "X25519" else "ECDH" if g["curve"] else str(group))
            kx_curve = g["curve"] if g["curve"] not in {"X25519"} else None
        elif suite["recognized"] and not suite["tls13"] and suite["key_exchange"] in {"ECDHE", "DHE", "RSA"}:
            kx_name = {"ECDHE": "ECDH", "DHE": "DHE", "RSA": "RSA"}[suite["key_exchange"]]
            kx_curve = None
        if kx_name:
            ref = f"tls-kex:{key}"
            components.append(_alg_component(
                ref, kx_name, curve=kx_curve, purpose="KEY_EXCHANGE", location=location, evidence=evidence,
                system=sys_info, role="TLS_NEGOTIATED_KEY_EXCHANGE",
                basis_note=("negotiated key-exchange group recorded by the collector" if group else
                            "key-exchange method named by the negotiated TLS 1.2 suite; group/curve not recorded")))
            provides.setdefault(proto_ref, []).append(ref)
            relationships.append(relationship(proto_ref, ref, "PROTOCOL_PROVIDES_ALGORITHM", **verified))
        if facts.get("cipher_suite"):
            # the suite's algorithms, by reference to components holding the same observation
            proto["cryptoProperties"]["protocolProperties"] = {"cipherSuites": [
                {"name": str(facts["cipher_suite"]), **({"algorithms": list(provides[proto_ref])}
                                                         if provides.get(proto_ref) else {})}]}
        # certificate + public key + signature algorithm
        fp = facts.get("certificate_fingerprint_sha256")
        if fp:
            cert_ref = f"certificate:{fp}"
            alg_ref = facts.get("certificate_asset_ref")
            sig_ref = None
            if facts.get("certificate_signature_algorithm"):
                sig_ref = f"cert-sig:{fp[:24]}"
                components.append(_alg_component(
                    sig_ref, str(facts["certificate_signature_algorithm"]), purpose="CERTIFICATE_SIGNATURE",
                    location=location, evidence=evidence, system=sys_info, role="CERTIFICATE_SIGNATURE_ALGORITHM",
                    basis_note="signatureAlgorithm of the leaf certificate presented in the handshake"))
            if not alg_ref and facts.get("certificate_public_key_algorithm"):
                alg_ref = f"cert-key-alg:{fp[:24]}"
                components.append(_alg_component(
                    alg_ref, str(facts["certificate_public_key_algorithm"]),
                    key_size=facts.get("certificate_public_key_bits"), curve=facts.get("certificate_curve"),
                    purpose="CERTIFICATE", location=location, evidence=evidence, system=sys_info,
                    role="CERTIFICATE_PUBLIC_KEY_ALGORITHM",
                    basis_note="subject public key algorithm of the leaf certificate"))
            key_ref = None
            if alg_ref:
                key_ref = f"cert-pubkey:{fp[:24]}"
                material: dict[str, Any] = {"type": "public-key", "algorithmRef": alg_ref, "format": "X.509 SPKI"}
                try:
                    if facts.get("certificate_public_key_bits"):
                        material["size"] = int(facts["certificate_public_key_bits"])
                except (TypeError, ValueError):
                    pass
                components.append({"type": "cryptographic-asset", "name": f"public key of {fp[:16]}",
                                   "bom-ref": key_ref,
                                   "cryptoProperties": {"assetType": "related-crypto-material",
                                                        "relatedCryptoMaterialProperties": material},
                                   "evidence": {"occurrences": [{"location": location, "additionalContext":
                                                                 f"evidence:{evid} sha256:{evidence['sha256']}"}]},
                                   "properties": [_prop("cryptoscan:evidence:id", evid), _prop("cryptoscan:evidence_link_status", "OBSERVATION"),
                                                  _prop("cryptoscan:component_role", "CERTIFICATE_SUBJECT_PUBLIC_KEY"),
                                                  _prop("cryptoscan:certificate:fingerprint_sha256", fp)]})
                depends.setdefault(key_ref, []).append(alg_ref)
                relationships.append(relationship(key_ref, alg_ref, "PUBLIC_KEY_USES_ALGORITHM", basis="OBSERVED",
                                                  evidence_id=evid, confidence="HIGH",
                                                  verification_status="PARSED_FROM_OBSERVED_CERTIFICATE",
                                                  first_seen=first, last_seen=captured))
            cert_props: dict[str, Any] = {"certificateFormat": "X.509"}
            for field, src in (("subjectName", "certificate_subject"), ("issuerName", "certificate_issuer")):
                if facts.get(src):
                    cert_props[field] = str(facts[src])
            for field, src in (("notValidBefore", "certificate_not_before"), ("notValidAfter", "certificate_not_after")):
                if facts.get(src):
                    cert_props[field] = str(facts[src]).replace(" ", "T")
            if sig_ref:
                cert_props["signatureAlgorithmRef"] = sig_ref
            if key_ref:
                cert_props["subjectPublicKeyRef"] = key_ref
            if cert_ref not in {c["bom-ref"] for c in components}:
                cprops = [_prop("cryptoscan:certificate:fingerprint_sha256", fp),
                          _prop("cryptoscan:certificate:observed_at", location),
                          _prop("cryptoscan:certificate:chain_length", str(facts.get("chain_length") or NOT_RECORDED)),
                          _prop("cryptoscan:certificate:chain_status", str(facts.get("chain_status") or NOT_RECORDED)),
                          _prop("cryptoscan:certificate:trust_status", str(facts.get("trust_status") or NOT_RECORDED)),
                          _prop("cryptoscan:certificate:self_signed",
                                str(facts.get("certificate_self_signed")).lower()
                                if facts.get("certificate_self_signed") is not None else NOT_RECORDED),
                          _prop("cryptoscan:evidence:id", evid), _prop("cryptoscan:evidence_link_status", "OBSERVATION"),
                          _prop("cryptoscan:evidence:sha256", f"sha256:{evidence['sha256']}"),
                          _prop("cryptoscan:evidence:captured_at", captured or NOT_RECORDED),
                          _prop("cryptoscan:verification_status", "COLLECTOR_OBSERVED_NOT_HUMAN_VERIFIED")]
                if facts.get("certificate_serial"):
                    cprops.append(_prop("cryptoscan:certificate:serial", str(facts["certificate_serial"])))
                if sys_info:
                    cprops.append(_prop("cryptoscan:system", sys_info["name"]))
                components.append({"type": "cryptographic-asset", "name": str(facts.get("certificate_subject") or fp[:16]),
                                   "bom-ref": cert_ref,
                                   "cryptoProperties": {"assetType": "certificate", "certificateProperties": cert_props},
                                   "evidence": {"occurrences": [{"location": location, "additionalContext":
                                                                 f"evidence:{evid} sha256:{evidence['sha256']}"}]},
                                   "properties": cprops})
            depends.setdefault(proto_ref, []).append(cert_ref)
            relationships.append(relationship(proto_ref, cert_ref, "PROTOCOL_AUTHENTICATED_BY_CERTIFICATE", **verified))
            for target, rtype in ((key_ref, "CERTIFICATE_HAS_PUBLIC_KEY"), (sig_ref, "CERTIFICATE_SIGNED_WITH")):
                if target:
                    depends.setdefault(cert_ref, []).append(target)
                    relationships.append(relationship(cert_ref, target, rtype, basis="OBSERVED", evidence_id=evid,
                                                      confidence="HIGH", verification_status="PARSED_FROM_OBSERVED_CERTIFICATE",
                                                      first_seen=first, last_seen=captured))
    # source references to TLS without a version: say where the version can come from
    versionless = 0
    for record in records:
        name = re.sub(r"[^A-Z]", "", str(record.get("algorithm") or "").upper())
        if name not in {"TLS", "SSL", "DTLS", "SSLTLS"} or str(record.get("file_path") or "").startswith("tls://"):
            continue
        versionless += 1
        observed = members.get(record.get("system_id"), [])
        props = [_prop("cryptoscan:tls:version_status", "NOT_RECORDED_IN_EVIDENCE"),
                 _prop("cryptoscan:tls:version_note",
                       "the source finding names TLS without a version; a negotiated version exists only for "
                       "endpoints a network collector observed")]
        if observed:
            props.append(_prop("cryptoscan:tls:same_system_observations", {
                "refs": observed, "basis": "INFERRED",
                "note": "TLS observed on an endpoint claimed by the same system; not proof that this code path "
                        "serves that endpoint"}))
        record_props.setdefault(str(record.get("id")), []).extend(props)
    summary["source_tls_references_without_version"] = versionless
    summary["components_added"] = len(components)
    summary["versions"] = dict(sorted(summary["versions"].items()))
    summary["missing_facts"] = dict(sorted(summary["missing_facts"].items()))
    return {"components": components, "provides": provides, "depends": depends, "relationships": relationships,
            "record_properties": record_props, "members": members, "summary": summary}


# --------------------------------------------------------------------------- #
# coverage dimensions
# --------------------------------------------------------------------------- #


def _system_class(system: Any) -> str | None:
    extra = system.extra if isinstance(getattr(system, "extra", None), dict) else {}
    value = extra.get("system_class") or extra.get("system_type")
    return str(value).upper() if value else None


def relevant_scans(db: Session, systems: list[Any], scans_by_system: dict[str, set[str]]) -> list[Any]:
    """Scan jobs this export may cite, newest first: jobs linked to an exported
    system (last job, or the source of its assets' evidence) and every job owned
    by the exporting tenant — failures included, so a failed collection is never
    hidden. Never a store-wide listing across owners."""
    from db.models.scan import Scan

    ids = {s.last_scan_id for s in systems if s.last_scan_id}
    for values in scans_by_system.values():
        ids |= {v for v in values if v}
    rows: dict[str, Any] = {}
    ordered = sorted(ids)
    for start in range(0, len(ordered), 500):
        for scan in db.execute(select(Scan).where(Scan.id.in_(ordered[start:start + 500]))).scalars():
            rows[scan.id] = scan
    # the owner's own jobs, strictly: a tenant scope also reads NULL-tenant
    # platform rows, which must not appear in a tenant's document (and a
    # platform export must not list tenants' jobs)
    from db.tenancy import current_tenant

    tenant = current_tenant()
    owner = Scan.tenant_id == tenant if tenant else Scan.tenant_id.is_(None)
    for scan in db.execute(select(Scan).where(owner).order_by(Scan.scan_start.desc())
                           .limit(_SCAN_LIMIT)).scalars():
        rows[scan.id] = scan
    floor = datetime.min.replace(tzinfo=timezone.utc)

    def started(scan: Any) -> datetime:
        value = scan.scan_start
        if value is None:
            return floor
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    return sorted(rows.values(), key=lambda scan: (started(scan), scan.id), reverse=True)[:_SCAN_LIMIT]


def collection_facts(db: Session, systems: list[Any], records: list[dict[str, Any]],
                     scans_by_system: dict[str, set[str]], observations: dict[str, dict[str, Any]],
                     scans: list[Any] | None = None) -> dict[str, Any]:
    """Coverage dimensions + per-system collection status, from job facts."""
    if scans is None:
        scans = relevant_scans(db, systems, scans_by_system)
    scan_by_id = {s.id: s for s in scans}
    by_target: dict[str, list[Any]] = {}
    for scan in scans:
        by_target.setdefault(_target_key(scan.target_location), []).append(scan)
    try:
        from db.models.network_scan_target import NetworkScanTarget

        net_targets = list(db.execute(select(NetworkScanTarget)).scalars())
    except Exception:  # noqa: BLE001
        net_targets = []
    assets_by_system: dict[str | None, set[str]] = {}
    runtime_assets: dict[str | None, int] = {}
    for record in records:
        assets_by_system.setdefault(record.get("system_id"), set()).add(str(record.get("id")))
        if str(record.get("file_path") or "").startswith(("tls://", "dtls://", "ssh://")):
            runtime_assets[record.get("system_id")] = runtime_assets.get(record.get("system_id"), 0) + 1

    per_system: dict[str, dict[str, Any]] = {}
    jobs_failed: list[dict[str, Any]] = []
    jobs_partial: list[dict[str, Any]] = []
    jobs_pending: list[dict[str, Any]] = []
    seen_targets: set[str] = set()
    repos_ok = repos_failed = repos_pending = 0
    files_scanned = 0
    files_recorded = False
    endpoints_total = endpoints_observed = endpoints_failed = 0
    for system in systems:
        related = set(scans_by_system.get(system.id, set()))
        if system.last_scan_id:
            related.add(system.last_scan_id)
        keys = {_target_key(scan_by_id[sid].target_location) for sid in related if sid in scan_by_id}
        registered_alias = None
        if system.scan_target:
            registered = _target_key(system.scan_target)
            # the registered target string can differ from where the linked job
            # actually ran (local path vs repository URL); it is a separate
            # never-run target only when nothing else is known for the system
            if registered in by_target or not keys:
                keys.add(registered)
            elif registered not in keys:
                registered_alias = registered
        source_targets = []
        for key in sorted(k for k in keys if k):
            history = by_target.get(key, [])
            latest = history[0] if history else None
            success = next((s for s in history if _job_state(s.status, s.statistics) in {"SUCCEEDED", "PARTIAL"}), None)
            state = _job_state(latest.status, latest.statistics) if latest else "NEVER_RUN"
            entry = {"target": key, "latest_job": state, "latest_job_id": latest.id if latest else None,
                     "latest_job_at": _iso(latest.scan_start) if latest else None,
                     "last_success_at": _iso(success.scan_end or success.scan_start) if success else None,
                     "collector": f"{latest.scanner_id}/{latest.scanner_version}" if latest else None}
            if latest is not None and state == "FAILED":
                entry["error"] = (latest.error_message or "")[:200] or None
            source_targets.append(entry)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            job = {"system": system.name, "target": key, "job_id": latest.id if latest else None,
                   "at": entry["latest_job_at"], "previous_success_at": entry["last_success_at"]}
            if state == "FAILED":
                repos_failed += 1
                jobs_failed.append({**job, "error": entry.get("error")})
            elif state == "PARTIAL":
                jobs_partial.append(job)
            elif state == "PENDING":
                repos_pending += 1
                jobs_pending.append(job)
            if success is not None:
                repos_ok += state != "FAILED"
                stats = success.statistics if isinstance(success.statistics, dict) else {}
                if isinstance(stats.get("files_scanned"), int):
                    files_scanned += stats["files_scanned"]
                    files_recorded = True
        network = []
        for target in (t for t in net_targets if t.system_id == system.id):
            endpoints_total += 1
            obs = observations.get(target.endpoint) or {}
            attempt = obs.get("last_attempt") or {}
            if obs.get("facts"):
                state = "OBSERVED"
                endpoints_observed += 1
            elif attempt and attempt.get("status") not in {"OK", None}:
                state = "FAILED"
                endpoints_failed += 1
                jobs_failed.append({"system": system.name, "target": target.endpoint, "job_id": attempt.get("run_id"),
                                    "at": attempt.get("at"), "error": attempt.get("error") or attempt.get("status")})
            else:
                state = "NEVER_OBSERVED"
            network.append({"endpoint": target.endpoint, "state": state,
                            "last_observed": (obs.get("evidence") or {}).get("captured_at"),
                            "evidence_id": (obs.get("evidence") or {}).get("evidence_id")})
        assets = len(assets_by_system.get(system.id, set()))
        src_ok = any(t["last_success_at"] for t in source_targets)
        src_failed = any(t["latest_job"] == "FAILED" for t in source_targets)
        src_partial = any(t["latest_job"] == "PARTIAL" for t in source_targets)
        net_ok = any(n["state"] == "OBSERVED" for n in network)
        net_gap = any(n["state"] in {"FAILED", "NEVER_OBSERVED"} for n in network)
        reached = src_ok or net_ok
        if not reached:
            state = "NOT_INSPECTED"
        elif src_failed or src_partial or net_gap or (source_targets and not src_ok) or (network and not net_ok):
            state = "PARTIAL"
        elif assets == 0:
            state = "INSPECTED_NO_FINDINGS"
        else:
            state = "INSPECTED_WITH_FINDINGS"
        collectors = (["NETWORK_TLS_HANDSHAKE"] if net_ok else []) + (["SOURCE_REPOSITORY_SCAN"] if src_ok else [])
        cls = _system_class(system)
        info: dict[str, Any] = {
            "inspection_state": state,
            "assets": assets,
            "runtime_observed_assets": runtime_assets.get(system.id, 0),
            "source_targets": source_targets,
            "network_targets": network,
            "collectors_reached": collectors,
            "key_custody_api_collection": "NOT_COLLECTED",
            **({"registered_target_without_own_jobs": registered_alias,
                "registered_target_note": "jobs linked to this system ran against the target(s) listed in "
                                          "source_targets; the registered target string has no job of its own"}
               if registered_alias else {}),
            "process_level_runtime_observation": "NOT_COLLECTED",
        }
        if state == "NOT_INSPECTED":
            info["note"] = ("no collector reached this system; its cryptography is unknown, not absent"
                            + (f" — {assets} asset link(s) exist without an inspection" if assets else ""))
        elif state == "INSPECTED_NO_FINDINGS":
            info["note"] = "collectors ran successfully and found no cryptographic asset in what they inspected"
        if cls:
            info["declared_class"] = cls
        if cls in _KEY_CUSTODY_CLASSES:
            info["key_custody_discovery"] = {
                "coverage": "LIMITED",
                "records": assets,
                "reached_by": collectors or ["NONE"],
                "not_collected": ["key inventory (labels, types, sizes, usage)", "enabled mechanisms / algorithms",
                                  "partitions / tenants", "firmware and FIPS 140-3 certificate", "key ceremonies"],
                "statement": (f"{assets} record(s) describe only what network collection saw at this system's "
                              "endpoints (e.g. its management TLS); no HSM/KMS API collector ran, so this is not the "
                              "system's cryptographic capability set"),
            }
        per_system[system.id] = info

    states = [info["inspection_state"] for info in per_system.values()]
    count = {s: states.count(s) for s in ("INSPECTED_WITH_FINDINGS", "INSPECTED_NO_FINDINGS", "PARTIAL",
                                           "NOT_INSPECTED")}
    total = len(systems)
    fully = count["INSPECTED_WITH_FINDINGS"] + count["INSPECTED_NO_FINDINGS"]
    targets_total = len(seen_targets) + endpoints_total
    targets_ok = repos_ok + endpoints_observed
    observed_assets = sum(runtime_assets.values())
    if total == 0:
        overall = "NO_REGISTERED_SYSTEMS"
    elif fully == total and not jobs_failed and not jobs_partial:
        overall = "ALL_REGISTERED_TARGETS_INSPECTED"
    elif fully + count["PARTIAL"] == 0:
        overall = "NONE"
    else:
        overall = "PARTIAL"
    coverage = {
        "schema": "cryptoscan.cbom-coverage-dimensions/1",
        "registered_system_coverage": {
            "registered": total, "fully_inspected": fully, "partially_inspected": count["PARTIAL"],
            "not_inspected": count["NOT_INSPECTED"], "inspected_with_findings": count["INSPECTED_WITH_FINDINGS"],
            "inspected_no_findings": count["INSPECTED_NO_FINDINGS"],
            "fully_inspected_pct": round(100.0 * fully / total, 1) if total else 0.0,
            "basis": "a system counts as inspected only when a collector's latest job for every one of its targets "
                     "succeeded; stored coverage_status is not used"},
        "successful_target_coverage": {
            "targets": targets_total, "succeeded": targets_ok,
            "source_repositories": {"total": len(seen_targets), "succeeded": repos_ok, "latest_job_failed": repos_failed,
                                    "latest_job_pending": repos_pending},
            "network_endpoints": {"total": endpoints_total, "observed": endpoints_observed,
                                  "latest_attempt_failed": endpoints_failed,
                                  "never_observed": endpoints_total - endpoints_observed - endpoints_failed},
            "pct": round(100.0 * targets_ok / targets_total, 1) if targets_total else 0.0},
        "repository_file_coverage": {
            "repositories_with_successful_scan": repos_ok, "repositories_latest_failed": repos_failed,
            "files_scanned": files_scanned if files_recorded else NOT_RECORDED,
            "excluded_or_unreadable_files": NOT_RECORDED,
            "basis": "files_scanned summed from the latest successful scan of each repository"},
        "crypto_discovery_completeness": {
            "status": "NOT_PROVEN",
            "reason": "detectors find what they recognise in what they inspected; dynamic loading, vendor binaries, "
                      "HSM/KMS internals and uninspected targets are outside that set"},
        "runtime_observation_coverage": {
            "network_endpoints_observed": endpoints_observed, "network_endpoints_registered": endpoints_total,
            "pct": round(100.0 * endpoints_observed / endpoints_total, 1) if endpoints_total else 0.0,
            "systems_with_runtime_observation": sum(1 for i in per_system.values()
                                                    if any(n["state"] == "OBSERVED" for n in i["network_targets"])),
            "runtime_observed_assets": observed_assets,
            "process_level_observation": "NOT_COLLECTED"},
        "jobs": {"failed": jobs_failed[:50], "partial": jobs_partial[:50], "pending": jobs_pending[:50],
                 "failed_count": len(jobs_failed), "partial_count": len(jobs_partial),
                 "pending_count": len(jobs_pending)},
        "overall_inspection_status": overall,
        "statement": (f"{fully}/{total} registered systems fully inspected, {count['PARTIAL']} partial, "
                      f"{count['NOT_INSPECTED']} not inspected; {len(jobs_failed)} failed and {len(jobs_pending)} "
                      "pending job(s); crypto discovery completeness NOT_PROVEN"),
    }
    return {"coverage": coverage, "systems": per_system}


# --------------------------------------------------------------------------- #
# collector provenance + reproducibility
# --------------------------------------------------------------------------- #


def collector_provenance(db: Session, observations: dict[str, dict[str, Any]], scans: list[Any]) -> dict[str, Any]:
    """Every collector that contributed, with version, runs, source commits and
    build digests — or the explicit statement that they were not recorded."""

    collectors: dict[str, dict[str, Any]] = {}
    revisions: list[dict[str, Any]] = []
    seen_rev: set[tuple[str, str]] = set()
    from api.cbom_provenance import safe_location

    for scan in scans:
        key = f"{scan.scanner_id}/{scan.scanner_version}"
        slot = collectors.setdefault(key, {"collector": scan.scanner_id, "version": scan.scanner_version,
                                           "kind": "SOURCE_REPOSITORY_SCAN", "jobs": 0, "jobs_by_state": {},
                                           "last_job_at": _iso(scan.scan_start), "build_digest": NOT_RECORDED})
        slot["jobs"] += 1
        state = _job_state(scan.status, scan.statistics)
        slot["jobs_by_state"][state] = slot["jobs_by_state"].get(state, 0) + 1
        repo = safe_location(scan.target_location) or ""
        rev = (repo, scan.target_commit or NOT_RECORDED)
        if repo and rev not in seen_rev and len(revisions) < 100:
            seen_rev.add(rev)
            revisions.append({"repository": repo, "commit": scan.target_commit or NOT_RECORDED,
                              "branch": scan.target_branch or NOT_RECORDED, "job_state": state,
                              "scan_manifest_sha256": scan.manifest_hash or NOT_RECORDED})
    for obs in observations.values():
        evidence = obs.get("evidence") or {}
        name = evidence.get("collector")
        if not name or name == NOT_RECORDED:
            continue
        key = f"{name}/{evidence.get('collector_version') or NOT_RECORDED}"
        slot = collectors.setdefault(key, {"collector": name, "version": evidence.get("collector_version") or NOT_RECORDED,
                                           "kind": "NETWORK_TLS_HANDSHAKE", "observations": 0,
                                           "build_digest": NOT_RECORDED})
        slot["observations"] = slot.get("observations", 0) + 1
    exporter = {"name": "cryptoscan-cbom-exporter",
                "source_commit": os.environ.get("CRYPTOSCAN_BUILD_COMMIT") or os.environ.get("GIT_COMMIT") or NOT_RECORDED,
                "build_digest": os.environ.get("CRYPTOSCAN_BUILD_DIGEST") or NOT_RECORDED}
    return {"collectors": [collectors[k] for k in sorted(collectors)], "source_revisions": revisions,
            "exporter": exporter,
            "commit_coverage": {"revisions": len(revisions),
                                "with_commit": sum(r["commit"] != NOT_RECORDED for r in revisions)},
            "note": "commits and build digests appear only where the collector recorded them"}


def reproducibility(records: Iterable[dict[str, Any]], observations: dict[str, dict[str, Any]],
                    scans: list[Any]) -> dict[str, Any]:
    """What the export was computed from, so a second export over the same
    store can be shown to be the same (see ``content_sha256``)."""

    from cbom.crypto_normalization import NORMALIZER_VERSION
    from cbom.crypto_risk import RISK_MODEL_VERSION
    from cbom.tls_analysis import TLS_MODEL_VERSION

    ids = sorted(str(r.get("id")) for r in records if r.get("id"))
    latest_scan = scans[0].scan_start if scans else None
    captured = sorted(str((o.get("evidence") or {}).get("captured_at")) for o in observations.values()
                      if (o.get("evidence") or {}).get("captured_at") not in (None, NOT_RECORDED))
    return {"asset_id_set_sha256": canonical_sha256(ids), "asset_rows": len(ids),
            "latest_scan_at": _iso(latest_scan), "latest_observation_at": captured[-1] if captured else None,
            "models": {"normalizer": NORMALIZER_VERSION, "risk": RISK_MODEL_VERSION, "tls": TLS_MODEL_VERSION,
                       "collection": COLLECTION_PROFILE},
            "ordering": "components and dependencies sorted by bom-ref; properties in emission order",
            "content_digest": "cryptoscan:export:content_sha256 = sha256 over the canonical JSON of components, "
                              "dependencies and compositions (metadata excluded: timestamps and run ids vary)"}


def content_sha256(document: dict[str, Any]) -> str:
    return canonical_sha256({k: document.get(k) for k in ("components", "dependencies", "compositions")})
