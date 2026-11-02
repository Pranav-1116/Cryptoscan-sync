"""Estate-wide CycloneDX CBOM inventory: summarize, search, ingest, and diff."""

from __future__ import annotations

import json

from collections import Counter
from typing import Any

from cbom import pqc_handoff


def record_to_dict(record: Any) -> dict[str, Any]:
    if hasattr(record, "to_dict"):
        data = record.to_dict()
    elif isinstance(record, dict):
        data = dict(record)
    else:
        data = {
            "id": getattr(record, "id", None),
            "algorithm": getattr(record, "algorithm", None),
            "mode": getattr(record, "mode", None),
            "padding": getattr(record, "padding", None),
            "key_size": getattr(record, "key_size", None),
            "purpose": getattr(record, "purpose", None),
            "file_path": getattr(record, "file_path", None),
            "line_number": getattr(record, "line_number", None),
            "normalized_crypto": getattr(record, "normalized_crypto", None),
        }
    return data


def record_algorithm(record: Any) -> str:
    data = record_to_dict(record)
    if data.get("cryptoProperties"):
        props = data.get("cryptoProperties") or {}
        algo_props = props.get("algorithmProperties") or {}
        return str(algo_props.get("algorithm") or data.get("name") or "UNKNOWN")
    normalized = data.get("normalized_crypto") or {}
    return str(data.get("algorithm") or normalized.get("standard_name") or data.get("name") or "UNKNOWN")


def record_mode(record: Any) -> str | None:
    data = record_to_dict(record)
    if data.get("cryptoProperties"):
        return (data.get("cryptoProperties") or {}).get("algorithmProperties", {}).get("mode")
    return data.get("mode")


def record_key_size(record: Any) -> int | None:
    data = record_to_dict(record)
    if data.get("cryptoProperties"):
        return _as_int((data.get("cryptoProperties") or {}).get("algorithmProperties", {}).get("parameterSetIdentifier"))
    return _as_int(data.get("key_size"))


def is_quantum_vulnerable(algorithm: str | None, key_size: int | None = None) -> bool:
    try:
        from quantum.risk import classify

        return bool(classify(algorithm, key_size=key_size).get("vulnerable"))
    except Exception:
        name = (algorithm or "").upper().replace("_", "-")
        tokens = (
            "RSA",
            "DSA",
            "ECDSA",
            "ECDH",
            "ED25519",
            "X25519",
            "DH",
            "MD5",
            "SHA-1",
            "SHA1",
            "DES",
            "3DES",
            "RC4",
            "AES-128",
        )
        return any(name == token or name.startswith(token) for token in tokens)


def fingerprint(record: Any) -> str:
    algo = record_algorithm(record).upper()
    mode = str(record_mode(record) or "").upper()
    bits = record_key_size(record)
    return f"{algo}|{mode}|{bits if bits is not None else ''}"


def summarize_records(
    records: list[Any],
    *,
    source_type: str,
    source_id: str | None,
    name: str,
    environment: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    algorithms: Counter[str] = Counter()
    quantum = 0
    pqc = 0
    for record in records:
        algo = record_algorithm(record)
        algorithms[algo] += 1
        if is_quantum_vulnerable(algo, record_key_size(record)):
            quantum += 1
        upper = algo.upper()
        if upper.startswith(("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS")):
            pqc += 1
    payload = {
        "source_type": source_type,
        "source_id": source_id,
        "name": name,
        "environment": environment,
        "spec": "CycloneDX 1.5",
        "components": len(records),
        "algorithms": dict(algorithms),
        "algorithm_count": len(algorithms),
        "quantum_vulnerable": quantum,
        "pqc_ready": pqc,
    }
    if extra:
        payload.update(extra)
    return payload


def search_records(records: list[Any], query: str, *, limit: int = 200) -> list[dict[str, Any]]:
    needle = (query or "").strip().lower()
    if not needle:
        return []
    hits: list[dict[str, Any]] = []
    for record in records:
        data = record_to_dict(record)
        haystack = " ".join(
            str(part)
            for part in (
                data.get("algorithm"),
                data.get("mode"),
                data.get("purpose"),
                data.get("file_path"),
                data.get("system_name"),
                data.get("system_id"),
                data.get("name"),
                (data.get("normalized_crypto") or {}).get("standard_name"),
                (data.get("cryptoProperties") or {}).get("oid"),
            )
            if part
        ).lower()
        if needle not in haystack:
            continue
        algo = record_algorithm(data)
        hits.append(
            {
                "id": data.get("id") or data.get("bom-ref") or data.get("evidence_id"),
                "algorithm": algo,
                "mode": record_mode(data),
                "key_size": record_key_size(data),
                "purpose": data.get("purpose"),
                "file_path": data.get("file_path") or ((data.get("evidence") or {}).get("file")),
                "line_number": data.get("line_number") or ((data.get("evidence") or {}).get("line")),
                "system_id": data.get("system_id"),
                "system_name": data.get("system_name"),
                "quantum_vulnerable": is_quantum_vulnerable(algo, record_key_size(data)),
                "fingerprint": fingerprint(data),
            }
        )
        if len(hits) >= limit:
            break
    return hits


def validate_document(bom: Any) -> dict[str, Any]:
    if isinstance(bom, dict) and bom.get("specVersion") == "1.6":
        from cbom.cyclonedx16 import validate_cyclonedx16
        return validate_cyclonedx16(bom)
    errors: list[str] = []
    if not isinstance(bom, dict):
        return {"ok": False, "errors": ["body must be a CycloneDX object"]}
    if bom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be CycloneDX")
    if bom.get("specVersion") not in {"1.4", "1.5", "1.6"}:
        errors.append("specVersion must be a CycloneDX 1.4+ release")
    if not isinstance(bom.get("components"), list):
        errors.append("components must be a list")
    return {"ok": not errors, "errors": errors}


def is_crypto_component(component: Any) -> bool:
    if not isinstance(component, dict):
        return False
    ctype = str(component.get("type") or "").lower()
    if ctype in {"cryptographic-asset", "crypto-asset", "cryptographic-algorithm"}:
        return True
    return bool(component.get("cryptoProperties"))


def records_from_bom(bom: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for component in bom.get("components") or []:
        if not is_crypto_component(component):
            continue
        props = component.get("cryptoProperties") or {}
        algo_props = props.get("algorithmProperties") or {}
        evidence = component.get("evidence") or {}
        occurrences = evidence.get("occurrences") or []
        first = occurrences[0] if occurrences and isinstance(occurrences[0], dict) else {}
        location = evidence.get("file") or first.get("location") or first.get("file")
        line = evidence.get("line") if evidence.get("line") is not None else first.get("line")
        name = str(component.get("name") or "UNKNOWN")
        profile_props = {p.get("name"): p.get("value") for p in component.get("properties", []) if isinstance(p, dict)}
        algorithm = str(algo_props.get("algorithm") or profile_props.get("cryptoscan:reported_algorithm") or name)
        key_size = _as_int(algo_props.get("parameterSetIdentifier") or algo_props.get("parameterSet"))
        pqc_parameter = False
        if bom.get("specVersion") == "1.6":
            from shared_models.algorithm_registry import parse_algorithm
            pqc_parameter = parse_algorithm(algorithm).family in {"kem-pqc", "signature-pqc", "kem-hybrid-pqc"}
            if pqc_parameter:
                key_size = _as_int(profile_props.get("cryptoscan:reported_key_size"))
        records.append(
            {
                "id": component.get("bom-ref") or component.get("bomRef"),
                "algorithm": algorithm,
                "mode": algo_props.get("mode"),
                "padding": algo_props.get("padding"),
                "key_size": key_size,
                "purpose": algo_props.get("primitive") or props.get("assetType"),
                "file_path": location or f"cbom://{name}",
                "line_number": int(line or 0),
                "name": name,
                "normalized_crypto": {
                    "standard_name": name,
                    "algorithm_family": algo_props.get("primitive"),
                    "nist_designation": props.get("nistDesignation"),
                    # Read through the handoff so a 1.5/1.6 document (property) and a
                    # pre-guide-144 document (legacy boolean) both resolve.
                    "quantum_vulnerable": pqc_handoff.vulnerable_from_component(component),
                    "quantum_status": pqc_handoff.status_from_component(component),
                    "cbom_component_type": component.get("type") or "cryptographic-asset",
                },
                "cryptoProperties": props or None,
            }
        )
        if pqc_parameter:
            records[-1]["parameter_set_identifier"] = algo_props.get("parameterSetIdentifier")
            records[-1]["key_size_basis"] = "REPORTED_UNIT_NOT_ESTABLISHED"
        from cbom.cyclonedx16 import CONTEXT_FIELDS
        contexts = []
        for prop in component.get("properties", []):
            if prop.get("name") == "cryptoscan:business_context":
                try:
                    context = json.loads(prop["value"])
                    if isinstance(context, dict):
                        contexts.append({k: v for k, v in context.items() if k in CONTEXT_FIELDS})
                except (ValueError, TypeError):
                    pass  # malformed contextual declaration never becomes verified context
        if contexts:
            records[-1]["business_contexts"] = contexts
        for field in CONTEXT_FIELDS:
            value = profile_props.get(f"cryptoscan:{field}")
            if value is not None and len(contexts) <= 1:
                records[-1][field] = _as_int(value) if field == "retention_years" else value
        # External native documents need not use our aggregated JSON property.
        # Preserve their allowlisted scalar properties too, without inventing
        # measured owner/confidence fields or duplicating an existing context.
        scalar_context = {field: profile_props[f"cryptoscan:{field}"] for field in CONTEXT_FIELDS
                          if f"cryptoscan:{field}" in profile_props}
        if scalar_context and scalar_context not in contexts:
            contexts.append(scalar_context)
        if contexts:
            records[-1]["business_contexts"] = contexts
    return records


def bom_system_name(bom: dict[str, Any], fallback: str = "imported-cbom") -> str:
    meta = (bom.get("metadata") or {}).get("component") or {}
    name = meta.get("name") or bom.get("serialNumber") or fallback
    return str(name)


def diff_records(left: list[Any], right: list[Any]) -> dict[str, Any]:
    left_map = {fingerprint(item): record_to_dict(item) for item in left}
    right_map = {fingerprint(item): record_to_dict(item) for item in right}
    added_keys = [key for key in right_map if key not in left_map]
    removed_keys = [key for key in left_map if key not in right_map]
    unchanged_keys = [key for key in left_map if key in right_map]

    def _item(key: str, data: dict[str, Any]) -> dict[str, Any]:
        return {
            "fingerprint": key,
            "algorithm": record_algorithm(data),
            "mode": record_mode(data),
            "key_size": record_key_size(data),
            "name": data.get("name") or data.get("algorithm"),
        }

    return {
        "added": [_item(key, right_map[key]) for key in sorted(added_keys)],
        "removed": [_item(key, left_map[key]) for key in sorted(removed_keys)],
        "unchanged": [_item(key, left_map[key]) for key in sorted(unchanged_keys)],
        "counts": {
            "added": len(added_keys),
            "removed": len(removed_keys),
            "unchanged": len(unchanged_keys),
        },
    }


def diff_boms(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return diff_records(records_from_bom(left), records_from_bom(right))


def semantic_diff_boms(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Classified diff over two BOM documents (see ``semantic_diff``)."""
    return semantic_diff(records_from_bom(left), records_from_bom(right))


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _site_of(data: dict[str, Any]) -> str:
    """A usage site: the file (line drift alone is not a semantic change —
    refactors shift lines constantly)."""
    return str(data.get("file_path") or "")


#: report 08 P2#8 — the classes a semantic diff distinguishes
SEMANTIC_CHANGE_CLASSES = ("ALGORITHM_CHANGED", "PARAMETER_CHANGED", "VERSION_CHANGED", "LOCATION_CHANGED")


def _classify_delta(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Attribute deltas between two observations of the same site."""
    classes: list[str] = []
    if (
        str(record_algorithm(before)).upper() != str(record_algorithm(after)).upper()
        or str(before.get("mode") or "").upper() != str(after.get("mode") or "").upper()
        or str(before.get("padding") or "").upper() != str(after.get("padding") or "").upper()
    ):
        classes.append("ALGORITHM_CHANGED")
    if record_key_size(before) != record_key_size(after):
        classes.append("PARAMETER_CHANGED")
    if str(before.get("version") or "") != str(after.get("version") or "") and (
        before.get("version") or after.get("version")
    ):
        classes.append("VERSION_CHANGED")
    return classes or ["LOCATION_CHANGED"]


def semantic_diff(left: list[Any], right: list[Any]) -> dict[str, Any]:
    """Classified diff (report 08 P2#8): algorithm change vs. parameter
    change vs. location change — not just added/removed fingerprints.

    Matching happens in two passes over *observations* (records are never
    deduplicated: two sites using identical crypto are two observations):

    1. **By site**: the same file on both sides pairs its observations —
       exact fingerprint first, then site-local pairing. Differing
       algorithm/mode/padding → ``ALGORITHM_CHANGED``; differing key size /
       parameter set → ``PARAMETER_CHANGED``; differing component version
       (ingested library BOMs) → ``VERSION_CHANGED``. Line-number drift is
       NOT a change (same site, same crypto).
    2. **By identity**: a leftover observation whose exact fingerprint
       appears on the other side at a *different* site is a
       ``LOCATION_CHANGED`` — the same crypto moved.

    Everything unmatched stays ADDED/REMOVED: a new usage site is a new
    logical component by definition.
    """
    left_obs = [(fingerprint(item), record_to_dict(item)) for item in left]
    right_obs = [(fingerprint(item), record_to_dict(item)) for item in right]

    left_by_site: dict[str, list[int]] = {}
    for idx, (_fp, data) in enumerate(left_obs):
        left_by_site.setdefault(_site_of(data), []).append(idx)
    right_by_site: dict[str, list[int]] = {}
    for idx, (_fp, data) in enumerate(right_obs):
        right_by_site.setdefault(_site_of(data), []).append(idx)

    def _item(fp: str, data: dict[str, Any]) -> dict[str, Any]:
        return {
            "fingerprint": fp,
            "algorithm": record_algorithm(data),
            "mode": record_mode(data),
            "key_size": record_key_size(data),
            "name": data.get("name") or data.get("algorithm"),
            "location": str(data.get("file_path") or ""),
        }

    matched_left: set[int] = set()
    matched_right: set[int] = set()
    unchanged: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []

    # pass 1 — same site on both sides
    for site in sorted(set(left_by_site) & set(right_by_site)):
        right_pool = [idx for idx in right_by_site[site] if idx not in matched_right]
        for lidx in left_by_site[site]:
            if lidx in matched_left:
                continue
            lfp, ldata = left_obs[lidx]
            exact = next(
                (ridx for ridx in right_pool if right_obs[ridx][0] == lfp), None
            )
            if exact is not None:
                matched_left.add(lidx)
                matched_right.add(exact)
                right_pool.remove(exact)
                unchanged.append(_item(lfp, ldata))
                continue
            if right_pool:
                ridx = right_pool.pop(0)
                matched_left.add(lidx)
                matched_right.add(ridx)
                rfp, rdata = right_obs[ridx]
                changed.append(
                    {
                        "algorithm": record_algorithm(ldata),
                        "name": ldata.get("name") or ldata.get("algorithm"),
                        "location": site,
                        "classifications": _classify_delta(ldata, rdata),
                        "from": _item(lfp, ldata),
                        "to": _item(rfp, rdata),
                    }
                )

    # pass 2 — identity moves: same fingerprint, different site
    for lidx, (lfp, ldata) in enumerate(left_obs):
        if lidx in matched_left:
            continue
        move = next(
            (
                ridx
                for ridx, (rfp, _rdata) in enumerate(right_obs)
                if ridx not in matched_right and rfp == lfp and _site_of(right_obs[ridx][1]) != _site_of(ldata)
            ),
            None,
        )
        if move is None:
            continue
        matched_left.add(lidx)
        matched_right.add(move)
        changed.append(
            {
                "algorithm": record_algorithm(ldata),
                "name": ldata.get("name") or ldata.get("algorithm"),
                "location": f"{_site_of(ldata)} -> {_site_of(right_obs[move][1])}",
                "classifications": ["LOCATION_CHANGED"],
                "from": _item(lfp, ldata),
                "to": _item(lfp, right_obs[move][1]),
            }
        )

    removed = [
        _item(fp, data) for idx, (fp, data) in enumerate(left_obs) if idx not in matched_left
    ]
    added = [
        _item(fp, data) for idx, (fp, data) in enumerate(right_obs) if idx not in matched_right
    ]

    return {
        "added": sorted(added, key=lambda item: item["fingerprint"]),
        "removed": sorted(removed, key=lambda item: item["fingerprint"]),
        "unchanged": sorted(unchanged, key=lambda item: item["fingerprint"]),
        "changed": sorted(changed, key=lambda item: str(item["algorithm"])),
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "unchanged": len(unchanged),
            "changed": len(changed),
        },
    }
