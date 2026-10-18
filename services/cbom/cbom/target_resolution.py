"""Exact identities before names; broad search discovers choices, never exposure."""

from copy import deepcopy
import json
import re
from shared_models.software_identity import package_identity, artifact_digest

SCHEMA = "cryptoscan.target-resolution/1"
LIMIT = 50
KINDS = (
    "package",
    "artifact",
    "certificate",
    "endpoint",
    "system",
    "vendor",
    "device",
    "library",
    "process",
    "algorithm",
)


def fingerprint(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.lower().startswith("sha256:"):
        value = value[7:]
    if re.fullmatch(r"(?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2}", value):
        value = value.replace(":", "")
    return value.lower() if re.fullmatch(r"[a-fA-F0-9]{64}", value) else None


def norm(value):
    return str(value or "").strip().casefold()


def _candidate(kind, row, method):
    if kind == "certificate":
        canonical = fingerprint(row.get("fingerprint_sha256"))
        label = row.get("subject") or canonical
    elif kind == "package":
        canonical = row.get("purl")
        label = canonical
    elif kind == "device":
        canonical = row.get("asset_id")
        label = row.get("model") or canonical
    else:
        canonical = row.get("id")
        label = row.get("name") or row.get("digest") or canonical
    return {
        "kind": kind,
        "canonical_target": canonical,
        "label": label,
        "matched_by": method,
        "selectable": bool(canonical),
    }


def resolve_target(snapshot, target, kind=None, *, allow_name_search=False, legacy_detector=None):
    text = str(target or "").strip()
    kind = norm(kind) or None
    if kind is not None and kind not in KINDS:
        raise ValueError(f"unknown target kind {kind!r}; available: {list(KINDS)}")
    coverage = deepcopy(snapshot.get("target_resolution_coverage"))
    if snapshot.get("software_supply_chain_coverage") is not None:
        coverage = {**(coverage or {}), "software_supply_chain": deepcopy(snapshot["software_supply_chain_coverage"])}
    base = {
        "schema": SCHEMA,
        "input": text,
        "requested_kind": kind,
        "allow_name_search": allow_name_search,
        "candidate_limit": LIMIT,
        "candidate_count_scope": "loaded_snapshot_only",
        "coverage": coverage,
        "references_verified": False,
        "note": "Identity resolution is not verified runtime use. Search results require an exact selection; missing matches do not prove absence.",
    }

    def finish(rows, method, *, search=False):
        # Duplicate projections of an identical record are harmless. Conflicting
        # records for one canonical key cannot be fixed by choosing the same key.
        grouped = {}
        expanded = {}
        for entity, row in rows:
            canonical = _candidate(entity, row, method)["canonical_target"]
            key = (entity, str(canonical))
            expanded.setdefault(key, (entity, registry_records.get(key, [row])))
        for entity, row in ((entity, row) for entity, records in expanded.values() for row in records):
            if entity == "certificate":
                row = {**row, "fingerprint_sha256": fingerprint(row.get("fingerprint_sha256"))}
            candidate = _candidate(entity, row, method)
            key = (entity, str(candidate["canonical_target"]))
            group = grouped.setdefault(key, {"candidate": candidate, "records": {}})
            group["records"][json.dumps(row, sort_keys=True, default=str)] = row
        groups = [g for _, g in sorted(grouped.items())]
        for g in groups:
            g["candidate"] = _candidate(g["candidate"]["kind"], g["records"][min(g["records"])], method)
            g["candidate"]["conflicting_records"] = len(g["records"]) > 1
            g["candidate"]["selectable"] = g["candidate"]["selectable"] and len(g["records"]) == 1
        incomplete_names = method == "exact_name" and any(
            (coverage or {}).get(k + "_truncated") for k in {g["candidate"]["kind"] for g in groups}
        )
        selectable = len(groups) == 1 and groups[0]["candidate"]["selectable"]
        status = (
            "SEARCH_RESULTS"
            if search
            else "INCOMPLETE"
            if incomplete_names
            else "RESOLVED"
            if selectable
            else "AMBIGUOUS"
        )
        result = {
            **base,
            "status": status,
            "method": method,
            "candidate_count": len(groups),
            "candidates": [g["candidate"] for g in groups[:LIMIT]],
            "candidates_truncated": len(groups) > LIMIT,
            "selected": groups[0]["candidate"] if status == "RESOLVED" else None,
            "reason": "Select a canonical identity; conflicting records require registry repair."
            if status != "RESOLVED"
            else None,
        }
        matched = deepcopy(next(iter(groups[0]["records"].values()))) if status == "RESOLVED" else None
        if matched is not None and groups[0]["candidate"]["kind"] == "certificate":
            matched["fingerprint_sha256"] = groups[0]["candidate"]["canonical_target"]
        return result, ({"kind": groups[0]["candidate"]["kind"], "matched": matched} if matched is not None else None)

    def missing(reason, status="NOT_FOUND"):
        return {
            **base,
            "status": status,
            "method": "none",
            "candidate_count": 0,
            "candidates": [],
            "candidates_truncated": False,
            "selected": None,
            "reason": reason,
        }, None

    if not text:
        return missing("target is required", "INVALID_IDENTITY")
    certs = list(snapshot.get("certificates") or [])
    vendors = list(snapshot.get("vendors") or [])
    # Name filtering must not hide another conflicting record for the selected
    # canonical key. Index once, rather than rescanning a large registry for
    # every candidate; no unscoped/global registry is consulted.
    registry_records = {}
    for entity, records in (("certificate", certs), ("vendor", vendors)):
        for row in records:
            canonical = _candidate(entity, row, "exact_identity")["canonical_target"]
            if canonical:
                registry_records.setdefault((entity, str(canonical)), []).append(row)
    packages = sorted(
        {
            c["package_identity"]
            for b in snapshot.get("software_sbom_bindings") or []
            for c in b.get("components") or []
            if package_identity(c.get("package_identity"))
        }
    )
    typed_package = kind == "package" or kind is None and text.startswith("pkg:")
    typed_artifact = kind == "artifact" or kind is None and text.lower().startswith("sha256:")
    if typed_package:
        if package_identity(text) and text in packages:
            return finish([("package", {"purl": text})], "exact_identity")
        if allow_name_search:
            rows = [("package", {"purl": p}) for p in packages if norm(text) in norm(p)]
            if rows:
                return finish(rows, "broad_search", search=True)
        return missing(
            "A package requires its exact versioned PURL, including qualifiers/subpath; names and ranges are not identities.",
            "NOT_FOUND",
        )
    if typed_artifact:
        try:
            digest = artifact_digest(text)
        except ValueError:
            digest = None
        rows = [
            ("artifact", {"id": r.get("id"), "digest": r.get("digest")})
            for r in snapshot.get("software_artifacts") or []
            if r.get("id") == text or digest is not None and r.get("digest") == digest
        ]
        if rows:
            return finish(rows, "exact_identity")
        return missing("No exact registered artifact ID/digest matched; no tag/name fallback.")
    identities = []
    fp = fingerprint(text)
    if kind in (None, "certificate") and fp:
        identities.extend(("certificate", r) for r in certs if fingerprint(r.get("fingerprint_sha256")) == fp)
        # A certificate fingerprint must not fall through to a vendor/system name.
        return (
            finish(identities, "exact_identity")
            if identities
            else missing("Exact certificate fingerprint not found in loaded registry.")
        )
    if kind in (None, "vendor"):
        identities.extend(("vendor", r) for r in vendors if r.get("id") == text)
    if kind is None:
        identities.extend(("system", r) for r in snapshot.get("systems") or [] if r.get("id") == text)
        identities.extend(("device", r) for r in snapshot.get("hardware") or [] if r.get("asset_id") == text)
        identities.extend(
            ("process", r)
            for rows in (snapshot.get("business_processes") or {}).values()
            for r in rows
            if r.get("id") == text
        )
        # Per-system process mappings are not conflicting process registry rows.
        identities = [(k, {"id": r["id"], "name": r.get("name")}) if k == "process" else (k, r) for k, r in identities]
    if identities:
        return finish(identities, "exact_identity")
    names = []
    if kind in (None, "certificate"):
        names.extend(("certificate", r) for r in certs if norm(r.get("subject")) == norm(text))
    if kind in (None, "vendor"):
        names.extend(("vendor", r) for r in vendors if norm(r.get("name")) == norm(text))
    if kind is None:
        names.extend(("system", r) for r in snapshot.get("systems") or [] if norm(r.get("name")) == norm(text))
    if names:
        return finish(names, "exact_name")
    if allow_name_search:
        matches = []
        if kind in (None, "certificate"):
            matches.extend(("certificate", r) for r in certs if norm(text) in norm(r.get("subject")))
        if kind in (None, "vendor"):
            matches.extend(("vendor", r) for r in vendors if norm(text) in norm(r.get("name")))
        if kind is None:
            matches.extend(("package", {"purl": p}) for p in packages if norm(text) in norm(p))
        if matches:
            return finish(matches, "broad_search", search=True)
    if kind in {"certificate", "vendor"}:
        return missing(
            "No exact identity or exact unique name matched. Broad name search is opt-in and does not execute a cascade."
        )
    if kind is None and any(
        norm(text) in norm(r.get(field)) for rows, field in ((certs, "subject"), (vendors, "name")) for r in rows
    ):
        return missing(
            "Partial certificate/vendor name match is not an identity. Opt into candidate search, or specify another target kind explicitly."
        )
    # Remaining target families retain their existing detection semantics; they
    # are explicitly not requalified as exact identity resolution by this stage.
    for other in [kind] if kind else ["endpoint", "system", "device", "library", "process", "algorithm"]:
        found = legacy_detector(snapshot, text, other) if legacy_detector else None
        if found:
            return {
                **base,
                "status": "RESOLVED",
                "method": "legacy_detector",
                "selected": {
                    "kind": other,
                    "canonical_target": (found["matched"].get("id") or found["matched"].get("asset_id") or text),
                    "label": text,
                    "matched_by": "legacy_detector",
                    "selectable": True,
                },
                "candidates": [],
                "candidate_count": 0,
                "candidates_truncated": False,
                "reason": "Other target families retain legacy matching; exactness is not certified.",
            }, found
    return missing("Target not found in loaded snapshot; coverage may be incomplete.")


def compare_resolution(old, new):
    """Stored decisions only: never reconstruct an identity for a historical run."""

    def key(result):
        r = (result or {}).get("target_resolution") or {}
        selected = r.get("selected") or {}
        if r.get("schema") != SCHEMA or r.get("status") != "RESOLVED" or result.get("analysis_performed") is not True:
            return None
        if not selected.get("kind") or not selected.get("canonical_target"):
            return None
        return (selected["kind"], selected["canonical_target"])

    left, right = key(old), key(new)
    comparable = bool(left and right and left == right)
    return {
        "comparable": comparable,
        "against_identity": list(left) if left else None,
        "run_identity": list(right) if right else None,
        "schema": SCHEMA,
        "reason": None
        if comparable
        else "Target resolution is unavailable, unresolved, or selects different canonical identities; impact deltas are withheld.",
    }
