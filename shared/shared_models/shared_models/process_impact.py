"""ID-based process projection. Declared business context is not predicted loss."""

from collections import defaultdict
import json
import math
from shared_models.relationship_lifecycle import current, possible, lifecycle_payload, utc
from shared_models.traversal_evidence import edge_evidence, metadata

SCHEMA = "cryptoscan.business-process-impact/1"
SCOPES = ("direct_exposure", "dependent_consumers", "supporting_context")
LIMIT = 500
REASON_LIMIT = 200


def classify_systems(direct, reverse, forward):
    direct, reverse, forward = set(direct), set(reverse), set(forward)
    groups = (direct, reverse - direct, forward - direct - reverse)
    result = {name: {"systems": sorted(ids), "count": len(ids)} for name, ids in zip(SCOPES, groups)}
    exposure = direct | reverse
    review = exposure | forward
    return {
        "schema": "cryptoscan.cascade-system-scope/1",
        **result,
        "exposure_systems": sorted(exposure),
        "exposure_system_count": len(exposure),
        "review_systems": sorted(review),
        "review_system_count": len(review),
    }


def _number(value, integer=False):
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
        if not math.isfinite(number) or number < 0 or integer and not number.is_integer():
            return None
        return int(number) if integer else number
    except (ValueError, TypeError, OverflowError):
        return None


def project_processes(registry, classification, *, now, uncertain_systems=(), witnesses=None, source_coverage=None):
    """Compute full ID sets/counts before bounding explanatory rows/reasons.

    Registry rows must carry process IDs; names never substitute for identity.
    Only a current SUPPORTS mapping on a current classified system contributes
    to active review/economic context. Nonterminal uncertain mappings/systems
    get separate potential reasons. No independent pointer verification occurs.
    """
    system_scopes = {sid: scope for scope in SCOPES for sid in classification[scope]["systems"]}
    for sid in uncertain_systems:
        system_scopes.setdefault(sid, "potential")
    processes = {}
    linked_systems = set()
    current_linked_systems = set()
    invalid = terminal = 0
    witnesses = witnesses or {}
    for sid, scope in sorted(system_scopes.items()):
        rows = sorted(registry.get(sid) or [], key=lambda r: json.dumps(r, sort_keys=True, default=str))
        for row in rows:
            if (
                not row.get("id")
                or row.get("process_registered") is False
                or row.get("process_resolution") == "not_in_loaded_registry"
            ):
                invalid += 1
                continue
            pid = str(row["id"])
            # Never confuse the process ID with the SUPPORTS assertion's ID.
            link = {
                **metadata(row),
                **lifecycle_payload({k: v for k, v in row.items() if k != "id"}),
                "record_id": row.get("relationship_record_id") or row.get("record_id"),
                "from": sid,
                "to": "process:" + pid,
                "label": "SUPPORTS",
            }
            if not possible(link, now=now):
                terminal += 1
                continue
            certainty = "current" if scope != "potential" and current(link, now=now) else "potential"
            linked_systems.add(sid)
            if certainty == "current":
                current_linked_systems.add(sid)
            proc = processes.setdefault(
                pid,
                {
                    "id": pid,
                    "names": set(),
                    "reasons": {},
                    "metrics": defaultdict(set),
                    "scopes": set(),
                    "current_scopes": set(),
                },
            )
            if row.get("name"):
                proc["names"].add(str(row["name"]))
            proc["scopes"].add(scope)
            if certainty == "current":
                proc["current_scopes"].add(scope)
            for key, integer in (("revenue_daily", False), ("customer_count", True)):
                proc["metrics"][key].add(_number(row.get(key), integer))
            group = {
                "direct_exposure": "direct",
                "dependent_consumers": "dependent_consumers",
                "supporting_context": "supporting_context",
                "potential": "potential",
            }[scope]
            witness = witnesses.get(group) or {}
            if group == "direct":
                available = any(s.get("system_id") == sid for s in witness) if isinstance(witness, list) else False
            else:
                available = any(p.get("system_id") == sid and p.get("available") for p in witness.get("paths", []))
            evidence = edge_evidence(link, now=now)
            reason = {
                "system_id": sid,
                "system_scope": scope,
                "certainty": certainty,
                "role": row.get("role"),
                "support_link": evidence,
                "system_explanation": {
                    "group": group,
                    "system_id": sid,
                    "available": available,
                    "note": "Reference to the system explanation, not a claim the full chain is verified.",
                },
            }
            proc["reasons"][json.dumps(reason, sort_keys=True, default=str)] = reason
    review, exposure, context_only, potential_only = [], [], [], []
    public = []
    for pid, proc in sorted(processes.items()):
        active = proc["current_scopes"]
        exposed = bool(active & set(SCOPES[:2]))
        if active:
            review.append(pid)
            (exposure if exposed else context_only).append(pid)
        else:
            potential_only.append(pid)
        reasons = sorted(
            proc["reasons"].values(),
            key=lambda r: (r["system_id"], r["certainty"], json.dumps(r, sort_keys=True, default=str)),
        )
        values = {k: next(iter(v)) if len(v) == 1 else None for k, v in proc["metrics"].items()}
        public.append(
            {
                "id": pid,
                "name": sorted(proc["names"])[0] if proc["names"] else None,
                "name_conflict": len(proc["names"]) > 1,
                "scopes": sorted(proc["scopes"]),
                "exposed": exposed,
                "context_only": bool(active) and not exposed,
                "potential_only": not active,
                "reasons": reasons[:REASON_LIMIT],
                "reason_count": len(reasons),
                "reasons_truncated": len(reasons) > REASON_LIMIT,
                "declared_business_context": values,
            }
        )
    selected = [p for p in public if p["exposed"]]
    exposed_systems = set(classification["exposure_systems"])
    unmapped_exposed = len(exposed_systems - current_linked_systems)
    economic = {}
    for key in ("revenue_daily", "customer_count"):
        known = [
            p["declared_business_context"][key] for p in selected if p["declared_business_context"][key] is not None
        ]
        missing = len(selected) - len(known)
        total = sum(known)
        overflow = isinstance(total, float) and not math.isfinite(total)
        economic[key] = {
            "known_sum": None if overflow else total,
            "aggregate_overflow": overflow,
            "missing_or_conflicting_process_count": missing,
            "complete_sum": total if not missing and not unmapped_exposed and not overflow else None,
        }
    review_ids = set(review)
    compact = [{"id": p["id"], "name": p["name"]} for p in public if p["id"] in review_ids]
    return {
        "schema": SCHEMA,
        "as_of": utc(now).isoformat(),
        "processes": public[:LIMIT],
        "review_processes": compact,
        "counts": {
            "review": len(review),
            "exposure": len(exposure),
            "context_only": len(context_only),
            "potential_only": len(potential_only),
        },
        "coverage": {
            "source_coverage": source_coverage,
            "requested_system_count": len(system_scopes),
            "systems_without_recorded_links": sorted(set(system_scopes) - linked_systems)[:LIMIT],
            "systems_without_recorded_links_count": len(set(system_scopes) - linked_systems),
            "missing_system_list_truncated": len(set(system_scopes) - linked_systems) > LIMIT,
            "unresolved_or_invalid_link_count": invalid,
            "terminal_link_count": terminal,
            "returned_process_count": min(len(public), LIMIT),
            "total_process_count": len(public),
            "process_limit": LIMIT,
            "processes_truncated": len(public) > LIMIT,
            "reason_limit_per_process": REASON_LIMIT,
        },
        "economic_context": {
            **economic,
            "unmapped_exposed_system_count": unmapped_exposed,
            "scope": "distinct exposed process IDs only; supporting context and potential-only processes excluded",
            "note": "Declared process business context, not predicted revenue loss or unique affected customers. Customer populations may overlap. Currency/unit compatibility is not verified.",
        },
        "note": "Recorded support does not prove operational failure. Missing mappings are unknown, not zero impact. Explanation bounds do not drive counts.",
    }
