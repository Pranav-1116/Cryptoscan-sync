"""Telecom posture rollup (pure) — NF verdicts → carrier/country/group views.

International dimension: every carrier optionally carries ``legal_entity``,
tying it into the group registry (cbom.group) — the group view aggregates
carrier posture per legal entity, and roaming edges (SEPP targets) are
reported separately because that is the inter-PLMN exposure a supervisor
or security chief asks about first.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

_SEV_RANK = {"ok": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _max_sev(rows: Iterable[Mapping[str, Any]]) -> str:
    severities = [str(r.get("severity", "info")) for r in rows]
    return max(severities, key=lambda s: _SEV_RANK.get(s, 0), default="ok") if severities else "ok"


def posture_rollup(
    verdicts: Iterable[Mapping[str, Any]],
    carriers: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Aggregate one scan pass. ``verdicts`` are classify_target rows;
    ``carriers`` is the registry's carrier map (code → record)."""
    carriers = carriers or {}
    rows = [dict(v) for v in verdicts]

    probed = [r for r in rows if r.get("status") not in ("NOT_PROBED",)]
    reachable = [r for r in probed if r.get("status") != "UNREACHABLE"]
    critical = [r for r in rows if r.get("severity") == "critical"]
    expiring = [r for r in rows if any(
        f.get("code") in ("cert.expiring", "cert.expired") for f in r.get("findings") or []
    )]
    pqc_ready = [r for r in rows if r.get("pqc_kex")]

    def _bucket(key: str) -> list[dict[str, Any]]:
        order = {"code": "carrier_code", "country": "country", "type": "nf_type"}
        field = order[key]
        out: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            out.setdefault(str(r.get(field) or "—"), []).append(r)
        return out

    by_carrier = {}
    for code, group in sorted(_bucket("code").items()):
        carrier = carriers.get(code) or {}
        by_carrier[code] = {
            "name": carrier.get("name") or code,
            "country": carrier.get("country") or "",
            "plmn": carrier.get("plmn") or "",
            "legal_entity": carrier.get("legal_entity") or "",
            "targets": len(group),
            "reachable": sum(1 for r in group if r.get("status") not in ("UNREACHABLE", "NOT_PROBED")),
            "critical": sum(1 for r in group if r.get("severity") == "critical"),
            "worst_severity": _max_sev(group),
            "avg_score": round(sum(int(r.get("score") or 0) for r in group) / len(group), 1),
        }

    by_country: dict[str, dict[str, Any]] = {}
    for code, view in by_carrier.items():
        country = view["country"] or "—"
        slot = by_country.setdefault(country, {"carriers": 0, "targets": 0, "critical": 0})
        slot["carriers"] += 1
        slot["targets"] += view["targets"]
        slot["critical"] += view["critical"]

    by_nf_type: dict[str, dict[str, int]] = {}
    for nf_type, group in sorted(_bucket("type").items()):
        by_nf_type[nf_type] = {
            "targets": len(group),
            "critical": sum(1 for r in group if r.get("severity") == "critical"),
            "avg_score": round(sum(int(r.get("score") or 0) for r in group) / len(group), 1),
        }

    # international / group view
    by_entity: dict[str, dict[str, Any]] = {}
    for code, view in by_carrier.items():
        entity = view["legal_entity"]
        if not entity:
            continue
        slot = by_entity.setdefault(entity, {
            "carriers": [], "targets": 0, "critical": 0, "countries": set(),
        })
        slot["carriers"].append(code)
        slot["targets"] += view["targets"]
        slot["critical"] += view["critical"]
        if view["country"]:
            slot["countries"].add(view["country"])
    international = {
        entity: {
            "carriers": slot["carriers"],
            "countries": sorted(slot["countries"]),
            "targets": slot["targets"],
            "critical": slot["critical"],
            "worst_severity": "critical" if slot["critical"] else "ok",
        }
        for entity, slot in sorted(by_entity.items())
    }

    roaming_rows = [r for r in rows if r.get("nf_type") == "sepp"]
    roaming_edges = {
        "sepp_targets": len(roaming_rows),
        "protected": sum(1 for r in roaming_rows if r.get("status") == "TLS_OK" and r.get("severity") not in ("critical",)),
        "unprotected": sum(1 for r in roaming_rows if r.get("severity") == "critical"),
    }

    worst = sorted(
        rows,
        key=lambda r: (-_SEV_RANK.get(str(r.get("severity")), 0), int(r.get("score") or 0)),
    )[:5]

    return {
        "totals": {
            "targets": len(rows),
            "probed": len(probed),
            "reachable": len(reachable),
            "unreachable": sum(1 for r in probed if r.get("status") == "UNREACHABLE"),
            "critical": len(critical),
            "expiring_certs": len(expiring),
            "pqc_ready": len(pqc_ready),
            "worst_severity": _max_sev(rows),
            "avg_score": round(sum(int(r.get("score") or 0) for r in rows) / len(rows), 1) if rows else 0,
        },
        "by_carrier": by_carrier,
        "by_country": by_country,
        "by_nf_type": by_nf_type,
        "international": international,
        "roaming_edges": roaming_edges,
        "worst_targets": [
            {"nf_id": r.get("nf_id"), "nf_type": r.get("nf_type"),
             "severity": r.get("severity"), "score": r.get("score"),
             "status": r.get("status"),
             "headline": ((r.get("findings") or [{}])[0].get("message") or "")}
            for r in worst
        ],
    }
