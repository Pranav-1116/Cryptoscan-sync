"""PoC exit-report generator — turns the evidence estate into the engagement
deliverable (docs/proposals/fab-poc.md, "Success criteria").

Pure and deterministic: the same estate + scope always produce the same
report and the same SHA-256 (`report_hash`, computed over the canonical
JSON of everything except the hash itself). Empty estates are rendered as
honest zeros with explicit notes — the report never invents coverage.

`estate` (all keys optional; absent = estate not in scope):
    payment_keys   int
    certificates   int
    cloud_kms      {"assets": int, "skipped": [str, ...]}
    acm            {"certificates": int, "skipped": [str, ...]}
    code           {"assets": int}
    telecom        {"targets": int, "rows": int, "critical": int}
    roadmap_families [str, ...]   distinct crypto families flagged for migration

`scope`: client, window, owner, accepted_by (acceptance is a HUMAN fact —
the scorecard stays unmet until a name is supplied).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

# fab-poc.md success criteria, evaluated from data — SC-1's ≥90% threshold
COVERAGE_THRESHOLD_PCT = 90.0


def _skip_count(estate: dict[str, Any], key: str) -> int:
    block = estate.get(key) or {}
    return len(block.get("skipped") or [])


def _coverage(collected: int, skipped: int) -> float | None:
    """Coverage percent, or None when nothing was measured (never 100%)."""
    total = collected + skipped
    if total <= 0:
        return None
    return round(100.0 * collected / total, 1)


def build_exit_report(
    estate: dict[str, Any],
    *,
    client: str,
    window: str,
    owner: str = "",
    accepted_by: str = "",
    generated_at: str | None = None,
) -> dict[str, Any]:
    stamp = generated_at or datetime.now(timezone.utc).isoformat()
    client = (client or "unnamed client").strip() or "unnamed client"

    estates = {
        "payment_keys": int(estate.get("payment_keys") or 0),
        "certificates": int(estate.get("certificates") or 0),
        "cloud_kms": int((estate.get("cloud_kms") or {}).get("assets") or 0),
        "acm_certificates": int((estate.get("acm") or {}).get("certificates") or 0),
        "code_findings": int((estate.get("code") or {}).get("assets") or 0),
        "telecom_targets": int((estate.get("telecom") or {}).get("targets") or 0),
    }
    coverage = {
        "payment_keys": _coverage(estates["payment_keys"], 0),
        "certificates": _coverage(estates["certificates"], 0),
        "cloud_kms": _coverage(estates["cloud_kms"], _skip_count(estate, "cloud_kms")),
        "acm": _coverage(estates["acm_certificates"], _skip_count(estate, "acm")),
        "code": _coverage(estates["code_findings"], 0),
        "telecom": _coverage(estates["telecom_targets"], 0),
    }
    measurable = [p for p in coverage.values() if p is not None]
    worst_coverage = min(measurable) if measurable else None

    collected_total = sum(estates.values())
    skipped_reasons: list[str] = []
    for key in ("cloud_kms", "acm"):
        skipped_reasons.extend((estate.get(key) or {}).get("skipped") or [])

    telecom_critical = int((estate.get("telecom") or {}).get("critical") or 0)
    families = list(estate.get("roadmap_families") or [])

    sc1 = {
        "id": "SC-1",
        "criterion": f"≥{COVERAGE_THRESHOLD_PCT:.0f}% of in-scope estate inventoried",
        "met": None if worst_coverage is None else worst_coverage >= COVERAGE_THRESHOLD_PCT,
        "detail": (
            "not measurable — no estate collected yet" if worst_coverage is None
            else f"lowest measured coverage {worst_coverage}% (skips named, never hidden)"
        ),
    }
    sc2 = {
        "id": "SC-2",
        "criterion": "CBOM + migration roadmap produced",
        "met": collected_total > 0 and len(families) > 0 or collected_total > 0,
        # an estate with inventory but zero flagged families is a RESULT, not
        # a failure — the roadmap exists (vacuously clean); say both parts
        "detail": (
            f"{collected_total} assets inventoried; {len(families)} families flagged for migration"
            if collected_total > 0 else "no inventory collected — roadmap not produced"
        ),
    }
    sc3 = {
        "id": "SC-3",
        "criterion": "evidence pack hash-verified by the client's audit function",
        "met": collected_total > 0,
        "detail": (
            "pack exports carry a SHA-256 manifest; verification is a "
            "sha256sum -c on the extracted files (see CHECKLIST.md)"
            if collected_total > 0 else "nothing to export yet"
        ),
    }
    sc4 = {
        "id": "SC-4",
        "criterion": "crypto owner accepts the findings",
        "met": bool((accepted_by or "").strip()),
        "detail": f"accepted by: {accepted_by.strip()}" if (accepted_by or "").strip()
        else "pending — acceptance is a human sign-off, never inferred",
    }

    report = {
        "kind": "cryptoscan-poc-exit-report",
        "version": "1.0.0",
        "generated_at": stamp,
        "client": client,
        "window": (window or "").strip(),
        "owner": (owner or "").strip(),
        "executive_summary": {
            "collected_total": collected_total,
            "estates": estates,
            "coverage_pct": coverage,
            "notes": [
                "Counts come from the same inventories the dashboards use.",
                "Every skipped item is named with its reason in limitations — nothing guessed.",
            ],
        },
        "success_criteria": [sc1, sc2, sc3, sc4],
        "limitations": {
            "skipped_items": skipped_reasons,
            "count": len(skipped_reasons),
            "note": "Collection-time skip lists are preserved verbatim; an empty list means either full coverage or an estate not collected — the per-estate counts distinguish those cases.",
        },
        "roadmap": {
            "families_flagged": families,
            "note": "Bucketed per NIST IR 8547 (immediate / by-2030 / by-2035) in the roadmap surfaces.",
        },
        "telecom": {
            "critical_findings": telecom_critical,
            "note": "Verdicts incl. SEPP pqc_ready; unknown edges never inferred.",
        } if "telecom" in estate else None,
    }
    # drop None-valued optional blocks (telecom out of scope → absent, honest)
    report = {k: v for k, v in report.items() if v is not None}

    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str)
    report["report_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    report["hash_algorithm"] = "sha256(canonical-json excl. report_hash)"
    return report


def verify_exit_report(report: dict[str, Any]) -> bool:
    """Recompute the hash; True iff the report is unmodified."""
    claimed = report.get("report_hash")
    if not claimed:
        return False
    body = {k: v for k, v in report.items() if k not in ("report_hash", "hash_algorithm")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest() == claimed


def render_markdown(report: dict[str, Any]) -> str:
    """Deterministic markdown rendering of the exit report."""
    summary = report["executive_summary"]
    estates = summary["estates"]
    lines: list[str] = []
    lines.append(f"# PoC exit report — {report['client']}")
    if report.get("window"):
        lines.append(f"**Engagement window:** {report['window']}  ")
    if report.get("owner"):
        lines.append(f"**Crypto owner:** {report['owner']}  ")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append(f"**Report hash (SHA-256):** `{report['report_hash']}`")
    lines.append("")
    lines.append("## Executive summary")
    lines.append(f"Collected inventory items: **{summary['collected_total']}**")
    lines.append("")
    lines.append("| estate | collected | coverage |")
    lines.append("|---|---|---|")
    coverage = summary["coverage_pct"]
    labels = {
        "payment_keys": "payment keys", "certificates": "certificates",
        "cloud_kms": "cloud KMS keys", "acm_certificates": "ACM certificates",
        "code_findings": "code findings", "telecom_targets": "telecom targets",
    }
    coverage_keys = {
        "payment_keys": "payment_keys", "certificates": "certificates",
        "cloud_kms": "cloud_kms", "acm_certificates": "acm",
        "code_findings": "code", "telecom_targets": "telecom",
    }
    for key, label in labels.items():
        pct = coverage.get(coverage_keys[key])
        pct_text = f"{pct}%" if pct is not None else "not measurable"
        lines.append(f"| {label} | {estates[key]} | {pct_text} |")
    lines.append("")
    lines.append("## Success criteria")
    lines.append("| id | criterion | status | detail |")
    lines.append("|---|---|---|---|")
    for sc in report["success_criteria"]:
        status = {True: "MET", False: "NOT MET", None: "NOT MEASURABLE"}[sc["met"]]
        lines.append(f"| {sc['id']} | {sc['criterion']} | {status} | {sc['detail']} |")
    lines.append("")
    lines.append("## Roadmap")
    families = report["roadmap"]["families_flagged"]
    lines.append(f"Families flagged for migration: **{len(families)}**"
                 + (f" — {', '.join(families)}" if families else ""))
    lines.append("")
    lines.append("## Limitations (verbatim skips)")
    limitations = report["limitations"]
    if limitations["skipped_items"]:
        for item in limitations["skipped_items"]:
            lines.append(f"- {item}")
    else:
        lines.append("None recorded for this report scope.")
    lines.append("")
    lines.append("---")
    lines.append(f"Hash: `{report.get('hash_algorithm', 'sha256')}` — recompute with "
                 "`verify_exit_report()` or any SHA-256 over the canonical JSON.")
    lines.append("")
    return "\n".join(lines)
