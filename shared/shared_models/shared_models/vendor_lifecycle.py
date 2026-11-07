"""Vendor lifecycle and supplier-risk workflow (gap analysis Phase 5).

The review's vendor requirements, in its own words:

* threat intelligence watches "Unsupported product and supplier changes";
* PQC compatibility must "check software, protocol, HSM, KMS and vendor
  support";
* risk carries a "Vendor lifecycle risk" dimension;
* the domain model stores "vendors, vendor_products, vendor_releases,
  vendor_declarations".

House rules enforced here:

- a lifecycle status claim is evidence-backed: a product's support state
  without a declaration or published date is refused, not assumed;
- "a product is not a version": every claim names vendor, product AND
  version — an unsupported version never condemns (or blesses) the whole
  product line;
- a product past its declared end-of-support date is never reported as
  SUPPORTED;
- supplier risk is a list of evidence-linked drivers, never one unexplained
  number;
- missing lifecycle data is not a clean supplier bill: no data reads as
  UNKNOWN with ``is_clean_result: false``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from typing import Any, Iterable, Mapping, Sequence

VENDOR_SCHEMA = "cryptoscan.vendor-lifecycle/1"

SUPPORTED = "SUPPORTED"
END_OF_SUPPORT = "END_OF_SUPPORT"
END_OF_LIFE = "END_OF_LIFE"
UNKNOWN = "UNKNOWN"
SUPPORT_STATES: tuple[str, ...] = (SUPPORTED, END_OF_SUPPORT, END_OF_LIFE,
                                   UNKNOWN)

RELEASE = "RELEASE"
END_OF_SUPPORT_ANNOUNCED = "END_OF_SUPPORT_ANNOUNCED"
OWNERSHIP_CHANGE = "OWNERSHIP_CHANGE"
ADVISORY = "ADVISORY"
CHANGE_KINDS: tuple[str, ...] = (RELEASE, END_OF_SUPPORT_ANNOUNCED,
                                 OWNERSHIP_CHANGE, ADVISORY)


def _freeze(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _require_evidence(evidence_ref: Any, claim: str) -> str:
    ref = str(evidence_ref or "").strip()
    if not ref:
        raise ValueError(
            f"{claim} needs a supporting declaration or published source "
            "(evidence_ref): a lifecycle claim without evidence is a guess")
    return ref


def product_support(*, vendor: str, product: str, version: str,
                    status: str, evidence_ref: str,
                    end_of_support_at: str | None = None,
                    end_of_life_at: str | None = None,
                    as_of: str | None = None) -> dict[str, Any]:
    """One evidence-backed support claim for one vendor product version."""
    for name, value in (("vendor", vendor), ("product", product),
                        ("version", version)):
        if not str(value or "").strip():
            raise ValueError(
                f"{name} is mandatory: a product is not a version, and a "
                "claim that names neither is untargetable")
    state = str(status or "").upper()
    if state not in SUPPORT_STATES:
        raise ValueError(f"unknown support status {status!r}; "
                         f"expected one of {', '.join(SUPPORT_STATES)}")
    ref = _require_evidence(evidence_ref, "a support status claim")
    today = str(as_of or date.today().isoformat())
    if end_of_support_at and str(end_of_support_at) < today and state == SUPPORTED:
        raise ValueError(
            "a product past its end-of-support date is not SUPPORTED: "
            "report END_OF_SUPPORT or dispute the date with evidence")
    return {
        "schema": VENDOR_SCHEMA,
        "kind": "product_support",
        "vendor": str(vendor), "product": str(product), "version": str(version),
        "status": state, "evidence_ref": ref,
        "end_of_support_at": end_of_support_at,
        "end_of_life_at": end_of_life_at,
        "as_of": today,
    }


def supplier_change(*, vendor: str, kind: str, announced_at: str,
                    evidence_ref: str, detail: str,
                    products: Sequence[str] = ()) -> dict[str, Any]:
    """One supplier change, recorded as evidence — never inferred."""
    if not str(vendor or "").strip():
        raise ValueError("vendor is mandatory for a supplier change")
    name = str(kind or "").upper()
    if name not in CHANGE_KINDS:
        raise ValueError(f"unknown change kind {kind!r}; "
                         f"expected one of {', '.join(CHANGE_KINDS)}")
    if not str(announced_at or "").strip():
        raise ValueError("announced_at is mandatory: an undated change "
                         "cannot be placed on a timeline")
    ref = _require_evidence(evidence_ref, "a supplier change")
    if not str(detail or "").strip():
        raise ValueError("detail is mandatory: a change with no description "
                         "cannot be reviewed")
    return {
        "schema": VENDOR_SCHEMA,
        "kind": "supplier_change",
        "vendor": str(vendor), "change": name,
        "announced_at": str(announced_at), "evidence_ref": ref,
        "detail": str(detail),
        "products": [str(p) for p in products if str(p).strip()],
    }


def deployed_exposure(*, deployments: Iterable[Mapping[str, Any]],
                      support_records: Iterable[Mapping[str, Any]],
                      as_of: str | None = None) -> dict[str, Any]:
    """Cross-check deployed products against lifecycle records.

    A deployment whose product version has an END_OF_SUPPORT or END_OF_LIFE
    record is a named exposure carrying BOTH record references. A deployment
    with no lifecycle data is UNKNOWN exposure — never a clean result.
    """
    today = str(as_of or date.today().isoformat())
    records: dict[tuple, dict[str, Any]] = {}
    for row in support_records:
        key = (str(row.get("vendor") or ""), str(row.get("product") or ""),
               str(row.get("version") or ""))
        records[key] = dict(row)
    findings = []
    unknown = []
    clean = []
    for dep in deployments:
        key = (str(dep.get("vendor") or ""), str(dep.get("product") or ""),
               str(dep.get("version") or ""))
        record = records.get(key)
        entry = {
            "deployment": dict(dep),
            "support_record": record,
        }
        if record is None:
            entry["exposure"] = UNKNOWN
            entry["note"] = ("no lifecycle record for this vendor product "
                             "version: unknown support, not a clean result")
            unknown.append(entry)
            continue
        state = record.get("status")
        end_of_support = record.get("end_of_support_at")
        past_eos = bool(end_of_support and str(end_of_support) < today)
        if state in (END_OF_SUPPORT, END_OF_LIFE) or past_eos:
            entry["exposure"] = "UNSUPPORTED_DEPLOYED"
            entry["note"] = (
                f"deployed product version is {state or 'past end of support'}"
                f" as of {today}")
            findings.append(entry)
        else:
            entry["exposure"] = "SUPPORTED"
            entry["note"] = "support claim is evidence-backed and current"
            clean.append(entry)
    return {
        "schema": VENDOR_SCHEMA,
        "kind": "deployed_exposure",
        "as_of": today,
        "unsupported_deployed": findings,
        "unknown_support": unknown,
        "supported": clean,
        "is_clean_result": len(unknown) == 0 and len(findings) == 0,
        "note": ("a clean result requires lifecycle data for every "
                 "deployment: unknown support is never counted as fine"),
    }


def supplier_risk(*, vendor: str,
                  deployments_report: Mapping[str, Any],
                  changes: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Evidence-linked risk drivers for one vendor — never a blended number.

    Each driver names its count and the records behind it. The report states
    its own completeness; missing data is UNKNOWN risk, not low risk.
    """
    if not str(vendor or "").strip():
        raise ValueError("vendor is mandatory")
    drivers = []
    unsupported = deployments_report.get("unsupported_deployed") or []
    if unsupported:
        drivers.append({
            "driver": "unsupported_product_deployed",
            "count": len(unsupported),
            "records": [row.get("support_record") for row in unsupported],
        })
    unknown = deployments_report.get("unknown_support") or []
    if unknown:
        drivers.append({
            "driver": "no_lifecycle_data_for_deployment",
            "count": len(unknown),
            "records": [row.get("deployment") for row in unknown],
        })
    for kind in (END_OF_SUPPORT_ANNOUNCED, OWNERSHIP_CHANGE):
        matched = [c for c in changes if str(c.get("change") or "").upper() == kind]
        if matched:
            drivers.append({
                "driver": f"supplier_change:{kind.lower()}",
                "count": len(matched),
                "records": [c.get("evidence_ref") for c in matched],
            })
    if not deployments_report.get("supported") and not drivers:
        state = UNKNOWN
        note = ("no lifecycle data at all: supplier risk is unknown, "
                "never a clean bill")
        is_clean = False
    elif drivers:
        state = "ACTION_REQUIRED" if unsupported else "ATTENTION"
        note = "each driver links the records behind it; no combined score"
        is_clean = False
    else:
        state = "NO_FINDINGS"
        note = ("every deployed version has a current evidence-backed "
                "support claim")
        is_clean = True
    return {
        "schema": VENDOR_SCHEMA,
        "kind": "supplier_risk",
        "vendor": str(vendor),
        "state": state,
        "drivers": drivers,
        "is_clean_result": is_clean,
        "note": note,
    }


def vendor_log_digest(events: Iterable[Mapping[str, Any]]) -> str:
    """Deterministic digest of a supplier-change log (order-insensitive)."""
    rows = sorted((_freeze(dict(e)) for e in events))
    return "sha256:" + hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


# ---- PQC supply-chain readiness ("Post-Quantum Questions to Ask Your Vendors")

READINESS_DIMENSIONS: tuple[str, ...] = (
    "pqc_roadmap",
    "implementation_capability",
    "testing_evidence",
    "product_support_lifecycle",
    "upgrade_commitment",
)

VENDOR_CLAIM = "VENDOR_CLAIM"
INDEPENDENT_TEST = "INDEPENDENT_TEST"
VERIFICATION_KINDS: tuple[str, ...] = (VENDOR_CLAIM, INDEPENDENT_TEST)

ANSWERED = "ANSWERED"
NOT_PROVIDED = "NOT_PROVIDED"
DECLINED = "DECLINED"
DIMENSION_STATES: tuple[str, ...] = (ANSWERED, NOT_PROVIDED, DECLINED)

READY = "READY"
PARTIAL = "PARTIAL"
NOT_READY = "NOT_READY"


def supplier_readiness(*, vendor: str, product: str | None,
                       responses: Iterable[Mapping[str, Any]],
                       as_of: str | None = None) -> dict[str, Any]:
    """One supplier's PQC-readiness questionnaire result.

    The review's third-party rule: assess "PQC roadmaps, implementation
    capabilities, testing evidence, product support lifecycles, and upgrade
    commitments" — and never infer readiness. House rules enforced here:

    - a positive answer needs evidence and a verification kind: a claim is
      not proof;
    - the testing_evidence dimension counts as met only when an INDEPENDENT
      test backs it — "don't claim support simply because an integration
      has a fixture": a vendor saying "we tested" is a VENDOR_CLAIM;
    - a dimension with no response is UNKNOWN for that dimension — no
      response is not readiness;
    - READY requires every dimension met with evidence; anything less is
      PARTIAL or NOT_READY, and ``is_clean_result`` is never true on
      missing answers.
    """
    if not str(vendor or "").strip():
        raise ValueError("vendor is mandatory for a readiness assessment")
    today = str(as_of or date.today().isoformat())

    answered: dict[str, dict[str, Any]] = {}
    for row in responses:
        dimension = str(row.get("dimension") or "").strip().lower()
        if dimension not in READINESS_DIMENSIONS:
            raise ValueError(f"unknown readiness dimension {row.get('dimension')!r}; "
                             f"expected one of {', '.join(READINESS_DIMENSIONS)}")
        if dimension in answered:
            raise ValueError(f"dimension {dimension!r} answered twice: a "
                             "questionnaire is one answer per question")
        state = str(row.get("status") or "").upper()
        if state not in DIMENSION_STATES:
            raise ValueError(f"unknown dimension status {row.get('status')!r}; "
                             f"expected one of {', '.join(DIMENSION_STATES)}")
        verification = str(row.get("verification") or "").upper() or None
        detail = str(row.get("detail") or "")
        if state == ANSWERED:
            ref = _require_evidence(
                row.get("evidence_ref"), f"an ANSWERED readiness claim for {dimension!r}")
            if verification not in VERIFICATION_KINDS:
                raise ValueError(
                    f"an ANSWERED {dimension!r} claim needs its verification "
                    f"kind ({VENDOR_CLAIM} or {INDEPENDENT_TEST}): a claim "
                    "without provenance cannot be weighed")
            entry = {"status": ANSWERED, "evidence_ref": ref,
                     "verification": verification, "detail": detail}
        else:
            entry = {"status": state, "evidence_ref": None,
                     "verification": None, "detail": detail}
        answered[dimension] = entry

    dimensions = []
    met = 0
    for dimension in READINESS_DIMENSIONS:
        entry = answered.get(dimension)
        if entry is None:
            dimensions.append({
                "dimension": dimension, "status": "UNKNOWN",
                "evidence_ref": None, "verification": None, "detail": "",
                "met": False,
                "note": "no response is not readiness",
            })
            continue
        is_met = entry["status"] == ANSWERED and not (
            dimension == "testing_evidence" and
            entry["verification"] != INDEPENDENT_TEST)
        note = ""
        if (dimension == "testing_evidence" and entry["status"] == ANSWERED
                and entry["verification"] != INDEPENDENT_TEST):
            note = ("a vendor claim of testing is not test evidence: only an "
                    "independent test meets this dimension")
        if is_met:
            met += 1
        dimensions.append({
            "dimension": dimension, **entry, "met": is_met, "note": note,
        })

    if met == len(READINESS_DIMENSIONS):
        state = READY
        note = ("every dimension is met with evidence, testing independently "
                "verified")
        is_clean = True
    elif met == 0 and all(d["status"] in ("UNKNOWN", NOT_PROVIDED, DECLINED)
                          for d in dimensions):
        state = NOT_READY if any(d["status"] == DECLINED for d in dimensions) else "UNKNOWN"
        note = ("no evidence-backed answers: readiness is unknown, never "
                "assumed")
        is_clean = False
    else:
        state = PARTIAL
        note = ("readiness is partial; the estate's migration pace is bound "
                "by its least-ready critical supplier")
        is_clean = False
    return {
        "schema": VENDOR_SCHEMA,
        "kind": "supplier_readiness",
        "vendor": str(vendor),
        "product": str(product) if product else None,
        "as_of": today,
        "dimensions": dimensions,
        "dimensions_met": met,
        "dimensions_total": len(READINESS_DIMENSIONS),
        "state": state,
        "is_clean_result": is_clean,
        "note": note,
    }


def least_ready_suppliers(
        assessments: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The estate's migration pace is bound by its least-ready suppliers.

    Per the review: "the migration readiness of an organization can be
    constrained by its least-prepared critical supplier." This names those
    suppliers — it never averages readiness into a score.
    """
    rows = [dict(a) for a in assessments]
    blockers = sorted(
        ({"vendor": r.get("vendor"), "product": r.get("product"),
          "state": r.get("state"),
          "dimensions_met": r.get("dimensions_met"),
          "dimensions_total": r.get("dimensions_total")}
         for r in rows if r.get("state") not in (READY,)),
        key=lambda r: (str(r["vendor"] or ""), str(r["product"] or "")))
    return {
        "schema": VENDOR_SCHEMA,
        "kind": "least_ready_suppliers",
        "suppliers": blockers,
        "state": "CONSTRAINED" if blockers else "NO_CONSTRAINT",
        "is_clean_result": not blockers,
        "note": ("each named supplier is a pacing constraint; there is no "
                 "average readiness number"),
    }
