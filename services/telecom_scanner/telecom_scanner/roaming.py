"""Roaming partner matrix (pure) — GSMA IR.21-style inter-PLMN view.

A carrier's roaming agreements point at partner networks (identified by
PLMN); the crypto question for each agreement is whether the inter-PLMN
SBI path is protected — TS 33.501 puts that on the carrier's SEPP edge.
The matrix joins the partner registry to the latest SEPP verdicts:

* ``protected``   — the SEPP for this carrier probed TLS_OK (no critical)
* ``unprotected`` — the SEPP probed with critical findings / NO_TLS
* ``unknown``     — no SEPP verdict yet (honest; the partner is not blamed
  for a scan that has not run)

References travel on the rows: GSMA IR.21 (roaming agreement context) and
3GPP TS 33.501 (SEPP obligation).
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from telecom_scanner.registry import validate_plmn

_REF_IR21 = "GSMA IR.21 (roaming context)"
_REF_33501 = "3GPP TS 33.501 (SEPP)"

_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,23}$")


def normalize_partner(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one roaming-partner record — raises ValueError on bad fields."""
    carrier_code = str(record.get("carrier_code") or "").strip().lower()
    if not _CODE_RE.match(carrier_code):
        raise ValueError(f"carrier_code must match {_CODE_RE.pattern}: {record.get('carrier_code')!r}")
    plmn = validate_plmn(record.get("partner_plmn") or "")
    partner_name = str(record.get("partner_name") or "").strip()
    if not (2 <= len(partner_name) <= 120):
        raise ValueError("partner_name must be 2-120 characters")
    country = str(record.get("country") or "").strip().lower()
    if not re.match(r"^[a-z]{2}$", country):
        raise ValueError(f"partner country must be ISO 3166-1 alpha-2: {record.get('country')!r}")
    sepp_nf_id = str(record.get("sepp_nf_id") or "").strip().lower()
    if sepp_nf_id and not _CODE_RE.match(sepp_nf_id.replace("_", "-").replace(".", "-")):
        raise ValueError(f"sepp_nf_id has invalid characters: {record.get('sepp_nf_id')!r}")
    return {
        "id": f"{carrier_code}:{plmn['mcc']}-{plmn['mnc']}",
        "carrier_code": carrier_code,
        "partner_plmn": f"{plmn['mcc']}-{plmn['mnc']}",
        "partner_name": partner_name,
        "country": country,
        "sepp_nf_id": sepp_nf_id,
    }


def roaming_matrix(
    partners: Iterable[Mapping[str, Any]],
    verdicts: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Partner rows + summary from the partner registry and latest verdicts.

    Resolution order for the protecting SEPP: the partner's explicit
    ``sepp_nf_id`` verdict, else the carrier's first SEPP verdict. The
    matrix never fabricates protection: an unprobed edge is ``unknown``.
    """
    by_nf: dict[str, Mapping[str, Any]] = {
        str(v.get("nf_id")): v for v in verdicts if v.get("nf_id")
    }
    carrier_sepp: dict[str, Mapping[str, Any]] = {}
    for verdict in verdicts:
        if verdict.get("nf_type") == "sepp":
            carrier = str(verdict.get("carrier_code") or "")
            carrier_sepp.setdefault(carrier, verdict)

    rows: list[dict[str, Any]] = []
    counts = {"protected": 0, "unprotected": 0, "unknown": 0}
    for partner in partners:
        carrier = str(partner.get("carrier_code") or "")
        sepp = None
        sepp_id = str(partner.get("sepp_nf_id") or "")
        if sepp_id:
            sepp = by_nf.get(sepp_id)
        if sepp is None:
            sepp = carrier_sepp.get(carrier)

        if sepp is None:
            status, severity = "unknown", "info"
        elif sepp.get("severity") == "critical" or sepp.get("status") != "TLS_OK":
            status, severity = "unprotected", "critical"
        else:
            status, severity = "protected", "info"
        counts[status] += 1
        rows.append({
            "id": str(partner.get("id") or ""),
            "carrier_code": carrier,
            "partner_plmn": str(partner.get("partner_plmn") or ""),
            "partner_name": str(partner.get("partner_name") or ""),
            "country": str(partner.get("country") or ""),
            "sepp_nf_id": (sepp or {}).get("nf_id") or sepp_id or None,
            "status": status,
            "severity": severity,
            "sepp_status": (sepp or {}).get("status"),
            "ref": f"{_REF_IR21}; {_REF_33501}",
        })

    # worst first: unprotected, then unknown, then protected
    order = {"unprotected": 0, "unknown": 1, "protected": 2}
    rows.sort(key=lambda r: (order[r["status"]], r["carrier_code"], r["partner_name"]))
    return {"rows": rows, "summary": {"partners": len(rows), **counts}}
