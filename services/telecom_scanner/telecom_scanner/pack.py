"""Per-carrier NRA pack (pure) — the national-regulator artifact.

Telecom counterpart of the banking supervisory pack: the regulator of ONE
country gets ONE carrier's posture — its NF verdicts, its roadmap rows on
the shared IR 8547 plan, the roaming edges it serves — with the platform's
declared limits riding along. Cross-carrier data is deliberately excluded:
a regulator of country X does not receive carrier Y's rows just because
they live in the same group.

Sections come from the same engines as every other surface; missing data
stays empty rather than being invented.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping

from telecom_scanner.roadmap import carrier_families
from telecom_scanner.rollup import posture_rollup

PACK_VERSION = "1.0.0"

DECLARED_LIMITS: tuple[str, ...] = (
    "Extract- and probe-based inventory: absence of a finding is not proof "
    "of absence — coverage follows the registered targets and successful probes.",
    "IPsec/NDS(IP) gateways are classified from operator-side ingest only; "
    "this pack never fabricates IKE parameters it did not observe.",
    "No key material is included, by design — cryptographic metadata only.",
)


def carrier_pack(
    carrier: Mapping[str, Any],
    verdicts: Iterable[Mapping[str, Any]],
    *,
    roaming_rows: Iterable[Mapping[str, Any]] | None = None,
    as_of: date | None = None,
) -> dict[str, Any]:
    """One carrier's NRA pack from the latest scan verdicts.

    ``verdicts`` — ALL verdicts from the latest pass; only this carrier's
    rows are included. ``roaming_rows`` — the roaming matrix rows; only
    agreements served by this carrier are included.
    """
    code = str(carrier.get("code") or "")
    mine = [dict(v) for v in verdicts if str(v.get("carrier_code") or "") == code]
    rollup = posture_rollup(mine, {code: dict(carrier)})
    families = carrier_families(mine).get(code, [])

    my_roaming = [
        dict(r) for r in (roaming_rows or [])
        if str(r.get("carrier_code") or "") == code
    ]
    this_date = as_of or datetime.now(timezone.utc).date()
    return {
        "pack": {
            "kind": "telecom-nra-pack",
            "version": PACK_VERSION,
            "carrier_code": code,
            "carrier_name": carrier.get("name") or code,
            "country": carrier.get("country") or "",
            "plmn": carrier.get("plmn") or "",
            "generated_for": this_date.isoformat(),
        },
        "posture": {
            "totals": rollup["totals"],
            "by_nf_type": rollup["by_nf_type"],
            "worst_targets": rollup["worst_targets"],
        },
        "families_flagged": families,
        "roaming_edges": my_roaming,
        "declared_limits": list(DECLARED_LIMITS),
    }
