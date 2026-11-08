"""Binary version comparison (§16 §6, §17 Phase 6) — what changed
between two artifact versions.

The diff is honest about evidence: a finding that disappears may mean
stripping or packing, not removal; a new string indicator is not proof
of new runtime behavior. Every delta carries its caveat — drift is
reported as drift of INDICATORS, never as drift of behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from binary_intelligence.evidence import CryptoFinding


@dataclass
class FindingDelta:
    change: str                # "added" | "removed" | "changed" | "unchanged"
    algorithm: str
    variant: str
    detail: str
    caveat: str

    def as_dict(self) -> Dict[str, Any]:
        return {"change": self.change, "algorithm": self.algorithm,
                "variant": self.variant, "detail": self.detail,
                "caveat": self.caveat}


@dataclass
class ComparisonReport:
    base_artifact_id: str
    base_sha256: str
    against_artifact_id: str
    against_sha256: str
    deltas: List[FindingDelta]
    summary: Dict[str, int]
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "base_artifact_id": self.base_artifact_id,
            "base_sha256": self.base_sha256,
            "against_artifact_id": self.against_artifact_id,
            "against_sha256": self.against_sha256,
            "deltas": [d.as_dict() for d in self.deltas],
            "summary": self.summary,
            "limitations": self.limitations,
            "note": "comparison reports drift of static INDICATORS, never "
                    "drift of runtime behavior (§6) — a missing indicator "
                    "may mean stripping or packing, not removal",
        }


def _get(finding: Any, key: str) -> Any:
    if isinstance(finding, dict):
        return finding.get(key)
    return getattr(finding, key, None)


def _class_of(finding: Any) -> str:
    value = _get(finding, "evidence_class")
    return getattr(value, "value", value) or ""


def _usage_of(finding: Any) -> str:
    value = _get(finding, "usage_status")
    return getattr(value, "value", value) or ""


def _key(finding: Any) -> Tuple[str, str, str]:
    return (_get(finding, "finding_type") or "",
            _get(finding, "algorithm") or "",
            _get(finding, "variant") or "")


def _describe(finding: Any) -> str:
    parts = [_class_of(finding), _usage_of(finding)]
    operation = _get(finding, "operation")
    if operation:
        parts.append(operation)
    key_size = _get(finding, "key_size_bits")
    if key_size:
        parts.append(f"{key_size}-bit")
    return ", ".join(p for p in parts if p)


def compare_findings(*, base_artifact_id: str, base_sha256: str,
                     base_findings: List[Any],
                     against_artifact_id: str, against_sha256: str,
                     against_findings: List[Any]
                     ) -> ComparisonReport:
    base_map = {_key(f): f for f in base_findings}
    against_map = {_key(f): f for f in against_findings}
    deltas: List[FindingDelta] = []

    for key in sorted(set(base_map) | set(against_map)):
        in_base = base_map.get(key)
        in_against = against_map.get(key)
        family, algorithm, variant = key
        if in_base is not None and in_against is None:
            deltas.append(FindingDelta(
                change="removed", algorithm=algorithm, variant=variant,
                detail=f"present in base ({_describe(in_base)}), absent in "
                       "the compared artifact",
                caveat="an indicator can disappear because symbols were "
                       "stripped or code was packed — removal of the "
                       "capability is not proven"))
        elif in_base is None and in_against is not None:
            deltas.append(FindingDelta(
                change="added", algorithm=algorithm, variant=variant,
                detail=f"absent in base, present in compared artifact "
                       f"({_describe(in_against)})",
                caveat="a new static indicator is not proof of new runtime "
                       "behavior (§5)"))
        else:
            detail_base = _describe(in_base)
            detail_against = _describe(in_against)
            if detail_base != detail_against:
                deltas.append(FindingDelta(
                    change="changed", algorithm=algorithm, variant=variant,
                    detail=f"{detail_base} -> {detail_against}",
                    caveat="evidence strength changed — the underlying "
                           "implementation change is not proven"))
            else:
                deltas.append(FindingDelta(
                    change="unchanged", algorithm=algorithm, variant=variant,
                    detail=detail_against,
                    caveat=""))

    summary = {
        "added": sum(1 for d in deltas if d.change == "added"),
        "removed": sum(1 for d in deltas if d.change == "removed"),
        "changed": sum(1 for d in deltas if d.change == "changed"),
        "unchanged": sum(1 for d in deltas if d.change == "unchanged"),
    }
    return ComparisonReport(
        base_artifact_id=base_artifact_id, base_sha256=base_sha256,
        against_artifact_id=against_artifact_id,
        against_sha256=against_sha256,
        deltas=deltas, summary=summary,
        limitations=[
            "both sides are static analyses with their own coverage "
            "limits; the comparison never proves behavior on either side"])
