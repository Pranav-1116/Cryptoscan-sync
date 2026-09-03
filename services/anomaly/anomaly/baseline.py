"""Deterministic crypto-posture baseline + drift detection (no AI/ML).

Captures a fingerprint of a scan's cryptographic posture — the set of weak
algorithms present, per-algorithm findings counts, and the weakest observed key
size — and compares a new snapshot against a sealed baseline. Any *new* weak
algorithm, a rise in weak-algorithm findings, or a smaller key size than the
baseline is reported as drift. This is exact set/count arithmetic, not a model.

The baseline is content-hashed (SHA-256 over a canonical form) so it can be
sealed in the data lake and any tampering detected on re-verify.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

#: algorithms that are broken/deprecated regardless of key size
WEAK_ALGORITHMS = frozenset({
    "DES", "3DES", "TDES", "DES-EDE", "RC4", "MD5", "SHA1",
    "ECB", "EXPORT",
})
_STRONG_FLOOR_BITS = {"RSA": 2048, "DSA": 2048, "DH": 2048, "EC": 224, "ECDSA": 224}


def _canon_algo(v: Any) -> str:
    return str(v or "").strip().upper().replace("_", "-").replace(" ", "")


def _safe_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class PostureBaseline:
    weak_algorithms: tuple[str, ...]
    algorithm_counts: dict[str, int]
    weak_findings_total: int
    min_key_size: int | None
    hardcoded_key_count: int
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "weak_algorithms": list(self.weak_algorithms),
            "algorithm_counts": dict(self.algorithm_counts),
            "weak_findings_total": self.weak_findings_total,
            "min_key_size": self.min_key_size,
            "hardcoded_key_count": self.hardcoded_key_count,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class Drift:
    kind: str          # new_weak_algorithm | weak_count_increase | key_size_regression | hardcoded_keys_increased
    severity: str      # HIGH | MEDIUM
    detail: str


@dataclass
class DriftReport:
    baseline_digest: str
    current_digest: str
    drifted: bool
    drifts: list[Drift] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_digest": self.baseline_digest,
            "current_digest": self.current_digest,
            "drifted": self.drifted,
            "drifts": [d.__dict__ for d in self.drifts],
        }


def _fingerprint_payload(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    weak_set: set[str] = set()
    weak_total = 0
    min_key: int | None = None
    hardcoded = 0
    for f in findings:
        algo = _canon_algo(f.get("algorithm") or f.get("normalized_algorithm"))
        if algo:
            counts[algo] = counts.get(algo, 0) + 1
        if algo in WEAK_ALGORITHMS:
            weak_set.add(algo)
            weak_total += 1
        # RSA/DSA/DH weak only when below their strength floor
        size = _safe_int(f.get("key_size"))
        if size is not None:
            if min_key is None or size < min_key:
                min_key = size
            floor = _STRONG_FLOOR_BITS.get(algo)
            if floor is not None and size < floor and algo not in weak_set:
                weak_set.add(f"{algo}<{floor}")
                weak_total += 1
        if f.get("is_hardcoded_key") is True:
            hardcoded += 1
    return {
        "weak_algorithms": sorted(weak_set),
        "algorithm_counts": dict(sorted(counts.items())),
        "weak_findings_total": weak_total,
        "min_key_size": min_key,
        "hardcoded_key_count": hardcoded,
    }


def _digest(payload: dict[str, Any]) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def build_baseline(findings: Sequence[dict[str, Any]]) -> PostureBaseline:
    """Create a sealed posture baseline from a set of findings."""
    payload = _fingerprint_payload(findings)
    digest = _digest(payload)
    return PostureBaseline(
        weak_algorithms=tuple(payload["weak_algorithms"]),
        algorithm_counts=payload["algorithm_counts"],
        weak_findings_total=payload["weak_findings_total"],
        min_key_size=payload["min_key_size"],
        hardcoded_key_count=payload["hardcoded_key_count"],
        digest=digest,
    )


def baseline_from_dict(data: dict[str, Any]) -> PostureBaseline:
    """Reconstruct a baseline and verify its stored digest (tamper check)."""
    payload = {
        "weak_algorithms": list(data.get("weak_algorithms") or []),
        "algorithm_counts": dict(data.get("algorithm_counts") or {}),
        "weak_findings_total": int(data.get("weak_findings_total") or 0),
        "min_key_size": data.get("min_key_size"),
        "hardcoded_key_count": int(data.get("hardcoded_key_count") or 0),
    }
    expected = _digest(payload)
    stored = str(data.get("digest") or "")
    if stored != expected:
        raise ValueError("baseline digest mismatch — sealed baseline has been tampered with")
    return PostureBaseline(
        weak_algorithms=tuple(payload["weak_algorithms"]),
        algorithm_counts=payload["algorithm_counts"],
        weak_findings_total=payload["weak_findings_total"],
        min_key_size=payload["min_key_size"],
        hardcoded_key_count=payload["hardcoded_key_count"],
        digest=stored,
    )


def compare_baseline(baseline: PostureBaseline,
                     current_findings: Sequence[dict[str, Any]]) -> DriftReport:
    """Compare a current snapshot against a sealed baseline; report any drift."""
    current = _fingerprint_payload(current_findings)
    current_digest = _digest(current)
    drifts: list[Drift] = []

    base_weak = set(baseline.weak_algorithms)
    cur_weak = set(current["weak_algorithms"])
    for new_weak in sorted(cur_weak - base_weak):
        drifts.append(Drift(
            kind="new_weak_algorithm",
            severity="HIGH",
            detail=f"weak/non-compliant algorithm appeared that was absent at baseline: {new_weak}",
        ))

    if current["weak_findings_total"] > baseline.weak_findings_total:
        drifts.append(Drift(
            kind="weak_count_increase",
            severity="MEDIUM",
            detail=(f"weak-algorithm findings rose from {baseline.weak_findings_total} "
                    f"to {current['weak_findings_total']}"),
        ))

    if (baseline.min_key_size is not None and current["min_key_size"] is not None
            and current["min_key_size"] < baseline.min_key_size):
        drifts.append(Drift(
            kind="key_size_regression",
            severity="HIGH",
            detail=(f"minimum observed key size fell from {baseline.min_key_size} "
                    f"to {current['min_key_size']} bits"),
        ))

    if current["hardcoded_key_count"] > baseline.hardcoded_key_count:
        drifts.append(Drift(
            kind="hardcoded_keys_increased",
            severity="MEDIUM",
            detail=(f"hardcoded-key findings rose from {baseline.hardcoded_key_count} "
                    f"to {current['hardcoded_key_count']}"),
        ))

    return DriftReport(
        baseline_digest=baseline.digest,
        current_digest=current_digest,
        drifted=bool(drifts),
        drifts=drifts,
    )
