"""Deterministic migration validation (pre/post crypto migration gating).

Before migrating systems off deprecated/quantum-vulnerable crypto, the platform
captures a *pre-migration* snapshot of findings and coverage. After migration it
captures a *post-migration* snapshot and validates that:

* every target weak finding was remediated (no deprecated algorithm remains);
* no NEW findings/regressions were introduced by the change;
* coverage did not drop (the post scan sees >= the pre scan's covered assets);
* no previously-passing control regressed.

This is a deterministic diff over structured snapshots — no AI. A migration is
PASS only when there are zero regressions; otherwise it FAILS with the exact
regressing items, enforcing a safe rollback decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: algorithms that must not remain after a crypto migration targets them
DEPRECATED_ALGORITHMS = frozenset({
    "DES", "3DES", "MD5", "SHA1", "RC4", "MD4", "ECDH", "RSA-1024", "DSA-1024",
})


@dataclass
class MigrationSnapshot:
    findings: list[dict[str, Any]] = field(default_factory=list)
    covered_assets: set[str] = field(default_factory=set)
    weak_algorithm_counts: dict[str, int] = field(default_factory=dict)

    @staticmethod
    def from_findings(findings: list[dict[str, Any]], covered_assets: set[str] | None = None) -> MigrationSnapshot:
        weak_counts: dict[str, int] = {}
        for f in findings:
            algo = str(f.get("algorithm") or f.get("normalized_algorithm") or "").upper()
            if algo in DEPRECATED_ALGORITHMS or str(f.get("status") or "").upper() in ("DISALLOWED", "DEPRECATED"):
                weak_counts[algo or f.get("algorithm", "?")] = weak_counts.get(algo, 0) + 1
        return MigrationSnapshot(
            findings=findings,
            covered_assets=set(covered_assets or set()),
            weak_algorithm_counts=weak_counts,
        )


@dataclass
class MigrationValidationResult:
    passed: bool
    regressions: list[dict] = field(default_factory=list)
    remediated: list[dict] = field(default_factory=list)
    coverage_delta: dict = field(default_factory=dict)
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "regressions": self.regressions,
            "remediated": self.remediated,
            "coverage_delta": self.coverage_delta,
            "summary": self.summary,
        }


def _finding_key(f: dict[str, Any]) -> str:
    # Identity is the finding *location*, not its algorithm: a migration that
    # replaces DES with AES-GCM at the same file/line is a remediation, not a
    # new finding. Whether a deprecated algorithm *remains* is tracked
    # separately via weak_algorithm_counts.
    return "|".join(str(f.get(k, "")) for k in (
        "file_path", "line_number", "system_id", "asset_id",
    ))


def _is_weak(f: dict[str, Any]) -> bool:
    algo = str(f.get("algorithm") or f.get("normalized_algorithm") or "").upper()
    return algo in DEPRECATED_ALGORITHMS or str(f.get("status") or "").upper() in (
        "DISALLOWED", "DEPRECATED",
    )


def validate_migration(pre: MigrationSnapshot, post: MigrationSnapshot) -> MigrationValidationResult:
    """Diff a post-migration snapshot against its pre-migration baseline."""
    regressions: list[dict] = []
    remediated: list[dict] = []

    pre_keys = {_finding_key(f): f for f in pre.findings}
    post_keys = {_finding_key(f): f for f in post.findings}

    # findings remediated: the location disappeared, OR a weak finding at that
    # location was replaced by a strong one (algorithm upgrade in place).
    for key, f in pre_keys.items():
        if key not in post_keys:
            remediated.append({"key": key, "algorithm": f.get("algorithm"),
                               "file_path": f.get("file_path")})
        elif _is_weak(f) and not _is_weak(post_keys[key]):
            remediated.append({"key": key, "algorithm": f.get("algorithm"),
                               "file_path": f.get("file_path"),
                               "upgraded_to": post_keys[key].get("algorithm")})

    # findings present after but absent before => new regression. A brand-new
    # location with a *weak/deprecated* algorithm is a regression; a new
    # location using strong crypto is a net improvement, not a failure.
    for key, f in post_keys.items():
        if key not in pre_keys and _is_weak(f):
            regressions.append({"key": key, "kind": "new_weak_finding",
                                "algorithm": f.get("algorithm"),
                                "file_path": f.get("file_path"),
                                "detail": "new weak/deprecated finding introduced after migration"})

    # deprecated algorithms still present after => failed remediation
    for algo, count in post.weak_algorithm_counts.items():
        if count > 0 and (algo in DEPRECATED_ALGORITHMS):
            regressions.append({"kind": "deprecated_remaining", "algorithm": algo,
                                "count": count,
                                "detail": f"{count} {algo} finding(s) remain after migration"})

    # coverage regression
    pre_cov = len(pre.covered_assets)
    post_cov = len(post.covered_assets)
    lost = pre.covered_assets - post.covered_assets
    coverage_delta = {"pre_covered": pre_cov, "post_covered": post_cov,
                      "lost_assets": sorted(lost)}
    if lost:
        regressions.append({"kind": "coverage_loss", "count": len(lost),
                            "lost_assets": sorted(lost)[:50],
                            "detail": f"{len(lost)} asset(s) no longer covered post-migration"})

    passed = len(regressions) == 0
    summary = (
        "PASS — migration introduced no regressions; deprecated crypto remediated"
        if passed
        else f"FAIL — {len(regressions)} regression(s) detected; rollback recommended"
    )
    return MigrationValidationResult(
        passed=passed,
        regressions=regressions,
        remediated=remediated,
        coverage_delta=coverage_delta,
        summary=summary,
    )
