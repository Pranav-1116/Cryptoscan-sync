"""Binary drift intelligence (§17 Phase 6) — what changed between
artifacts and scans, and WHEN.

Three honest measurements, never upgraded:
- a drift SERIES groups artifacts by subject (filename / source
  location) and compares consecutive versions — drift of static
  INDICATORS, never drift of behavior (§6);
- a HISTORY timeline shows how findings moved across scan runs of ONE
  immutable artifact (rescans with new profiles or signature versions);
- an ESTATE view groups findings by vendor/product/format for vendor
  intelligence — grouping by metadata is not proof of common origin.

Missing data is named, never zero-filled. An indicator that appears may
be a new capability, a new compiler, or a new fingerprint version —
the delta carries the caveat.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from binary_intelligence.comparison import ComparisonReport, compare_findings


@dataclass
class DriftPoint:
    artifact_id: str
    sha256: str
    received_at: Optional[str]
    original_filename: str
    source_type: str
    source_location: Optional[str]
    detected_format: str
    scan_count: int
    delta_vs_previous: Optional[Dict[str, Any]]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id, "sha256": self.sha256,
            "received_at": self.received_at,
            "original_filename": self.original_filename,
            "source_type": self.source_type,
            "source_location": self.source_location,
            "detected_format": self.detected_format,
            "scan_count": self.scan_count,
            "delta_vs_previous": self.delta_vs_previous,
        }


@dataclass
class DriftSeries:
    subject: str
    points: List[DriftPoint]
    summary: Dict[str, int]
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "points": [p.as_dict() for p in self.points],
            "summary": self.summary,
            "limitations": self.limitations,
            "note": "drift is reported for static INDICATORS, never for "
                    "runtime behavior (§6); a change may come from a new "
                    "compiler, a new signature-database version, or "
                    "packing — each delta carries its caveat",
        }


def build_drift_series(*, subject: str,
                       artifacts: List[Dict[str, Any]],
                       findings_by_artifact: Dict[str, List[Dict[str, Any]]]
                       ) -> DriftSeries:
    """artifacts: ordered by received_at ascending, each with keys
    artifact_id, sha256, received_at, original_filename, source_type,
    source_location, detected_format. findings_by_artifact maps
    artifact_id -> finding dicts (as stored)."""
    points: List[DriftPoint] = []
    previous: Optional[Dict[str, Any]] = None
    totals = {"added": 0, "removed": 0, "changed": 0, "unchanged": 0}
    for artifact in artifacts:
        delta = None
        if previous is not None:
            report = compare_findings(
                base_artifact_id=previous["artifact_id"],
                base_sha256=previous["sha256"],
                base_findings=findings_by_artifact.get(
                    previous["artifact_id"], []),
                against_artifact_id=artifact["artifact_id"],
                against_sha256=artifact["sha256"],
                against_findings=findings_by_artifact.get(
                    artifact["artifact_id"], []))
            body = report.as_dict()
            delta = {"summary": body["summary"], "deltas": body["deltas"]}
            for key in totals:
                totals[key] += body["summary"].get(key, 0)
        points.append(DriftPoint(
            artifact_id=artifact["artifact_id"],
            sha256=artifact["sha256"],
            received_at=artifact.get("received_at"),
            original_filename=artifact.get("original_filename", ""),
            source_type=artifact.get("source_type", ""),
            source_location=artifact.get("source_location"),
            detected_format=artifact.get("detected_format", "unknown"),
            scan_count=artifact.get("scan_count", 0),
            delta_vs_previous=delta))
        previous = artifact

    limitations = [
        "each artifact is analyzed within its own coverage limits; the "
        "series never proves behavior on any version",
        "a series groups by subject name — the same name may be "
        "different software; grouping is metadata, not proof of common "
        "origin (§8)",
    ]
    return DriftSeries(subject=subject, points=points, summary=totals,
                       limitations=limitations)


@dataclass
class HistoryTimeline:
    artifact_id: str
    runs: List[Dict[str, Any]]
    finding_timeline: List[Dict[str, Any]]
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id, "runs": self.runs,
            "finding_timeline": self.finding_timeline,
            "limitations": self.limitations,
            "note": "the timeline shows when an INDICATOR was recorded "
                    "under which scanner and signature-database version "
                    "— a change between runs may be a new signature, not "
                    "a change in the artifact (the artifact is immutable)",
        }


def build_history(*, artifact_id: str, runs: List[Dict[str, Any]],
                  findings_by_run: Dict[str, List[Dict[str, Any]]]
                  ) -> HistoryTimeline:
    """runs: ordered scan runs for ONE immutable artifact, each with
    scan_id, scan_profile, scanner_version, signature_database_version,
    status, scanned_at. findings_by_run maps scan_id -> findings."""
    timeline: List[Dict[str, Any]] = []
    keys: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for run in runs:
        for finding in findings_by_run.get(run["scan_id"], []):
            key = (finding.get("finding_type", ""),
                   finding.get("algorithm", ""),
                   finding.get("variant", ""))
            entry = keys.get(key)
            if entry is None:
                entry = {
                    "finding_type": key[0], "algorithm": key[1],
                    "variant": key[2],
                    "first_seen": run.get("scanned_at"),
                    "first_scan": run["scan_id"],
                    "last_seen": run.get("scanned_at"),
                    "last_scan": run["scan_id"],
                    "observations": [],
                }
                keys[key] = entry
                timeline.append(entry)
            entry["last_seen"] = run.get("scanned_at")
            entry["last_scan"] = run["scan_id"]
            entry["observations"].append({
                "scan_id": run["scan_id"],
                "scanned_at": run.get("scanned_at"),
                "evidence_class": finding.get("evidence_class",
                                              finding.get("confidence")),
                "usage_status": finding.get("usage_status"),
                "signature_database_version":
                    run.get("signature_database_version"),
            })
    return HistoryTimeline(
        artifact_id=artifact_id, runs=runs, finding_timeline=timeline,
        limitations=[
            "the artifact is immutable — differences between runs are "
            "differences of scanner, profile or signature database",
        ])


def build_estate(*, findings_with_artifacts: List[Dict[str, Any]]
                 ) -> Dict[str, Any]:
    """Group findings by vendor/format/source for vendor intelligence.
    Grouping by metadata is not proof of common origin (§8)."""
    by_format: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    by_library: Dict[str, int] = {}
    by_algorithm: Dict[str, int] = {}
    quantum_vulnerable = 0
    pqc = 0
    for row in findings_with_artifacts:
        by_format[row.get("detected_format", "unknown")] = \
            by_format.get(row.get("detected_format", "unknown"), 0) + 1
        by_source[row.get("source_type", "unknown")] = \
            by_source.get(row.get("source_type", "unknown"), 0) + 1
        library = row.get("library") or "(unattributed)"
        by_library[library] = by_library.get(library, 0) + 1
        algorithm = row.get("algorithm") or "(non-algorithm finding)"
        by_algorithm[algorithm] = by_algorithm.get(algorithm, 0) + 1
        if row.get("quantum_vulnerable"):
            quantum_vulnerable += 1
        if row.get("pqc_family"):
            pqc += 1
    return {
        "findings_total": len(findings_with_artifacts),
        "by_format": dict(sorted(by_format.items())),
        "by_source_type": dict(sorted(by_source.items())),
        "by_library": dict(sorted(by_library.items())),
        "by_algorithm": dict(sorted(by_algorithm.items())),
        "quantum_vulnerable_findings": quantum_vulnerable,
        "pqc_family_findings": pqc,
        "note": "grouping is metadata-based vendor intelligence — "
                "shared names or libraries are not proof of common "
                "origin or common behavior (§8); counts are counts of "
                "RECORDED FINDINGS, not of running cryptography",
    }
