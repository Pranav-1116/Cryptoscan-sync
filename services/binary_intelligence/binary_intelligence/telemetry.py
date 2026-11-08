"""Binary-engine telemetry into the Performance Intelligence store
(§13 measurement list, §17 Phase 6 integration).

Measurements of the SCANNER — never of production traffic. Counts are
counts of RECORDED findings, never of running cryptography. Coverage is
reported as coverage and never presented as confidence. Units come from
the shared taxonomy — a metric outside the taxonomy is refused, never
ingested with a guessed unit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from binary_intelligence.detection import SCANNER_NAME
from shared_models.performance_collectors import _metric, _metric_id
from shared_models.performance_metrics import QualityStatus

SOURCE_ID = "cryptoscan-binary-intelligence"


def scan_metrics(*, tenant_id: str, scan_id: str, artifact_id: str,
                 result: Any, observed_at: Optional[datetime] = None
                 ) -> List[Any]:
    """Turn one ScanResult into PerformanceMetric rows. Every metric
    carries the scan_id as evidence_id and the scan profile as a label —
    provenance on every row."""
    observed = observed_at or datetime.now(timezone.utc)
    labels_base = {
        "scan_id": scan_id[:24],
        "profile": result.profile,
        "format": result.identity.detected_format.value,
    }
    total = (result.timings or {}).get("total_seconds")
    coverage_pct = None
    if result.coverage.total_bytes:
        coverage_pct = round(
            100.0 * result.coverage.bytes_inspected
            / result.coverage.total_bytes, 4)
    rows = []
    for family, value, extra_labels in (
        ("binary.scan.duration_seconds", total, {}),
        ("binary.scan.findings_recorded", float(len(result.findings)), {}),
        ("binary.scan.evidence_items",
         float(sum(len(f.evidence) for f in result.findings)), {}),
        ("binary.scan.coverage_pct", coverage_pct, {}),
    ):
        labels = {**labels_base, **extra_labels}
        row = _metric(
            metric_name=family,
            value=value,
            quality=(QualityStatus.VALID if value is not None
                     else QualityStatus.MISSING),
            unit=None,
            asset_id=artifact_id,
            tenant_id=tenant_id,
            source_id=SOURCE_ID,
            observed_at=observed,
            metric_id=_metric_id(SOURCE_ID, family, labels, observed),
            labels=labels)
        row.evidence_id = scan_id    # provenance on every row
        rows.append(row)
    return rows


def scan_cryptolog_event(*, tenant_id: str, scan_id: str,
                         result: Any) -> Dict[str, Any]:
    """One CryptoLog event per scan (§17 Phase 6 integration).

    The event is a NOTIFICATION with references — CryptoLog is not a
    second evidence store (§ of the CryptoLog spec): it carries counts,
    identifiers and evidence REFERENCES, never finding contents. Its
    evidence level is STATIC — static analysis never claims runtime
    usage. Severity is COMPUTED from the result, never named freely."""
    from shared_models.cryptolog_events import make_event

    private_events = len(result.private_key_events)
    quantum_vulnerable = sum(1 for f in result.findings
                             if f.quantum_vulnerable)
    pqc = sum(1 for f in result.findings if f.pqc_family)
    if private_events:
        severity = "MEDIUM"      # computed: a private-key detection event
    elif quantum_vulnerable:
        severity = "LOW"         # computed: exposure indicators present
    else:
        severity = "INFO"
    evidence_ids = [scan_id] + [f.finding_id for f in result.findings][:16]
    return make_event(
        event_type="BINARY_CRYPTO_DISCOVERED",
        category="CRYPTO_DRIFT",
        logging_kind="ACTIVITY",
        tenant_id=tenant_id,
        severity=severity,
        asset_id=result.identity.artifact_id,
        source={
            "source_type": "CONFIGURATION_OBSERVATION",
            "scanner_version": SCANNER_NAME,
            "scan_profile": result.profile,
        },
        cryptographic_context={
            "evidence_level": "STATIC",
            "detected_format": result.identity.detected_format.value,
            "findings_recorded": len(result.findings),
            "quantum_vulnerable_indicators": quantum_vulnerable,
            "pqc_indicators": pqc,
            "private_key_detection_events": private_events,
            "note": "static analysis only — presence is not usage; a "
                    "static scan never confirms runtime behavior",
        },
        observed_at=datetime.now(timezone.utc).isoformat(),
        evidence_ids=evidence_ids,
        deduplication_key=f"binary-scan:{scan_id}",
        attributes={
            "artifact_sha256": result.identity.sha256,
            "coverage_bytes_inspected": result.coverage.bytes_inspected,
            "coverage_is_not_confidence": True,
        })
