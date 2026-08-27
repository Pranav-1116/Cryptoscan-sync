"""Prometheus text exposition for container scan results and drift.

Families (all ``cryptoscan_container_`` prefixed except drift, which mirrors
the network scanner's ``cryptoscan_drift_`` naming):

* scan counters — packages / libraries / binaries / vulnerabilities /
  secrets / files_scanned
* label breakdowns — packages_by_manager{manager}, binaries_by_type{type},
  secrets_by_kind{kind}, cves{severity}
* one-hots — scan_telemetry verdict and risk posture
* drift — change_total, changes{severity}, verdict one-hot

Rendering follows the same rules as the network exporter: escaped label
values, HELP/TYPE lines, trailing newline, and a valid comment-only document
for unrecognized payloads.
"""

from __future__ import annotations

from typing import Any, Iterable

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_VERDICTS = ("OK", "PARTIAL", "FAILED", "SKIPPED")
_POSTURES = ("PASS", "WARN", "FAIL")
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _escape(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _sample(name: str, labels: dict[str, Any] | None, value: Any) -> str:
    if labels:
        joined = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
        return f"{name}{{{joined}}} {value}"
    return f"{name} {value}"


def _family(name: str, help_text: str, samples: Iterable[tuple[dict[str, Any] | None, Any]]) -> list[str]:
    return [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"] + [
        _sample(name, labels, value) for labels, value in samples
    ]


def _telemetry_from(payload: dict[str, Any]) -> dict[str, Any] | None:
    telemetry = payload.get("scan_telemetry")
    if isinstance(telemetry, dict):
        return telemetry
    if "packages_by_manager" in payload or "files_scanned" in payload:
        return payload
    return None


def render_prometheus(payload: dict[str, Any] | None) -> str:
    payload = payload or {}
    out: list[str] = []
    telemetry = _telemetry_from(payload)
    risk = payload.get("risk_report") if isinstance(payload.get("risk_report"), dict) else None

    if telemetry:
        out += _family("cryptoscan_container_packages", "Packages found in the last scan", [(None, telemetry.get("packages", 0))])
        out += _family("cryptoscan_container_libraries", "Crypto libraries fingerprinted", [(None, telemetry.get("libraries_fingerprinted", 0))])
        out += _family("cryptoscan_container_binaries", "Crypto binaries found", [(None, telemetry.get("binaries", 0))])
        out += _family("cryptoscan_container_vulnerabilities", "CVE matches in the last scan", [(None, telemetry.get("vulnerabilities", 0))])
        out += _family("cryptoscan_container_secrets", "Hardcoded secrets found", [(None, telemetry.get("secrets", 0))])
        if telemetry.get("files_scanned") is not None:
            out += _family("cryptoscan_container_files_scanned", "Files walked during the scan", [(None, telemetry["files_scanned"])])
        if telemetry.get("fingerprint_hit_rate") is not None:
            out += _family("cryptoscan_container_fingerprint_hit_rate", "Binary fingerprint hit rate (0-1)", [(None, telemetry["fingerprint_hit_rate"])])
        for field, metric, help_text in (
            ("packages_by_manager", "cryptoscan_container_packages_by_manager", "Packages by package manager"),
            ("binaries_by_type", "cryptoscan_container_binaries_by_type", "Crypto binaries by type"),
            ("secrets_by_kind", "cryptoscan_container_secrets_by_kind", "Hardcoded secrets by kind"),
        ):
            counts = telemetry.get(field) or {}
            if counts:
                out += _family(metric, help_text, [({"kind" if field == "secrets_by_kind" else "manager" if field == "packages_by_manager" else "type": k}, v) for k, v in sorted(counts.items())])
        verdict = str(telemetry.get("status") or "SKIPPED")
        out += _family(
            "cryptoscan_container_scan_verdict",
            "Scan coverage verdict (1 = active)",
            [({"verdict": name}, 1 if name == verdict else 0) for name in _VERDICTS],
        )
        cves = payload.get("risk_report", {}).get("cve_severity_counts") if risk else None
        if isinstance(cves, dict):
            out += _family(
                "cryptoscan_container_cves",
                "CVE matches by severity",
                [({"severity": sev}, cves.get(sev, 0)) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")],
            )

    if risk:
        posture = str(risk.get("posture") or "PASS")
        out += _family(
            "cryptoscan_container_posture",
            "Container crypto posture (1 = active)",
            [({"posture": name}, 1 if name == posture else 0) for name in _POSTURES],
        )

    if payload.get("verdict") in {"REGRESSED", "IMPROVED", "MIXED", "UNCHANGED"} and "changes" in payload:
        counts = payload.get("severity_counts") or {}
        total = payload.get("change_count", len(payload.get("changes") or []))
        out += _family("cryptoscan_drift_change_total", "Container scan changes since the previous run", [(None, total)])
        out += _family(
            "cryptoscan_drift_changes",
            "Container drift changes by severity",
            [({"severity": sev}, counts.get(sev, 0)) for sev in _SEVERITIES],
        )
        verdict = str(payload.get("verdict"))
        out += _family(
            "cryptoscan_drift_verdict",
            "Container drift verdict (1 = active)",
            [({"verdict": name}, 1 if name == verdict else 0) for name in ("REGRESSED", "IMPROVED", "MIXED", "UNCHANGED")],
        )

    if not out:
        out.append("# cryptoscan: no recognizable container telemetry in payload")
    return "\n".join(out) + "\n"
