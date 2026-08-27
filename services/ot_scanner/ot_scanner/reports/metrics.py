"""Prometheus text exposition for OT passive scan results.

Families (``cryptoscan_ot_``): devices, findings, per-protocol findings,
security-level counts, unencrypted observations, devices with CVEs, and the
posture one-hot.  A passive scanner must also be honest in its metrics:
``cryptoscan_ot_packets_sent 0`` is emitted on every render.
"""

from __future__ import annotations

from typing import Any, Iterable

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_POSTURES = ("PASS", "WARN", "FAIL")


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


def render_prometheus(payload: dict[str, Any] | None) -> str:
    payload = payload or {}
    posture = payload.get("risk_report") if isinstance(payload.get("risk_report"), dict) else None
    telemetry = payload.get("ot_telemetry") if isinstance(payload.get("ot_telemetry"), dict) else None
    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else None
    out: list[str] = []
    if posture is None and telemetry is None and findings is None:
        return "# cryptoscan: no recognizable OT telemetry in payload\n"
    if posture:
        out += _family("cryptoscan_ot_devices", "OT devices observed", [(None, posture.get("device_count", 0))])
        out += _family("cryptoscan_ot_unencrypted_observations", "Unencrypted protocol observations", [(None, posture.get("unencrypted_observations", 0))])
        out += _family("cryptoscan_ot_weak_crypto_observations", "Observations using weak crypto", [(None, posture.get("weak_crypto_observations", 0))])
        out += _family("cryptoscan_ot_devices_with_cves", "Devices with matched CVEs", [(None, len(posture.get("devices_with_cves") or []))])
        for field, metric, label, help_text in (
            ("protocol_counts", "cryptoscan_ot_findings_by_protocol", "protocol", "Findings by OT protocol"),
            ("security_level_counts", "cryptoscan_ot_findings_by_security_level", "level", "Findings by security level"),
            ("issue_counts", "cryptoscan_ot_issues", "issue", "Compliance issues observed"),
        ):
            counts = posture.get(field) or {}
            if counts:
                out += _family(metric, help_text, [({label: key}, value) for key, value in sorted(counts.items())])
        active = str(posture.get("posture") or "PASS")
        out += _family(
            "cryptoscan_ot_posture",
            "OT posture (1 = active)",
            [({"posture": name}, 1 if name == active else 0) for name in _POSTURES],
        )
    elif findings is not None:
        out += _family("cryptoscan_ot_devices", "OT devices observed", [(None, payload.get("device_count", 0))])
        out += _family("cryptoscan_ot_unencrypted_observations", "Unencrypted protocol observations", [(None, payload.get("unencrypted", 0))])
    out += _family("cryptoscan_ot_packets_sent", "Packets sent by the passive OT scanner (always 0)", [(None, 0)])
    if telemetry:
        active = str(telemetry.get("status") or "SKIPPED")
        out += _family(
            "cryptoscan_ot_scan_verdict",
            "OT scan verdict (1 = active)",
            [({"verdict": name}, 1 if name == active else 0) for name in ("OK", "FAILED", "SKIPPED")],
        )
        if telemetry.get("records_analyzed") is not None:
            out += _family("cryptoscan_ot_records_analyzed", "Records parsed from captures/logs", [(None, telemetry["records_analyzed"])])
    if not out:
        out.append("# cryptoscan: no recognizable OT telemetry in payload")
    return "\n".join(out) + "\n"
