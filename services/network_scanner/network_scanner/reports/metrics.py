"""Prometheus text exposition for scan telemetry, SSH findings, and drift.

Everything the deep probes measure already lands in honest telemetry dicts;
this module renders them in the Prometheus text format (version 0.0.4) so a
scraper can consume them directly:

* TLS scan results (``probe_telemetry`` + ``certificates``) ->
  per-status probe outcomes, weak-counter gauges, verdict one-hot, and
  certificate expiry aggregates (plus the fleet minimum days-to-expiry)
* SSH scan results (``ssh_probe_telemetry``) -> probe outcomes, weak host
  keys, host-key changes, weak algorithm offers
* drift reports (``verdict`` + ``changes``) -> change counts by severity and
  the verdict as a one-hot gauge

Detection is by shape, so the same renderer accepts a full scan result, a
bare telemetry dict, or a drift report.  Label values are escaped per the
spec (backslash, quote, newline); metric names use the ``cryptoscan_``
prefix; unknown payloads still render as a valid (comment-only) document —
a scrape must never 500 because a payload was unfamiliar.
"""

from __future__ import annotations

from typing import Any, Iterable

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_VERDICTS = ("OK", "PARTIAL", "FAILED", "SKIPPED")
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _escape_label(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _format_sample(name: str, labels: dict[str, Any] | None, value: Any) -> str:
    if labels:
        joined = ",".join(f'{key}="{_escape_label(val)}"' for key, val in labels.items())
        return f"{name}{{{joined}}} {value}"
    return f"{name} {value}"


def _family(name: str, help_text: str, samples: Iterable[tuple[dict[str, Any] | None, Any]], metric_type: str = "gauge") -> list[str]:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"]
    lines.extend(_format_sample(name, labels, value) for labels, value in samples)
    return lines


def _tls_telemetry_from(payload: dict[str, Any]) -> dict[str, Any] | None:
    telemetry = payload.get("probe_telemetry")
    if isinstance(telemetry, dict):
        return telemetry
    if "statuses" in payload and "probed" in payload:
        return payload  # a bare telemetry dict
    return None


def _ssh_telemetry_from(payload: dict[str, Any]) -> dict[str, Any] | None:
    telemetry = payload.get("ssh_probe_telemetry")
    if isinstance(telemetry, dict):
        return telemetry
    if "ssh_weak_host_keys" in payload and "probed" in payload:
        return payload
    return None


def _render_tls(telemetry: dict[str, Any], out: list[str]) -> None:
    out += _family(
        "cryptoscan_network_scan_probed",
        "Endpoints probed in the last TLS scan",
        [(None, telemetry.get("probed", 0))],
    )
    out += _family(
        "cryptoscan_network_scan_ok",
        "Endpoints whose last probe returned OK",
        [(None, telemetry.get("ok", 0))],
    )
    statuses = telemetry.get("statuses") or {}
    out += _family(
        "cryptoscan_network_probe_status",
        "Probe outcomes by status",
        [({"status": status}, count) for status, count in sorted(statuses.items())],
    )
    verdict = str(telemetry.get("status") or "SKIPPED")
    out += _family(
        "cryptoscan_network_scan_verdict",
        "Scan verdict (1 = the active verdict)",
        [({"verdict": name}, 1 if name == verdict else 0) for name in _VERDICTS],
    )
    for key, help_text in (
        ("weak_tls_versions", "Endpoints accepting weak TLS versions"),
        ("weak_cipher_suites", "Endpoints accepting weak or disallowed ciphers"),
        ("insecure_renegotiation", "Endpoints without RFC 5746 secure renegotiation"),
        ("client_renegotiation_accepted", "Endpoints accepting client-initiated renegotiation"),
        ("chain_order_issues", "Endpoints with sent-chain order/link problems"),
        ("revoked_certificates", "Endpoints presenting revoked certificates"),
    ):
        if key in telemetry:
            out += _family(f"cryptoscan_network_{key}", help_text, [(None, telemetry[key])])


def _render_ssh(telemetry: dict[str, Any], out: list[str]) -> None:
    out += _family(
        "cryptoscan_ssh_scan_probed",
        "SSH hosts probed in the last scan",
        [(None, telemetry.get("probed", 0))],
    )
    out += _family(
        "cryptoscan_ssh_scan_ok",
        "SSH hosts whose last probe returned OK",
        [(None, telemetry.get("ok", 0))],
    )
    statuses = telemetry.get("statuses") or {}
    out += _family(
        "cryptoscan_ssh_probe_status",
        "SSH probe outcomes by status",
        [({"status": status}, count) for status, count in sorted(statuses.items())],
    )
    verdict = str(telemetry.get("status") or "SKIPPED")
    out += _family(
        "cryptoscan_ssh_scan_verdict",
        "SSH scan verdict (1 = the active verdict)",
        [({"verdict": name}, 1 if name == verdict else 0) for name in _VERDICTS],
    )
    for key, help_text in (
        ("ssh_weak_host_keys", "SSH hosts with weak host keys"),
        ("ssh_host_key_changes", "SSH hosts whose host key changed (TOFU)"),
        ("ssh_weak_algorithm_offers", "SSH hosts offering weak ciphers/MACs/KEX"),
    ):
        if key in telemetry:
            out += _family(f"cryptoscan_{key}", help_text, [(None, telemetry[key])])


def _cert_expiry_status(days: Any) -> str:
    try:
        remaining = int(days)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if remaining < 0:
        return "EXPIRED"
    if remaining <= 7:
        return "EXPIRING_7D"
    if remaining <= 30:
        return "EXPIRING_30D"
    return "VALID"


def _render_certificates(certificates: list[dict[str, Any]], out: list[str]) -> None:
    counts: dict[str, int] = {}
    known_days: list[int] = []
    for cert in certificates:
        status = _cert_expiry_status(cert.get("days_until_expiry"))
        counts[status] = counts.get(status, 0) + 1
        try:
            known_days.append(int(cert["days_until_expiry"]))
        except (TypeError, ValueError, KeyError):
            continue
    out += _family(
        "cryptoscan_network_cert_expiry_status",
        "Observed certificates by expiry status",
        [({"status": name}, counts.get(name, 0)) for name in ("VALID", "EXPIRING_30D", "EXPIRING_7D", "EXPIRED", "UNKNOWN")],
    )
    if known_days:
        out += _family(
            "cryptoscan_network_cert_min_days_until_expiry",
            "Fleet minimum days until certificate expiry",
            [(None, min(known_days))],
        )


def _render_drift(report: dict[str, Any], out: list[str]) -> None:
    changes = report.get("changes") or []
    counts = report.get("severity_counts") or {}
    total = report.get("change_count", len(changes))
    out += _family(
        "cryptoscan_drift_change_total",
        "Changes between the previous and current scan",
        [(None, total)],
    )
    out += _family(
        "cryptoscan_drift_changes",
        "Drift changes by severity",
        [({"severity": severity}, counts.get(severity, 0)) for severity in _SEVERITIES],
    )
    verdict = str(report.get("verdict") or "UNCHANGED")
    out += _family(
        "cryptoscan_drift_verdict",
        "Drift verdict (1 = the active verdict)",
        [({"verdict": name}, 1 if name == verdict else 0) for name in ("REGRESSED", "IMPROVED", "MIXED", "UNCHANGED")],
    )


def render_prometheus(payload: dict[str, Any] | None) -> str:
    """Render any combination of scan/SSH/drift payloads to text format."""
    out: list[str] = []
    payload = payload or {}
    tls = _tls_telemetry_from(payload)
    ssh = _ssh_telemetry_from(payload)
    drift = payload.get("verdict") in {"REGRESSED", "IMPROVED", "MIXED", "UNCHANGED"} and "changes" in payload
    certificates = payload.get("certificates")
    if tls:
        _render_tls(tls, out)
    if isinstance(certificates, list) and certificates:
        _render_certificates(certificates, out)
    if ssh:
        _render_ssh(ssh, out)
    if drift:
        _render_drift(payload, out)
    if not out:
        out.append("# cryptoscan: no recognizable telemetry in payload")
    return "\n".join(out) + "\n"
