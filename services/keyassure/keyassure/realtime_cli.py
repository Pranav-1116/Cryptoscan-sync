"""Realtime key-assurance adapter for the common live-scan pipeline.

The adapter exposes the existing deterministic key-assurance scanners as one
structured, bounded pass. Every configured mode is operator supplied:
TLS/certificate audits, CT monitoring, and source code rules. A missing mode
is reported as SKIP; a failed mode is never converted to an empty success.
No certificate/private-key material is returned.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _evidence(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _error_status(exc: Exception) -> str:
    """Keep dependency, access, and scanner failures distinct at mode level."""
    if isinstance(exc, (ImportError, ModuleNotFoundError, FileNotFoundError)):
        return "UNAVAILABLE"
    if isinstance(exc, PermissionError):
        return "BLOCKED"
    return "FAIL"


def _tls_configs(config: dict[str, Any]) -> list[dict[str, Any]]:
    rows = config.get("tls") or config.get("endpoints") or []
    if isinstance(rows, dict):
        rows = [rows]
    if not rows and config.get("host"):
        rows = [config]
    return [dict(row) for row in rows if isinstance(row, dict)]


def _domains(config: dict[str, Any]) -> list[dict[str, Any]]:
    rows = config.get("ct") or config.get("domains") or []
    if isinstance(rows, str):
        rows = [{"domain": rows}]
    elif isinstance(rows, dict):
        rows = [rows]
    return [dict(row) if isinstance(row, dict) else {"domain": str(row)} for row in rows]


def run(config: dict[str, Any]) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    modes: dict[str, str] = {}

    tls_rows = _tls_configs(config)
    if tls_rows:
        from keyassure.tls_audit import audit_tls_endpoint

        for row in tls_rows:
            host = str(row.get("host") or "").strip()
            if not host:
                errors.append({"mode": "tls", "error": "TLS entry requires host"})
                continue
            try:
                result = audit_tls_endpoint(
                    host,
                    int(row.get("port") or 443),
                    sni=row.get("sni"),
                    timeout=float(row.get("timeout") or config.get("timeout") or 6.0),
                )
                result["evidence_reference"] = _evidence(result)
                for collection_name in ("protocols", "cipher_probes"):
                    for item in result.get(collection_name) or []:
                        if isinstance(item, dict):
                            item["evidence_reference"] = _evidence(item)
                if isinstance(result.get("certificate"), dict):
                    result["certificate"]["evidence_reference"] = _evidence(result["certificate"])
                observations.append({"mode": "tls", **result})
                findings.extend({"source": "keyassure", "mode": "tls",
                                 "evidence_reference": result["evidence_reference"], **item}
                                for item in result.get("findings") or [])
            except Exception as exc:  # noqa: BLE001 — preserve mode failure
                errors.append({"mode": "tls", "status": _error_status(exc),
                               "error": f"{host}: {exc}"})
        tls_errors = [item for item in errors if item["mode"] == "tls"]
        modes["tls"] = ("DEGRADED" if tls_errors and any(item.get("mode") == "tls" for item in observations)
                         else tls_errors[0].get("status", "FAIL") if tls_errors else "PASS")
    else:
        modes["tls"] = "SKIP"

    domain_rows = _domains(config)
    if domain_rows:
        from keyassure.ct_monitor import monitor_domain

        for row in domain_rows:
            domain = str(row.get("domain") or "").strip()
            if not domain:
                errors.append({"mode": "ct", "error": "CT entry requires domain"})
                continue
            try:
                report = monitor_domain(
                    domain,
                    known_fingerprints=row.get("known_fingerprints") or [],
                    known_serials=row.get("known_serials") or [],
                    allowed_issuers=row.get("allowed_issuers") or config.get("allowed_issuers") or [],
                )
                for cert in report.observed:
                    cert["evidence_reference"] = _evidence(cert)
                    observations.append({"mode": "ct", "domain": domain, "certificate": cert})
                findings.extend({"source": "keyassure", "mode": "ct",
                                 "evidence_reference": item.get("evidence_reference"),
                                 "severity": "HIGH" if item in report.rogue_certs else "MEDIUM",
                                 "kind": "CT_CERTIFICATE", **item}
                                for item in (report.new_certs + report.rogue_certs))
            except Exception as exc:  # noqa: BLE001
                errors.append({"mode": "ct", "status": _error_status(exc),
                               "error": f"{domain}: {exc}"})
        ct_errors = [item for item in errors if item["mode"] == "ct"]
        modes["ct"] = ("DEGRADED" if ct_errors and any(item.get("mode") == "ct" for item in observations)
                        else ct_errors[0].get("status", "FAIL") if ct_errors else "PASS")
    else:
        modes["ct"] = "SKIP"

    code_paths = config.get("code") or config.get("code_paths") or []
    if isinstance(code_paths, str):
        code_paths = [code_paths]
    if code_paths:
        from keyassure.code_rules import scan_paths

        try:
            code_result = scan_paths([str(path) for path in code_paths])
            code_algorithms = {
                "WP-MD5": "MD5", "WP-SHA1": "SHA-1", "WP-DES": "DES",
                "WP-ECB": "ECB", "WP-RSA-SHORT": "RSA", "WP-EC-SHORT": "EC",
                "WP-STATIC-IV": "IV",
            }
            for finding in code_result.get("findings") or []:
                finding = dict(finding)
                if finding.get("rule_id") in code_algorithms:
                    finding["algorithm"] = code_algorithms[finding["rule_id"]]
                finding["evidence_reference"] = _evidence(finding)
                findings.append({"source": "keyassure", "mode": "code", **finding})
            observations.append({"mode": "code", **{key: value for key, value in code_result.items()
                                                       if key != "findings"}})
            modes["code"] = "PASS"
        except Exception as exc:  # noqa: BLE001
            status = _error_status(exc)
            errors.append({"mode": "code", "status": status, "error": str(exc)})
            modes["code"] = status
    else:
        modes["code"] = "SKIP"

    active = [status for status in modes.values() if status != "SKIP"]
    status = "FAIL" if active and all(item == "FAIL" for item in active) else \
        "DEGRADED" if errors or any(item == "FAIL" for item in active) else \
        "PASS" if active else "SKIP"
    return {
        "scanner": "keyassure",
        "scan_status": status,
        "modes": modes,
        "observations": observations,
        "findings": findings,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run key-assurance TLS, CT, and code scans")
    parser.add_argument("--config", required=True, help="JSON with tls/endpoints, ct/domains, and/or code paths")
    args = parser.parse_args(argv)
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("key-assurance config must be a JSON object")
        result = run(config)
    except Exception as exc:  # noqa: BLE001 — preserve an honest failed scan
        result = {"scanner": "keyassure", "scan_status": "PREFLIGHT", "modes": {},
                  "observations": [], "findings": [], "errors": [{"mode": "preflight", "error": str(exc)}]}
    print(json.dumps(result, sort_keys=True, default=str))
    return 0 if result.get("scan_status") in {"PASS", "DEGRADED", "SKIP"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
