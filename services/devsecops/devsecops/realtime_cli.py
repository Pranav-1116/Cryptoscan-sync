"""Realtime DevSecOps crypto adapter.

Runs one or more existing bounded scanners from an operator-supplied JSON
configuration: binary/firmware, source dependency/SBOM, and container/image.
Each mode retains its real result and status; no empty result is treated as a
successful scan and no secret/key material is emitted by this adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from devsecops.binary_scan import scan_path


def _evidence(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _with_evidence(result: Any) -> Any:
    """Attach stable references to explicit records without retaining raw input."""
    if not isinstance(result, dict):
        return result
    # These are scanner-produced records that can contain explicit crypto
    # observations. Referencing each row lets the common CBOM projection retain
    # provenance even when it walks a nested package/binary result.
    for key in ("binaries", "libraries", "packages", "findings", "observations", "components"):
        rows = result.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and not row.get("evidence_reference"):
                row["evidence_reference"] = _evidence(row)
    result["evidence_reference"] = _evidence(result)
    return result


def _load_config(args: argparse.Namespace) -> dict[str, Any]:
    config_path = args.config
    # A .json target is treated as a mode configuration; all other positional
    # targets remain the backwards-compatible binary/firmware input.
    if not config_path and args.target and str(args.target).lower().endswith(".json"):
        candidate = Path(args.target)
        if candidate.is_file():
            config_path = str(candidate)
    if config_path:
        payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("DevSecOps config must be a JSON object")
        return payload
    if not args.target:
        raise ValueError("target or --config is required")
    return {"binary": args.target}


def _status_for(value: Any) -> str:
    state = str(value or "PASS").upper()
    return {"COMPLETE": "PASS", "PARTIAL": "DEGRADED", "REFUSED": "BLOCKED"}.get(state, state)


def _error_status(exc: Exception) -> str:
    if isinstance(exc, (ImportError, ModuleNotFoundError, FileNotFoundError)):
        return "UNAVAILABLE"
    if isinstance(exc, PermissionError):
        return "BLOCKED"
    if isinstance(exc, ValueError) and "not a directory" in str(exc).lower():
        return "UNAVAILABLE"
    return "FAIL"


def run(config: dict[str, Any]) -> dict[str, Any]:
    observations: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    modes: dict[str, str] = {}

    binary = config.get("binary") or config.get("firmware")
    if binary:
        try:
            result = _with_evidence(scan_path(str(binary)))
            status = _status_for(result.get("result_state"))
            observations["binary"] = result
            modes["binary"] = status
            findings.extend({"mode": "binary", "evidence_reference": _evidence(item), **item}
                            for item in result.get("findings") or [])
        except Exception as exc:  # noqa: BLE001
            modes["binary"] = _error_status(exc)
            errors.append({"mode": "binary", "error": str(exc)})
    else:
        modes["binary"] = "SKIP"

    source = config.get("source") or config.get("source_path")
    if source:
        try:
            from devsecops.sbom_scan import scan_source

            result = scan_source(
                str(source),
                include_vendored=bool(config.get("include_vendored", False)),
                use_lockfiles=bool(config.get("use_lockfiles", True)),
            )
            result = _with_evidence(result)
            observations["source"] = result
            modes["source"] = "PASS"
            findings.extend({"mode": "source", "evidence_reference": _evidence(item), **item}
                            for item in result.get("findings") or [])
        except Exception as exc:  # noqa: BLE001
            modes["source"] = _error_status(exc)
            errors.append({"mode": "source", "error": str(exc)})
    else:
        modes["source"] = "SKIP"

    container = config.get("container") or config.get("image")
    if container:
        try:
            from devsecops.sbom_scan import scan_container

            target = container.get("target") if isinstance(container, dict) else container
            as_image = bool(container.get("as_image", False)) if isinstance(container, dict) else False
            result = _with_evidence(scan_container(str(target), as_image=as_image))
            observations["container"] = result
            risk = result.get("risk_report") or {}
            modes["container"] = "DEGRADED" if risk.get("posture") in {"HIGH", "CRITICAL"} else "PASS"
            findings.extend({"mode": "container", "evidence_reference": _evidence(item), **item}
                            for item in result.get("findings") or [])
        except Exception as exc:  # noqa: BLE001
            modes["container"] = _error_status(exc)
            errors.append({"mode": "container", "error": str(exc)})
    else:
        modes["container"] = "SKIP"

    sbom = config.get("sbom")
    if sbom:
        try:
            path = Path(str(sbom))
            document = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("SBOM must be a JSON object")
            components = document.get("components") or document.get("packages") or []
            summary = {"path": str(path),
                       "format": document.get("bomFormat") or document.get("spdxVersion"),
                       "component_count": len(components) if isinstance(components, list) else 0}
            summary["evidence_reference"] = _evidence(summary)
            observations["sbom"] = summary
            modes["sbom"] = "PASS"
        except Exception as exc:  # noqa: BLE001
            modes["sbom"] = _error_status(exc)
            errors.append({"mode": "sbom", "error": str(exc)})
    else:
        modes["sbom"] = "SKIP"

    active = [status for status in modes.values() if status != "SKIP"]
    status = "FAIL" if active and all(item == "FAIL" for item in active) else \
        "DEGRADED" if errors or any(item in {"DEGRADED", "BLOCKED"} for item in active) else \
        "PASS" if active else "SKIP"
    return {"scanner": "devsecops", "scan_status": status, "modes": modes,
            "observations": observations, "findings": findings, "errors": errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run realtime DevSecOps crypto scans")
    parser.add_argument("target", nargs="?", help="binary/firmware path for the default binary mode")
    parser.add_argument("--config", help="JSON with binary/source/container/sbom modes")
    args = parser.parse_args(argv)
    try:
        result = run(_load_config(args))
    except Exception as exc:  # noqa: BLE001
        result = {"scanner": "devsecops", "scan_status": "PREFLIGHT", "modes": {},
                  "observations": {}, "findings": [], "errors": [{"mode": "preflight", "error": str(exc)}]}
    print(json.dumps(result, sort_keys=True, default=str))
    return 0 if result.get("scan_status") in {"PASS", "DEGRADED", "SKIP"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
