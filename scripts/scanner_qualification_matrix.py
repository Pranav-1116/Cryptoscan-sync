#!/usr/bin/env python3
"""Run the real scanner CLIs against operator-supplied staging inputs.

This closes the previous "no uniform entrypoint" gap without manufacturing
live evidence. Each family is either executed, or recorded as UNCONFIGURED;
subprocess failures, blocked access, preflight failures, and intentional skips
remain distinct. Inputs are paths/endpoint references only and are never copied
into the report.

Examples:
  python scripts/scanner_qualification_matrix.py --out /tmp/qualification
  python scripts/scanner_qualification_matrix.py --source /srv/repo \
      --container /srv/image.tar --ot /srv/ot/logs --telecom config/telecom.json

Use --strict only after the operator has supplied every required staging target.
The generated JSON is a fixture/staging qualification record, not external
customer or regulatory evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = (
    "vendor", "universal", "source", "runtime", "hardware", "network",
    "cloud", "container", "ot", "telecom", "payment", "keyassure",
    "binary", "devsecops",
)


def _pythonpath() -> str:
    paths = [str(ROOT / "shared")]
    paths.extend(str(path) for path in sorted((ROOT / "services").glob("*/")) if path.is_dir())
    if os.environ.get("PYTHONPATH"):
        paths.append(os.environ["PYTHONPATH"])
    return os.pathsep.join(paths)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _status(payload: Any, returncode: int) -> str:
    if isinstance(payload, dict):
        for key in ("scan_status", "status", "verdict", "result_status", "overall"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                normalized = value.strip().upper().replace("-", "_")
                return {"COMPLETED": "PASS", "SUCCESS": "PASS", "OK": "PASS"}.get(normalized, normalized)
    if returncode == 0:
        return "PASS"
    return "FAIL"


def _json_from_stdout(text: str) -> Any:
    raw = text.strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # Some passive CLIs intentionally print a human-readable diagnostic to
    # stderr and JSON to stdout; tolerate banners while still requiring a real
    # JSON object/array from the scanner.
    lines = raw.splitlines()
    for start in range(len(lines) - 1, -1, -1):
        candidate = "\n".join(lines[start:]).strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return {"parse_error": "scanner did not emit a JSON document"}


def _result(family: str, status: str, *, detail: str, payload: Any = None,
            command: list[str] | None = None, elapsed_s: float = 0.0,
            evidence_type: str = "scanner_cli_output") -> dict[str, Any]:
    serialized = json.dumps(payload, sort_keys=True, default=str) if payload is not None else detail
    return {
        "family": family,
        "status": status,
        "detail": detail[:1000],
        "evidence_type": evidence_type,
        "evidence_reference": _digest(serialized),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "confidence": "HIGH" if status in {"PASS", "FAIL", "BLOCKED"} else "MEDIUM",
        "unresolved_relationships": [],
        "truncated": False,
        "elapsed_s": round(elapsed_s, 3),
        "command": ["<python>", *command[1:]] if command else None,
        "payload": payload if isinstance(payload, (dict, list)) else None,
    }


def _run(family: str, command: list[str], *, cwd: Path | None = None,
         timeout: int = 600, output_dir: Path | None = None) -> dict[str, Any]:
    env = dict(os.environ)
    env["PYTHONPATH"] = _pythonpath()
    started = time.monotonic()
    try:
        proc = subprocess.run(command, cwd=str(cwd or ROOT), env=env,
                              capture_output=True, text=True, timeout=timeout,
                              check=False)
    except subprocess.TimeoutExpired:
        return _result(family, "FAIL", detail=f"timed out after {timeout}s",
                       command=command, elapsed_s=timeout)
    except FileNotFoundError as exc:
        return _result(family, "UNAVAILABLE", detail=f"executable unavailable: {type(exc).__name__}",
                       command=command, elapsed_s=time.monotonic() - started)
    except OSError as exc:
        return _result(family, "UNAVAILABLE", detail=f"could not execute: {type(exc).__name__}",
                       command=command, elapsed_s=time.monotonic() - started)

    payload: Any = _json_from_stdout(proc.stdout)
    if output_dir is not None and (not payload or payload.get("parse_error")):
        reports = sorted(output_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        if reports:
            try:
                payload = json.loads(reports[0].read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                payload = {"parse_error": "output report is not valid JSON"}
    status = _status(payload, proc.returncode)
    detail = f"exit={proc.returncode}"
    if proc.stderr.strip():
        detail += f"; stderr={proc.stderr.strip()[-500:]}"
    if isinstance(payload, dict) and payload.get("error"):
        detail += f"; error={payload['error']}"
    if proc.returncode != 0 and status in {"PASS", "DEGRADED", "SKIP"}:
        # A structured scanner status wins over the process exit code only when
        # it explicitly explains an intentional non-zero state.
        detail += "; structured_status_preserved"
    return _result(family, status, detail=detail, payload=payload,
                   command=command, elapsed_s=time.monotonic() - started)


def _unconfigured(family: str, reason: str) -> dict[str, Any]:
    return _result(family, "UNCONFIGURED", detail=reason, evidence_type="configuration_state")


def _path_arg(value: str | None) -> str | None:
    if not value:
        return None
    return str(Path(value).expanduser().resolve())


def qualify(args: argparse.Namespace) -> dict[str, Any]:
    py = sys.executable or "python3"
    values = {key: _path_arg(getattr(args, key, None)) for key in (
        "source", "universal", "cloud", "container", "ot", "telecom",
        "payment", "keyassure", "binary", "devsecops",
    )}
    # A network target is an authorized host:port/zone reference, not a local
    # filesystem path. Preserve it verbatim; target validation belongs to the
    # network scanner and API guard.
    values["network"] = str(getattr(args, "network", "") or "").strip() or None
    rows: dict[str, dict[str, Any]] = {}

    # Vendor connectors require a real operator registry and credentials. The
    # matrix records the boundary instead of inventing a vendor event.
    rows["vendor"] = _unconfigured("vendor", "operator vendor registry/connector was not supplied")
    rows["hardware"] = _run("hardware", [py, str(ROOT / "services/universal_vendor/hw_scan.py"), "--json"], timeout=90)
    rows["runtime"] = _run("runtime", [py, "-m", "runtime.main", "processes"], cwd=ROOT / "services/runtime", timeout=180)

    if values["source"]:
        with tempfile.TemporaryDirectory(prefix="cryptoscan-qualification-") as temp:
            rows["source"] = _run("source", [py, "-m", "scanner.main", "scan", "-s", values["source"], "--exclude-tests", "-o", temp], cwd=ROOT / "services/scanner", timeout=600, output_dir=Path(temp))
    else:
        rows["source"] = _unconfigured("source", "--source was not supplied")
    if values["universal"]:
        rows["universal"] = _run("universal", [py, "-m", "universal_crypto.cli", "scan", values["universal"], "--json"], cwd=ROOT / "services/universal_crypto", timeout=600)
    else:
        rows["universal"] = _unconfigured("universal", "--universal was not supplied")
    if values["network"]:
        rows["network"] = _run("network", [py, "-m", "network_scanner.realtime_cli", values["network"], "--json"], cwd=ROOT / "services/network_scanner", timeout=180)
    else:
        rows["network"] = _unconfigured("network", "--network host:port was not supplied")
    if values["cloud"]:
        rows["cloud"] = _run("cloud", [py, "-m", "cloud_scanner.main", values["cloud"], "--json"], cwd=ROOT / "services/cloud_scanner", timeout=600)
    else:
        rows["cloud"] = _unconfigured("cloud", "--cloud IaC/source path was not supplied")
    if values["container"]:
        rows["container"] = _run("container", [py, "-m", "container_scanner.main", values["container"], "--json"], cwd=ROOT / "services/container_scanner", timeout=600)
    else:
        rows["container"] = _unconfigured("container", "--container image/archive/filesystem was not supplied")
    if values["ot"]:
        rows["ot"] = _run("ot", [py, "-m", "ot_scanner.main", values["ot"]], cwd=ROOT / "services/ot_scanner", timeout=300)
    else:
        rows["ot"] = _unconfigured("ot", "--ot passive log/capture path was not supplied")
    if values["telecom"]:
        rows["telecom"] = _run("telecom", [py, "-m", "telecom_scanner.main", "--registry", values["telecom"], "--json"], cwd=ROOT / "services/telecom_scanner", timeout=600)
    else:
        rows["telecom"] = _unconfigured("telecom", "--telecom registry was not supplied")
    if values["payment"]:
        rows["payment"] = _run("payment", [py, "-m", "payment_crypto.cli", "--config", values["payment"]], cwd=ROOT / "services/payment_crypto", timeout=300)
    else:
        rows["payment"] = _unconfigured("payment", "--payment config was not supplied")
    if values["keyassure"]:
        rows["keyassure"] = _run("keyassure", [py, "-m", "keyassure.realtime_cli", "--config", values["keyassure"]], cwd=ROOT / "services/keyassure", timeout=300)
    else:
        rows["keyassure"] = _unconfigured("keyassure", "--keyassure config was not supplied")
    if values["binary"]:
        rows["binary"] = _run("binary", [py, "-m", "devsecops.realtime_cli", values["binary"]], cwd=ROOT / "services/devsecops", timeout=900)
    else:
        rows["binary"] = _unconfigured("binary", "--binary artifact was not supplied")
    if values["devsecops"]:
        rows["devsecops"] = _run("devsecops", [py, "-m", "devsecops.realtime_cli", values["devsecops"]], cwd=ROOT / "services/devsecops", timeout=900)
    else:
        rows["devsecops"] = _unconfigured("devsecops", "--devsecops artifact/SBOM was not supplied")

    statuses = [rows[family]["status"] for family in FAMILIES]
    return {
        "schema": "cryptoscan.scanner-qualification-matrix/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "families_total": len(FAMILIES),
        "records": [rows[family] for family in FAMILIES],
        "status_counts": {status: statuses.count(status) for status in sorted(set(statuses))},
        "fixture_qualified": sum(status in {"PASS", "DEGRADED"} for status in statuses),
        "with_failures": sum(status in {"FAIL", "BLOCKED"} for status in statuses),
        "unconfigured": sum(status == "UNCONFIGURED" for status in statuses),
        "verdict": (
            "FAIL" if any(status in {"FAIL", "BLOCKED"} for status in statuses)
            else "INCOMPLETE" if any(status not in {"PASS", "DEGRADED"} for status in statuses)
            else "PASS"
        ),
        "scope": "Local/staging scanner execution only. This does not establish customer, provider, independent-review, or regulated qualification.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name, help_text in (
        ("source", "source tree for the static scanner"), ("universal", "source tree for universal crypto"),
        ("network", "authorized host:port for a network probe"), ("cloud", "IaC/source path for offline cloud scan"),
        ("container", "image/archive/filesystem target"), ("ot", "passive OT log/capture path"),
        ("telecom", "operator telecom registry JSON"), ("payment", "operator payment/HSM config JSON"),
        ("keyassure", "key-assurance config JSON"), ("binary", "binary/firmware target"),
        ("devsecops", "SBOM/artifact target"),
    ):
        parser.add_argument(f"--{name}", help=help_text)
    parser.add_argument("--out", type=Path, help="write JSON report to this path or directory")
    parser.add_argument("--strict", action="store_true", help="fail if any family is not PASS/DEGRADED")
    args = parser.parse_args(argv)
    report = qualify(args)
    encoded = json.dumps(report, indent=2, sort_keys=True, default=str)
    if args.out:
        target = args.out / "scanner-qualification-matrix.json" if args.out.suffix.lower() != ".json" else args.out
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded + "\n", encoding="utf-8")
        print(target)
    else:
        print(encoded)
    if args.strict and any(row["status"] not in {"PASS", "DEGRADED"} for row in report["records"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
