"""Parse Envoy / Istio access logs for TLS version and cipher metadata."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from network_scanner.probing.cipher_suite_parser import parse_cipher_suite, tls_algorithm

KV = re.compile(r"\b(tls_version|tls.version|cipher|cipher_suite|downstream_tls_version)=([^\s,;]+)", re.I)
QUOTED = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+\S+\s+HTTP/[\d.]+".*?(TLSv[\d.]+)\s+(\S+)', re.I)


def parse_envoy_line(line: str) -> dict[str, Any] | None:
    raw = (line or "").strip()
    if not raw:
        return None
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            version = (
                data.get("tls_version")
                or data.get("downstream_tls_version")
                or (data.get("tls") or {}).get("version")
            )
            cipher = data.get("cipher") or data.get("cipher_suite") or (data.get("tls") or {}).get("cipher")
            host = data.get("authority") or data.get("requested_server_name") or data.get("upstream_cluster")
            if version or cipher:
                return _finding(str(host or "mesh"), version, cipher, raw)
    fields = {key.lower(): value.strip("\"'") for key, value in KV.findall(raw)}
    if fields:
        version = fields.get("tls_version") or fields.get("tls.version") or fields.get("downstream_tls_version")
        cipher = fields.get("cipher") or fields.get("cipher_suite")
        return _finding("mesh", version, cipher, raw)
    quoted = QUOTED.search(raw)
    if quoted:
        return _finding("mesh", quoted.group(1), quoted.group(2), raw)
    return None


def parse_envoy_file(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[dict[str, Any]] = []
    for line in text.splitlines():
        item = parse_envoy_line(line)
        if item:
            item["file_path"] = str(path)
            item["source"]["file_path"] = str(path)
            findings.append(item)
    return findings


def discover_mesh_logs(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not root.exists():
        return findings
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if not (
            "envoy" in name
            or "istio" in name
            or name.endswith(".access.log")
            or name.endswith("access.log")
        ):
            continue
        findings.extend(parse_envoy_file(path))
    return findings


def _finding(host: str, version: str | None, cipher: str | None, raw: str) -> dict[str, Any]:
    parsed = parse_cipher_suite(cipher, tls_version=version)
    algo = tls_algorithm(version) if version else (parsed.get("algorithm") or "TLS")
    return {
        "scanner_id": "network-tls-scanner-v1.0",
        "endpoint": host,
        "status": "OK",
        "algorithm": algo,
        "purpose": "NETWORK_ENCRYPTION",
        "file_path": f"mesh://{host}",
        "line_number": 0,
        "source": {"type": "SERVICE_MESH", "file_path": f"mesh://{host}", "line_number": 0, "language": "TLS"},
        "crypto": {
            "tls_version": version,
            "cipher_suite": parsed.get("cipher_suite") or cipher,
            "algorithm": algo,
            "mode": parsed.get("mode"),
            "key_exchange_algorithm": parsed.get("key_exchange"),
            "purpose": "NETWORK_ENCRYPTION",
        },
        "metadata": {"confidence": "HIGH", "scan_method": "PASSIVE_MESH", "library": "envoy"},
        "raw": raw[:240],
    }
