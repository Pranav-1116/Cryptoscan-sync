"""TLS scan orchestrator: discover + optional live probe + cert inventory."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable

from network_scanner.certificates.cert_parser import parse_pem
from network_scanner.discovery.config_file_loader import load_targets
from network_scanner.discovery.kubernetes_discoverer import discover_from_tree
from network_scanner.inventory.certificate_inventory import merge_certificates
from network_scanner.inventory.expiry_monitor import expiry_alerts
from network_scanner.probing.active_prober import probe_endpoint
from scanner.core.file_discovery import DEFAULT_EXCLUDED_DIRS


def live_tls_enabled(flag: bool | None = None) -> bool:
    if flag is not None:
        return bool(flag)
    return os.environ.get("CRYPTOSCAN_TLS_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


class NetworkTlsScanner:
    def __init__(self, *, live: bool | None = None, timeout: float = 5.0):
        self.live = live_tls_enabled(live)
        self.timeout = timeout

    def scan_filesystem(self, root: str | Path, *, scan_id: str | None = None) -> dict[str, Any]:
        root_path = Path(root)
        targets = []
        for candidate in (
            root_path / "config" / "network-scan-targets.yaml",
            root_path / "network-scan-targets.yaml",
            Path(os.environ.get("CRYPTOSCAN_ROOT") or ".") / "config" / "network-scan-targets.yaml",
        ):
            targets.extend(load_targets(candidate))
        targets.extend(discover_from_tree(root_path))
        pem_certs = self._collect_pem(root_path)
        findings: list[dict[str, Any]] = []
        live_results: list[dict[str, Any]] = []
        if self.live:
            seen = set()
            for target in targets:
                endpoint = target.get("endpoint")
                if not endpoint or endpoint in seen:
                    continue
                seen.add(endpoint)
                # Skip obviously non-routable k8s service names unless they have a dot
                if ":" in endpoint and "." not in endpoint.split(":")[0] and not endpoint[0].isdigit():
                    continue
                result = probe_endpoint(endpoint, timeout=self.timeout)
                live_results.append(result)
                findings.append(result)
        for cert in pem_certs:
            findings.append(self._cert_finding(cert))
        inventory = merge_certificates([], [self._usage(cert) for cert in pem_certs] + self._live_certs(live_results))
        return {
            "scan_id": scan_id,
            "target_kind": "filesystem",
            "live": self.live,
            "targets": targets,
            "findings": findings,
            "certificates": inventory,
            "alerts": expiry_alerts(inventory),
            "probes": live_results,
        }

    def scan_hosts(self, endpoints: Iterable[str], *, scan_id: str | None = None) -> dict[str, Any]:
        results = [probe_endpoint(item, timeout=self.timeout) for item in endpoints]
        inventory = merge_certificates([], self._live_certs(results))
        return {
            "scan_id": scan_id,
            "target_kind": "hosts",
            "live": True,
            "findings": results,
            "certificates": inventory,
            "alerts": expiry_alerts(inventory),
            "probes": results,
        }

    def _collect_pem(self, root: Path) -> list[dict[str, Any]]:
        certs: list[dict[str, Any]] = []
        if not root.exists():
            return certs
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".pem", ".crt", ".cer"}:
                continue
            if any(part in DEFAULT_EXCLUDED_DIRS or part.startswith(".") for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for cert in parse_pem(text):
                cert["file_path"] = str(path)
                cert["usages"] = [str(path)]
                certs.append(cert)
        return certs

    def _cert_finding(self, cert: dict[str, Any]) -> dict[str, Any]:
        algo = cert.get("public_key_algorithm") or "UNKNOWN"
        return {
            "finding_id": cert.get("fingerprint_sha256"),
            "scanner_id": "network-tls-scanner-v1.0",
            "algorithm": algo,
            "key_size": cert.get("public_key_size"),
            "purpose": "CERTIFICATE",
            "file_path": cert.get("file_path") or cert.get("endpoint") or "certificate",
            "line_number": 1,
            "confidence": "HIGH",
            "source": {
                "type": "CERTIFICATE",
                "file_path": cert.get("file_path") or cert.get("endpoint"),
                "line_number": 1,
                "language": "PEM",
            },
            "crypto": {
                "algorithm": algo,
                "key_size": cert.get("public_key_size"),
                "purpose": "CERTIFICATE",
            },
            "metadata": {
                "confidence": "HIGH",
                "library": "x509",
                "expiry_status": cert.get("expiry_status"),
                "days_until_expiry": cert.get("days_until_expiry"),
                "fingerprint": cert.get("fingerprint_sha256"),
            },
            "certificates": [cert],
        }

    def _usage(self, cert: dict[str, Any]) -> dict[str, Any]:
        payload = dict(cert)
        payload.setdefault("usages", [])
        if cert.get("file_path") and cert["file_path"] not in payload["usages"]:
            payload["usages"].append(cert["file_path"])
        return payload

    def _live_certs(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for result in results:
            for cert in result.get("certificates") or []:
                payload = dict(cert)
                payload.setdefault("usages", [])
                endpoint = result.get("endpoint")
                if endpoint:
                    payload["endpoint"] = endpoint
                    if endpoint not in payload["usages"]:
                        payload["usages"].append(endpoint)
                out.append(payload)
        return out
