"""TLS scan orchestrator: discover + optional live probe + cert inventory."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from network_scanner.certificates.cert_parser import parse_pem
from network_scanner.certificates.chain_validator import validate_chain
from network_scanner.certificates.crl_checker import check_crl, extract_crl_urls
from network_scanner.certificates.ocsp_checker import check_ocsp, extract_ocsp_urls
from network_scanner.discovery.config_file_loader import load_targets
from network_scanner.discovery.dns_discoverer import discover_from_tree as discover_dns
from network_scanner.discovery.kubernetes_discoverer import discover_from_tree
from network_scanner.passive.service_mesh_observer import discover_mesh_logs
from network_scanner.inventory.certificate_inventory import merge_certificates
from network_scanner.inventory.expiry_monitor import expiry_alerts
from network_scanner.inventory.usage_tracker import usage_records
from network_scanner.probing.active_prober import probe_endpoint
from scanner.core.file_discovery import DEFAULT_EXCLUDED_DIRS


def live_tls_enabled(flag: bool | None = None) -> bool:
    if flag is not None:
        return bool(flag)
    return os.environ.get("CRYPTOSCAN_TLS_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


class NetworkTlsScanner:
    def __init__(self, *, live: bool | None = None, timeout: float = 5.0, workers: int | None = None):
        self.live = live_tls_enabled(live)
        self.timeout = timeout
        self.workers = workers or _default_workers()

    def scan_filesystem(self, root: str | Path, *, scan_id: str | None = None) -> dict[str, Any]:
        root_path = Path(root)
        targets = []
        for candidate in (
            root_path / "config" / "network-scan-targets.yaml",
            root_path / "network-scan-targets.yaml",
            Path(__file__).resolve().parents[1] / "config" / "scan_targets.yaml",
            Path(os.environ.get("CRYPTOSCAN_ROOT") or ".") / "config" / "network-scan-targets.yaml",
        ):
            targets.extend(load_targets(candidate))
        targets.extend(discover_from_tree(root_path))
        targets.extend(discover_dns(root_path))
        pem_certs = self._collect_pem(root_path)
        findings: list[dict[str, Any]] = []
        live_results: list[dict[str, Any]] = []
        findings.extend(discover_mesh_logs(root_path))
        if self.live:
            seen = set()
            probe_list: list[str] = []
            for target in targets:
                endpoint = target.get("endpoint")
                if not endpoint or endpoint in seen:
                    continue
                seen.add(endpoint)
                # Skip obviously non-routable k8s service names unless they have a dot
                if ":" in endpoint and "." not in endpoint.split(":")[0] and not endpoint[0].isdigit():
                    continue
                probe_list.append(endpoint)
            live_results = self._probe_all(probe_list)
            findings.extend(live_results)
        for cert in pem_certs:
            findings.append(self._cert_finding(cert))
        inventory = merge_certificates([], [self._usage(cert) for cert in pem_certs] + self._live_certs(live_results))
        self._attach_revocation(inventory)
        return {
            "scan_id": scan_id,
            "target_kind": "filesystem",
            "live": self.live,
            "targets": targets,
            "findings": findings,
            "certificates": inventory,
            "usages": usage_records(inventory),
            "alerts": expiry_alerts(inventory),
            "probes": live_results,
            "probe_telemetry": probe_telemetry(live_results),
        }

    def scan_hosts(
        self,
        endpoints: Iterable[str],
        *,
        scan_id: str | None = None,
        sni: str | None = None,
        starttls: str | bool | None = None,
        workers: int | None = None,
        scan_versions: bool = False,
        scan_ciphers: bool = False,
        check_renegotiation: bool = False,
        check_chain_sent: bool = False,
        live_revocation: bool = False,
    ) -> dict[str, Any]:
        endpoint_list = [str(item) for item in endpoints if str(item).strip()]
        results = self._probe_all(
            endpoint_list,
            sni=sni,
            starttls=starttls,
            workers=workers,
            scan_versions=scan_versions,
            scan_ciphers=scan_ciphers,
            check_renegotiation=check_renegotiation,
            check_chain_sent=check_chain_sent,
            live_revocation=live_revocation,
        )
        inventory = merge_certificates([], self._live_certs(results))
        self._attach_revocation(inventory)
        return {
            "scan_id": scan_id,
            "target_kind": "hosts",
            "live": True,
            "findings": results,
            "certificates": inventory,
            "usages": usage_records(inventory),
            "alerts": expiry_alerts(inventory),
            "probes": results,
            "probe_telemetry": probe_telemetry(results),
        }

    def scan_ssh_hosts(
        self,
        endpoints: Iterable[str],
        *,
        scan_id: str | None = None,
        known_host_keys: dict[str, dict[str, str]] | None = None,
        include_kex: bool = False,
    ) -> dict[str, Any]:
        """SSH host-key scan + TOFU drift against caller-supplied baselines.

        ``include_kex`` also reads each server's KEXINIT algorithm offer and
        merges weak-algorithm issues into the finding (policy_issues is a
        set-deduped list; host-key and offer issues coexist).
        """
        from network_scanner.probing.ssh_keyscan import scan_ssh_host_keys, split_ssh_target, ssh_probe_telemetry

        baselines = known_host_keys or {}
        findings: list[dict[str, Any]] = []
        updated: dict[str, dict[str, str]] = dict(baselines)
        for item in endpoints:
            host, port = split_ssh_target(str(item))
            endpoint = f"{host}:{port}"
            try:
                finding = scan_ssh_host_keys(host, port, timeout=self.timeout, baseline=baselines.get(endpoint))
            except Exception as exc:  # noqa: BLE001 — one host must not sink the scan
                finding = {
                    "endpoint": endpoint,
                    "status": "PROBE_ERROR",
                    "detail": f"{type(exc).__name__}: {exc}"[:300],
                    "keys": [],
                    "policy_issues": [],
                    "key_drift": None,
                }
            if include_kex:
                try:
                    from network_scanner.probing.ssh_kex import probe_ssh_kex_offer

                    offer = probe_ssh_kex_offer(host, port, timeout=self.timeout)
                    finding["kex_offer"] = offer
                    merged = list(finding.get("policy_issues") or [])
                    merged.extend(offer.get("policy_issues") or [])
                    finding["policy_issues"] = sorted(set(merged))
                    if merged and not finding.get("compliance_issue"):
                        finding["compliance_issue"] = finding["policy_issues"][0]
                except Exception as exc:  # noqa: BLE001 — offer probe must not sink the scan
                    finding["kex_offer"] = {
                        "endpoint": endpoint,
                        "status": "PROBE_ERROR",
                        "detail": f"{type(exc).__name__}: {exc}"[:200],
                        "policy_issues": [],
                    }
            findings.append(finding)
            drift = finding.get("key_drift") or {}
            if drift.get("observed"):
                updated[endpoint] = {str(k): str(v) for k, v in drift["observed"].items()}
        return {
            "scan_id": scan_id,
            "target_kind": "ssh-hosts",
            "findings": findings,
            "ssh_probe_telemetry": ssh_probe_telemetry(findings),
            "known_host_keys": updated,
        }

    def scan_ipsec_hosts(
        self,
        endpoints: Iterable[str],
        *,
        scan_id: str | None = None,
        ports: Iterable[int] = (500, 4500),
        check_transfer: bool = True,
    ) -> dict[str, Any]:
        """IPsec/IKE VPN posture probe: SA proposals + weak crypto classification.

        One IKEv2 SA_INIT per endpoint (UDP 500 then 4500); the responder's
        accepted transform set is parsed and weak encryption / MAC / DH group /
        missing-PFS configurations are flagged. Active opt-in — you must pass
        explicit endpoints. Never completes a handshake or exchanges keys.
        """
        from network_scanner.probing.ipsec_probe import probe_ike

        findings: list[dict[str, Any]] = []
        for item in endpoints:
            host = str(item).split(":")[0].strip()
            if not host:
                continue
            try:
                finding = probe_ike(host, ports=ports, timeout=self.timeout)
            except Exception as exc:  # noqa: BLE001 — one endpoint must not sink the scan
                finding = {
                    "endpoint": f"{host}:{list(ports)[0]}",
                    "status": "PROBE_ERROR",
                    "detail": f"{type(exc).__name__}: {exc}"[:300],
                    "issues": [],
                }
            findings.append(finding)
        return {
            "scan_id": scan_id,
            "target_kind": "ipsec-vpn",
            "findings": findings,
            "alerts": [],
            "probe_telemetry": {
                "probed": len(findings),
                "responded": sum(1 for f in findings if f.get("status") == "OK"),
                "weak": sum(1 for f in findings if f.get("issues")),
            },
        }

    def scan_dnssec_zones(
        self,
        zones: Iterable[str],
        *,
        scan_id: str | None = None,
        resolver: str | None = None,
        check_transfer: bool = True,
    ) -> dict[str, Any]:
        """DNSSEC posture for a set of zones: signing status + weak algorithms."""
        from network_scanner.discovery.dnssec_checker import scan_dnssec

        results: list[dict[str, Any]] = []
        for zone in zones:
            try:
                results.append(scan_dnssec(zone, resolver=resolver, timeout=self.timeout,
                                           check_transfer=check_transfer))
            except Exception as exc:  # noqa: BLE001
                results.append(
                    {"zone": str(zone), "status": "ERROR", "issues": [f"DNS_ERROR:{type(exc).__name__}"]}
                )
        issues_total = sorted({issue for r in results for issue in r.get("issues") or []})
        return {
            "scan_id": scan_id,
            "target_kind": "dnssec",
            "zones": results,
            "unsigned": sum(1 for r in results if r.get("status") == "UNSIGNED"),
            "issues": issues_total,
        }

    def discover_network(
        self,
        scope_specs: list[str] | list[dict],
        *,
        scan_id: str | None = None,
        mode: str = "SAFE",
        authorization_scope: str = "",
        plugins: list[str] | None = None,
        passive_sources: list[dict] | None = None,
        options: dict | None = None,
    ) -> dict:
        """Global Network Discovery — full enterprise pipeline.

        Runs target expansion, active/vendor/passive discovery, protocol
        detection, TLS + certificate intelligence, the dependency graph, PQC
        readiness, migration simulation, blast radius and geographic exposure.
        ``mode`` defaults to SAFE; DEEP/AGGRESSIVE require authorization_scope.
        """
        from network_scanner.enterprise.engine import GlobalNetworkDiscoveryEngine
        from network_scanner.enterprise.passive_engine import PassiveSource
        from network_scanner.enterprise.scan_modes import ScanAuthorization, ScanMode

        engine = GlobalNetworkDiscoveryEngine(
            mode=ScanMode(mode, authorization=ScanAuthorization(authorization_scope=authorization_scope)),
            authorization_scope=authorization_scope,
        )
        sources: list[PassiveSource] = []
        for source in passive_sources or []:
            sources.append(PassiveSource(
                kind=str(source.get("kind") or "LOG"),
                name=str(source.get("name") or "source"),
                lines=list(source.get("lines") or []),
            ))
        report = engine.run(scope_specs, plugins=plugins, passive_sources=sources, options=options)
        report["scan_id"] = scan_id
        report["target_kind"] = "global-network-discovery"
        return report

    def live_monitor(
        self,
        scope_specs: list[str] | list[dict],
        *,
        mode: str = "SAFE",
        authorization_scope: str = "",
        plugins: list[str] | None = None,
        options: dict | None = None,
        **live_options: Any,
    ):
        """Start the 24/7 Live Network Scanner loop over ``scope_specs``.

        Returns a ``LiveNetworkMonitor`` whose ``cycle()`` / ``run()`` methods
        drive the five monitoring modes.  The scan function is wired to
        :meth:`discover_network`, so each cycle reuses the full enterprise
        pipeline (assets, TLS/cert intel, topology, PQC, simulation).
        """
        from network_scanner.enterprise.live.loop import LiveNetworkMonitor

        scan_fn = lambda specs, scan_mode: self.discover_network(  # noqa: E731
            list(specs),
            mode=scan_mode or mode,
            authorization_scope=authorization_scope,
            plugins=plugins,
            options=dict(options or {}),
        )
        return LiveNetworkMonitor(scope_specs=scope_specs, scan_fn=scan_fn,
                                  **live_options)

    def _probe_all(
        self,
        endpoints: list[str],
        *,
        sni: str | None = None,
        starttls: str | bool | None = None,
        workers: int | None = None,
        scan_versions: bool = False,
        scan_ciphers: bool = False,
        check_renegotiation: bool = False,
        check_chain_sent: bool = False,
        live_revocation: bool = False,
    ) -> list[dict[str, Any]]:
        """Probe endpoints in parallel (bounded); failures never stop the rest."""
        if not endpoints:
            return []
        worker_count = max(1, min(workers or self.workers, len(endpoints)))
        if worker_count == 1:
            return [
                self._safe_probe(
                    item,
                    sni=sni,
                    starttls=starttls,
                    scan_versions=scan_versions,
                    scan_ciphers=scan_ciphers,
                    check_renegotiation=check_renegotiation,
                    check_chain_sent=check_chain_sent,
                    live_revocation=live_revocation,
                )
                for item in endpoints
            ]
        by_endpoint: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = {
                pool.submit(
                    self._safe_probe,
                    item,
                    sni=sni,
                    starttls=starttls,
                    scan_versions=scan_versions,
                    scan_ciphers=scan_ciphers,
                    check_renegotiation=check_renegotiation,
                    check_chain_sent=check_chain_sent,
                    live_revocation=live_revocation,
                ): item
                for item in endpoints
            }
            for future in as_completed(futures):
                row = future.result()
                by_endpoint[str(row.get("endpoint") or futures[future])] = row
        # keep input order for deterministic reports
        return [by_endpoint[item] for item in endpoints if item in by_endpoint]

    def _safe_probe(
        self,
        endpoint: str,
        *,
        sni: str | None = None,
        starttls: str | bool | None = None,
        scan_versions: bool = False,
        scan_ciphers: bool = False,
        check_renegotiation: bool = False,
        check_chain_sent: bool = False,
        live_revocation: bool = False,
    ) -> dict[str, Any]:
        try:
            return probe_endpoint(
                endpoint,
                timeout=self.timeout,
                sni=sni,
                starttls=starttls,
                scan_versions=scan_versions,
                scan_ciphers=scan_ciphers,
                check_renegotiation=check_renegotiation,
                check_chain_sent=check_chain_sent,
                live_revocation=live_revocation,
            )
        except Exception as exc:  # noqa: BLE001 — one endpoint must not sink the scan
            return {
                "finding_id": endpoint,
                "scanner_id": "network-tls-scanner-v1.0",
                "endpoint": endpoint,
                "status": "PROBE_ERROR",
                "error": f"{type(exc).__name__}: {exc}"[:300],
                "metadata": {"confidence": "LOW", "scan_method": "ACTIVE_PROBE"},
                "certificates": [],
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
        verdict = certificate_verdict(cert)
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
            "compliance_issue": verdict.get("compliance_issue"),
            "policy_issues": verdict.get("policy_issues"),
            "metadata": {
                "confidence": "HIGH",
                "library": "x509",
                "expiry_status": cert.get("expiry_status"),
                "days_until_expiry": cert.get("days_until_expiry"),
                "fingerprint": cert.get("fingerprint_sha256"),
                "status": verdict.get("status"),
                "quantum_impact": verdict.get("quantum_impact"),
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

    def _attach_revocation(self, inventory: list[dict[str, Any]]) -> None:
        for cert in inventory:
            ocsp = check_ocsp(cert, live=self.live)
            crl = check_crl(cert, live=self.live)
            chosen = ocsp if ocsp.get("urls") else crl
            cert["revocation_status"] = chosen.get("status")
            cert["revocation_method"] = chosen.get("method")
            cert["revocation"] = {"ocsp": ocsp, "crl": crl}
            if ocsp.get("urls"):
                cert["ocsp_url"] = ocsp["urls"][0]
            if crl.get("urls"):
                cert["crl_url"] = crl["urls"][0]
            cert.setdefault("chain_validation", self._chain_for(cert, inventory))
            ocsp_urls = extract_ocsp_urls(cert)
            crl_urls = extract_crl_urls(cert)
            if ocsp_urls and not cert.get("ocsp_url"):
                cert["ocsp_url"] = ocsp_urls[0]
            if crl_urls and not cert.get("crl_url"):
                cert["crl_url"] = crl_urls[0]

    def _chain_for(self, cert: dict[str, Any], inventory: list[dict[str, Any]]) -> dict[str, Any]:
        by_fp = {
            item.get("fingerprint_sha256"): item
            for item in inventory
            if item.get("fingerprint_sha256")
        }
        chain = [cert]
        seen = {cert.get("fingerprint_sha256")}
        parent_id = cert.get("issuer_cert_id")
        while parent_id and parent_id in by_fp and parent_id not in seen:
            parent = by_fp[parent_id]
            chain.append(parent)
            seen.add(parent_id)
            parent_id = parent.get("issuer_cert_id")
        return validate_chain(chain)

def _default_workers() -> int:
    try:
        return max(1, int(os.environ.get("CRYPTOSCAN_TLS_WORKERS") or 8))
    except ValueError:
        return 8


def probe_telemetry(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate probe outcomes — mirrors cloud_scanner's honest verdicts."""
    statuses: dict[str, int] = {}
    weak_versions = weak_suites = 0
    insecure_reneg = client_reneg = chain_issues = revoked = 0
    for row in results:
        status = str(row.get("status") or "UNKNOWN")
        statuses[status] = statuses.get(status, 0) + 1
        issues = row.get("policy_issues") or []
        if "WEAK_TLS_VERSION" in issues:
            weak_versions += 1
        if "DISALLOWED_CIPHER" in issues or "WEAK_CIPHER_SUITE" in issues or "DISALLOWED_CIPHER_ACCEPTED" in issues:
            weak_suites += 1
        if "WEAK_TLS_VERSION_ACCEPTED" in issues:
            weak_versions += 1
        if "INSECURE_RENEGOTIATION_ENABLED" in issues:
            insecure_reneg += 1
        if "CLIENT_RENEGOTIATION_ACCEPTED" in issues:
            client_reneg += 1
        if any(issue.startswith("CHAIN_") for issue in issues):
            chain_issues += 1
        if "CERT_REVOKED" in issues:
            revoked += 1
    probed = len(results)
    ok = statuses.get("OK", 0)
    if probed == 0:
        verdict = "SKIPPED"
    elif ok == 0:
        verdict = "FAILED"
    elif ok < probed or weak_versions or weak_suites or insecure_reneg or client_reneg or chain_issues or revoked:
        verdict = "PARTIAL"
    else:
        verdict = "OK"
    return {
        "status": verdict,
        "probed": probed,
        "ok": ok,
        "statuses": statuses,
        "weak_tls_versions": weak_versions,
        "weak_cipher_suites": weak_suites,
        "insecure_renegotiation": insecure_reneg,
        "client_renegotiation_accepted": client_reneg,
        "chain_order_issues": chain_issues,
        "revoked_certificates": revoked,
    }


def certificate_verdict(cert: dict[str, Any]) -> dict[str, Any]:
    """Registry verdict for a certificate's key + signature algorithm."""
    issues: list[str] = []
    status = "UNKNOWN"
    quantum_impact = None
    try:
        from shared_models.algorithm_registry import parse_algorithm

        key_info = parse_algorithm(
            f"{cert.get('public_key_algorithm') or 'RSA'}-{cert.get('public_key_size') or ''}".rstrip("-")
            if cert.get("public_key_size")
            else str(cert.get("public_key_algorithm") or "RSA")
        )
        status = key_info.status
        quantum_impact = key_info.quantum_impact
        if status == "DISALLOWED":
            issues.append("WEAK_CERTIFICATE_KEY")
        sig = str(cert.get("signature_algorithm") or "").lower()
        if sig.startswith("sha1") or sig.startswith("md5"):
            issues.append("WEAK_SIGNATURE_ALGORITHM")
            status = "DISALLOWED" if status != "DISALLOWED" else status
    except Exception:  # noqa: BLE001 — registry unavailable: degrade, don't crash
        pass
    return {
        "status": status,
        "quantum_impact": quantum_impact,
        "policy_issues": issues,
        "compliance_issue": issues[0] if issues else None,
    }
