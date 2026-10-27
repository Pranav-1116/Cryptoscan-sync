"""Active TLS handshake probe using the stdlib ssl module."""

from __future__ import annotations

import socket
import ssl
import uuid
from typing import Any

from network_scanner.certificates.cert_parser import from_ssl_dict, hostname_matches, parse_der
from network_scanner.certificates.chain_validator import validate_chain
from network_scanner.certificates.crl_checker import check_crl
from network_scanner.certificates.ocsp_checker import check_ocsp
from network_scanner.probing.cipher_suite_parser import (
    headline_issue,
    parse_cipher_suite,
    policy_issues,
    registry_verdict,
    tls_algorithm,
)
from network_scanner.probing.http_headers import check_http_headers
from network_scanner.probing.starttls import negotiate_starttls, protocol_for_port


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    raw = endpoint.strip()
    if raw.startswith("["):
        host, _, rest = raw[1:].partition("]")
        port = int(rest[1:] or "443")
        return host, port
    if raw.count(":") == 1:
        host, port_s = raw.rsplit(":", 1)
        return host, int(port_s)
    return raw, 443


def probe_endpoint(
    endpoint: str,
    *,
    timeout: float = 5.0,
    sni: str | None = None,
    starttls: str | bool | None = None,
    check_http: bool = True,
    scan_versions: bool = False,
    scan_ciphers: bool = False,
    check_renegotiation: bool = False,
    check_chain_sent: bool = False,
    live_revocation: bool = False,
) -> dict[str, Any]:
    host, port = _split_endpoint(endpoint)
    finding: dict[str, Any] = {
        "finding_id": str(uuid.uuid4()),
        "scanner_id": "network-tls-scanner-v1.0",
        "endpoint": f"{host}:{port}",
        "status": "OK",
        "source": {"type": "NETWORK_ENDPOINT", "file_path": f"tls://{host}:{port}", "line_number": 0, "language": "TLS"},
        "crypto": {"purpose": "NETWORK_ENCRYPTION", "algorithm": "TLS"},
        "metadata": {"confidence": "HIGH", "scan_method": "ACTIVE_PROBE", "library": "stdlib-ssl", "starttls": None},
        "certificates": [],
        "chain_validation": {"is_valid": False, "errors": []},
        "revocation_status": {"method": None, "status": "UNKNOWN"},
    }
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ip = infos[0][4][0] if infos else None
    except socket.gaierror as exc:
        finding["status"] = "DNS_FAILED"
        finding["error"] = str(exc)
        finding["metadata"]["confidence"] = "LOW"
        return finding
    finding["ip_address"] = ip

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_alpn_protocols(["h2", "http/1.1"])
    except (ssl.SSLError, NotImplementedError):
        pass
    starttls_protocol = _resolve_starttls(starttls, port)
    if starttls_protocol == "none":
        starttls_protocol = None
    try:
        with socket.create_connection((ip or host, port), timeout=timeout) as raw:
            if starttls_protocol:
                upgrade = negotiate_starttls(raw, starttls_protocol, timeout=timeout)
                if not upgrade.get("ok"):
                    finding["status"] = "STARTTLS_REFUSED"
                    finding["error"] = upgrade.get("detail")
                    finding["metadata"]["starttls"] = starttls_protocol
                    finding["metadata"]["confidence"] = "MEDIUM"
                    return finding
                finding["metadata"]["starttls"] = starttls_protocol
            with context.wrap_socket(raw, server_hostname=sni or host) as tls:
                version = tls.version()
                cipher = tls.cipher() or (None, None, None)
                parsed = parse_cipher_suite(cipher[0], tls_version=version or cipher[1], bits=cipher[2])
                algo = tls_algorithm(version)
                der = None
                try:
                    der = tls.getpeercert(binary_form=True)
                except Exception:
                    der = None
                peer = tls.getpeercert() or {}
                leaf = parse_der(der) if der else from_ssl_dict(peer, der=der)
                if not leaf:
                    leaf = from_ssl_dict(peer, der=der)
                if peer and not leaf.get("san"):
                    ssl_leaf = from_ssl_dict(peer, der=der)
                    if ssl_leaf.get("san"):
                        leaf["san"] = ssl_leaf["san"]
                leaf["endpoint"] = f"{host}:{port}"
                chain_certs = [leaf]
                extra_ders = []
                for getter_name in ("get_unverified_chain", "getpeercert_chain"):
                    getter = getattr(tls, getter_name, None)
                    if not callable(getter):
                        continue
                    try:
                        extra_ders = list(getter() or [])
                        break
                    except Exception:
                        extra_ders = []
                for extra in extra_ders:
                    parsed_extra = parse_der(extra if isinstance(extra, (bytes, bytearray)) else None)
                    if not parsed_extra:
                        continue
                    if parsed_extra.get("fingerprint_sha256") == leaf.get("fingerprint_sha256"):
                        continue
                    chain_certs.append(parsed_extra)
                chain = validate_chain(chain_certs, hostname=host)
                if not hostname_matches(host, leaf) and "HOSTNAME_MISMATCH" not in chain["errors"]:
                    chain["errors"].append("HOSTNAME_MISMATCH")
                    chain["is_valid"] = False
                revoked_live = False
                if live_revocation:
                    from network_scanner.certificates.revocation_live import check_revocation_live

                    revocation = check_revocation_live(leaf, chain_certs, timeout=min(timeout, 6.0))
                    revoked_live = revocation.get("status") == "REVOKED"
                else:
                    revocation = check_ocsp(leaf, live=False)
                    if revocation.get("status") == "UNKNOWN":
                        crl = check_crl(leaf, live=False)
                        if crl.get("urls") and not revocation.get("urls"):
                            revocation = crl
                verdict = registry_verdict(parsed.get("cipher_suite"))
                parsed.setdefault("status", verdict["status"])
                headers = None
                if check_http and not starttls_protocol:
                    headers = check_http_headers(tls, sni or host, timeout=min(timeout, 4.0))
                issues = policy_issues(
                    {
                        "tls_version": version,
                        "cipher_suite": parsed.get("cipher_suite"),
                        "encryption_algorithm": parsed.get("encryption"),
                        "encryption_mode": parsed.get("mode"),
                        "status": verdict["status"],
                    },
                    hsts=headers,
                )
                if revoked_live:
                    issues.append("CERT_REVOKED")
                alpn = None
                try:
                    alpn = tls.selected_alpn_protocol()
                except (ssl.SSLError, NotImplementedError, ValueError):
                    alpn = None
                if scan_versions:
                    from network_scanner.probing.version_floor import probe_version_floor

                    floor = probe_version_floor(host, port, ip=ip, timeout=min(timeout, 4.0), sni=sni)
                    finding["version_floor"] = floor
                    if floor.get("weak_accepted"):
                        issues.append("WEAK_TLS_VERSION_ACCEPTED")
                if scan_ciphers:
                    from network_scanner.probing.cipher_probe import probe_weak_ciphers

                    weak = probe_weak_ciphers(host, port, ip=ip, timeout=min(timeout, 4.0), sni=sni)
                    finding["weak_cipher_probe"] = weak
                    if weak.get("disallowed_accepted"):
                        issues.append("DISALLOWED_CIPHER_ACCEPTED")
                    if weak.get("cbc_accepted"):
                        issues.append("CBC_ACCEPTED")
                if check_renegotiation:
                    from network_scanner.probing.renegotiation import probe_renegotiation

                    reneg = probe_renegotiation(host, port, ip=ip, sni=sni, timeout=min(timeout, 5.0))
                    finding["renegotiation"] = reneg
                    if reneg.get("secure_renegotiation") == "NOT_SUPPORTED":
                        issues.append("INSECURE_RENEGOTIATION_ENABLED")
                    if reneg.get("client_renegotiation") == "ACCEPTED":
                        issues.append("CLIENT_RENEGOTIATION_ACCEPTED")
                if check_chain_sent:
                    from network_scanner.certificates.chain_order import probe_chain_sent

                    sent = probe_chain_sent(host, port, ip=ip, sni=sni, timeout=min(timeout, 5.0))
                    finding["chain_sent"] = sent
                    for issue in sent.get("issues") or []:
                        if issue != "CHAIN_UNAVAILABLE":
                            issues.append(issue)
                issues = sorted(set(issues), key=lambda issue: _issue_rank(issue))
                finding.update(
                    {
                        "status": "OK",
                        "algorithm": parsed.get("algorithm") or algo,
                        "mode": parsed.get("mode"),
                        "key_size": parsed.get("key_size"),
                        "purpose": "NETWORK_ENCRYPTION",
                        "file_path": f"tls://{host}:{port}",
                        "line_number": 0,
                        "crypto": {
                            "tls_version": version,
                            "cipher_suite": parsed.get("cipher_suite"),
                            "key_exchange_algorithm": parsed.get("key_exchange"),
                            "authentication_algorithm": parsed.get("authentication"),
                            "encryption_algorithm": parsed.get("encryption"),
                            "encryption_mode": parsed.get("mode"),
                            "mac_algorithm": parsed.get("mac"),
                            "key_size": parsed.get("key_size"),
                            "algorithm": algo,
                            "mode": parsed.get("mode"),
                            "purpose": "NETWORK_ENCRYPTION",
                            "raw_transformation": parsed.get("cipher_suite"),
                            "status": verdict["status"],
                            "quantum_impact": verdict["quantum_impact"],
                            "alpn": alpn,
                        },
                        "compliance_issue": headline_issue(issues),
                        "policy_issues": issues,
                        "algorithm_verdict": verdict,
                        "http_headers": headers,
                        "certificates": chain_certs,
                        "chain_validation": chain,
                        "revocation_status": revocation,
                    }
                )
                finding["algorithm"] = algo
                finding["policy_issues"] = issues
    except TimeoutError:
        finding["status"] = "TIMEOUT"
        finding["metadata"]["confidence"] = "LOW"
    except ConnectionRefusedError:
        finding["status"] = "PORT_CLOSED"
        finding["metadata"]["confidence"] = "LOW"
    except ssl.SSLError as exc:
        error_type = _classify_ssl_error(exc)
        finding["error"] = str(exc)
        finding["error_type"] = error_type
        if error_type == "MTLS_REQUIRED":
            # the server demanded a client certificate: a fact, not a failure
            finding["status"] = "MTLS_REQUIRED"
            finding["metadata"]["confidence"] = "HIGH"
        else:
            finding["status"] = "TLS_ERROR"
            finding["metadata"]["confidence"] = "MEDIUM"
    except OSError as exc:
        finding["status"] = "CONNECT_ERROR"
        finding["error"] = str(exc)
        finding["metadata"]["confidence"] = "LOW"
    return finding


def _resolve_starttls(starttls: str | bool | None, port: int) -> str | None:
    """None/False -> plain TLS; 'auto' -> by port; named protocol wins."""
    if starttls is None or starttls is False:
        return None
    if starttls is True:
        return protocol_for_port(port) or "none"
    text = str(starttls).lower().strip()
    if text in {"auto", "port", "detect"}:
        return protocol_for_port(port) or "none"
    if text in {"off", "no", "none", "false", "0"}:
        return None
    return text


def _classify_ssl_error(exc: ssl.SSLError) -> str:
    text = str(exc).lower()
    compact = text.replace("_", " ")
    if "certificate required" in compact or "peer did not return a certificate" in compact:
        return "MTLS_REQUIRED"
    if "version" in text or "protocol" in text:
        return "PROTOCOL_VERSION_MISMATCH"
    if "cipher" in text:
        return "CIPHER_SUITE_MISMATCH"
    if "handshake failure" in compact:
        # NOTE: servers that require a client certificate often send this
        # generic alert instead of certificate_required — treat as a TLS
        # mismatch, mTLS detection relies on the explicit alert when present
        return "HANDSHAKE_FAILURE"
    if "certificate" in text or "verify" in text:
        return "CERTIFICATE_VERIFY_FAILED"
    return "TLS_ERROR"


def _issue_rank(issue: str) -> int:
    from network_scanner.probing.cipher_suite_parser import _ISSUE_ORDER

    return _ISSUE_ORDER.get(issue, 99) - (100 if issue.endswith("_ACCEPTED") else 0)
