"""Active TLS handshake probe using the stdlib ssl module."""

from __future__ import annotations

import socket
import ssl
import uuid
from typing import Any

from network_scanner.certificates.cert_parser import from_ssl_dict, hostname_matches
from network_scanner.certificates.chain_validator import validate_chain
from network_scanner.certificates.crl_checker import check_crl
from network_scanner.certificates.ocsp_checker import check_ocsp
from network_scanner.probing.cipher_suite_parser import parse_cipher_suite, tls_algorithm
from network_scanner.probing.ssl_error_classifier import classify_ssl_error


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


def probe_endpoint(endpoint: str, *, timeout: float = 5.0, sni: str | None = None) -> dict[str, Any]:
    host, port = _split_endpoint(endpoint)
    finding: dict[str, Any] = {
        "finding_id": str(uuid.uuid4()),
        "scanner_id": "network-tls-scanner-v1.0",
        "endpoint": f"{host}:{port}",
        "status": "OK",
        "source": {"type": "NETWORK_ENDPOINT", "file_path": f"tls://{host}:{port}", "line_number": 0, "language": "TLS"},
        "crypto": {"purpose": "NETWORK_ENCRYPTION", "algorithm": "TLS"},
        "metadata": {"confidence": "HIGH", "scan_method": "ACTIVE_PROBE", "library": "stdlib-ssl"},
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
        with socket.create_connection((ip or host, port), timeout=timeout) as raw:
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
                leaf = from_ssl_dict(peer, der=der)
                leaf["endpoint"] = f"{host}:{port}"
                chain = validate_chain([leaf], hostname=host)
                if not hostname_matches(host, leaf) and "HOSTNAME_MISMATCH" not in chain["errors"]:
                    chain["errors"].append("HOSTNAME_MISMATCH")
                    chain["is_valid"] = False
                revocation = check_ocsp(leaf, live=False)
                if revocation.get("status") == "UNKNOWN":
                    crl = check_crl(leaf, live=False)
                    if crl.get("urls") and not revocation.get("urls"):
                        revocation = crl
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
                        },
                        "certificates": [leaf],
                        "chain_validation": chain,
                        "revocation_status": revocation,
                    }
                )
                finding["algorithm"] = algo
    except TimeoutError:
        finding["status"] = "TIMEOUT"
        finding["metadata"]["confidence"] = "LOW"
    except ConnectionRefusedError:
        finding["status"] = "PORT_CLOSED"
        finding["metadata"]["confidence"] = "LOW"
    except ssl.SSLError as exc:
        finding["status"] = "TLS_ERROR"
        finding["error"] = str(exc)
        finding["error_type"] = _classify_ssl_error(exc)
        finding["metadata"]["confidence"] = "MEDIUM"
    except OSError as exc:
        finding["status"] = "CONNECT_ERROR"
        finding["error"] = str(exc)
        finding["metadata"]["confidence"] = "LOW"
    return finding


def _classify_ssl_error(exc: ssl.SSLError) -> str:
    text = str(exc).lower()
    if "version" in text or "protocol" in text:
        return "PROTOCOL_VERSION_MISMATCH"
    if "cipher" in text:
        return "CIPHER_SUITE_MISMATCH"
    if "certificate" in text or "verify" in text:
        return "CERTIFICATE_VERIFY_FAILED"
    return "TLS_ERROR"
