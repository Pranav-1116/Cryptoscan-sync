"""SSH algorithm-offer probing: read the server's KEXINIT, flag weak accepts.

``ssh-keyscan`` answers *what keys does this host have*; it cannot answer
*what ciphers, MACs, and key exchanges the server still accepts* — the
question that actually decides whether a 15-year-old client can drag the
connection down to arcfour/3DES/CBC/hmac-md5.  The server's full algorithm
offer is in its very first packet (SSH_MSG_KEXINIT), sent unprompted right
after the version banner, so this probe speaks just enough SSH — banner
exchange, one packet read, disconnect — to capture it.  Pure stdlib, no
external binaries; nothing is negotiated and no auth is attempted.

Honesty rules:

* a port whose banner is not ``SSH-2.0-...`` is ``NOT_SSH`` (e.g. a TLS
  port), never a parse failure;
* connection refused/timeout -> ``SSH_UNREACHABLE`` / ``TIMEOUT`` with the
  raw error fact;
* OpenSSH list *markers* (``kex-strict-*``, ``ext-info-*``) are protocol
  signals, not algorithms, and are excluded from policy analysis;
* the ``legacy`` tier (hmac-sha1, umac-64, ssh-rsa host key alg) is recorded
  but only raises an issue with ``strict=True`` — stock servers ship these
  for compatibility, and noise is not honesty.
"""

from __future__ import annotations

import socket
from typing import Any

SSH_MSG_KEXINIT = 20
OFFER_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_client_to_server",
    "encryption_server_to_client",
    "mac_client_to_server",
    "mac_server_to_client",
    "compression_client_to_server",
    "compression_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)
_MARKER_PREFIXES = ("kex-strict-", "ext-info-")

WEAK_CIPHER_PATTERNS = ("arcfour", "arcfour128", "arcfour256", "3des", "-cbc")
WEAK_MAC_PATTERNS = ("md5", "sha1-96")
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}
LEGACY_MAC_PATTERNS = ("hmac-sha1", "umac-64")
LEGACY_HOST_KEY = "ssh-rsa"
LEGACY_KEX_PATTERNS = ("diffie-hellman-group14-sha1",)


def is_marker(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in _MARKER_PREFIXES)


def _algorithms(name_list: str) -> list[str]:
    return [name for name in (name_list or "").split(",") if name and not is_marker(name)]


def parse_kexinit_packet(body: bytes) -> dict[str, list[str]] | None:
    """Pure: SSH_MSG_KEXINIT body (msg byte stripped) -> the 10 name-lists."""
    if not body or len(body) < 17:
        return None
    payload = body[16:]  # 16-byte cookie
    fields: dict[str, list[str]] = {}
    position = 0
    for field in OFFER_FIELDS:
        if position + 4 > len(payload):
            return None
        count = int.from_bytes(payload[position : position + 4], "big")
        position += 4
        if position + count > len(payload):
            return None
        raw = payload[position : position + count].decode("utf-8", "replace")
        position += count
        fields[field] = _algorithms(raw)
    return fields


def analyze_ssh_kex_offer(offer: dict[str, Any] | None, *, strict: bool = False) -> dict[str, Any]:
    """Policy over the server's offer; weak always flagged, legacy only strict."""
    result: dict[str, Any] = {
        "weak_ciphers": [],
        "weak_macs": [],
        "weak_kex": [],
        "legacy_macs": [],
        "legacy_host_keys": [],
        "legacy_kex": [],
        "policy_issues": [],
    }
    if not offer:
        return result
    for field, weak, patterns in (
        ("encryption_client_to_server", "weak_ciphers", WEAK_CIPHER_PATTERNS),
        ("mac_client_to_server", "weak_macs", WEAK_MAC_PATTERNS),
    ):
        for name in offer.get(field) or []:
            if any(pattern in name for pattern in patterns):
                result[weak].append(name)
    for name in offer.get("kex_algorithms") or []:
        if name in WEAK_KEX:
            result["weak_kex"].append(name)
        elif any(name.startswith(pattern.rsplit("-", 2)[0]) for pattern in LEGACY_KEX_PATTERNS):
            result["legacy_kex"].append(name)
    for name in offer.get("mac_client_to_server") or []:
        if any(pattern in name for pattern in LEGACY_MAC_PATTERNS):
            result["legacy_macs"].append(name)
    for name in offer.get("server_host_key_algorithms") or []:
        if name == LEGACY_HOST_KEY:
            result["legacy_host_keys"].append(name)
    issues: list[str] = []
    if result["weak_ciphers"]:
        issues.append("SSH_WEAK_CIPHER_OFFERED")
    if result["weak_macs"]:
        issues.append("SSH_WEAK_MAC_OFFERED")
    if result["weak_kex"]:
        issues.append("SSH_WEAK_KEX_OFFERED")
    if strict and (result["legacy_macs"] or result["legacy_host_keys"] or result["legacy_kex"]):
        issues.append("SSH_LEGACY_ALGORITHM_OFFERED")
    result["policy_issues"] = issues
    return result


def _read_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed mid-read")
        data += chunk
    return data


def read_server_offer(sock: socket.socket) -> tuple[str, dict[str, list[str]] | None]:
    """Banner exchange + one packet read -> (server_banner, offer)."""
    banner = _read_exact(sock, 1)
    while not banner.endswith(b"\r\n"):
        if len(banner) > 255:
            raise ValueError("oversized banner")
        banner += _read_exact(sock, 1)
    sock.sendall(b"SSH-2.0-CryptoScanProbe_1.0\r\n")
    header = _read_exact(sock, 5)
    length = int.from_bytes(header[:4], "big")
    if length < 16 or length > 65536:
        raise ValueError(f"implausible packet length {length}")
    padding = header[4]
    if padding < 4:
        raise ValueError("implausible padding")
    body = _read_exact(sock, length - 1)
    if body[0] != SSH_MSG_KEXINIT:
        raise ValueError(f"expected KEXINIT (20), got msg {body[0]}")
    return banner.decode("utf-8", "replace").strip(), parse_kexinit_packet(body[1:])


def probe_ssh_kex_offer(
    host: str,
    port: int = 22,
    *,
    timeout: float = 6.0,
    strict: bool = False,
) -> dict[str, Any]:
    """Fetch one host's SSH algorithm offer and grade it."""
    finding: dict[str, Any] = {
        "endpoint": f"{host}:{port}",
        "status": "OK",
        "method": "ssh-kexinit",
        "server_banner": None,
        "kex_algorithms": None,
        "host_key_algorithms": None,
        "ciphers": None,
        "macs": None,
        "compression": None,
        "weak": None,
        "legacy": None,
        "policy_issues": [],
        "detail": None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner, offer = read_server_offer(sock)
            except ValueError as exc:
                text = str(exc)
                if "banner" in text or "KEXINIT" in text:
                    finding["status"] = "NOT_SSH"
                else:
                    finding["status"] = "PROBE_ERROR"
                finding["detail"] = text[:200]
                return finding
    except ConnectionRefusedError as exc:
        finding["status"] = "SSH_UNREACHABLE"
        finding["detail"] = f"refused: {exc}"[:200]
        return finding
    except TimeoutError as exc:
        finding["status"] = "TIMEOUT"
        finding["detail"] = f"timeout: {exc}"[:200]
        return finding
    except OSError as exc:
        finding["status"] = "SSH_UNREACHABLE"
        finding["detail"] = f"{type(exc).__name__}: {exc}"[:200]
        return finding
    if not offer:
        finding["status"] = "PROBE_ERROR"
        finding["detail"] = "kexinit packet unparsable"
        return finding
    analysis = analyze_ssh_kex_offer(offer, strict=strict)
    finding.update(
        {
            "server_banner": banner,
            "kex_algorithms": offer.get("kex_algorithms"),
            "host_key_algorithms": offer.get("server_host_key_algorithms"),
            "ciphers": offer.get("encryption_client_to_server"),
            "macs": offer.get("mac_client_to_server"),
            "compression": offer.get("compression_client_to_server"),
            "weak": {key: analysis[key] for key in ("weak_ciphers", "weak_macs", "weak_kex")},
            "legacy": {
                key: analysis[key]
                for key in ("legacy_macs", "legacy_host_keys", "legacy_kex")
            },
            "policy_issues": analysis["policy_issues"],
        }
    )
    return finding
