"""Extract cert chain from a TLS handshake result."""

from __future__ import annotations

from typing import Any

from network_scanner.certificates.cert_parser import from_ssl_dict


def extract_leaf(handshake: dict[str, Any], *, endpoint: str | None = None) -> dict[str, Any]:
    peer = handshake.get("peercert") or {}
    der = handshake.get("der")
    leaf = from_ssl_dict(peer, der=der)
    if endpoint:
        leaf["endpoint"] = endpoint
    return leaf


def extract_chain(handshake: dict[str, Any], *, endpoint: str | None = None) -> list[dict[str, Any]]:
    chain = handshake.get("chain") or []
    if chain:
        out = []
        for item in chain:
            parsed = from_ssl_dict(item if isinstance(item, dict) else {}, der=item if not isinstance(item, dict) else None)
            if endpoint:
                parsed["endpoint"] = endpoint
            out.append(parsed)
        return out
    return [extract_leaf(handshake, endpoint=endpoint)]
