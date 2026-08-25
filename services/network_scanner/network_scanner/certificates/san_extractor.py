"""Extract DNS / IP names from a parsed certificate dict."""

from __future__ import annotations

from typing import Any


def extract_sans(cert: dict[str, Any]) -> list[str]:
    return [str(item) for item in (cert.get("san") or []) if item]


def extract_dns_names(cert: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for item in extract_sans(cert):
        raw = item.split(":", 1)[-1].strip().lower()
        if raw and not raw.replace(".", "").isdigit():
            names.append(raw)
    subject = str(cert.get("subject") or "")
    for part in subject.split(","):
        piece = part.strip()
        if piece.lower().startswith("cn="):
            names.append(piece.split("=", 1)[1].strip().lower())
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out
