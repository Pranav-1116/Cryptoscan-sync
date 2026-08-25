"""Discover TLS endpoints from hosts files and BIND-style zone files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

A_RECORD = re.compile(r"^(\S+)\s+(?:\d+\s+)?IN\s+A\s+(\S+)", re.I)
HOSTS = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(\S+)")


def parse_hosts(text: str) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        stripped = line.split("#", 1)[0].strip()
        match = HOSTS.match(stripped)
        if not match:
            continue
        host = match.group(2)
        if host in {"localhost", "broadcasthost"}:
            continue
        targets.append({"endpoint": f"{host}:443", "source": "hosts", "ip": match.group(1)})
    return targets


def parse_zone(text: str) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        match = A_RECORD.match(line.strip())
        if not match:
            continue
        name = match.group(1).rstrip(".")
        if name in {"@", "localhost"}:
            continue
        targets.append({"endpoint": f"{name}:443", "source": "dns-zone", "ip": match.group(2)})
    return targets


def discover_from_tree(root: Path) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    if not root.exists():
        return targets
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if name in {"hosts", "hosts.txt"} or name.endswith(".hosts"):
            targets.extend(parse_hosts(text))
        elif name.endswith(".zone") or name.endswith(".db") and "IN A" in text:
            targets.extend(parse_zone(text))
    return targets
