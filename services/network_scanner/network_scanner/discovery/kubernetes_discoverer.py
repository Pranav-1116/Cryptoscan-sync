"""Discover TLS endpoints from Kubernetes Service / Ingress manifests."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from pathlib import Path
from typing import Any

import yaml

from scanner.core.file_discovery import DEFAULT_EXCLUDED_DIRS


def discover_from_tree(root: str | Path) -> list[dict[str, Any]]:
    root_path = Path(root)
    if not root_path.exists():
        return []
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in root_path.rglob("*"):
        if not path.is_file():
            continue
        if any(part in DEFAULT_EXCLUDED_DIRS or part.startswith(".") for part in path.parts):
            continue
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8", errors="replace")))
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            continue
        for doc in documents:
            if not isinstance(doc, dict):
                continue
            kind = str(doc.get("kind") or "")
            spec = doc.get("spec") or {}
            if kind == "Ingress":
                tls_hosts = []
                for block in spec.get("tls") or []:
                    tls_hosts.extend(block.get("hosts") or [])
                rules = spec.get("rules") or []
                for rule in rules:
                    host = rule.get("host")
                    if host:
                        tls_hosts.append(host)
                for host in tls_hosts:
                    endpoint = f"{host}:443"
                    if endpoint in seen:
                        continue
                    seen.add(endpoint)
                    targets.append(
                        {
                            "endpoint": endpoint,
                            "source": str(path),
                            "kind": "Ingress",
                            "tls": True,
                        }
                    )
            if kind == "Service":
                ports = spec.get("ports") or []
                name = ((doc.get("metadata") or {}).get("name")) or "service"
                for port in ports:
                    number = port.get("port") or port.get("targetPort")
                    proto = str(port.get("name") or port.get("protocol") or "").lower()
                    if number in {443, 8443} or "https" in proto or "tls" in proto:
                        endpoint = f"{name}:{number}"
                        if endpoint in seen:
                            continue
                        seen.add(endpoint)
                        targets.append(
                            {
                                "endpoint": endpoint,
                                "source": str(path),
                                "kind": "Service",
                                "tls": True,
                            }
                        )
    return targets
