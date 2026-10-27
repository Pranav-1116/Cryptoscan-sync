"""Kubernetes TLS secrets, Ingress TLS, and encryption-config snippets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from cloud_scanner.common.finding import cloud_finding
from scanner.core.file_discovery import DEFAULT_EXCLUDED_DIRS


def parse_kubernetes_tree(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not root.exists():
        return findings
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        if any(part in DEFAULT_EXCLUDED_DIRS or part.startswith(".") for part in path.parts):
            continue
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8", errors="replace")))
        except Exception:
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = str(doc.get("kind") or "")
            spec = doc.get("spec") or {}
            meta = (doc.get("metadata") or {}).get("name") or path.name
            if kind == "Secret" and str(doc.get("type") or "") == "kubernetes.io/tls":
                findings.append(
                    cloud_finding(
                        source_type="K8S_TLS_SECRET",
                        resource=str(meta),
                        algorithm="TLS",
                        purpose="TLS_CERTIFICATE",
                        file_path=str(path),
                        provider="KUBERNETES",
                    )
                )
            if kind == "Ingress" and spec.get("tls"):
                findings.append(
                    cloud_finding(
                        source_type="K8S_INGRESS_TLS",
                        resource=str(meta),
                        algorithm="TLS",
                        purpose="LOAD_BALANCER_TLS",
                        file_path=str(path),
                        provider="KUBERNETES",
                        extra={"hosts": [h for block in spec.get("tls") or [] for h in (block.get("hosts") or [])]},
                    )
                )
            if kind in {"EncryptionConfiguration", "EncryptionConfig"}:
                resources = spec.get("resources") or doc.get("resources") or []
                providers = []
                for item in resources:
                    for provider in (item.get("providers") or []):
                        providers.extend(provider.keys())
                aescbc = any(name.lower() == "aescbc" for name in providers)
                findings.append(
                    cloud_finding(
                        source_type="K8S_ENCRYPTION_CONFIG",
                        resource=str(meta),
                        algorithm="AES" if providers else None,
                        mode="CBC" if aescbc else None,
                        purpose="DATA_AT_REST_ENCRYPTION",
                        file_path=str(path),
                        provider="KUBERNETES",
                        issue="WEAK_K8S_PROVIDER" if aescbc else None,
                    )
                )
    return findings
