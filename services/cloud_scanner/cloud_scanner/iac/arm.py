"""Parse Azure Resource Manager templates for Key Vault and storage crypto."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cloud_scanner.common.finding import cloud_finding


def looks_like_arm(path: Path, head: str = "") -> bool:
    name = path.name.lower()
    if "arm" in name or "azuredeploy" in name or name.endswith(".arm.json"):
        return True
    blob = head or ""
    return "deploymentTemplate.json" in blob or "Microsoft.KeyVault" in blob or "Microsoft.Storage" in blob


def parse_arm(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    resources = data.get("resources")
    if not isinstance(resources, list):
        return []
    findings: list[dict[str, Any]] = []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        rtype = str(resource.get("type") or "")
        name = str(resource.get("name") or rtype)
        props = resource.get("properties") or {}
        if "Microsoft.KeyVault/vaults/keys" in rtype or rtype.endswith("/keys"):
            kty = str(props.get("kty") or props.get("keyType") or "RSA")
            bits = props.get("keySize") or props.get("key_size")
            findings.append(
                cloud_finding(
                    source_type="AZURE_KEY_VAULT_KEY",
                    resource=name,
                    algorithm=kty.upper(),
                    key_size=int(bits) if bits else None,
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                    provider="AZURE",
                )
            )
        elif "Microsoft.KeyVault/vaults" in rtype:
            findings.append(
                cloud_finding(
                    source_type="AZURE_KEY_VAULT",
                    resource=name,
                    algorithm="RSA",
                    purpose="KEY_MANAGEMENT",
                    file_path=str(path),
                    provider="AZURE",
                )
            )
        elif "Microsoft.Storage/storageAccounts" in rtype:
            enc = ((props.get("encryption") or {}).get("services") or {})
            https = props.get("supportsHttpsTrafficOnly")
            if https is False or (not enc and props.get("encryption") is None):
                issue = "NO_ENCRYPTION" if not enc else "NO_HTTPS_ONLY"
                algo = None
            else:
                issue = None
                algo = "AES-256"
            findings.append(
                cloud_finding(
                    source_type="AZURE_STORAGE_ACCOUNT",
                    resource=name,
                    algorithm=algo,
                    purpose="DATA_AT_REST_ENCRYPTION",
                    file_path=str(path),
                    provider="AZURE",
                    issue=issue,
                )
            )
    return findings
