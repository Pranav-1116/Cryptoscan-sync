"""CycloneDX 1.5 Cryptographic Bill of Materials generator."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring


class CbomGenerator:
    def from_records(
        self,
        records: list[Any],
        *,
        name: str = "cryptoscan-target",
        version: str = "unknown",
        tool_version: str = "1.0.0",
    ) -> dict[str, Any]:
        components = [self._component(record) for record in records]
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{hashlib.sha256(name.encode()).hexdigest()[:32]}",
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": {"type": "application", "name": name, "version": version},
                "tools": [{"name": "CryptoScan", "version": tool_version}],
            },
            "components": components,
        }

    def to_json(self, bom: dict[str, Any]) -> str:
        return json.dumps(bom, indent=2, ensure_ascii=False)

    def to_xml(self, bom: dict[str, Any]) -> str:
        root = Element("bom")
        root.set("xmlns", "http://cyclonedx.org/schema/bom/1.5")
        root.set("version", str(bom.get("version") or 1))
        metadata = SubElement(root, "metadata")
        ts = SubElement(metadata, "timestamp")
        ts.text = str((bom.get("metadata") or {}).get("timestamp") or "")
        component = SubElement(metadata, "component")
        component.set("type", "application")
        name = SubElement(component, "name")
        name.text = str(((bom.get("metadata") or {}).get("component") or {}).get("name") or "target")
        components_el = SubElement(root, "components")
        for item in bom.get("components") or []:
            el = SubElement(components_el, "component")
            el.set("type", str(item.get("type") or "cryptographic-asset"))
            el.set("bom-ref", str(item.get("bom-ref") or ""))
            n = SubElement(el, "name")
            n.text = str(item.get("name") or "UNKNOWN")
        return tostring(root, encoding="unicode")

    def sign(self, bom: dict[str, Any], secret: str) -> dict[str, Any]:
        payload = json.dumps(bom, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        signed = dict(bom)
        metadata = dict(signed.get("metadata") or {})
        properties = list(metadata.get("properties") or [])
        properties.append({"name": "cryptoscan:signature", "value": digest})
        properties.append({"name": "cryptoscan:signatureAlg", "value": "HMAC-SHA256"})
        metadata["properties"] = properties
        signed["metadata"] = metadata
        return signed

    def _component(self, record: Any) -> dict[str, Any]:
        if hasattr(record, "to_dict"):
            data = record.to_dict()
        elif isinstance(record, dict):
            data = record
        else:
            data = {
                "id": getattr(record, "id", None),
                "algorithm": getattr(record, "algorithm", "UNKNOWN"),
                "mode": getattr(record, "mode", None),
                "padding": getattr(record, "padding", None),
                "key_size": getattr(record, "key_size", None),
                "file_path": getattr(record, "file_path", None),
                "line_number": getattr(record, "line_number", None),
                "content_hash": getattr(record, "content_hash", None),
                "chain_hash": getattr(record, "chain_hash", None),
                "compliance_status": getattr(record, "compliance_status", None),
                "normalized_crypto": getattr(record, "normalized_crypto", None),
            }
        normalized = data.get("normalized_crypto") or {}
        return {
            "type": normalized.get("cbom_component_type") or "cryptographic-asset",
            "name": normalized.get("standard_name") or data.get("algorithm") or "UNKNOWN",
            "bom-ref": data.get("id") or data.get("evidence_id") or data.get("finding_id"),
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": normalized.get("algorithm_family") or "unknown",
                    "algorithm": data.get("algorithm"),
                    "mode": data.get("mode"),
                    "padding": data.get("padding"),
                    "parameterSetIdentifier": str(data.get("key_size")) if data.get("key_size") else None,
                },
                "nistDesignation": normalized.get("nist_designation"),
                "quantumVulnerable": normalized.get("quantum_vulnerable"),
            },
            "evidence": {
                "file": data.get("file_path"),
                "line": data.get("line_number"),
                "content_hash": data.get("content_hash"),
                "chain_hash": data.get("chain_hash"),
                "compliance_status": data.get("compliance_status"),
            },
        }
