"""CycloneDX 1.5 Cryptographic Bill of Materials generator."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring

ALGORITHM_OIDS = {
    "AES": "2.16.840.1.101.3.4.1",
    "AES-128": "2.16.840.1.101.3.4.1.2",
    "AES-192": "2.16.840.1.101.3.4.1.22",
    "AES-256": "2.16.840.1.101.3.4.1.42",
    "SHA-1": "1.3.14.3.2.26",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA3-256": "2.16.840.1.101.3.4.2.8",
    "MD5": "1.2.840.113549.2.5",
    "RSA": "1.2.840.113549.1.1.1",
    "ECDSA": "1.2.840.10045.2.1",
    "DSA": "1.2.840.10040.4.1",
    "3DES": "1.2.840.113549.3.7",
    "DES": "1.3.14.3.2.7",
    "HMAC-SHA256": "1.2.840.113549.2.9",
    "HMAC-SHA1": "1.2.840.113549.2.7",
    "HMAC-SHA384": "1.2.840.113549.2.10",
    "HMAC-SHA512": "1.2.840.113549.2.11",
    "PBKDF2": "1.2.840.113549.1.5.12",
}

PRIMITIVES = {
    "AES": "block-cipher",
    "DES": "block-cipher",
    "3DES": "block-cipher",
    "RC2": "block-cipher",
    "RC4": "stream-cipher",
    "CHACHA20": "stream-cipher",
    "CHACHA20-POLY1305": "aead",
    "SHA-1": "hash",
    "SHA-256": "hash",
    "SHA-384": "hash",
    "SHA-512": "hash",
    "SHA3-256": "hash",
    "MD5": "hash",
    "HMAC-SHA256": "mac",
    "HMAC-SHA1": "mac",
    "HMAC-SHA384": "mac",
    "HMAC-SHA512": "mac",
    "HMACSHA256": "mac",
    "RSA": "pke",
    "ECDSA": "signature",
    "DSA": "signature",
    "ECDH": "key-agree",
    "PBKDF2": "kdf",
    "BCRYPT": "kdf",
    "SCRYPT": "kdf",
    "ARGON2": "kdf",
}


class CbomGenerator:
    def from_records(
        self,
        records: list[Any],
        *,
        name: str = "cryptoscan-target",
        version: str = "unknown",
        tool_version: str = "1.0.0",
        vulnerabilities: list[dict[str, Any]] | None = None,
        dependencies: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        components = [self._component(record) for record in records]
        bom: dict[str, Any] = {
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
        if vulnerabilities:
            bom["vulnerabilities"] = [
                {
                    "id": item.get("cve") or item.get("id"),
                    "source": {"name": "CryptoScan-local"},
                    "ratings": [{"severity": str(item.get("severity") or "unknown").lower()}],
                    "description": item.get("summary") or item.get("description"),
                    "affects": [{"ref": item.get("package") or item.get("bom-ref")}],
                }
                for item in vulnerabilities
            ]
        if dependencies:
            bom["dependencies"] = dependencies
        elif components:
            bom["dependencies"] = [
                {
                    "ref": str(((bom.get("metadata") or {}).get("component") or {}).get("name") or name),
                    "dependsOn": [str(item.get("bom-ref")) for item in components if item.get("bom-ref")],
                }
            ]
        return bom

    def validate(self, bom: dict[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        if bom.get("bomFormat") != "CycloneDX":
            errors.append("bomFormat must be CycloneDX")
        if bom.get("specVersion") not in {"1.4", "1.5", "1.6"}:
            errors.append("specVersion must be a CycloneDX 1.4+ release")
        if not isinstance(bom.get("components"), list):
            errors.append("components must be a list")
        for index, item in enumerate(bom.get("components") or []):
            if not item.get("name"):
                errors.append(f"components[{index}] missing name")
            if not item.get("cryptoProperties"):
                errors.append(f"components[{index}] missing cryptoProperties")
        return {"ok": not errors, "errors": errors}

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
        algorithm = str(data.get("algorithm") or normalized.get("standard_name") or "UNKNOWN")
        primitive = (
            normalized.get("algorithm_family")
            or PRIMITIVES.get(algorithm.upper())
            or PRIMITIVES.get(algorithm)
            or "unknown"
        )
        oid = ALGORITHM_OIDS.get(algorithm.upper()) or ALGORITHM_OIDS.get(algorithm)
        return {
            "type": normalized.get("cbom_component_type") or "cryptographic-asset",
            "name": normalized.get("standard_name") or data.get("algorithm") or "UNKNOWN",
            "bom-ref": data.get("id") or data.get("evidence_id") or data.get("finding_id"),
            "cryptoProperties": {
                "assetType": "algorithm",
                "oid": oid,
                "algorithmProperties": {
                    "primitive": primitive,
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
