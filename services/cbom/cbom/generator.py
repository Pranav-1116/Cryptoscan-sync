"""Legacy1.5 CryptoScan exports and explicit native CycloneDX1.6 JSON profile."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring

# round 38: oid/primitive mapping moved with construction into the
# component registry

#: recorded observation confidence -> CycloneDX evidence-method confidence.
#: Unrecorded confidence keeps the historical source-analysis default (0.9);
#: nothing is ever rounded up (report 08 P1#6 - confidence propagation).
_CONFIDENCE_SCORES = {
    "HIGH": 0.9,
    "CONFIRMED": 0.9,
    "MEDIUM": 0.6,
    "LIKELY": 0.6,
    "LOW": 0.3,
    "TENTATIVE": 0.3,
}
from shared_models.canonical import (
    b64url_decode,
    b64url_encode,
    canonical_bytes,
    canonical_json,
    constant_time_eq,
    hmac_sha256,
)


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
        metadata_properties: list[dict[str, Any]] | None = None,
        scan_id: str | None = None,
        spec_version: str = "1.5",
    ) -> dict[str, Any]:
        if spec_version not in {"1.5", "1.6"}:
            raise ValueError("Only legacy1.5 and native1.6 JSON exports are supported")
        def is_receipt(record):
            data = record.to_dict() if hasattr(record, "to_dict") else record if isinstance(record, dict) else {"finding_data": getattr(record, "finding_data", {})}
            finding = data.get("finding_data") or data.get("finding") or data if isinstance(data, dict) else {}
            return finding.get("finding_type") == "HOST_COLLECTION_RECEIPT" and bool(finding.get("host_evidence"))
        components = [self._component(record) for record in records if not is_receipt(record)]
        metadata: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": name, "version": version},
            "tools": [{"name": "CryptoScan", "version": tool_version}],
        }
        if metadata_properties:
            metadata["properties"] = list(metadata_properties)
        digest = hashlib.sha256(name.encode()).hexdigest()[:32]
        uuid_text = f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
        bom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid_text}",
            "metadata": metadata,
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
        # Report 08 P2#7: compositions + externalReferences.
        #
        # ``compositions`` is the honest completeness claim: a discovery-based
        # CBOM lists what the scanners found, never a guarantee of coverage,
        # so the assemblies aggregate is INCOMPLETE (CycloneDX semantics:
        # "the component list may not be exhaustive"). Claiming COMPLETE
        # would be fabricated assurance.
        if components:
            bom["compositions"] = [
                {
                    "aggregate": "INCOMPLETE",
                    "assemblies": [
                        str(item["bom-ref"]) for item in components if item.get("bom-ref")
                    ],
                }
            ]
        # ``externalReferences``: provenance back to the scan that produced
        # this BOM (urn form — a resolvable pointer within the deployment).
        refs: list[dict[str, str]] = []
        if scan_id:
            refs.append({"type": "provenance", "url": f"urn:cryptoscan:scan:{scan_id}"})
        if refs:
            bom["externalReferences"] = refs
        root_ref = None
        if dependencies:
            bom["dependencies"] = dependencies
        elif components:
            bom_metadata = dict(bom.get("metadata") or {})
            meta_component = dict(bom_metadata.get("component") or {})
            root_ref = str(meta_component.get("bom-ref") or f"root:{name}")
            meta_component["bom-ref"] = root_ref
            bom_metadata["component"] = meta_component
            bom["metadata"] = bom_metadata
            bom["dependencies"] = [
                {
                    "ref": root_ref,
                    "dependsOn": [str(item.get("bom-ref")) for item in components if item.get("bom-ref")],
                }
            ]
        if spec_version == "1.6":
            from cbom.cyclonedx16 import to_cyclonedx16
            return to_cyclonedx16(bom, omit_inventory_dependencies=dependencies is None)
        return bom

    def validate(self, bom: dict[str, Any]) -> dict[str, Any]:
        if bom.get("specVersion") == "1.6":
            from cbom.cyclonedx16 import validate_cyclonedx16
            return validate_cyclonedx16(bom)
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
        """CycloneDX 1.5 XML serialization with full CBOM fidelity:
        cryptoProperties (assetType/oid/nistDesignation/primitive), evidence,
        metadata properties (incl. cryptoscan:jws), dependencies and
        vulnerabilities. ``quantumVulnerable`` is deliberately absent: it is not a
        CycloneDX 1.5 field, and a boolean could not carry the status anyway —
        the JSON export writes ``cryptoscan:quantum_status`` instead."""
        if bom.get("specVersion") == "1.6":
            raise ValueError("Native CycloneDX1.6 export supports JSON only; legacy XML cannot serialize it")
        root = Element("bom")
        root.set("xmlns", "http://cyclonedx.org/schema/bom/1.5")
        root.set("version", str(bom.get("version") or 1))
        if bom.get("serialNumber"):
            root.set("serialNumber", str(bom["serialNumber"]))

        meta = bom.get("metadata") or {}
        metadata = SubElement(root, "metadata")
        ts = SubElement(metadata, "timestamp")
        ts.text = str(meta.get("timestamp") or "")
        component = SubElement(metadata, "component")
        component.set("type", str((meta.get("component") or {}).get("type") or "application"))
        if (meta.get("component") or {}).get("bom-ref"):
            component.set("bom-ref", str(meta["component"]["bom-ref"]))
        name = SubElement(component, "name")
        name.text = str((meta.get("component") or {}).get("name") or "target")
        if (meta.get("component") or {}).get("version"):
            version_el = SubElement(component, "version")
            version_el.text = str(meta["component"]["version"])
        for prop in meta.get("properties") or []:
            if not isinstance(prop, dict):
                continue
            props_el = SubElement(metadata, "properties")
            prop_el = SubElement(props_el, "property")
            prop_el.set("name", str(prop.get("name") or ""))
            prop_el.text = str(prop.get("value") or "")

        components_el = SubElement(root, "components")
        for item in bom.get("components") or []:
            el = SubElement(components_el, "component")
            el.set("type", str(item.get("type") or "cryptographic-asset"))
            el.set("bom-ref", str(item.get("bom-ref") or ""))
            n = SubElement(el, "name")
            n.text = str(item.get("name") or "UNKNOWN")
            crypto = item.get("cryptoProperties") or {}
            if crypto:
                props = SubElement(el, "cryptoProperties")
                asset_type = SubElement(props, "assetType")
                asset_type.text = str(crypto.get("assetType") or "algorithm")
                if crypto.get("oid"):
                    oid = SubElement(props, "oid")
                    oid.text = str(crypto["oid"])
                algo_props = crypto.get("algorithmProperties") or {}
                primitive = algo_props.get("primitive")
                if primitive:
                    prim = SubElement(props, "algorithmProperties")
                    prim_el = SubElement(prim, "primitive")
                    prim_el.text = str(primitive)
                if crypto.get("nistDesignation"):
                    nist = SubElement(props, "nistDesignation")
                    nist.text = str(crypto["nistDesignation"])
            evidence = item.get("evidence") or {}
            if evidence.get("file"):
                ev = SubElement(el, "evidence")
                occ = SubElement(ev, "occurrence")
                loc = SubElement(occ, "location")
                loc.text = str(evidence.get("file"))
            for ref in item.get("externalReferences") or []:
                if isinstance(ref, dict) and ref.get("url"):
                    refs_el = SubElement(el, "externalReferences")
                    ref_el = SubElement(refs_el, "reference")
                    ref_el.set("type", str(ref.get("type") or "other"))
                    url_el = SubElement(ref_el, "url")
                    url_el.text = str(ref["url"])
                if evidence.get("line") is not None:
                    line = SubElement(occ, "line")
                    line.text = str(evidence.get("line"))

        dependencies = bom.get("dependencies") or []
        if dependencies:
            deps_el = SubElement(root, "dependencies")
            for dep in dependencies:
                if not isinstance(dep, dict):
                    continue
                dep_el = SubElement(deps_el, "dependency")
                dep_el.set("ref", str(dep.get("ref") or ""))
                for child in dep.get("dependsOn") or []:
                    child_el = SubElement(deps_el, "dependency")
                    child_el.set("ref", str(child))

        vulnerabilities = bom.get("vulnerabilities") or []
        if vulnerabilities:
            vulns_el = SubElement(root, "vulnerabilities")
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                vuln_el = SubElement(vulns_el, "vulnerability")
                vuln_el.set("ref", str(vuln.get("id") or ""))
                if vuln.get("id"):
                    vid = SubElement(vuln_el, "id")
                    vid.text = str(vuln["id"])
                ratings = vuln.get("ratings") or []
                if ratings:
                    rating_el = SubElement(vuln_el, "ratings")
                    score_el = SubElement(rating_el, "severity")
                    score_el.text = str((ratings[0] or {}).get("severity") or "unknown")

        for ref in bom.get("externalReferences") or []:
            if isinstance(ref, dict) and ref.get("url"):
                refs_el = SubElement(root, "externalReferences")
                ref_el = SubElement(refs_el, "reference")
                ref_el.set("type", str(ref.get("type") or "other"))
                url_el = SubElement(ref_el, "url")
                url_el.text = str(ref["url"])
        for comp in bom.get("compositions") or []:
            if not isinstance(comp, dict):
                continue
            comps_el = SubElement(root, "compositions")
            comp_el = SubElement(comps_el, "composition")
            comp_el.set("aggregate", str(comp.get("aggregate") or "UNKNOWN"))
            assemblies = comp.get("assemblies") or []
            if assemblies:
                asm_el = SubElement(comp_el, "assemblies")
                for ref in assemblies:
                    a = SubElement(asm_el, "assembly")
                    a.set("ref", str(ref))

        return tostring(root, encoding="unicode")

    def sign(self, bom: dict[str, Any], secret: str, *, key_id: str | None = None) -> dict[str, Any]:
        """Sign with a standards-compliant JWS (HS256, RFC 7515 compact form).

        The JWS is stored as the `cryptoscan:jws` metadata property and covers
        the canonical JSON of the BOM without signature properties, so any
        RFC 7515 verifier can validate it independently of CryptoScan.
        ``key_id`` is embedded as the JWS ``kid`` header so verification can
        pick the right key after rotation.
        """
        unsigned = self._without_signature(bom)
        payload = canonical_bytes(unsigned)
        header_fields: dict[str, Any] = {"alg": "HS256", "typ": "JWT"}
        if key_id:
            header_fields["kid"] = key_id
        header = canonical_json(header_fields).encode("utf-8")
        signing_input = f"{b64url_encode(header)}.{b64url_encode(payload)}".encode("ascii")
        signature = hmac_sha256(secret, signing_input)
        jws = signing_input.decode("ascii") + "." + b64url_encode(signature)

        signed = dict(unsigned)
        metadata = dict(signed.get("metadata") or {})
        properties = [
            item
            for item in list(metadata.get("properties") or [])
            if item.get("name") not in {"cryptoscan:jws", "cryptoscan:signature", "cryptoscan:signatureAlg"}
        ]
        properties.append({"name": "cryptoscan:jws", "value": jws})
        properties.append({"name": "cryptoscan:signatureAlg", "value": "JWS-HS256"})
        metadata["properties"] = properties
        signed["metadata"] = metadata
        return signed

    def sign_standard(
        self,
        bom: dict[str, Any],
        key: Any,
        alg: str = "ES256",
        *,
        key_id: str | None = None,
    ) -> dict[str, Any]:
        """Sign with the CycloneDX-spec standard enveloped signature (JSF).

        Emits the top-level ``signature`` field CycloneDX >= 1.4 defines
        (report 08 P2#6): ``{algorithm, publicKey (JWK) | keyId, value}``
        where the signed bytes are the document with ``signature.value``
        removed — verifiable by any JSF implementation, no
        CryptoScan-specific property required.
        """
        from cbom.signing.jsf_signer import sign_jsf

        return sign_jsf(bom, key, alg=alg, key_id=key_id)

    def verify_standard(self, bom: dict[str, Any], key: Any = None) -> tuple[bool, str | None]:
        """Verify the standard ``signature`` field. ``key`` None uses the
        embedded JWK (integrity); pass a trusted key for authenticity."""
        from cbom.signing.jsf_signer import verify_jsf

        return verify_jsf(bom, key)

    def sign_jws(
        self,
        bom: dict[str, Any],
        private_key,
        alg: str = "RS256",
        *,
        key_id: str | None = None,
    ) -> dict[str, Any]:
        """Sign with a real RFC 7515 JWS (RS256/ES256/HS256) over the
        canonical BOM body. ``private_key`` is a PEM string/bytes or a
        ``cryptography`` private key object."""
        from cbom.signing.jws_signer import sign_cbom_jws

        return sign_cbom_jws(bom, private_key, alg=alg, key_id=key_id)

    def verify_jws(self, bom: dict[str, Any], public_key) -> tuple[bool, str]:
        """Verify a JWS-signed BOM with a public key (or shared secret for
        HS256). Returns (ok, error)."""
        from cbom.signing.jws_signer import verify_cbom_jws

        return verify_cbom_jws(bom, public_key)

    def verify(self, bom: dict[str, Any], secret: str | dict[str, str]) -> bool:
        """True iff the BOM carries a valid signature (JWS, or legacy HMAC)."""
        return self.verify_report(bom, secret)["ok"]

    def verify_report(
        self, bom: dict[str, Any], secret: str | dict[str, str]
    ) -> dict[str, Any]:
        """Structured verification result: what was checked and what failed.

        ``secret`` is either the current HMAC secret or a keyring mapping
        ``kid -> secret`` (used first when the JWS carries a ``kid``).
        """
        props = {item.get("name"): item.get("value") for item in ((bom.get("metadata") or {}).get("properties") or [])}
        jws = props.get("cryptoscan:jws")
        keyring = secret if isinstance(secret, dict) else None
        primary = secret if isinstance(secret, str) else (keyring or {}).get("primary", "")

        def report(ok: bool, algorithm: str, checks: list[dict[str, Any]], error: str | None, key_id: Any = None):
            return {
                "ok": ok,
                "algorithm": algorithm,
                "key_id": key_id,
                "checks": checks,
                "error": error,
            }

        # report 08 P2#6: the CycloneDX-spec standard ``signature`` field
        # takes precedence; the property-based JWS remains the fallback.
        if isinstance(bom.get("signature"), dict) and bom["signature"].get("value"):
            from cbom.signing.jsf_signer import verify_jsf

            alg_name = str(bom["signature"].get("algorithm") or "").upper()
            if alg_name == "HS256":
                if isinstance(secret, dict):
                    # keyring: kid first (rotation), primary as fallback
                    kid = bom["signature"].get("keyId")
                    key = (secret.get(kid) if kid else None) or secret.get("primary")
                else:
                    key = secret
            else:
                # asymmetric: the shared-secret argument cannot carry an
                # EC/RSA public key — verify against the embedded JWK
                # (integrity). Authenticity with a trusted PEM goes through
                # verify_standard / a configured public key.
                key = None
            ok, error = verify_jsf(bom, key if key else None)
            return report(
                ok,
                str(bom["signature"].get("algorithm") or "JSF"),
                [
                    {"name": "standard_signature_field", "passed": ok},
                    {"name": "value_decodes_and_matches", "passed": ok},
                ],
                error,
                key_id=bom["signature"].get("keyId"),
            )

        if jws:
            checks: list[dict[str, Any]] = []
            try:
                parts = str(jws).split(".")
                if len(parts) != 3:
                    checks.append({"name": "jws_format", "ok": False, "detail": f"{len(parts)} segments"})
                    return report(False, "JWS-HS256", checks, "malformed JWS: expected header.payload.signature")
                checks.append({"name": "jws_format", "ok": True, "detail": "3 segments"})
                header_b64, payload_b64, sig_b64 = parts
                header = json.loads(b64url_decode(header_b64))
                alg = header.get("alg")
                if alg != "HS256":
                    checks.append({"name": "algorithm", "ok": False, "detail": f"alg={alg}"})
                    return report(False, "JWS-HS256", checks, f"unsupported JWS algorithm: {alg}")
                checks.append({"name": "algorithm", "ok": True, "detail": "HS256"})

                kid = header.get("kid")
                if keyring is not None and kid:
                    key = keyring.get(str(kid), "")
                    if not key:
                        checks.append({"name": "key_resolution", "ok": False, "detail": f"kid={kid} not in keyring"})
                        return report(False, "JWS-HS256", checks, f"unknown key id: {kid}", key_id=kid)
                    checks.append({"name": "key_resolution", "ok": True, "detail": f"kid={kid}"})
                else:
                    key = primary
                    checks.append({"name": "key_resolution", "ok": bool(key), "detail": "primary key" if key else "no key"})
                    if not key:
                        return report(False, "JWS-HS256", checks, "no signing key provided", key_id=kid)

                signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
                expected_sig = hmac_sha256(key, signing_input)
                actual_sig = b64url_decode(sig_b64)
                signature_ok = constant_time_eq(actual_sig, expected_sig)
                checks.append({"name": "signature", "ok": signature_ok})
                unsigned = json.loads(b64url_decode(payload_b64))
                # The JWS payload must be the BOM itself (minus signature props).
                canonical = self._without_signature(bom)
                payload_ok = unsigned == json.loads(canonical_json(canonical))
                checks.append({"name": "payload_matches_bom", "ok": payload_ok})
                if not signature_ok and not payload_ok:
                    error = "signature invalid and payload does not match the BOM"
                elif not signature_ok:
                    error = "signature does not verify (wrong key or tampered header)"
                elif not payload_ok:
                    error = "payload does not match the BOM (tampered content)"
                else:
                    error = None
                return report(signature_ok and payload_ok, "JWS-HS256", checks, error, key_id=kid)
            except Exception as exc:
                return report(False, "JWS-HS256", checks, f"verification error: {exc}")

        # Legacy format (pre-JWS): bare HMAC-SHA256 hex digest property.
        expected = props.get("cryptoscan:signature")
        checks = [{"name": "legacy_property_present", "ok": bool(expected)}]
        if not expected:
            return report(False, "legacy-hmac-sha256", checks, "no signature properties on BOM")
        digest = hmac_sha256(primary, canonical_bytes(self._without_signature(bom))).hex()
        digest_ok = constant_time_eq(str(expected), digest)
        checks.append({"name": "signature", "ok": digest_ok})
        return report(
            digest_ok,
            "legacy-hmac-sha256",
            checks,
            None if digest_ok else "legacy HMAC digest mismatch",
        )

    def _without_signature(self, bom: dict[str, Any]) -> dict[str, Any]:
        cleaned = dict(bom)
        metadata = dict(cleaned.get("metadata") or {})
        properties = [
            item
            for item in list(metadata.get("properties") or [])
            if item.get("name") not in {"cryptoscan:jws", "cryptoscan:signature", "cryptoscan:signatureAlg"}
        ]
        if properties:
            metadata["properties"] = properties
        else:
            metadata.pop("properties", None)
        cleaned["metadata"] = metadata
        return cleaned

    def _component(self, record: Any) -> dict[str, Any]:
        # round 38: construction lives in the component registry (the
        # 46 single-generator merge) — the generator is an assembler
        from cbom.component_registry import cbom_crypto_component

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
                "confidence": getattr(record, "confidence", None),
                "system_name": getattr(record, "system_name", None),
                "system_id": getattr(record, "system_id", None),
            }
        finding = data.get("finding_data") or data.get("finding") or data
        reference = finding.get("host_evidence")
        if reference:
            from shared_models.host_collection import HostEvidenceRef
            ref = HostEvidenceRef.model_validate(reference).model_dump(mode="json")
            # Offline host facts have no trusted normalization/policy rollup.
            # Build from the hash-covered source, never mutable enrichment or
            # caller-supplied bank-context columns alongside that source.
            data = {"id": data.get("id") or data.get("evidence_id") or data.get("finding_id"),
                    **finding.get("crypto", {}), "source_basis": "IMPORTED", "confidence": "LOW",
                    "system_id": ref["system_id"], "host_evidence": ref, "library": "UNKNOWN",
                    "content_hash": data.get("content_hash"), "chain_hash": data.get("chain_hash"),
                    "normalized_crypto": {}, "compliance_status": None,
                    "file_path": finding.get("source", {}).get("file_path"), "line_number": 0}
        return cbom_crypto_component(data)
