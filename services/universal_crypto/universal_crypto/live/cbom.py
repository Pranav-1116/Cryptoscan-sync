"""§35 Live CBOM producer.

Continuously produces a CycloneDX CBOM from the live crypto state:
algorithms, protocols, certificates, keys (metadata), crypto libraries,
implementations, crypto providers, hardware crypto and relationships.

Speaks the CycloneDX cryptography registry ecosystem — components carry
``cryptography`` type + the registry OID (see universal_crypto.registry.OID)
so algorithm families/variants (RSA-PKCS1, Ed25519, AES) use the standard
representation rather than a ZELNX-only one.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_crypto.live.state import LiveCryptoState
from universal_crypto.registry import oid_for


class LiveCbomProducer:
    """§35 CycloneDX CBOM from live state."""

    def produce(self, state: LiveCryptoState) -> dict[str, Any]:
        components: list[dict[str, Any]] = []
        relationships: list[dict[str, str]] = []

        def _component(comp_type: str, name: str, *,
                       oid: str = "", properties: Optional[list[dict[str, str]]] = None,
                       bom_ref: str = "") -> str:
            ref = bom_ref or f"{comp_type}:{name}"
            component = {
                "type": comp_type,
                "bom-ref": ref,
                "name": name,
            }
            if oid:
                component["cryptography"] = {"algorithm": {"oid": oid}}
            if properties:
                component["properties"] = properties
            components.append(component)
            return ref

        app_ref = _component("application", state.asset_id,
                             properties=[{"name": "live-state", "value": "true"}])

        # algorithms
        for algorithm, details in sorted(state.algorithms.items()):
            alg_ref = _component("cryptography", algorithm,
                                 oid=oid_for(algorithm),
                                 properties=[
                                     {"name": "operation",
                                      "value": str(details.get("operation") or "")},
                                     {"name": "quantum-status",
                                      "value": state.quantum_status.get(algorithm, "PQC_UNKNOWN")},
                                     {"name": "usage",
                                      "value": str(bool(state.usage.get(algorithm, False))).lower()},
                                 ])
            relationships.append({"source": app_ref, "target": alg_ref,
                                  "relationship": "uses"})

        # protocols
        for protocol, details in sorted(state.protocols.items()):
            proto_ref = _component("protocol", protocol, oid=oid_for(protocol),
                                   properties=[
                                       {"name": "min-version",
                                        "value": str(details.get("min_version") or "")},
                                       {"name": "pfs",
                                        "value": str(bool(details.get("pfs", False))).lower()},
                                   ])
            relationships.append({"source": app_ref, "target": proto_ref,
                                  "relationship": "uses"})

        # certificates
        for cert_id, details in sorted(state.certificates.items()):
            cert_ref = _component("certificate", cert_id,
                                  properties=[
                                      {"name": "signature-algorithm",
                                       "value": str(details.get("signature_algorithm") or "")},
                                      {"name": "public-key-algorithm",
                                       "value": str(details.get("public_key_algorithm") or "")},
                                      {"name": "key-size",
                                       "value": str(details.get("key_size") or "")},
                                      {"name": "status",
                                       "value": str(details.get("status") or "")},
                                  ])
            relationships.append({"source": app_ref, "target": cert_ref,
                                  "relationship": "uses"})
            sig_alg = details.get("signature_algorithm")
            if sig_alg and sig_alg != "UNKNOWN":
                alg_ref = _component("cryptography", sig_alg, oid=oid_for(sig_alg))
                relationships.append({"source": cert_ref, "target": alg_ref,
                                      "relationship": "uses"})

        # libraries / implementations / providers
        for library, details in sorted(state.libraries.items()):
            lib_ref = _component("library", library,
                                 properties=[
                                     {"name": "version", "value": str(details.get("version") or "")},
                                     {"name": "pqc-support",
                                      "value": str(bool(details.get("pqc_support", False))).lower()},
                                 ])
            relationships.append({"source": app_ref, "target": lib_ref,
                                  "relationship": "dependsOn"})
            if details.get("implementation"):
                impl_ref = _component("implementation", f"{library}:implementation")
                relationships.append({"source": lib_ref, "target": impl_ref,
                                      "relationship": "contains"})

        # hardware crypto capabilities (§27 — capability, not usage)
        for algorithm, supported in sorted(state.capabilities.items()):
            if supported:
                cap_ref = _component("device", f"hardware:{algorithm}",
                                     properties=[{"name": "capability", "value": "true"}])
                relationships.append({"source": app_ref, "target": cap_ref,
                                      "relationship": "invokes"})

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:live-cbom-{state.asset_id}-{state.cbom_version}",
            "version": state.cbom_version,
            "metadata": {
                "component": {"type": "application", "name": state.asset_id},
                "properties": [
                    {"name": "cbom-kind", "value": "live"},
                    {"name": "readiness", "value": state.readiness},
                    {"name": "agility", "value": str(state.agility)},
                    {"name": "quantum-status",
                     "value": _overall_quantum(state)},
                ],
            },
            "components": components,
            "relationships": relationships,
        }


def _overall_quantum(state: LiveCryptoState) -> str:
    statuses = set(state.quantum_status.values())
    if not statuses:
        return "PQC_UNKNOWN"
    if statuses == {"QUANTUM_SAFE"} or statuses == {"PQC_READY"}:
        return "PQC_READY"
    if "QUANTUM_VULNERABLE" in statuses:
        return "QUANTUM_VULNERABLE"
    return "PQC_UNKNOWN"
