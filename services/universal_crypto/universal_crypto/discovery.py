"""§1 Universal Crypto Discovery.

Detect cryptography from every source the platform touches — source code,
binaries, shared libraries, package dependencies, configuration,
certificates, key *metadata*, trust stores, network protocols (TLS/SSH/IPsec/
VPN), databases, APIs, HSMs, TPMs, network devices, cloud services,
containers, Kubernetes, firmware metadata, applications, CI/CD and
infrastructure-as-code.

Every source emits the same draft shape and the orchestrator **correlates**
observations across sources instead of treating each discovery independently:
the same algorithm found in source *and* TLS *and* a certificate becomes one
observation with multi-source evidence (§28 feeds on this).
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from universal_crypto.models import Evidence, EvidenceType, Operation
from universal_crypto.registry import find as registry_find

#: the 25 discovery sources (§1)
SOURCES = [
    "source_code", "binaries", "shared_libraries", "package_dependencies",
    "configuration", "certificates", "keys_metadata", "trust_stores",
    "network_protocols", "tls_endpoints", "ssh", "ipsec", "vpn",
    "databases", "apis", "hsms", "tpms", "network_devices", "cloud_services",
    "containers", "kubernetes", "firmware_metadata", "applications",
    "ci_cd", "infrastructure_as_code",
]

_SOURCE_LABELS = {
    "source_code": "source code (AST/semantic)",
    "binaries": "binary analysis (ELF/PE/Mach-O/WASM)",
    "shared_libraries": "shared library inventory",
    "package_dependencies": "package dependency manifests",
    "configuration": "configuration files",
    "certificates": "certificate analysis (metadata only)",
    "keys_metadata": "key metadata (never secret material)",
    "trust_stores": "trust store analysis",
    "network_protocols": "protocol analysis",
    "tls_endpoints": "TLS endpoint scanning",
    "ssh": "SSH configuration/host keys",
    "ipsec": "IPsec/VPN policy",
    "vpn": "VPN crypto policy",
    "databases": "database crypto configuration",
    "apis": "management API crypto settings",
    "hsms": "HSM capabilities",
    "tpms": "TPM capabilities",
    "network_devices": "network device crypto config",
    "cloud_services": "cloud service crypto settings",
    "containers": "container image analysis",
    "kubernetes": "Kubernetes secrets metadata / ingress TLS",
    "firmware_metadata": "firmware crypto metadata",
    "applications": "application runtime metadata",
    "ci_cd": "CI/CD pipeline crypto config",
    "infrastructure_as_code": "IaC templates (Terraform/CloudFormation/...)",
}


class Draft:
    """Raw discovery draft before canonicalization/fusion."""

    def __init__(
        self,
        *,
        algorithm: str,
        operation: Optional[Operation] = None,
        library: Optional[str] = None,
        key_size: Optional[int] = None,
        curve: Optional[str] = None,
        padding: Optional[str] = None,
        digest: Optional[str] = None,
        protocol: Optional[str] = None,
        asset_id: str = "default",
        location: str = "",
        source: str = "source_code",
        detail: str = "",
        usage: bool = False,
        capability: bool = False,
        raw: Optional[dict[str, Any]] = None,
    ) -> None:
        self.algorithm = algorithm
        self.operation = operation
        self.library = library
        self.key_size = key_size
        self.curve = curve
        self.padding = padding
        self.digest = digest
        self.protocol = protocol
        self.asset_id = asset_id
        self.location = location
        self.source = source
        self.detail = detail
        self.usage = usage
        self.capability = capability
        self.raw = raw or {}

    def to_evidence(self) -> Evidence:
        kind = _EVIDENCE_KIND.get(self.source, EvidenceType.CONFIG)
        return Evidence(kind=kind, detail=self.detail or self.algorithm, location=self.location)

    def canonical_algorithm(self) -> str:
        entry = registry_find(self.algorithm)
        return entry.algorithm if entry else self.algorithm.upper()


_EVIDENCE_KIND: dict[str, EvidenceType] = {
    "source_code": EvidenceType.AST,
    "binaries": EvidenceType.BINARY,
    "shared_libraries": EvidenceType.BINARY,
    "package_dependencies": EvidenceType.DEPENDENCY,
    "configuration": EvidenceType.CONFIG,
    "certificates": EvidenceType.CERTIFICATE,
    "keys_metadata": EvidenceType.KEY_METADATA,
    "trust_stores": EvidenceType.TRUST_STORE,
    "network_protocols": EvidenceType.PROTOCOL,
    "tls_endpoints": EvidenceType.PROTOCOL,
    "ssh": EvidenceType.PROTOCOL,
    "ipsec": EvidenceType.PROTOCOL,
    "vpn": EvidenceType.PROTOCOL,
    "databases": EvidenceType.CONFIG,
    "apis": EvidenceType.CONFIG,
    "hsms": EvidenceType.CONFIG,
    "tpms": EvidenceType.CONFIG,
    "network_devices": EvidenceType.CONFIG,
    "cloud_services": EvidenceType.CONFIG,
    "containers": EvidenceType.BINARY,
    "kubernetes": EvidenceType.CONFIG,
    "firmware_metadata": EvidenceType.CONFIG,
    "applications": EvidenceType.RUNTIME,
    "ci_cd": EvidenceType.CONFIG,
    "infrastructure_as_code": EvidenceType.CONFIG,
}


# --------------------------------------------------------------------------- #
# per-source adapters — each takes its structured input and emits drafts
# --------------------------------------------------------------------------- #

_DRAFT_FIELDS = frozenset({
    "algorithm", "operation", "library", "key_size", "curve", "padding",
    "digest", "usage", "capability", "raw",
})


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Keep only Draft fields; map 'operation' strings to the Operation enum."""
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key not in _DRAFT_FIELDS:
            continue
        if key == "operation" and isinstance(value, str):
            try:
                value = Operation(value.lower())
            except ValueError:
                continue  # unknown operation — drop rather than guess
        out[key] = value
    return out


def _iter_algos(value: Any) -> list[dict[str, Any]]:
    """Normalize one of: str, [str], {name: details}, [{...}], {row}."""
    out: list[dict[str, Any]] = []
    if isinstance(value, str):
        out.append({"algorithm": value})
    elif isinstance(value, list):
        for item in value:
            out.extend(_iter_algos(item))
    elif isinstance(value, dict):
        if "algorithm" in value:  # a single row dict, not a name→details map
            out.append(_normalize_row(value))
            return out
        for name, details in value.items():
            row: dict[str, Any] = {"algorithm": name}
            if isinstance(details, dict):
                row.update(_normalize_row(details))
            elif isinstance(details, (int, float)):
                row["key_size"] = int(details)
            out.append(row)
    return out


class UniversalDiscovery:
    """Runs every §1 source that has input and correlates the drafts."""

    def __init__(self) -> None:
        self.drafts: list[Draft] = []
        self.sources_run: list[str] = []

    # -- per-source adapters (deterministic) ------------------------------

    def _source_code(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="source_code",
                             detail="semantic API/import match in source",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _binaries(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="binaries",
                             detail="binary symbol/import/constant evidence",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _shared_libraries(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="shared_libraries",
                             detail="library symbol table evidence",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _package_dependencies(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="package_dependencies",
                             detail="dependency manifest entry",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _configuration(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="configuration",
                             detail="crypto configuration value",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _certificates(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="certificates",
                             detail="certificate public-key/signature algorithm",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _keys_metadata(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="keys_metadata",
                             detail="key metadata record (no secret material)",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _trust_stores(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="trust_stores",
                             detail="trust anchor / CA algorithm",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _network_protocols(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="network_protocols",
                             protocol=row.get("protocol") or inputs.get("protocol"),
                             detail="protocol algorithm (TLS/SSH/IPsec/QUIC)",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _tls_endpoints(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="tls_endpoints", protocol="TLS",
                             detail="TLS handshake algorithm observation",
                             location=str(inputs.get("endpoint") or inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _ssh(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="ssh", protocol="SSH",
                             detail="SSH algorithm (host key/KEX/cipher/MAC)",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _ipsec(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="ipsec", protocol="IPsec",
                             detail="IPsec/IKE algorithm",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _vpn(self, inputs: Any) -> list[Draft]:
        return self._ipsec(inputs)  # VPN policy maps through the IPsec adapter

    def _databases(self, inputs: Any) -> list[Draft]:
        return self._configuration(inputs)

    def _apis(self, inputs: Any) -> list[Draft]:
        return self._configuration(inputs)

    def _hsms(self, inputs: Any) -> list[Draft]:
        return self._capability_drafts(inputs, "hsms")

    def _tpms(self, inputs: Any) -> list[Draft]:
        return self._capability_drafts(inputs, "tpms")

    def _capability_drafts(self, inputs: Any, source: str) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("capabilities", inputs)):
            out.append(Draft(**row, source=source, capability=True,
                             detail="hardware crypto capability (support ≠ usage, §27)",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _network_devices(self, inputs: Any) -> list[Draft]:
        return self._configuration(inputs)

    def _cloud_services(self, inputs: Any) -> list[Draft]:
        return self._configuration(inputs)

    def _containers(self, inputs: Any) -> list[Draft]:
        return self._binaries(inputs)

    def _kubernetes(self, inputs: Any) -> list[Draft]:
        return self._configuration(inputs)

    def _firmware_metadata(self, inputs: Any) -> list[Draft]:
        return self._configuration(inputs)

    def _applications(self, inputs: Any) -> list[Draft]:
        out = []
        for row in _iter_algos(inputs.get("algorithms", inputs)):
            out.append(Draft(**row, source="applications", usage=True,
                             detail="runtime observation — capability exercised (§27)",
                             location=str(inputs.get("location") or ""),
                             asset_id=str(inputs.get("asset_id") or "default")))
        return out

    def _ci_cd(self, inputs: Any) -> list[Draft]:
        return self._configuration(inputs)

    def _infrastructure_as_code(self, inputs: Any) -> list[Draft]:
        return self._configuration(inputs)

    # -- orchestrator ------------------------------------------------------

    def discover(self, sources: dict[str, Any]) -> "UniversalDiscovery":
        """Run the adapters for every §1 source that has input.

        ``sources`` maps source name -> structured input (see tests for the
        shape). Returns self; drafts land in ``self.drafts``.
        """
        self.drafts = []
        self.sources_run = []
        for name in SOURCES:
            if name not in sources:
                continue
            inputs = sources[name]
            if inputs is None or inputs == {}:
                continue
            adapter: Callable[[Any], list[Draft]] = getattr(self, f"_{name}")
            self.drafts.extend(adapter(inputs))
            self.sources_run.append(name)
        return self

    # -- §1 correlation ----------------------------------------------------

    def correlate(self) -> list[dict[str, Any]]:
        """Merge drafts by (asset, canonical algorithm, operation).

        Returns correlated groups: every group carries the evidence of all
        sources that saw it — source + TLS + certificate for the same
        algorithm become one group with multi-source evidence, never three
        independent findings.
        """
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for draft in self.drafts:
            alg = draft.canonical_algorithm()
            key = (draft.asset_id, alg)
            group = groups.setdefault(key, {
                "asset_id": draft.asset_id,
                "algorithm": alg,
                "operation": None,
                "library": draft.library,
                "key_size": draft.key_size,
                "curve": draft.curve,
                "padding": draft.padding,
                "digest": draft.digest,
                "protocol": draft.protocol,
                "usage": draft.usage,
                "capability": draft.capability,
                "sources": [],
                "evidence": [],
                "locations": [],
            })
            group["sources"].append(draft.source)
            group["evidence"].append(draft.to_evidence())
            if draft.location and draft.location not in group["locations"]:
                group["locations"].append(draft.location)
            if draft.usage:
                group["usage"] = True
            if draft.capability:
                group["capability"] = True
            if not group["operation"] and draft.operation:
                group["operation"] = draft.operation.value
        return list(groups.values())
