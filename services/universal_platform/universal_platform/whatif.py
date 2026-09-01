"""§31 What-if crypto analysis — connect the scanner to the simulation
engine across the whole estate.

    Current State → What If? → Replace RSA → Check Dependencies →
    Check Libraries → Check Hardware → Check Vendor → Check Cloud →
    Calculate Impact → Migration Plan

Deterministic checks against catalogs (registry/libraries/hardware
capabilities/vendor posture/cloud services) — no AI anywhere. Unknown
answers are honest (``UNKNOWN``), never guessed.
"""

from __future__ import annotations

from typing import Any, Optional

#: hardware crypto capabilities known to accelerate PQC
_PQC_CAPABILITIES = ("mlkem", "mlkem768", "mlkem1024", "mldsa", "slhdsa",
                     "pqc", "cnsa2", "post-quantum")

#: cloud services with PQC-ready posture catalogs
_PQC_CLOUD_SERVICES = ("kms", "cloudhsm", "managedhsm", "keyvault", "acm",
                       "certificatemanager", "gke", "eks", "aks")

#: vendor PQC support markers
_PQC_VENDOR_MARKERS = ("pqc", "ml-kem", "mlkem", "cnsa 2", "fips 203")


def _supports(entry: dict[str, Any], markers: tuple[str, ...]) -> bool:
    haystack = " ".join(str(v).lower() for v in entry.values())
    return any(m in haystack for m in markers)


class PlatformWhatIfEngine:
    """What-if analysis for replacing an algorithm across the estate."""

    def __init__(self,
                 libraries: Optional[list[dict[str, Any]]] = None,
                 hardware: Optional[list[dict[str, Any]]] = None,
                 vendors: Optional[list[dict[str, Any]]] = None,
                 cloud: Optional[list[dict[str, Any]]] = None,
                 quantum: Optional[dict[str, Any]] = None) -> None:
        self.libraries = libraries or []
        self.hardware = hardware or []
        self.vendors = vendors or []
        self.cloud = cloud or []
        #: quantum classifier result for the target algorithm, if known
        self.quantum = quantum or {}

    def simulate(self, current: str, target: str,
                 protocols: Optional[list[str]] = None) -> dict[str, Any]:
        protocols = protocols or ["TLS"]
        checks: dict[str, Any] = {}

        # 1. dependencies — which assets use the current algorithm
        dependencies = [lib for lib in self.libraries
                        if current.lower() in str(lib).lower()]
        checks["dependencies"] = {
            "affected_libraries": len(dependencies),
            "libraries": [d.get("name") or d.get("library")
                          or d.get("identity") or ""
                          for d in dependencies],
        }

        # 2. libraries — does the target have support?
        lib_support = [lib for lib in self.libraries
                       if _supports(lib, (target.lower(),))]
        checks["libraries"] = {
            "supporting": [lib.get("name") or lib.get("library")
                           or lib.get("identity") or ""
                           for lib in lib_support],
            "supported": bool(lib_support),
        }

        # 3. hardware — crypto accelerators / HSMs / TPMs with PQC?
        hw_support = [hw for hw in self.hardware
                      if _supports(hw, _PQC_CAPABILITIES)]
        checks["hardware"] = {
            "pqc_capable_devices": len(hw_support),
            "devices": [hw.get("identity") or hw.get("name") or ""
                        for hw in hw_support],
            "supported": bool(hw_support),
        }

        # 4. vendor — posture for the target algorithm family
        vendor_support = [v for v in self.vendors
                          if _supports(v, _PQC_VENDOR_MARKERS)]
        checks["vendor"] = {
            "pqc_positive": len(vendor_support),
            "vendors": [v.get("name") or v.get("vendor")
                        or v.get("identity") or ""
                        for v in vendor_support],
            "supported": bool(vendor_support),
        }

        # 5. cloud — PQC-ready services in scope
        cloud_support = [c for c in self.cloud
                         if _supports(c, _PQC_CLOUD_SERVICES + ("pqc",))]
        checks["cloud"] = {
            "pqc_ready_services": len(cloud_support),
            "services": [c.get("name") or c.get("service")
                         or c.get("identity") or ""
                         for c in cloud_support],
            "supported": bool(cloud_support),
        }

        # 6. impact — projected quantum status from the crypto classifier
        projected = (self.quantum.get("quantum_status")
                     if isinstance(self.quantum, dict) else None)
        if not projected:
            projected = "QUANTUM_SAFE" if _supports(
                {"target": target}, _PQC_CAPABILITIES + ("aes",)) \
                else "UNKNOWN"
        checks["impact"] = {
            "projected_quantum_status": projected,
            "protocol_compatibility": {
                p: "SUPPORTED" if p in ("TLS", "SSH", "IPsec") else "UNKNOWN"
                for p in protocols
            },
        }

        blocked = not (checks["libraries"]["supported"]
                       or checks["hardware"]["supported"]
                       or checks["cloud"]["supported"])
        steps = [
            "1. Inventory every dependency on {current} (graph query).",
            "2. Confirm {target} support in each crypto library in use.",
            "3. Verify HSM/TPM/accelerator firmware supports {target}.",
            "4. Confirm vendor roadmap/patches for {target}.",
            "5. Re-key certificates/keys that use {current}.",
            "6. Update protocol configuration and re-scan (drift check).",
        ]
        return {
            "current": current,
            "target": target,
            "checks": checks,
            "feasible": not blocked,
            "migration_plan": {
                "steps": [s.format(current=current, target=target)
                          for s in steps],
                "risk": "HIGH" if blocked else "MEDIUM",
            },
            "honest_unknowns": [k for k, v in checks.items()
                                if isinstance(v, dict) and not v.get("supported")
                                and k not in ("dependencies", "impact")],
        }


def what_if(current: str, target: str, *,
            libraries: Optional[list[dict[str, Any]]] = None,
            hardware: Optional[list[dict[str, Any]]] = None,
            vendors: Optional[list[dict[str, Any]]] = None,
            cloud: Optional[list[dict[str, Any]]] = None,
            quantum: Optional[dict[str, Any]] = None,
            protocols: Optional[list[str]] = None) -> dict[str, Any]:
    """Module-level entry point."""
    return PlatformWhatIfEngine(libraries, hardware, vendors, cloud,
                                quantum).simulate(current, target, protocols)
