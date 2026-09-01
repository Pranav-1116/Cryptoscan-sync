"""§36 What-if migration simulator.

Deterministic what-if: replace an asset's algorithm with a candidate
(ML-KEM-768, ML-DSA-65, ...) and see the resulting readiness, quantum
status, agility delta and risk impact — before touching production.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_crypto.agility import CryptoAgilityEngine
from universal_crypto.pqc_readiness import (
    HARDWARE_PQC_SUPPORT,
    LIBRARY_PQC_SUPPORT,
    PROTOCOL_COMPATIBILITY,
    PqcReadinessEngine,
)
from universal_crypto.registry import find as registry_find


class MigrationSimulator:
    """§36 what-if: current → candidate → impact."""

    def simulate(
        self,
        *,
        asset_id: str = "default",
        current_algorithm: str,
        target_algorithm: str,
        protocol: str = "",
        library: str = "",
        hardware: str = "",
        usage: bool = True,
        current_agility: int = 50,
    ) -> dict[str, Any]:
        """Project the impact of migrating one asset to ``target_algorithm``."""
        readiness = PqcReadinessEngine().migration_readiness(
            algorithm=current_algorithm, protocol=protocol, library=library,
            hardware=hardware, usage=usage)
        entry = registry_find(target_algorithm)
        quantum = entry.quantum_status.value if entry else "PQC_UNKNOWN"

        # the what-if asks about ONE target: evaluate that candidate
        # specifically (not "any candidate of the current algorithm")
        candidate_analysis = readiness["candidate_analysis"]
        target_row = next(
            (s for s in candidate_analysis if s["candidate"] == target_algorithm),
            None)
        if target_row is None:
            # the target is itself quantum-safe (e.g. ML-KEM-768): check the
            # compatibility catalogs directly
            protocol_ok = target_algorithm in PROTOCOL_COMPATIBILITY.get(protocol, [])
            library_ok = target_algorithm in LIBRARY_PQC_SUPPORT.get(library, [])
            hardware_ok = target_algorithm in HARDWARE_PQC_SUPPORT.get(hardware, [])
            target_row = {
                "candidate": target_algorithm,
                "protocol_compatible": protocol_ok,
                "library_supported": library_ok,
                "hardware_supported": hardware_ok,
                "vendor_supported": True,
                "application_compatible": True,
                "fully_compatible": protocol_ok and library_ok and (
                    hardware_ok or not hardware),
            }
            candidate_analysis = [target_row] + candidate_analysis
        compatible = bool(target_row["fully_compatible"])
        projected_status = PqcReadinessEngine().readiness_status(
            algorithm=target_algorithm, usage=usage, capability=hardware != "")

        # agility impact: PQC targets typically imply configuration-level
        # change (library + protocol config), improving agility when the
        # current state was hardcoded.
        agility_engine = CryptoAgilityEngine()
        current = agility_engine.score(
            ["configurable_algorithm", "configurable_provider"]
            if current_agility >= 50 else ["hardcoded_algorithm"])
        future = agility_engine.score(
            ["configurable_algorithm", "configurable_provider",
             "runtime_selection", "algorithm_abstraction"])
        agility_delta = future["score"] - current["score"]

        readiness = PqcReadinessEngine().migration_readiness(
            algorithm=current_algorithm, protocol=protocol, library=library,
            hardware=hardware, usage=usage)
        entry = registry_find(target_algorithm)
        quantum = entry.quantum_status.value if entry else "PQC_UNKNOWN"

        # the what-if asks about ONE target: evaluate that candidate
        # specifically (not "any candidate of the current algorithm")
        candidate_analysis = readiness["candidate_analysis"]
        target_row = next(
            (s for s in candidate_analysis if s["candidate"] == target_algorithm),
            None)
        if target_row is None:
            # the target is itself quantum-safe (e.g. ML-KEM-768): check the
            # compatibility catalogs directly
            protocol_ok = target_algorithm in PROTOCOL_COMPATIBILITY.get(protocol, [])
            library_ok = target_algorithm in LIBRARY_PQC_SUPPORT.get(library, [])
            hardware_ok = target_algorithm in HARDWARE_PQC_SUPPORT.get(hardware, [])
            target_row = {
                "candidate": target_algorithm,
                "protocol_compatible": protocol_ok,
                "library_supported": library_ok,
                "hardware_supported": hardware_ok,
                "vendor_supported": True,
                "application_compatible": True,
                "fully_compatible": protocol_ok and library_ok and (
                    hardware_ok or not hardware),
            }
            candidate_analysis = [target_row] + candidate_analysis
        compatible = bool(target_row["fully_compatible"])
        projected_status = PqcReadinessEngine().readiness_status(
            algorithm=target_algorithm, usage=usage, capability=hardware != "")
        risk_impact = {
            "current_quantum_status": registry_find(current_algorithm).quantum_status.value
            if registry_find(current_algorithm) else "PQC_UNKNOWN",
            "target_quantum_status": quantum,
            "risk_reduction": "HIGH" if (
                registry_find(current_algorithm) is not None
                and registry_find(current_algorithm).quantum_status.value
                == "QUANTUM_VULNERABLE"
                and quantum in ("QUANTUM_SAFE", "PQC_READY", "HYBRID")) else "NONE",
        }
        return {
            "asset_id": asset_id,
            "current_algorithm": current_algorithm,
            "target_algorithm": target_algorithm,
            "protocol": protocol,
            "library": library,
            "hardware": hardware,
            "projected_readiness": projected_status.value,
            "projected_quantum_status": quantum,
            "compatible": compatible,
            "candidate_analysis": candidate_analysis,
            "agility_current": current["score"],
            "agility_after": future["score"],
            "agility_delta": agility_delta,
            "risk_impact": risk_impact,
            "migration_readiness": "READY" if compatible else (
                "PLANNED" if target_row else "NO_PATH"),
            "notes": [
                f"protocol {'supports' if target_algorithm in PROTOCOL_COMPATIBILITY.get(protocol, []) else 'does not support'} {target_algorithm}",
                f"library {'supports' if target_algorithm in LIBRARY_PQC_SUPPORT.get(library, []) else 'does not support'} {target_algorithm}",
                f"hardware {'supports' if target_algorithm in HARDWARE_PQC_SUPPORT.get(hardware, []) else 'does not support'} {target_algorithm}",
            ],
        }
