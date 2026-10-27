"""
Quantum-impact enricher (registry-first).

The shared algorithm registry carries ``quantum_impact`` ("shor" = broken by a
cryptographically relevant quantum computer, "grover" = security level halved)
for every algorithm it knows. Until 2026-09 the normaliser only set
``quantum_vulnerable`` from the ten hand-written YAML rules, so DH, DSA, ECDH,
Ed25519, X25519 and RSA signature combos reached the CBOM as *not* quantum
vulnerable. This enricher asks the registry and never downgrades a rule that
already says vulnerable.
"""
from __future__ import annotations

import re

from ..core.registry_bridge import model_family, quantum_impact
from ..models.normalized_crypto import NormalizedCrypto

# default FIPS 203/204 replacement by what the algorithm is used for
_REPLACEMENT_BY_FAMILY = {
    "signature": "ML-DSA-65",
    "key-agreement": "ML-KEM-768",
    "asymmetric": "ML-KEM-768",
}


class QuantumEnricher:
    def enrich(self, normalized: NormalizedCrypto) -> NormalizedCrypto:
        candidates = [normalized.standard_name, normalized.algorithm]
        impact = None
        for name in candidates:
            if name:
                impact = quantum_impact(name)
                if impact:
                    break
        if impact == "shor":
            normalized.quantum_vulnerable = True
            if not normalized.pqc_replacement:
                family = normalized.algorithm_family if normalized.algorithm_family not in (None, "unknown") else None
                for name in candidates:
                    if family or not name:
                        break
                    family = model_family(name)
                sig_combo = any(re.search(r"(?i)(with|-)SHA|PSS|PKCS1", n or "") for n in candidates)
                normalized.pqc_replacement = "ML-DSA-65" if sig_combo else _REPLACEMENT_BY_FAMILY.get(family or "", "ML-KEM-768")
        return normalized
