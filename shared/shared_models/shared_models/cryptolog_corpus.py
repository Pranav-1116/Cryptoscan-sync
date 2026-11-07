"""Deterministic SYNTHETIC CryptoLog event corpus (Phase 8 qualification).

Every corpus event is labelled SYNTHETIC at the source: collector id
'synthetic-corpus' and attributes.synthetic = True. A synthetic result
never masquerades as an observation — synthetic evidence never qualifies
a real-environment act.
"""

from __future__ import annotations

import random
from typing import Any


SCHEMA = "cryptoscan.cryptolog-synthetic-corpus/1"
SYNTHETIC_COLLECTOR = "synthetic-corpus"

_TEMPLATES = (
    # (event_type, category, logging_kind, severity, source_type, evidence_level)
    ("TLS_NEGOTIATION_OBSERVED", "TLS", "ACTIVITY", "INFO",
     "NETWORK_OBSERVATION", "NETWORK_NEGOTIATED"),
    ("HSM_KEY_METADATA_CHANGE", "HSM_KMS", "CHANGE", "HIGH",
     "HSM_OBSERVATION", "CONFIGURED"),
    ("CERTIFICATE_REPLACEMENT", "CERTIFICATE", "CHANGE", "MEDIUM",
     "CERTIFICATE_OBSERVATION", "CONFIGURED"),
    ("CRYPTO_LIBRARY_REGRESSION", "CRYPTO_LIBRARY", "CHANGE", "HIGH",
     "SBOM_OBSERVATION", "CONFIGURED"),
    ("CRYPTO_CONFIGURATION_CHANGED", "CONFIGURATION", "CHANGE", "CRITICAL",
     "CONFIGURATION_OBSERVATION", "CONFIGURED"),
    ("ALGORITHM_OBSERVED", "ALGORITHM", "ACTIVITY", "LOW",
     "RUNTIME_OBSERVATION", "RUNTIME"),
)


def generate_corpus(count: int, *, seed: int = 20261107,
                    tenant_id: str = "tenant_synthetic") -> list[dict[str, Any]]:
    """`count` deterministic synthetic events for the same seed, same order."""
    rng = random.Random(seed)
    events: list[dict[str, Any]] = []
    for index in range(count):
        (event_type, category, kind, severity,
         source_type, level) = _TEMPLATES[index % len(_TEMPLATES)]
        day = 1 + (index % 28)
        hour = index % 24
        events.append({
            "event_id": f"synth_{seed:08d}_{index:06d}",
            "event_type": event_type,
            "category": category,
            "logging_kind": kind,
            "severity": severity,
            "tenant_id": tenant_id,
            "asset_id": f"asset_synthetic_{index % 7:03d}",
            "source": {
                "collector_id": SYNTHETIC_COLLECTOR,
                "collector_version": "synthetic",
                "source_type": source_type,
            },
            "cryptographic_context": {
                "protocol": "TLS",
                "protocol_version": "TLS1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "evidence_level": level,
            },
            "observation": {
                "observed_at": f"2026-10-{day:02d}T{hour:02d}:{index % 60:02d}:00Z",
            },
            "evidence": {"evidence_ids": [f"evidence_synth_{index:06d}"]},
            "attributes": {
                "synthetic": True,
                "corpus": SCHEMA,
                "corpus_id": f"{SCHEMA}:{seed}",
                "index": index,
                "nonce": rng.randrange(1 << 32),
            },
        })
    return events
