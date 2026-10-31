"""Synthetic banks with known answers — the corpus a scale curve is measured on.

A scale benchmark without ground truth measures speed and nothing else. This module
builds estates whose facts are *planted*: every crypto artefact, every relationship and
every relationship that must be **refused** is known before the graph is built, so
precision, recall, false positives and false negatives are computed against an answer
key rather than against the graph itself.

What it generates, per bank, is the shape of a real estate rather than a fixture:

* applications with their hosts, a crypto library, a load balancer, a database, a
  certificate, and — for some banks — an HSM and a KMS key;
* evidence with a provenance (source, collector, layer) and a type that decides its
  strength, so the graph's own confidence rules are exercised;
* relationships with the basis that makes each one legitimate, plus edges that must be
  **refused**: a co-location, an inference, and an edge citing evidence that was never
  recorded. A generator that only planted true edges would report 100% precision for
  any engine, which is why these are planted too.

Determinism is a requirement, not a nicety: the same seed and the same bank count must
produce byte-identical estates, so a scale curve can be re-run and compared.

These estates are synthetic and written from public standards. They are not any bank's
system, and no number derived from them describes a real institution.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "cryptoscan.synthetic-estate/1"

#: application archetypes a bank runs. Names are the shape, not any bank's inventory.
APPS: tuple[str, ...] = (
    "payments-api",
    "auth-api",
    "core-banking",
    "mobile-gateway",
    "card-processing",
    "fraud-scoring",
    "statement-engine",
    "open-banking-hub",
    "treasury",
    "clearing-adapter",
)

#: (algorithm, key_size, role) — includes deliberately weak choices, because an estate
#: with no weak crypto cannot measure a scanner's ability to find it
CRYPTO_CHOICES: tuple[tuple[str, int, str], ...] = (
    ("AES-256-GCM", 256, "encryption"),
    ("AES-128-CBC", 128, "encryption"),
    ("RSA-2048", 2048, "signing"),
    ("RSA-4096", 4096, "signing"),
    ("ECDSA-P256", 256, "signing"),
    ("SHA-256", 256, "hashing"),
    ("SHA-1", 160, "hashing"),
    ("3DES", 168, "encryption"),
    ("ML-KEM-768", 768, "key-exchange"),
)

LIBRARIES: tuple[str, ...] = (
    "openssl-3.0.13",
    "openssl-1.1.1w",
    "gnutls-3.7.9",
    "bouncycastle-1.78",
)

#: relationships the generator plants, each with a basis the graph accepts
PLANTED_EDGES: tuple[tuple[str, str, str], ...] = (
    ("runs_on", "APPLICATION", "HOST"),
    ("uses_crypto_library", "APPLICATION", "LIBRARY"),
    ("uses_algorithm", "APPLICATION", "ALGORITHM"),
    ("terminates_tls_for", "LOAD_BALANCER", "APPLICATION"),
    ("uses_certificate", "LOAD_BALANCER", "CERTIFICATE"),
    ("hosted_on", "DATABASE", "HOST"),
    ("uses_hsm", "APPLICATION", "HSM"),
    ("uses_kms", "APPLICATION", "KMS_KEY"),
    ("connects_to", "APPLICATION", "DATABASE"),
)


@dataclass(frozen=True)
class BankEstate:
    """One bank, as rows to ingest plus the answers those rows imply."""

    bank: str
    assets: tuple[dict[str, Any], ...]
    evidence: tuple[dict[str, Any], ...]
    relationships: tuple[dict[str, Any], ...]
    planted_crypto: tuple[tuple[str, str], ...]
    planted_edges: tuple[tuple[str, str, str], ...]
    refused_edges: tuple[dict[str, Any], ...]
    #: assets the bank holds but nothing was collected from — the blind spot a scale
    #: curve has to carry, because a corpus where every asset is observed reports
    #: coverage 100% for an engine that would miss every dark asset in a real estate
    unobserved_assets: tuple[str, ...] = ()
    #: subjects where two planes disagree about the algorithm. The graph must hold both
    #: facts and report the conflict, not pick a winner.
    expected_conflicts: int = 0
    #: the subject the correlation probes: it is described by two planes (so agreement
    #: must fire on it), and — when the bank has an HSM — by a third plane that records
    #: it absent (so a contradiction must fire too)
    correlation_probe: dict[str, Any] = field(default_factory=dict)
    note: str = ""

    def counts(self) -> dict[str, int]:
        return {
            "assets": len(self.assets),
            "evidence": len(self.evidence),
            "relationships": len(self.relationships),
            "planted_crypto": len(self.planted_crypto),
            "planted_edges": len(self.planted_edges),
            "refused_edges": len(self.refused_edges),
            "unobserved_assets": len(self.unobserved_assets),
            "expected_conflicts": self.expected_conflicts,
        }


@dataclass
class Corpus:
    """The whole synthetic group, with an answer key for every bank."""

    seed: int
    banks: tuple[BankEstate, ...] = field(default_factory=tuple)

    @property
    def assets(self) -> tuple[dict[str, Any], ...]:
        return tuple(asset for bank in self.banks for asset in bank.assets)

    @property
    def evidence(self) -> tuple[dict[str, Any], ...]:
        return tuple(row for bank in self.banks for row in bank.evidence)

    @property
    def relationships(self) -> tuple[dict[str, Any], ...]:
        return tuple(row for bank in self.banks for row in bank.relationships)

    def summary(self) -> dict[str, Any]:
        rows = [bank.counts() for bank in self.banks]
        return {
            "schema": SCHEMA,
            "seed": self.seed,
            "banks": len(self.banks),
            "assets": sum(row["assets"] for row in rows),
            "evidence": sum(row["evidence"] for row in rows),
            "relationships": sum(row["relationships"] for row in rows),
            "planted_crypto": sum(row["planted_crypto"] for row in rows),
            "planted_edges": sum(row["planted_edges"] for row in rows),
            "refused_edges": sum(row["refused_edges"] for row in rows),
            "unobserved_assets": sum(row["unobserved_assets"] for row in rows),
            "expected_conflicts": sum(row["expected_conflicts"] for row in rows),
            "note": (
                "synthetic estates written from public standards — not any bank's inventory, "
                "and no number derived from them describes a real institution"
            ),
        }


def _tag(bank_index: int, name: str) -> str:
    """A per-bank name that is unique across the group and stable for a seed."""
    return f"bank{bank_index:03d}-{name}"


def build_bank(bank_index: int, *, seed: int = 7) -> BankEstate:
    """One bank's estate, deterministic in ``(bank_index, seed)``."""
    # a per-bank stream: adding a bank must not change any earlier bank's estate
    rnd = random.Random(f"{seed}:{bank_index}:estate")
    bank = f"bank-{bank_index:03d}"

    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    planted_crypto: list[tuple[str, str]] = []
    planted_edges: list[tuple[str, str, str]] = []
    refused: list[dict[str, Any]] = []
    unobserved: list[str] = []
    conflicts = 0
    probe: dict[str, Any] = {}

    def refs(suffix: str) -> str:
        """A stable evidence *reference*; the graph assigns the real content id."""
        digest = hashlib.sha256(f"{seed}|{bank_index}|{suffix}".encode()).hexdigest()[:12]
        return f"ref-{digest}"

    # -- the bank's own infrastructure ------------------------------------
    library = _tag(bank_index, rnd.choice(LIBRARIES))
    host_shared = _tag(bank_index, "host-app-01")
    lb = _tag(bank_index, "lb-public")
    database = _tag(bank_index, "db-core")
    certificate = _tag(bank_index, "cert-public")
    has_hsm = rnd.random() < 0.7
    has_kms = rnd.random() < 0.8
    hsm = _tag(bank_index, "hsm-payments") if has_hsm else None
    kms = _tag(bank_index, "kms-data") if has_kms else None

    assets += [
        {"asset_type": "LIBRARY", "name": library, "identity": {"name": library}},
        {"asset_type": "HOST", "name": host_shared, "identity": {"hostname": host_shared}},
        {"asset_type": "LOAD_BALANCER", "name": lb, "identity": {"hostname": lb}},
        {"asset_type": "DATABASE", "name": database, "identity": {"name": database}},
        {"asset_type": "CERTIFICATE", "name": certificate, "identity": {"common_name": certificate}},
    ]
    if hsm:
        assets.append({"asset_type": "HSM", "name": hsm, "identity": {"name": hsm}})
    # a second module in the group's disaster-recovery zone: co-located with the app,
    # never referenced by it. The edge attempting to use it must be refused, and the
    # triple can never also appear as a planted edge.
    dr_hsm = _tag(bank_index, "hsm-dr-zone")
    assets.append({"asset_type": "HSM", "name": dr_hsm, "identity": {"name": dr_hsm}})
    if kms:
        assets.append({"asset_type": "KMS_KEY", "name": kms, "identity": {"name": kms}})

    # the library's presence is static evidence — and is deliberately *not* a crypto
    # artefact: a version is not an algorithm, which is the distinction the graph makes
    lib_ref = refs("lib")
    evidence.append(
        {
            "ref": lib_ref,
            "target": library,
            "evidence_type": "STATIC_OBSERVED",
            "layer": "static",
            "facts": {"version": library.rsplit("-", 1)[-1], "package": library.rsplit("-", 1)[0]},
            "source": "inventory.linux_packages",
            "collector": "inventory.linux_packages:dpkg_status",
        }
    )

    # -- applications ------------------------------------------------------
    count = rnd.randint(3, 6)
    apps = rnd.sample(APPS, count)
    for app_index, app_name in enumerate(apps):
        app = _tag(bank_index, app_name)
        host = host_shared if app_index < 2 else _tag(bank_index, f"host-{app_name}")
        if host != host_shared:
            assets.append({"asset_type": "HOST", "name": host, "identity": {"hostname": host}})
        assets.append({"asset_type": "APPLICATION", "name": app, "identity": {"name": app}})

        # a dark asset: it exists in the CMDB and nothing was collected from it. The
        # answer key says so, so a detector that "found" crypto here would be inventing.
        # the first application is always observed: it carries the correlation probe,
        # so a bank whose probe asset went dark could not be scored
        if app_index > 0 and rnd.random() < 0.12:
            unobserved.append(app)
            continue

        # runtime evidence: an observed call, with its algorithm
        algorithm, key_size, role = rnd.choice(CRYPTO_CHOICES)
        runtime_ref = refs(f"runtime-{app_name}")
        evidence.append(
            {
                "ref": runtime_ref,
                "target": app,
                "evidence_type": "RUNTIME_OBSERVED",
                "layer": "runtime",
                "facts": {
                    "algorithm": algorithm,
                    "key_size": key_size,
                    "role": role,
                    "function": "EVP_CipherInit_ex",
                },
                "source": "runtime.agent.preload_trace",
                "collector": "runtime.agent.preload_trace:trace_command",
            }
        )
        planted_crypto.append((app, algorithm))

        # two planes disagreeing about the same subject: the runtime saw one algorithm,
        # the service's configuration declares another. Both are facts; the graph must
        # report the conflict rather than choose.
        if app_index == 0 or rnd.random() < 0.08:
            other, other_size, _ = rnd.choice(
                [choice for choice in CRYPTO_CHOICES if choice[0] != algorithm]
            )
            evidence.append(
                {
                    "ref": refs(f"config-{app_name}"),
                    "target": app,
                    "evidence_type": "CONFIGURED",
                    "layer": "configuration",
                    "facts": {
                        "algorithm": other,
                        "key_size": other_size,
                        "role": "declared",
                    },
                    "source": "drift.core.config_detector",
                    "collector": "drift.core.config_detector:detect_config_drift",
                }
            )
            planted_crypto.append((app, other))
            conflicts += 1

        # ...and a library link that the same observation supports
        planted_edges.append(("runs_on", app, host))
        relationships.append(
            {
                "subject": app, "predicate": "runs_on", "object": host,
                "basis": "CONFIGURATION", "evidence_refs": [runtime_ref],
            }
        )
        planted_edges.append(("uses_crypto_library", app, library))
        relationships.append(
            {
                "subject": app, "predicate": "uses_crypto_library", "object": library,
                "basis": "RUNTIME_OBSERVATION", "evidence_refs": [runtime_ref],
            }
        )
        planted_edges.append(("connects_to", app, database))
        relationships.append(
            {
                "subject": app, "predicate": "connects_to", "object": database,
                "basis": "CONFIGURATION", "evidence_refs": [runtime_ref],
            }
        )

        if app_index == 0:
            probe = {
                "subject": app,
                "expect_agreement": True,
                "expect_contradiction": bool(has_hsm),
                "absent_plane": "HSM" if has_hsm else None,
            }
        if has_hsm and rnd.random() < 0.6:
            planted_edges.append(("uses_hsm", app, hsm or ""))
            relationships.append(
                {
                    "subject": app, "predicate": "uses_hsm", "object": hsm,
                    "basis": "PKCS11_REFERENCE", "evidence_refs": [runtime_ref],
                }
            )
        if has_kms and rnd.random() < 0.5:
            planted_edges.append(("uses_kms", app, kms or ""))
            relationships.append(
                {
                    "subject": app, "predicate": "uses_kms", "object": kms,
                    "basis": "KMS_REFERENCE", "evidence_refs": [runtime_ref],
                }
            )

        # an edge that must be refused: the app and the *other* bank's HSM are
        # co-located in the same rack, which is an environment fact, not a use
        if app_index == 0:
            refused.append(
                {
                    "subject": app, "predicate": "uses_hsm", "object": dr_hsm,
                    "basis": "INFERRED",
                    "evidence_refs": [runtime_ref],
                    "why": "co-location and inference cannot establish use",
                }
            )
            # ...and an edge citing evidence nobody recorded
            refused.append(
                {
                    "subject": app, "predicate": "protected_by", "object": certificate,
                    "basis": "CONFIGURATION",
                    "evidence_refs": ["ref-never-recorded"],
                    "why": "an edge cannot cite evidence the graph does not hold",
                }
            )

    # -- the load balancer's TLS termination -------------------------------
    cert_ref = refs("cert")
    cert_algorithm = rnd.choice(["RSA-2048", "ECDSA-P256", "RSA-4096"])
    cert_key_size = {"RSA-2048": 2048, "ECDSA-P256": 256, "RSA-4096": 4096}[cert_algorithm]
    evidence.append(
        {
            "ref": cert_ref,
            "target": certificate,
            "evidence_type": "CERTIFICATE_OBSERVED",
            "layer": "network",
            "facts": {
                "algorithm": cert_algorithm,
                "key_size": cert_key_size,
                "role": "signing",
                "not_after": "2027-06-01",
            },
            "source": "inventory.tls_session",
            "collector": "inventory.tls_session:probe_session",
        }
    )
    # the certificate's algorithm is a crypto artefact the graph must hold, and the
    # answer key has to say so or a correct finding would score as a false positive
    planted_crypto.append((certificate, cert_algorithm))
    planted_edges.append(("uses_certificate", lb, certificate))
    relationships.append(
        {
            "subject": lb, "predicate": "uses_certificate", "object": certificate,
            "basis": "NETWORK_OBSERVATION", "evidence_refs": [cert_ref],
        }
    )
    first_app = _tag(bank_index, apps[0])
    planted_edges.append(("terminates_tls_for", lb, first_app))
    relationships.append(
        {
            "subject": lb, "predicate": "terminates_tls_for", "object": first_app,
            "basis": "NETWORK_OBSERVATION", "evidence_refs": [cert_ref],
        }
    )

    planted_edges.append(("hosted_on", database, host_shared))
    relationships.append(
        {
            "subject": database, "predicate": "hosted_on", "object": host_shared,
            "basis": "DEPLOYMENT_CONFIG", "evidence_refs": [lib_ref],
        }
    )

    return BankEstate(
        bank=bank,
        assets=tuple(assets),
        evidence=tuple(evidence),
        relationships=tuple(relationships),
        planted_crypto=tuple(sorted(set(planted_crypto))),
        planted_edges=tuple(sorted(set(edge for edge in planted_edges if edge[2]))),
        refused_edges=tuple(refused),
        unobserved_assets=tuple(sorted(unobserved)),
        expected_conflicts=conflicts,
        correlation_probe=probe,
        note="synthetic estate; every planted fact is part of the answer key",
    )


def build(banks: int, *, seed: int = 7) -> Corpus:
    """The whole group: ``banks`` estates, each deterministic in its own index."""
    if banks < 1:
        raise ValueError("a corpus needs at least one bank")
    return Corpus(seed=seed, banks=tuple(build_bank(index, seed=seed) for index in range(banks)))


__all__ = [
    "APPS",
    "CRYPTO_CHOICES",
    "Corpus",
    "LIBRARIES",
    "PLANTED_EDGES",
    "SCHEMA",
    "BankEstate",
    "build",
    "build_bank",
]
