"""The eleven planes a correlation may draw on, and which of them are actually read.

"Complete attack correlation" is the product vision's phrase for joining static
inventory, runtime observation, network evidence, certificates, HSM, KMS, identity,
configuration, SBOM, CBOM and temporal behaviour into one picture. A list of eleven
names is not that: what matters is whether the correlator *consumes* a plane, and
whether a collector in this build can produce facts for it.

This module answers both, and neither answer is a sentence someone typed:

* **consumed** — measured by running :func:`shared_models.attack_patterns.correlate`
  with a canonical statement from that plane, alongside one witness plane, and asking
  whether the plane appears in a pattern the correlator emitted. A plane that the
  engine silently drops is ``REJECTED`` here on the next run;
* **producer** — measured by importing the module:attribute that would supply the
  facts. A producer that disappears from the build degrades its own row.

The two axes are deliberately independent, because they fail differently. A plane
with a producer and no consuming rule is a collector writing into nothing; a plane
with a rule and no producer is a rule that can never fire on a real estate. Both are
reported as they are, and ``blind`` names them.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import attack_patterns

SCHEMA = "cryptoscan.attack-planes/1"

#: status of the *reading* half: can the correlator cite a fact from this plane?
CONSUMED = "CONSUMED"
REJECTED = "REJECTED"

#: status of the *supply* half: does a collector in this build produce the facts?
SUPPLIED = "SUPPLIED"
UNSUPPLIED = "UNSUPPLIED"


@dataclass(frozen=True)
class Plane:
    """One evidence plane, what it asserts, and what it structurally cannot say."""

    id: str
    label: str
    #: what a fact from this plane asserts, in one sentence
    asserts: str
    #: what a fact from this plane can never establish, however many of them there are
    blind_spot: str
    #: module:attribute that would produce these facts, resolved by import
    producers: tuple[str, ...] = ()
    #: the statement the probe sends, which is what a real collector would say
    probe: str = ""
    #: evidence ids the probe cites, so provenance is exercised too
    probe_evidence: tuple[str, ...] = ()
    #: a plane whose facts corroborate without being a change feed
    independent: bool = True
    missing: tuple[str, ...] = field(default=())

    def producer_refs(self) -> list[dict[str, Any]]:
        return [{"ref": ref, **resolve_producer(ref)} for ref in self.producers]


def resolve_producer(ref: str) -> dict[str, Any]:
    """Resolve ``module:attribute`` by import — the only honest test of "it exists"."""
    module_name, _, attribute = ref.partition(":")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - any import failure is a missing producer
        return {"present": False, "reason": f"{type(exc).__name__}: {exc}"[:200]}
    if not attribute:
        return {"present": True, "reason": None}
    if not hasattr(module, attribute):
        return {"present": False, "reason": f"{module_name} has no attribute {attribute!r}"}
    return {"present": True, "reason": None}


PLANES: tuple[Plane, ...] = (
    Plane(
        id="STATIC",
        label="Static inventory",
        asserts="this asset, library or configuration exists on this host right now",
        blind_spot=(
            "existence is not use: a library present and never loaded looks identical to one "
            "called a million times"
        ),
        producers=("api.estate_discovery:collect_static",),
        probe="libssl.so.3 present, signature verified",
        probe_evidence=("ev-static-1",),
    ),
    Plane(
        id="RUNTIME",
        label="Runtime observation",
        asserts="this process made this cryptographic call, counted",
        blind_spot=(
            "only processes launched under the tracer are visible; a statically linked stack, a "
            "JVM, a Go or Rust binary produces nothing and that silence is not inactivity"
        ),
        producers=(
            "runtime.agent.crypto_events:observations_from_trace",
            "runtime.agent.preload_trace:trace_command",
        ),
        probe="EVP_CipherInit_ex AES-256-GCM, 412 calls, pid 3181",
        probe_evidence=("ev-runtime-1",),
    ),
    Plane(
        id="NETWORK",
        label="Network evidence",
        asserts="this endpoint offered this protocol version and cipher suite on the wire",
        blind_spot=(
            "the wire shows what was negotiated, not what the application chose to protect; a "
            "client that ignores a strong offer looks the same as one that honours it"
        ),
        producers=(
            "api.estate_discovery:collect_network",
            "inventory.tls_session:probe_session",
        ),
        probe="myserver:443 negotiated TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384",
        probe_evidence=("ev-network-1",),
    ),
    Plane(
        id="CERTIFICATE",
        label="Certificate evidence",
        asserts="this certificate exists, with this subject, key size, signature algorithm and expiry",
        blind_spot=(
            "a certificate in the store says nothing about which services present it, and expiry "
            "is a property of the artefact rather than of the traffic"
        ),
        producers=("api.estate_discovery:collect_pki",),
        probe="CN=payments.bank.example, RSA-2048, SHA256withRSA, expires 2027-03-01",
        probe_evidence=("ev-cert-1",),
    ),
    Plane(
        id="HSM",
        label="HSM evidence",
        asserts="this key object exists on the module with these attributes and usage counters",
        blind_spot=(
            "key attributes describe what the module can do with a key, not what an application did "
            "with it; operation-level proof needs the HSM's own audit log"
        ),
        producers=(
            "api.estate_discovery:collect_hsm_plane",
            "cbom.kmip:assess_kmip_object",
        ),
        probe="KMIP object key-payments-01 AES-256, state Active, usage 2048",
        probe_evidence=("ev-hsm-1",),
    ),
    Plane(
        id="KMS",
        label="Cloud KMS evidence",
        asserts="this key exists in the provider with these usage counters and this rotation state",
        blind_spot=(
            "aggregate counters are not per-request audit events: they cannot be attributed to a "
            "workload or a record"
        ),
        producers=("api.estate_kms:collect_kms_usage",),
        probe="alias/payments-data AWS KMS SYMMETRIC_DEFAULT, decrypt calls 18342",
        probe_evidence=("ev-kms-1",),
    ),
    Plane(
        id="IDENTITY",
        label="Identity evidence",
        asserts="this workload or principal is who it presents itself as, resolved from its credential",
        blind_spot=(
            "a resolved identity says who acted, not what they were entitled to do; entitlement is a "
            "policy question this plane does not answer"
        ),
        producers=("control_plane.identity:resolve_identity",),
        probe="spiffe://bank.example/ns/payments/sa/api resolved from x5c chain",
        probe_evidence=("ev-identity-1",),
    ),
    Plane(
        id="CONFIGURATION",
        label="Configuration evidence",
        asserts="this service was configured with these crypto settings, as read from its config",
        blind_spot=(
            "configuration is the intent of the operator, not the behaviour of the process: a "
            "configured cipher list is not a negotiated one"
        ),
        producers=("drift.core.config_detector:detect_config_drift",),
        probe="tls.ciphers = TLS_AES_256_GCM_SHA384, min_version = 1.2",
        probe_evidence=("ev-config-1",),
    ),
    Plane(
        id="SBOM",
        label="Software bill of materials",
        asserts="this component, at this version, is part of the delivered artefact",
        blind_spot=(
            "a component in the SBOM is a declaration of what was shipped, not a measurement of "
            "what is running"
        ),
        producers=("cbom.linux_sbom:build_linux_sbom",),
        probe="openssl 3.0.13-0ubuntu3 in image payments-api:2.4.1",
        probe_evidence=("ev-sbom-1",),
    ),
    Plane(
        id="CBOM",
        label="Cryptography bill of materials",
        asserts="this cryptographic asset exists with this algorithm, size and primitive",
        blind_spot=(
            "a CBOM entry is a projection of evidence, not a second observation: it cannot "
            "corroborate the plane it was built from"
        ),
        producers=("cbom.inventory:records_from_bom",),
        probe="AES-256-GCM, symmetric, keySize 256, in payments-api",
        probe_evidence=("ev-cbom-1",),
        # a CBOM entry is built from other planes' evidence; counting it as a second
        # witness would let one source corroborate itself
        independent=False,
    ),
    Plane(
        id="TEMPORAL",
        label="Temporal behaviour",
        asserts="this subject's rate or pattern moved away from its own baseline",
        blind_spot=(
            "a baseline is learned from what was observed; a subject that was never observed has "
            "no baseline, and a gap in observation is not a change in behaviour"
        ),
        producers=("anomaly.detect:detect_series",),
        probe="crypto calls/hour for payments-api rose 4.2 sigma above its 30-day baseline",
        probe_evidence=("ev-temporal-1",),
    ),
)

PLANE_INDEX = {plane.id: plane for plane in PLANES}

#: the plane that always witnesses the probe subject, so the agreement rule has a second
#: witness and the measurement is of *this* plane rather than of a single-fact no-op
WITNESS = "STATIC"


def _probe_events(subject: str, moment: datetime) -> list[dict[str, Any]]:
    """One canonical change on the probe subject — the thing a plane corroborates."""
    return [
        {
            "event_id": f"probe-{subject}",
            "run_id": 1,
            "last_detected_at": moment.isoformat(),
            "changes": [
                {
                    "kind": "CRYPTO_DEMOTED",
                    "subject": subject,
                    "severity": "WARNING",
                    "evidence_ids": [f"ev-probe-{subject}"],
                }
            ],
        }
    ]


def measure(plane: Plane, *, now: datetime | None = None) -> dict[str, Any]:
    """Run the correlator with this plane's facts and report whether it read them."""
    moment = now or datetime(2026, 1, 1, tzinfo=timezone.utc)
    subject = f"probe-{plane.id.lower()}"
    facts: list[dict[str, Any]] = [
        {
            "plane": plane.id,
            "subject": subject,
            "relation": "OBSERVED",
            "statement": plane.probe,
            "evidence_ids": list(plane.probe_evidence),
            "collector": plane.producers[0] if plane.producers else "",
        }
    ]
    if plane.id != WITNESS:
        facts.append(
            {
                "plane": WITNESS,
                "subject": subject,
                "relation": "OBSERVED",
                "statement": PLANE_INDEX[WITNESS].probe,
                "evidence_ids": ["ev-static-witness"],
            }
        )
    document = attack_patterns.correlate(
        _probe_events(subject, moment),
        now=moment + timedelta(minutes=1),
        plane_facts=facts,
    )
    counted = int((document.get("planes", {}).get("by_plane") or {}).get(plane.id, 0))
    citing = [
        pattern["name"]
        for pattern in document.get("patterns") or []
        if plane.id in (pattern.get("planes") or [])
    ]
    rejected = int(document.get("planes", {}).get("unrecognised_plane_facts") or 0)
    status = CONSUMED if counted and citing and not rejected else REJECTED
    reason = (
        f"the correlator cited {plane.id} in {len(citing)} pattern(s): {', '.join(citing)}"
        if status == CONSUMED
        else (
            "the correlator did not cite a fact from this plane"
            + (f" and rejected {rejected} fact(s) as unrecognised" if rejected else "")
        )
    )
    return {
        "status": status,
        "facts_accepted": counted,
        "corroborates": bool(plane.independent and status == CONSUMED),
        "patterns_citing_plane": citing,
        "reason": reason,
        "probe_statement": plane.probe,
    }


#: Two assets that a real estate would hold, with the spellings its collectors use.
_PROBE_IDENTITIES: tuple[dict[str, Any], ...] = (
    {
        "asset_id": "HOST-payments",
        "name": "payments-api",
        "identity": {
            "hostname": "alb-payments-01",
            "ip": "10.0.3.4",
            "spiffe_id": "spiffe://bank.example/ns/payments/sa/api",
        },
    },
    {"asset_id": "HOST-auth", "name": "auth-api", "identity": {"hostname": "alb-auth-01"}},
)


def _resolution_probe() -> dict[str, Any]:
    """Join four spellings of one host — and check that a collision is refused.

    Correlation is only as good as the name the planes agree on, so the resolution
    layer is measured here the same way the planes are: run it, and report what it did.
    """
    from .subject_resolution import AMBIGUOUS, RESOLVED, SubjectIndex

    index = SubjectIndex.from_assets(_PROBE_IDENTITIES)
    spellings = (
        "alb-payments-01",
        "payments-api",
        "10.0.3.4:443",
        "spiffe://bank.example/ns/payments/sa/api",
    )
    resolutions = [index.resolve(subject) for subject in spellings]
    assets = {item.asset_id for item in resolutions if item.status == RESOLVED}
    schemes = {item.scheme for item in resolutions if item.status == RESOLVED}

    collide = SubjectIndex.from_assets(
        [
            {"asset_id": "HOST-a", "name": "payments", "identity": {"hostname": "payments-a"}},
            {"asset_id": "HOST-b", "name": "payments", "identity": {"hostname": "payments-b"}},
        ]
    )
    refusal = collide.resolve("payments")

    merged = len(assets) == 1 and len(resolutions) == len(spellings)
    return {
        "state": "MERGED" if merged and refusal.status == AMBIGUOUS else "FAILED",
        "spellings": list(spellings),
        "assets": sorted(assets),
        "schemes": sorted(scheme or "" for scheme in schemes),
        "merges_all_spellings": merged,
        "refuses_ambiguity": refusal.status == AMBIGUOUS,
        "refusal_candidates": list(refusal.candidates),
        "note": (
            "keys are declared by assets and matched exactly; a key two assets claim is refused "
            "rather than resolved by preference, because picking one of two owners is how a "
            "correlator invents agreement between two hosts"
        ),
    }


def register(*, now: datetime | None = None) -> dict[str, Any]:
    """The eleven-plane matrix, measured against the shipped correlator."""
    rows: list[dict[str, Any]] = []
    for plane in PLANES:
        reading = measure(plane, now=now)
        producers = plane.producer_refs()
        present = [item for item in producers if item["present"]]
        supplied = SUPPLIED if present and len(present) == len(producers) else UNSUPPLIED
        rows.append(
            {
                "id": plane.id,
                "label": plane.label,
                "reading": reading["status"],
                "supply": supplied,
                "consumed": reading["status"] == CONSUMED,
                "independent": plane.independent,
                "corroborates": reading["corroborates"],
                "correlated": reading["status"] == CONSUMED and supplied == SUPPLIED,
                "asserts": plane.asserts,
                "blind_spot": plane.blind_spot,
                "producers": producers,
                "producers_present": len(present),
                "producers_declared": len(producers),
                "measurement": reading,
                "missing": [item["ref"] for item in producers if not item["present"]],
            }
        )

    consumed = [row["id"] for row in rows if row["consumed"]]
    supplied = [row["id"] for row in rows if row["supply"] == SUPPLIED]
    both = [row["id"] for row in rows if row["correlated"]]
    corroborating = [row["id"] for row in rows if row["corroborates"]]
    blind = [
        {
            "id": row["id"],
            "why": (
                "no consuming rule cites facts from this plane"
                if not row["consumed"]
                else "no producer in this build supplies facts for this plane"
            ),
        }
        for row in rows
        if not row["correlated"]
    ]
    return {
        "schema": SCHEMA,
        "planes": rows,
        "vocabulary": list(attack_patterns.PLANES),
        "vocabulary_matches": tuple(row["id"] for row in rows) == tuple(attack_patterns.PLANES),
        "counts": {
            "planes": len(rows),
            "consumed": len(consumed),
            "supplied": len(supplied),
            "correlated": len(both),
            "corroborating": len(corroborating),
            "blind": len(blind),
        },
        "consumed": consumed,
        "supplied": supplied,
        "correlated": both,
        "corroborating": corroborating,
        "blind": blind,
        "claim": (
            "a plane is CORRELATED only when the shipped correlator cites a fact from it *and* a "
            "producer in this build can supply one. Eleven names in a slide is not coverage; these "
            "counts are of rows in that state"
        ),
        "derived_planes": [row["id"] for row in rows if not row["independent"]],
        "resolution": _resolution_probe(),
        "note": (
            "correlation joins planes on the subject a change names. It does not model causality, "
            "does not rank by likelihood and never reaches SECURITY_INCIDENT. A derived plane "
            "(CBOM) is cited but never counted as a witness: it is built from the planes it would "
            "otherwise corroborate"
        ),
    }


def facts_from_records(
    records: Iterable[dict[str, Any]],
    *,
    subjects: Iterable[str],
) -> list[dict[str, Any]]:
    """Turn stored evidence records into plane facts, for the subjects asked about.

    A record states which collector produced a fact and against which target. The plane
    is decided by the collector, never by the evidence type alone: two collectors can
    share an evidence type and belong to different planes, and relabelling one as the
    other would manufacture corroboration.
    """
    wanted = {str(subject) for subject in subjects if subject}
    facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        target = str(record.get("target") or "").strip()
        if not target or (wanted and target not in wanted):
            continue
        collector = str(record.get("collector") or "").strip()
        plane = plane_for_collector(collector)
        if plane is None:
            continue
        key = (plane, target, str(record.get("evidence_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        facts.append(
            {
                "plane": plane,
                "subject": target,
                "relation": "OBSERVED",
                "statement": str(record.get("summary") or record.get("kind") or "")[:240],
                "evidence_ids": [str(record["evidence_id"])] if record.get("evidence_id") else [],
                "collector": collector,
            }
        )
    return facts


#: collector module prefix → plane. A collector is one plane's witness; the same module
#: appearing under two planes would double-count a single source as corroboration.
_COLLECTOR_PLANES: tuple[tuple[str, str], ...] = (
    ("api.estate_discovery:collect_static", "STATIC"),
    ("runtime.agent.", "RUNTIME"),
    ("api.estate_discovery:collect_runtime", "RUNTIME"),
    ("api.estate_discovery:collect_network", "NETWORK"),
    ("inventory.tls_session", "NETWORK"),
    ("api.estate_discovery:collect_pki", "CERTIFICATE"),
    ("api.estate_discovery:collect_hardware", "HSM"),
    ("api.estate_discovery:collect_hsm_plane", "HSM"),
    ("cbom.kmip", "HSM"),
    ("api.estate_kms", "KMS"),
    ("api.estate_discovery:collect_kms_plane", "KMS"),
    ("control_plane.identity", "IDENTITY"),
    ("drift.core.config_detector", "CONFIGURATION"),
    ("cbom.linux_sbom", "SBOM"),
    ("cbom.inventory", "CBOM"),
    ("anomaly.detect", "TEMPORAL"),
)


def plane_for_collector(collector: str) -> str | None:
    """The plane a collector's facts belong to, or ``None`` when it is not a witness."""
    name = str(collector or "").strip()
    if not name:
        return None
    for prefix, plane in _COLLECTOR_PLANES:
        if name == prefix or name.startswith(prefix):
            return plane
    return None


__all__ = [
    "CONSUMED",
    "PLANES",
    "PLANE_INDEX",
    "REJECTED",
    "SCHEMA",
    "SUPPLIED",
    "UNSUPPLIED",
    "WITNESS",
    "facts_from_records",
    "measure",
    "plane_for_collector",
    "register",
    "resolve_producer",
]
