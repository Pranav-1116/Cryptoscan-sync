"""Where each capability actually reaches, stated once (spec 94 §4, docs/CAPABILITY-MATURITY.md).

An assessment that says "partially implemented" is not actionable until every
surface names three things: what exists, what does not, and which route or module
proves it. This module is that list, and it is *checked* rather than trusted —
``services/api/tests/unit/test_maturity_register.py`` fails when:

* a referenced module no longer exists,
* a referenced route is not registered in this build,
* an area that is not ``SUBSTANTIAL`` lists no missing work (an area with nothing
  left to do is either finished or unmeasured),
* the six BOM kinds drift from ``api.bom_maturity.BOMS``,
* or a claim sentence contradicts its own state ("complete" on a ``PARTIAL``).

The states are deliberately not scores. A number invites rounding up; a state
plus a missing list asks the reader to check one thing.

    SUBSTANTIAL  a collector reads a source of truth; its facts reach the projections
    PARTIAL      a real collector covers part of the surface; the rest is named here
    CANDIDATE    code exercises a candidate input and is explicitly not admitted
    FOUNDATION   models and seams exist; no collection path reaches the surface yet
    IMPORT_ONLY  facts arrive only through an approved file import
    ABSENT       nothing reads this surface

Every state below was set by reading the code in this tree, not from a roadmap.
"""

from __future__ import annotations

SCHEMA = "cryptoscan.maturity-register/1"

SUBSTANTIAL = "SUBSTANTIAL"
PARTIAL = "PARTIAL"
CANDIDATE = "CANDIDATE"
FOUNDATION = "FOUNDATION"
IMPORT_ONLY = "IMPORT_ONLY"
ABSENT = "ABSENT"

STATE_MEANING = {
    SUBSTANTIAL: "a collector reads this surface from a source of truth and the facts reach the projections",
    PARTIAL: "a real collector covers part of this surface; the uncovered part is listed",
    CANDIDATE: "code exercises a candidate input; it is not admitted as a collector",
    FOUNDATION: "models and seams exist; no collection path reaches this surface yet",
    IMPORT_ONLY: "facts arrive only through an approved file import",
    ABSENT: "nothing reads this surface",
}

#: States that must name their remaining work. Only a substantial surface may
#: claim to have none left, and even then the claim is about this build.
MUST_LIST_MISSING = (PARTIAL, CANDIDATE, FOUNDATION, IMPORT_ONLY)


def _surface(identifier: str, label: str, state: str, *, collector: str | None,
             note: str, missing: tuple[str, ...] = ()) -> dict:
    if state not in STATE_MEANING:
        raise ValueError(f"unknown maturity state {state!r}")
    return {
        "id": identifier,
        "label": label,
        "state": state,
        "state_meaning": STATE_MEANING[state],
        "collector": collector,
        "note": note,
        "missing": list(missing),
    }


# --------------------------------------------------------------------------- #
# the eight links of the Digital Twin, as surfaces in their own right
# --------------------------------------------------------------------------- #

TWIN_SURFACES: tuple[dict, ...] = (
    _surface(
        "TWIN_ESTATE", "Estate", SUBSTANTIAL,
        collector="services/api/api/routers/estate_graph.py",
        note="one discovery run is the estate; the twin is a projection of its payload",
        missing=("estates larger than one discovery run need partitioned collection",),
    ),
    _surface(
        "TWIN_ASSETS", "Assets", SUBSTANTIAL,
        collector="shared/shared_models/shared_models/estate_graph.py",
        note="typed assets (application, load balancer, host, HSM, KMS, system) with identity",
    ),
    _surface(
        "TWIN_RELATIONSHIPS", "Relationships", PARTIAL,
        collector="shared/shared_models/shared_models/estate_graph.py",
        note="an edge needs a basis and evidence; without both it is recorded UNKNOWN, never assumed",
        missing=(
            "inference from co-location or naming is refused by design and needs an operator-approved mapping instead",
            "multi-hop correlation across collectors that observe the same asset differently",
            "vendor/CMDB hierarchies beyond the imported ServiceNow shape",
        ),
    ),
    _surface(
        "TWIN_CRYPTO_GRAPH", "Crypto graph", PARTIAL,
        collector="shared/shared_models/shared_models/estate_twin.py",
        note="artefacts carry usage_state from the evidence class (SUPPORTED/CONFIGURED/NEGOTIATED/OBSERVED)",
        missing=(
            "key material lineage (which key protects which record) is not modelled",
            "cross-plane artefacts (a TLS session using a certificate using a private key) are separate facts, not one path",
        ),
    ),
    _surface(
        "TWIN_EVIDENCE_GRAPH", "Evidence graph", SUBSTANTIAL,
        collector="services/api/api/routers/estate_graph.py",
        note="every fact carries collector, source, confidence and hash; /twin/why answers why an edge exists",
    ),
    _surface(
        "TWIN_HISTORY", "History", PARTIAL,
        collector="services/api/api/estate_twin_store.py",
        note="snapshots are keyed by projection id, so re-observing the same evidence is not a new version",
        missing=(
            "per-fact time series: the store keeps evidence-state versions, not a queryable value history",
            "retention policy for snapshots (nothing prunes them yet)",
        ),
    ),
    _surface(
        "TWIN_IMPACT", "Impact analysis", SUBSTANTIAL,
        collector="shared/shared_models/shared_models/estate_twin.py",
        note="breadth-first over established edges only, with blind spots, blockers and per-hop paths; /twin/impact-as-of compares a stored state with now",
        missing=(
            "impact is topological, not business-criticality weighted — a system's criticality does not shorten the radius",
        ),
    ),
    _surface(
        "TWIN_SIMULATION", "Simulation", PARTIAL,
        collector="shared/shared_models/shared_models/estate_twin.py",
        note="ten scenario types plus three cascade models, applied to a copy; the live projection id is checked unchanged",
        missing=(
            "no queueing or capacity model: a simulated failover says what is reached, not what it costs",
            "cascades travel declared predicates only; a predicate without a rule stops the failure and says so",
        ),
    ),
)

# --------------------------------------------------------------------------- #
# static cryptographic discovery, surface by surface
# --------------------------------------------------------------------------- #

STATIC_SURFACES: tuple[dict, ...] = (
    _surface("LINUX", "Linux hosts", SUBSTANTIAL,
             collector="services/agent/",
             note="packages, libraries, services, listeners, certificates and configuration from an owned host agent"),
    _surface("WINDOWS", "Windows hosts", CANDIDATE,
             collector="services/api/api/windows_collector.py",
             note="OS/uninstall/file/SCM, public-certificate, process/module and TPM device-info candidates",
             missing=(
                 "CNG/legacy CAPI provider metadata",
                 "TLS listener attribution",
                 "native execution and independent security review",
                 "universal job/materializer admission",
             )),
    _surface("KUBERNETES", "Kubernetes", PARTIAL,
             collector="services/scanner/",
             note="manifest and image inspection; secret objects are read as configuration, not decrypted",
             missing=(
                 "live API-server admission-time inspection",
                 "service-mesh certificate authority inventory",
                 "etcd encryption-configuration coverage",
             )),
    _surface("CLOUD", "Cloud (AWS/Azure/GCP)", PARTIAL,
             collector="services/cloud_scanner/",
             note="read-only estate scan with credentials; several managed crypto services are metadata-only",
             missing=(
                 "per-service key policy interpretation for every KMS variant",
                 "cross-account and organisation-wide enumeration",
             )),
    _surface("HSM", "HSM", FOUNDATION,
             collector="services/scanner/",
             note="vendor catalogue and PKCS#11 metadata; key contents are never read",
             missing=(
                 "live partition/slot enumeration per vendor",
                 "key-use attestation from the HSM audit log",
             )),
    _surface("KMS", "KMS", PARTIAL,
             collector="services/cloud_scanner/",
             note="managed key inventories where the provider API exposes them",
             missing=("key rotation history", "grant/policy graph across accounts")),
    _surface("DATABASES", "Databases", PARTIAL,
             collector="services/network_scanner/",
             note="TLS handshake and configuration reading for the supported engines",
             missing=(
                 "column/table-level encryption inventory",
                 "TDE keystore discovery per vendor",
                 "stored-procedure crypto usage",
             )),
    _surface("NETWORK_DEVICES", "Network devices", PARTIAL,
             collector="services/network_scanner/",
             note="TLS and SSH offer reading on reachable endpoints",
             missing=("SNMP/vendor configuration parsing", "routing/overlay correlation")),
    _surface("VPN_IPSEC", "VPN / IPsec", PARTIAL,
             collector="services/network_scanner/",
             note="IKE proposal offers are read; a completed IKE session is not",
             missing=("IKEv2 session and child-SA reading", "PSK/certificate source attribution")),
    _surface("PKI", "PKI / CA", PARTIAL,
             collector="services/api/api/routers/certificates.py",
             note="certificate inventory with expiry, issuer and renewal state",
             missing=(
                 "CA hierarchy traversal and cross-signing",
                 "CRL/OCSP revocation state per certificate",
                 "key custody proof for issuing keys",
             )),
    _surface("LEGACY", "Legacy systems", IMPORT_ONLY,
             collector="services/api/api/routers/ingestion.py",
             note="facts arrive only as approved imports; no collector reads these systems",
             missing=("any native collector", "mainframe and COBOL/RPG source parsing are sample-scoped, not customer-qualified")),
    _surface("VENDOR", "Vendor ecosystem", PARTIAL,
             collector="services/universal_vendor/universal_vendor",
             note="vendor and product metadata with mapping to the shipped catalogue",
             missing=("vendor-published crypto posture feeds", "end-of-life/end-of-support automation per product")),
)

# --------------------------------------------------------------------------- #
# runtime and network observation
# --------------------------------------------------------------------------- #

RUNTIME_FAMILIES: tuple[dict, ...] = (
    _surface("RUNTIME_PROCESES", "Processes and libraries", PARTIAL,
             collector="services/agent/",
             note="process tree, loaded libraries and package versions from the host agent",
             missing=("library version-to-algorithm reasoning for every vendor build",)),
    _surface("RUNTIME_LISTENERS", "Listeners and services", PARTIAL,
             collector="services/agent/",
             note="bound sockets and service units with their configuration",
             missing=("mapping a listener to the cipher suite it will accept without a probe",)),
    _surface("RUNTIME_INVOCATION", "Algorithm invocation", FOUNDATION,
             collector="services/agent/",
             note="one family reaches call-level evidence; installed is never reported as executed",
             missing=(
                 "tracing for every crypto provider (OpenSSL, CNG, JCA, BouncyCastle)",
                 "attribution of a call to the requesting application",
                 "kernel-level observation (kTLS, dm-crypt)",
             )),
)

NETWORK_PROTOCOLS: tuple[dict, ...] = (
    _surface("TLS", "TLS", SUBSTANTIAL,
             collector="services/network_scanner/",
             note="completed-handshake reader: version, cipher suite, certificate chain, negotiated key exchange"),
    _surface("SSH", "SSH", PARTIAL,
             collector="services/network_scanner/",
             note="offer reader: algorithms the server will accept, taken before authentication",
             missing=("session-level observation", "per-user key and rekey events")),
    _surface("IPSEC", "IPsec / IKE", PARTIAL,
             collector="services/network_scanner/",
             note="proposal offer reader",
             missing=("child-SA reading", "transport vs tunnel attribution")),
    _surface("DB_PROTOCOLS", "Database protocols", PARTIAL,
             collector="services/network_scanner/",
             note="handshake and negotiation where the engine exposes it before authentication",
             missing=("post-authentication cipher state for engines that change it",)),
    _surface("MQ", "Message queues", ABSENT,
             collector=None,
             note="no reader exists in this build",
             missing=("AMQP/MQTT/Kafka SASL and TLS negotiation readers",)),
    _surface("SERVICE_MESH", "Service mesh", ABSENT,
             collector=None,
             note="no reader exists in this build",
             missing=("mTLS policy and identity documents from a mesh control plane",)),
    _surface("PASSIVE", "Passive traffic", ABSENT,
             collector=None,
             note="no passive capture path exists in this build",
             missing=("flow-level crypto observation", "decrypt-free metadata extraction")),
    _surface("PROPRIETARY", "Proprietary financial protocols", ABSENT,
             collector=None,
             note="no reader exists in this build",
             missing=("SWIFT/ISO 8583/FIX crypto posture readers",)),
)

# --------------------------------------------------------------------------- #
# the six BOM projections
# --------------------------------------------------------------------------- #

BOM_STATES: tuple[dict, ...] = (
    _surface("CBOM", "Cryptography BOM", SUBSTANTIAL,
             collector="services/cbom/",
             note="the projection every collector feeds; components carry usage_state from the evidence class"),
    _surface("SBOM", "Software BOM", SUBSTANTIAL,
             collector="services/evidence/",
             note="package and licence facts from source and image scanners",
             missing=("binary-only components without a package database",)),
    _surface("NBOM", "Network BOM", PARTIAL,
             collector="services/network_scanner/",
             note="endpoints and the protocols observed on them",
             missing=("multi-hop path correlation", "passive and mesh coverage")),
    _surface("TECHBOM", "Technology BOM", PARTIAL,
             collector="shared/shared_models/shared_models/bom_export.py",
             note="technology families derived from collected facts",
             missing=("vendor product lifecycle data",)),
    _surface("HBOM", "Hardware BOM", FOUNDATION,
             collector="services/scanner/",
             note="hardware and firmware metadata where a plugin can read it",
             missing=("live firmware attestation", "TPM/HSM part-level inventory beyond device info")),
    _surface("VBOM", "Vulnerability BOM", FOUNDATION,
             collector="shared/shared_models/shared_models/bom_export.py",
             note="vulnerability facts as projections of collected evidence, not a scanner of its own",
             missing=("CVE feed ingestion and matching", "VEX consumption beyond imported statements")),
)

# --------------------------------------------------------------------------- #
# the claims this register permits
# --------------------------------------------------------------------------- #

CLAIMS: dict[str, object] = {
    "may_claim": (
        "CryptoScan provides an evidence-driven framework for discovering cryptographic assets across "
        "multiple infrastructure surfaces, with coverage that expands one collector at a time, and it "
        "states per surface where that coverage stops."
    ),
    "may_not_claim": (
        "CryptoScan discovers every cryptographic asset in any bank environment.",
        "CryptoScan proves which algorithms executed everywhere.",
        "All six BOMs are equally mature.",
        "The Digital Twin models the whole chain completely.",
    ),
    "why": (
        "Each of those is a completeness claim over an estate the product has not seen. What the "
        "product can prove is bounded: this collector read this surface, this evidence class backs "
        "this fact, and this list is what is still missing."
    ),
}

#: Checked by the test: a route named here must be registered in this build.
ROUTES: tuple[str, ...] = (
    "/estate/evidence/discovery/runtime-depth",
    "/estate/evidence/discovery/network-protocols",
    "/estate/evidence/discovery/windows-collector",
    "/estate/evidence/discovery/bom-maturity",
    "/estate/evidence/discovery/maturity",
    "/estate/evidence/twin",
    "/estate/evidence/twin/impact",
    "/estate/evidence/twin/impact-as-of",
    "/estate/evidence/twin/simulate",
    "/estate/evidence/twin/simulate-as-of",
    "/estate/evidence/twin/why",
)


def register() -> dict:
    """The whole register, in the order a reader should meet it."""
    areas = (
        {
            "id": "DIGITAL_TWIN",
            "label": "Digital Twin",
            "state": PARTIAL,
            "summary": (
                "Estate → assets → relationships → crypto graph → evidence graph → history → impact → "
                "simulation. Every link exists and reports where it stops; relationship inference and "
                "per-fact history are the thin links."
            ),
            "surfaces": list(TWIN_SURFACES),
            "missing": (
                "relationship discovery beyond approved mappings and collected evidence",
                "per-fact history over time, rather than per-evidence-state snapshots",
                "business-criticality weighting in the impact radius",
            ),
            "measured_by": ("/estate/evidence/twin", "/estate/evidence/twin/impact-as-of"),
            "claim": (
                "The twin answers, per link, what it holds for a real estate right now, and refuses to "
                "call an unread store empty."
            ),
        },
        {
            "id": "STATIC_DISCOVERY",
            "label": "Static crypto discovery",
            "state": PARTIAL,
            "summary": (
                "Twelve infrastructure surfaces with a real collector on some of them and a stated gap "
                "on the rest. Linux is the deepest; Windows is a candidate, not a collector."
            ),
            "surfaces": list(STATIC_SURFACES),
            "missing": (
                "Windows CNG/CAPI provider metadata and native admission",
                "live HSM partition enumeration",
                "column-level database encryption inventory",
                "native legacy-system collectors",
            ),
            "measured_by": ("/estate/evidence/discovery/windows-collector",),
            "claim": (
                "Coverage is per surface: each row names its collector and what that collector does "
                "not read."
            ),
        },
        {
            "id": "RUNTIME_DISCOVERY",
            "label": "Runtime discovery",
            "state": PARTIAL,
            "summary": (
                "Processes, libraries, listeners, services, packages, certificates and configuration are "
                "observed. Algorithm invocation is not: installed is never reported as executed."
            ),
            "surfaces": list(RUNTIME_FAMILIES),
            "missing": (
                "call-level evidence for every crypto provider",
                "kernel-level observation",
            ),
            "measured_by": ("/estate/evidence/discovery/runtime-depth",),
            "claim": "Runtime facts carry the evidence class that produced them, and configuration is never promoted to execution.",
        },
        {
            "id": "NETWORK_DISCOVERY",
            "label": "Network discovery",
            "state": PARTIAL,
            "summary": (
                "TLS is a completed-handshake reader. SSH and IPsec are offer readers. Message queues, "
                "service mesh, passive capture and proprietary financial protocols have no reader."
            ),
            "surfaces": list(NETWORK_PROTOCOLS),
            "missing": (
                "SSH session-level observation",
                "IPsec child-SA reading",
                "message-queue and service-mesh readers",
                "passive traffic coverage",
                "multi-hop correlation",
            ),
            "measured_by": ("/estate/evidence/discovery/network-protocols",),
            "claim": "Each protocol is reported with the reader that exists, or as absent.",
        },
        {
            "id": "WINDOWS",
            "label": "Windows",
            "state": CANDIDATE,
            "summary": (
                "Candidate collectors for OS/uninstall/file/SCM, public certificates, process/module "
                "inventory and TPM device info. No universal Windows admission, no complete collector."
            ),
            "surfaces": [surface for surface in STATIC_SURFACES if surface["id"] == "WINDOWS"],
            "missing": (
                "CNG/CAPI provider metadata",
                "TLS listener attribution",
                "native execution and security review",
                "universal job/materializer admission",
            ),
            "measured_by": ("/estate/evidence/discovery/windows-collector",),
            "claim": "The server's own answer to 'is this a complete Windows collector' is NO.",
        },
        {
            "id": "BOM_PROJECTIONS",
            "label": "Six BOM projections",
            "state": PARTIAL,
            "summary": (
                "One projection engine, six depths. CBOM and SBOM are fed by collectors that read a "
                "source of truth; HBOM and VBOM depend on planes most estates do not expose."
            ),
            "surfaces": list(BOM_STATES),
            "missing": (
                "HBOM firmware attestation",
                "VBOM CVE feed ingestion",
                "NBOM multi-hop correlation",
            ),
            "measured_by": ("/estate/evidence/discovery/bom-maturity",),
            "claim": "Each BOM states the deepest evidence class behind its components; the depths are not equal and are not presented as equal.",
        },
    )
    return {
        "schema": SCHEMA,
        "areas": list(areas),
        "claims": dict(CLAIMS),
        "routes": list(ROUTES),
        "note": (
            "States are set by reading this build, not from a roadmap. An area that is not SUBSTANTIAL "
            "always lists what is missing; an empty missing list on a partial area would be a claim, "
            "and the test rejects it."
        ),
    }


__all__ = [
    "ABSENT",
    "BOM_STATES",
    "CANDIDATE",
    "CLAIMS",
    "FOUNDATION",
    "IMPORT_ONLY",
    "MUST_LIST_MISSING",
    "NETWORK_PROTOCOLS",
    "PARTIAL",
    "ROUTES",
    "RUNTIME_FAMILIES",
    "SCHEMA",
    "STATE_MEANING",
    "STATIC_SURFACES",
    "SUBSTANTIAL",
    "TWIN_SURFACES",
    "register",
]
