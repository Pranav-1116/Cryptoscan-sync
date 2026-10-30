"""Runtime crypto observation depth — *installed* is not *executed*.

    OpenSSL installed            ≠   AES-256 actually executed
    a library mapped in a process ≠   a crypto API call made by that process
    a negotiated TLS session     ≠   the application's own cipher

Every runtime claim this product makes has to name which of those three
statements it is actually supporting. This module is the single place where
that is decided, per runtime family, from the code that exists in this build:

``depth``
    the deepest fact this build can establish for that family:

    ``INVOCATION``       a crypto API call was observed in a running process
                         (symbol-level instrumentation, counted per call)
    ``CONFIGURATION``    provider / certificate / policy state was read — no call
    ``PROCESS_LIBRARY``  a library is mapped by a running process — no call
    ``INGEST_ONLY``      the platform accepts observations from this source, but
                         nothing in this build *produces* them
    ``ABSENT``           no producer and no adapter

``producers``
    ``"module:attribute"`` refs resolved by import. A producer that disappears
    from the build degrades the row on its own, exactly like the discovery
    surface registry: the matrix cannot drift ahead of the code.

``ingest_only``
    engine adapter sources (`runtime.engine.adapters`) that can be *received*
    over the API but have no collector here. Listing them as coverage would be
    the exact overclaim this module exists to prevent, so they are shipped in a
    separate field with the reason.

The measured half (``observed``) reads the runtime finding store: how many
stored observations exist, how many are invocation-level (the LD_PRELOAD shim
tags its rows ``extra.source = "ld-preload"``), and which hosts reported. An
unread store is ``NOT_EVALUATED``, never zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from api.estate_surfaces import resolve_detector

SCHEMA = "cryptoscan.runtime-depth/1"

DEPTH_INVOCATION = "INVOCATION"
DEPTH_CONFIGURATION = "CONFIGURATION"
DEPTH_PROCESS_LIBRARY = "PROCESS_LIBRARY"
DEPTH_INGEST_ONLY = "INGEST_ONLY"
DEPTH_ABSENT = "ABSENT"

#: ordered strongest → weakest, so a reader can rank two rows at a glance
DEPTHS: tuple[str, ...] = (
    DEPTH_INVOCATION,
    DEPTH_CONFIGURATION,
    DEPTH_PROCESS_LIBRARY,
    DEPTH_INGEST_ONLY,
    DEPTH_ABSENT,
)

DEPTH_MEANING: dict[str, str] = {
    DEPTH_INVOCATION: "a cryptographic API call in a running process was observed and counted",
    DEPTH_CONFIGURATION: "provider, certificate or policy state was read — no call was observed",
    DEPTH_PROCESS_LIBRARY: "a crypto library is mapped by a running process — nothing about its use",
    DEPTH_INGEST_ONLY: "the platform can receive these observations, but no collector here produces them",
    DEPTH_ABSENT: "no producer and no adapter in this build",
}


@dataclass(frozen=True)
class RuntimePath:
    """One runtime family and what this build can actually say about it."""

    id: str
    label: str
    family: str
    depth: str
    producers: tuple[str, ...]
    reads: str
    cannot_claim: str
    ingest_only: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.depth not in DEPTHS:
            raise ValueError(f"unknown depth {self.depth!r}")


#: The families a bank's production estate actually runs. Order is by how much
#: of a typical estate they carry, not by how well they are covered.
PATHS: tuple[RuntimePath, ...] = (
    RuntimePath(
        id="openssl_native",
        label="Native processes (OpenSSL / BoringSSL / LibreSSL)",
        family="ELF / dynamically linked",
        depth=DEPTH_INVOCATION,
        producers=(
            "runtime.agent.preload_trace:trace_command",
            "runtime.agent.preload_trace:parse_trace_log",
            "runtime.agent.crypto_events:observations_from_trace",
            "runtime.agent.process_discovery:scan_processes",
        ),
        ingest_only=("OPENSSL_TRACE",),
        reads=(
            "one record per EVP_* call in a process started under the LD_PRELOAD shim: function, "
            "algorithm, mode, key size and call count, plus the libraries each process maps"
        ),
        cannot_claim=(
            "the shim hooks dynamically resolved symbols. A statically linked binary, a Go or Rust "
            "binary carrying its own TLS stack, a JVM/CLR that reaches crypto through native "
            "providers, or a process that was not started under the shim produces NOTHING — and "
            "'no observation' then means 'not observed', never 'did not run'"
        ),
        gaps=(
            "no eBPF/uprobe capture, so long-running services cannot be observed without a restart",
            "no provider-level (OpenSSL 3 provider dispatch) instrumentation below the EVP entry point",
            "no memory or key-material inspection, by policy",
        ),
    ),
    RuntimePath(
        id="jvm",
        label="JVM applications (JCE, BouncyCastle)",
        family="Java virtual machine",
        depth=DEPTH_PROCESS_LIBRARY,
        producers=("runtime.agent.process_discovery:scan_processes",),
        ingest_only=("JVM_JCE",),
        reads=(
            "that a JVM process exists and which native crypto libraries it maps (libjvm plus "
            "libcrypto/libssl when the JVM loads a native provider). The JCE call itself is not "
            "observed: the engine accepts JVM_JCE observations and no Java agent here produces them"
        ),
        cannot_claim=(
            "a JVM application's crypto is not observed by this platform today. Static analysis of "
            "JARs and source is the only evidence available, and that is presence, not execution"
        ),
        gaps=(
            "no `-javaagent` collector (Cipher/MessageDigest/Signature instrumentation)",
            "no JFR crypto event consumption",
            "no BouncyCastle provider-level hook",
        ),
    ),
    RuntimePath(
        id="dotnet_windows",
        label=".NET / Windows CNG applications",
        family="CLR on Windows",
        depth=DEPTH_PROCESS_LIBRARY,
        producers=(
            "runtime.agent.process_discovery:scan_processes",
            "inventory.windows_capi:collect_default_provider",
            "inventory.windows_cng:collect_registration",
        ),
        ingest_only=("DOTNET_CNG",),
        reads=(
            "that a CLR process exists and which native crypto libraries it maps, plus the *default "
            "CNG provider*, registered CNG algorithms and certificates — process and provider "
            "state, never an invocation"
        ),
        cannot_claim=(
            "a registered algorithm is not a call and a default provider is not a use. Without ETW "
            "or EventPipe consumption this platform cannot say which .NET application encrypted "
            "what, and it does not pretend otherwise"
        ),
        gaps=(
            "no ETW (Microsoft-Windows-Crypto-*) consumer",
            "no EventPipe/DiagnosticSource listener",
            "no Schannel per-connection trace",
        ),
    ),
    RuntimePath(
        id="go_runtime",
        label="Go services (crypto/tls, crypto/aes)",
        family="Go runtime",
        depth=DEPTH_INGEST_ONLY,
        producers=(),
        ingest_only=("GO_CRYPTO",),
        reads=(
            "nothing at the call level. The engine accepts GO_CRYPTO observations; no collector here "
            "produces them, and the LD_PRELOAD shim cannot see a Go binary's own TLS stack"
        ),
        cannot_claim=(
            "Go's crypto is statically linked and does not resolve libcrypto symbols, so the shim "
            "produces no evidence for it. Wire-level observation of its listeners is the only "
            "runtime evidence available for these services"
        ),
        gaps=(
            "no uprobe on crypto/tls handshake symbols",
            "no `GODEBUG`-based trace consumption",
        ),
    ),
    RuntimePath(
        id="rust_runtime",
        label="Rust services (ring, rustls, openssl crate)",
        family="Rust native",
        depth=DEPTH_INGEST_ONLY,
        producers=(),
        ingest_only=("RUST_CRYPTO",),
        reads=(
            "nothing at the call level. The engine accepts RUST_CRYPTO observations; no collector "
            "here produces them"
        ),
        cannot_claim=(
            "rustls and ring are statically linked in typical builds, so neither symbol "
            "interposition nor the LD_PRELOAD shim sees them"
        ),
        gaps=("no uprobe instrumentation", "no tracing-subscriber integration"),
    ),
    RuntimePath(
        id="interpreted",
        label="Interpreted services (Python, Node.js, PHP, Ruby)",
        family="Managed interpreter",
        depth=DEPTH_ABSENT,
        producers=(),
        ingest_only=(),
        reads=(
            "nothing at invocation level. These runtimes resolve their crypto either through "
            "libcrypto (visible to the shim when the interpreter is started under it) or through "
            "bundled native modules; there is no language-level hook here"
        ),
        cannot_claim=(
            "a Python `cryptography` call or a Node `crypto.createCipheriv` call is invisible unless "
            "the interpreter itself was started under the LD_PRELOAD shim, and even then the "
            "language-level operation name is lost"
        ),
        gaps=(
            "no import hook / require hook instrumentation",
            "no OpenTelemetry crypto span convention",
        ),
    ),
    RuntimePath(
        id="hsm_provider",
        label="HSM / PKCS#11 providers",
        family="Hardware security module",
        depth=DEPTH_CONFIGURATION,
        producers=(
            "api.estate_discovery:collect_hsm_plane",
            "cbom.kmip:assess_kmip_object",
        ),
        ingest_only=("PKCS11_API", "HSM_AUDIT"),
        reads=(
            "keys and mechanisms *present* on the HSM via KMIP/PKCS#11 inventory: algorithm, "
            "size and usage attributes"
        ),
        cannot_claim=(
            "key attributes describe what the module can do with a key, not what applications did "
            "with it. Operation-level evidence requires the HSM's own audit log, which this build "
            "does not consume"
        ),
        gaps=(
            "no HSM audit-log ingestion (operation-level Level 3 telemetry)",
            "no PKCS#11 API interposition on application hosts",
        ),
    ),
    RuntimePath(
        id="kms_audit",
        label="Cloud KMS audit telemetry",
        family="Cloud key management",
        depth=DEPTH_CONFIGURATION,
        producers=(
            "api.estate_kms:collect_kms_usage",
            "inventory.cloud_kms:collect_aws_kms",
        ),
        ingest_only=("KMS_AUDIT",),
        reads=(
            "key inventory and the usage counters the provider exposes per key (encrypt/decrypt/"
            "sign call counts where the API reports them)"
        ),
        cannot_claim=(
            "aggregate call counters are not per-request audit events: they cannot be attributed to "
            "a workload or a record. Nothing here proves which data was encrypted"
        ),
        gaps=(
            "no CloudTrail / Azure Activity Log / GCP Audit Log ingestion",
            "no per-principal attribution of key use",
        ),
    ),
)

PATH_INDEX = {path.id: path for path in PATHS}


def _row(path: RuntimePath) -> dict[str, Any]:
    producers = [{"ref": ref, **resolve_detector(ref)} for ref in path.producers]
    present = [item for item in producers if item["present"]]
    depth = path.depth
    notes: list[str] = []
    if depth == DEPTH_INVOCATION and not present:
        # The claim of call-level observation collapses the moment its producer
        # is missing: report the truth about this build, not the design intent.
        depth = DEPTH_ABSENT
        notes.append("every declared producer is absent from this build, so no invocation is observed")
    elif depth == DEPTH_CONFIGURATION and not present:
        depth = DEPTH_ABSENT
        notes.append("every declared producer is absent from this build")
    return {
        "id": path.id,
        "label": path.label,
        "family": path.family,
        "depth": depth,
        "declared_depth": path.depth,
        "depth_meaning": DEPTH_MEANING[depth],
        "producers": producers,
        "producers_present": len(present),
        "ingest_only": list(path.ingest_only),
        "reads": path.reads,
        "cannot_claim": path.cannot_claim,
        "gaps": list(path.gaps),
        "notes": notes,
    }


#: rows scanned to classify the store. The matrix reports that it sampled
#: rather than silently generalising from the first N.
SAMPLE_CAP = 5000


def observe(db: Any, graph: Any | None = None) -> dict[str, Any]:
    """What the runtime store actually holds, classified by observation depth.

    The three kinds this platform stores are *not* interchangeable:

    * ``ld-preload`` rows     a crypto call was counted   → invocation evidence
    * session rows            a negotiated TLS/IPsec/SSH  → wire evidence
    * ``tls-library-risk``    a library version was judged → installed, not used

    A store holding only the last two has **no** invocation evidence, and this
    reports that as its own state rather than as a low number.
    """
    try:
        from sqlalchemy import select

        from db.models.runtime_finding import RuntimeFinding

        rows = list(
            db.execute(
                select(
                    RuntimeFinding.kind,
                    RuntimeFinding.extra,
                    RuntimeFinding.hostname,
                    RuntimeFinding.observation_count,
                ).limit(SAMPLE_CAP)
            ).all()
        )
    except Exception as exc:  # a failed read is a fact about the read (§29)
        return {
            "state": "NOT_EVALUATED",
            "reason": f"runtime finding store unreadable: {type(exc).__name__}: {exc}"[:240],
            "rows": None,
            "invocation_observations": None,
        }

    invocation = wire = library = 0
    hosts: set[str] = set()
    invocation_calls = 0
    for kind, extra, hostname, count in rows:
        payload = extra if isinstance(extra, dict) else {}
        source = str(payload.get("source") or "").lower()
        if source == "ld-preload" or payload.get("function"):
            invocation += 1
            invocation_calls += int(count or 1)
        elif str(kind or "").lower() == "tls-library-risk":
            library += 1
        else:
            wire += 1
        if hostname:
            hosts.add(str(hostname))

    estate = _estate_observations(graph)
    if estate and estate.get("invocation_evidence"):
        invocation = max(invocation, 1)

    if invocation:
        state, reason = "INVOCATION_OBSERVED", None
    elif rows:
        state, reason = (
            "NO_INVOCATION_EVIDENCE",
            (
                "the store holds only wire and library evidence — no process has been traced, so no "
                "algorithm invocation is known. This is not a statement that none ran"
            ),
        )
    elif estate and estate.get("state") == "OBSERVED":
        state, reason = (
            "ESTATE_OBSERVATION_ONLY",
            (
                "the estate observation holds runtime evidence (process/library or endpoint) but the "
                "agent finding feed is empty, so no per-call detail exists here. Depth below is what "
                "the estate measured; INVOCATION stays a capability"
            ),
        )
    else:
        state, reason = (
            "NO_RUNTIME_OBSERVATIONS",
            "no runtime observation has been stored; every runtime depth below is a capability, not a finding",
        )
    return {
        "state": state,
        "reason": reason,
        "rows": len(rows),
        "sampled": len(rows) >= SAMPLE_CAP,
        "sample_cap": SAMPLE_CAP,
        "invocation_rows": invocation,
        "invocation_calls": invocation_calls,
        "wire_rows": wire,
        "library_risk_rows": library,
        "hosts": sorted(hosts)[:50],
        "host_count": len(hosts),
        "estate": estate,
        "note": (
            "two stores are read: the runtime finding feed (agent submissions) and the estate "
            "observation (/ingestion/observations). A row in either is evidence; neither is a "
            "statement that every process was instrumented"
        ),
    }


def _estate_observations(graph: Any | None) -> dict[str, Any] | None:
    """Runtime evidence the stored estate observation carries, if there is one."""
    if graph is None:
        return None
    invocation = process_library = other = 0
    calls = 0
    hosts: set[str] = set()
    for record in graph.evidence():
        if str(record.get("evidence_type")) != "RUNTIME_OBSERVED":
            continue
        facts = record.get("facts") or {}
        kind = str(facts.get("evidence_kind") or "").upper()
        if kind == "INVOCATION" or facts.get("function"):
            invocation += 1
            calls += int(facts.get("observations") or 1)
        elif kind == "PROCESS_LIBRARY":
            process_library += 1
        else:
            other += 1
        if facts.get("hostname"):
            hosts.add(str(facts["hostname"]))
    return {
        "state": "OBSERVED" if (invocation or process_library or other) else "NO_RUNTIME_EVIDENCE",
        "invocation_evidence": invocation,
        "invocation_calls": calls,
        "process_library_evidence": process_library,
        "other_runtime_evidence": other,
        "hosts": sorted(hosts)[:50],
        "note": (
            "process-library evidence says a library was mapped by a running process; only "
            "INVOCATION evidence says a call was counted"
        ),
    }


def registry(observed: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The runtime-depth matrix, optionally with the measured store attached."""
    rows = [_row(path) for path in PATHS]
    by_depth: dict[str, int] = {depth: 0 for depth in DEPTHS}
    for row in rows:
        by_depth[row["depth"]] = by_depth.get(row["depth"], 0) + 1
    return {
        "schema": SCHEMA,
        "paths": rows,
        "depths": list(DEPTHS),
        "depth_meaning": DEPTH_MEANING,
        "rollup": {
            "paths": len(rows),
            "by_depth": by_depth,
            "call_level_paths": by_depth.get(DEPTH_INVOCATION, 0),
            "ingest_only_paths": by_depth.get(DEPTH_INGEST_ONLY, 0),
            "absent_paths": by_depth.get(DEPTH_ABSENT, 0),
        },
        "observed": dict(observed) if observed is not None else None,
        "axiom": (
            "OpenSSL installed is not AES-256 executed. A mapped library, a registered provider, a "
            "negotiated TLS session and a counted EVP_* call are four different facts, and only the "
            "last one is invocation evidence"
        ),
        "claim": (
            "this lists what the platform can observe at runtime, per family, in this build. It is "
            "not a statement that every process in a bank is instrumented: only the families marked "
            "INVOCATION produce call-level evidence, and only for processes started under the shim"
        ),
        "note": (
            "ingest_only means the event contract accepts that source but no collector here "
            "produces it. Counting those as coverage is the overclaim this matrix exists to prevent"
        ),
    }


__all__ = [
    "DEPTHS",
    "DEPTH_ABSENT",
    "DEPTH_CONFIGURATION",
    "DEPTH_INGEST_ONLY",
    "DEPTH_INVOCATION",
    "DEPTH_MEANING",
    "DEPTH_PROCESS_LIBRARY",
    "PATHS",
    "PATH_INDEX",
    "SAMPLE_CAP",
    "SCHEMA",
    "observe",
    "registry",
]
