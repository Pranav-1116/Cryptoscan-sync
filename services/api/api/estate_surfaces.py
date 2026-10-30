"""Discovery surface coverage — what this build can read, and what it did read.

A crypto-discovery product makes a claim about *coverage*, and that claim is only
honest if it is compiled from the code that exists rather than written by hand.
This module is the single place where the surfaces a bank actually has (Linux and
Windows hosts, Kubernetes, cloud control planes, HSMs, KMS, databases, network
devices, VPN/IPsec, PKI, source code, runtime, legacy imports, vendor
declarations, CMDB) are mapped onto the collectors this build ships.

Three things are kept deliberately separate, because merging them is how a
partial collector turns into a marketing claim:

``kind``
    *how* the surface is read — a live control-plane API, a live probe, an
    artifact the operator supplies, static analysis, or a declared/imported
    record. The ranking below is the ranking of evidence strength, strongest
    first.

``maturity``
    the *ceiling* of what this collector can establish on that surface, derived
    from its kind and from the gaps it declares. Nothing here is "complete":
    every row names what it cannot claim.

``configuration`` / ``observed``
    whether *this deployment* can ask the source right now (the plane's own
    config resolver decides), and what the newest discovery run actually
    collected from it. ``UNKNOWN`` and ``NOT_OBSERVED`` are distinct answers and
    neither is rendered as zero.

A detector is recorded as ``"module:attribute"`` and is resolved by import. If a
detector named here disappears from the build, the row degrades to
``NOT_IMPLEMENTED`` on its own — the registry cannot drift ahead of the code.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

SCHEMA = "cryptoscan.discovery-surfaces/1"

# -- vocabularies (single source of truth for the API and the console) ------ #
KIND_LIVE_CONTROL_PLANE = "LIVE_CONTROL_PLANE"
KIND_LIVE_PROBE = "LIVE_PROBE"
KIND_ARTIFACT_PARSER = "ARTIFACT_PARSER"
KIND_STATIC_ANALYSIS = "STATIC_ANALYSIS"
KIND_IMPORT = "IMPORT"
KIND_DECLARATION = "DECLARATION"

KINDS: tuple[str, ...] = (
    KIND_LIVE_CONTROL_PLANE,
    KIND_LIVE_PROBE,
    KIND_ARTIFACT_PARSER,
    KIND_STATIC_ANALYSIS,
    KIND_IMPORT,
    KIND_DECLARATION,
)

KIND_MEANING: dict[str, str] = {
    KIND_LIVE_CONTROL_PLANE: "read from the source's own API, on demand",
    KIND_LIVE_PROBE: "observed on the wire or on the appliance under an approved scope",
    KIND_ARTIFACT_PARSER: "parsed from an artifact the operator supplies (config, banner, dump)",
    KIND_STATIC_ANALYSIS: "derived from source code and build files",
    KIND_IMPORT: "imported from a system of record the bank maintains",
    KIND_DECLARATION: "asserted by a vendor; never proof of use in this estate",
}

MATURITY_MEASURED = "MEASURED"
MATURITY_PARTIAL = "PARTIAL"
MATURITY_METADATA_ONLY = "METADATA_ONLY"
MATURITY_IMPORT_ONLY = "IMPORT_ONLY"
MATURITY_DECLARED_ONLY = "DECLARED_ONLY"
MATURITY_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

MATURITIES: tuple[str, ...] = (
    MATURITY_MEASURED,
    MATURITY_PARTIAL,
    MATURITY_METADATA_ONLY,
    MATURITY_IMPORT_ONLY,
    MATURITY_DECLARED_ONLY,
    MATURITY_NOT_IMPLEMENTED,
)

MATURITY_MEANING: dict[str, str] = {
    MATURITY_MEASURED: "the collector reads this surface's own source of truth",
    MATURITY_PARTIAL: "a real collector exists, but it reads a subset — see cannot_claim",
    MATURITY_METADATA_ONLY: "metadata and state are read; key material and content never are",
    MATURITY_IMPORT_ONLY: "only what the bank already recorded is known",
    MATURITY_DECLARED_ONLY: "vendor assertion only; absence of a declaration is not absence of use",
    MATURITY_NOT_IMPLEMENTED: "no detector for this surface is present in this build",
}

CONFIGURED = "CONFIGURED"
NOT_CONFIGURED = "NOT_CONFIGURED"
CONFIGURATION_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Surface:
    """One discovery surface and the detector(s) this build has for it."""

    id: str
    label: str
    planes: tuple[str, ...]
    kind: str
    maturity: str
    detectors: tuple[str, ...]
    reads: str
    cannot_claim: str
    gaps: tuple[str, ...] = ()
    #: ``"module:function"`` config resolver; raises ``PlaneNotConfigured`` when
    #: this deployment cannot reach the source.
    config: str | None = None


SURFACES: tuple[Surface, ...] = (
    Surface(
        id="linux_host",
        label="Linux / UNIX hosts",
        planes=("HARDWARE", "STATIC"),
        kind=KIND_ARTIFACT_PARSER,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "universal_vendor.plugins.os:UbuntuPlugin",
            "universal_vendor.plugins.os:RedHatPlugin",
            "scanner.parsers.shell_parser:parse_shell_file",
        ),
        reads=(
            "OS banner and library versions (OpenSSL/LibreSSL/GnuTLS), SSH client and server "
            "configuration, CA trust stores, and crypto call sites found in shell tooling"
        ),
        cannot_claim=(
            "no agent-side enumeration: a package that is installed but never exported in an "
            "artifact is NOT_OBSERVED, and 'no finding' is never 'no cryptography'"
        ),
        gaps=(
            "no native /etc enumeration of provider registrations or PKCS#11 modules",
            "an artifact without an exported configuration contributes identity only",
        ),
    ),
    Surface(
        id="windows_host",
        label="Windows hosts",
        planes=("HARDWARE", "STATIC"),
        kind=KIND_LIVE_CONTROL_PLANE,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "universal_vendor.plugins.os:WindowsPlugin",
            "inventory.windows_cng:collect_registration",
            "inventory.windows_capi:collect_default_provider",
            "inventory.windows_certificates:read_certificate",
            "inventory.windows_listeners:collect_listeners",
            "inventory.windows_runtime:query_status",
            "inventory.windows_tpm:collect_device",
            "inventory.windows_images:collect_images",
            "inventory.windows_schannel:evaluate",
        ),
        reads=(
            "on the host, through the inventory agent: SCM service state, listening sockets, the "
            "registered CNG algorithms and providers, the default CryptoAPI provider, a named "
            "machine certificate's public material, TPM presence, and the Schannel protocol/"
            "cipher-suite policy read from the registry"
        ),
        cannot_claim=(
            "all of this is substrate and configuration — registered providers, bound "
            "certificates, running services. Not one layer observes a Windows cryptographic "
            "operation: there is no Schannel/CNG ETW consumer and no CLR instrumentation, so "
            "'AES-GCM was used by this process' is NOT_OBSERVED on Windows in this build"
        ),
        gaps=(
            "no Schannel/CNG ETW event consumption (the invocation gap)",
            "no .NET EventPipe/clr profiler instrumentation",
            "no SCHANNEL registry policy or cipher-suite-order read",
            "no machine certificate store enumeration (named certificate only)",
            "no AD CS / Kerberos enctype / LSA policy read",
        ),
    ),
    Surface(
        id="kubernetes",
        label="Kubernetes / OpenShift clusters",
        planes=("KUBERNETES",),
        kind=KIND_LIVE_CONTROL_PLANE,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "api.estate_kubernetes:collect_kubernetes",
            "universal_vendor.plugins.kubernetes:KubernetesCorePlugin",
        ),
        reads=(
            "namespaces, ingresses (TLS blocks), services, pods and container images; "
            "the cluster's own API is the source of truth"
        ),
        cannot_claim=(
            "read-only and CONFIGURED only: an Ingress TLS block is a declaration by the "
            "manifest, not the negotiated suite, and Secrets are never read"
        ),
        gaps=(
            "no admission-webhook or service-mesh (mTLS) policy read",
            "no etcd encryption-config inspection",
        ),
        config="api.estate_kubernetes:cluster_config",
    ),
    Surface(
        id="cloud",
        label="Cloud control planes (AWS)",
        planes=("CLOUD",),
        kind=KIND_LIVE_CONTROL_PLANE,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "api.estate_cloud:collect_cloud",
            "universal_vendor.plugins.cloud:AwsPlugin",
        ),
        reads=(
            "ELBv2 listeners and policies, ACM certificates, RDS engine parameters, KMS key "
            "specs, API Gateway TLS settings"
        ),
        cannot_claim=(
            "control-plane configuration only: a listener policy is what the service allows, "
            "not what a client negotiated; Azure and GCP control planes are not read here"
        ),
        gaps=(
            "no Azure or GCP collector",
            "no S3/bucket encryption policy sweep",
        ),
        config="api.estate_cloud:cloud_config",
    ),
    Surface(
        id="hsm",
        label="HSM appliances",
        planes=("HSM",),
        kind=KIND_LIVE_CONTROL_PLANE,
        maturity=MATURITY_METADATA_ONLY,
        detectors=(
            "api.estate_discovery:collect_hsm_plane",
            "cbom.kmip:assess_kmip_object",
        ),
        reads=(
            "KMIP Locate + GetAttributes: key states, algorithms, usage counters and "
            "appliance attributes"
        ),
        cannot_claim=(
            "key material is never read and a zero usage counter means 'not counted', not "
            "'unused'; key residency beyond D5/D6 is a declaration"
        ),
        gaps=(
            "no PKCS#11 session probe",
            "no HSM firmware/CVSS lifecycle feed",
        ),
        config="api.hsm_usage:hsm_config",
    ),
    Surface(
        id="kms",
        label="KMS key usage",
        planes=("KMS",),
        kind=KIND_LIVE_CONTROL_PLANE,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "api.estate_kms:collect_kms_usage",
            "universal_vendor.plugins.cloud:AwsPlugin",
        ),
        reads="KMS key usage from the provider audit trail (CloudTrail) and key metadata",
        cannot_claim=(
            "an audit trail only covers its retention window: a key last used before it is "
            "NOT_OBSERVED, never 'unused'"
        ),
        gaps=(
            "no cross-account key policy graph",
            "no bring-your-own-key (external key store) probe",
        ),
        config="api.estate_kms:kms_config",
    ),
    Surface(
        id="database",
        label="Database engines",
        planes=("NETWORK", "CLOUD"),
        kind=KIND_LIVE_PROBE,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "network_scanner.probing.db_probe:probe_database",
            "universal_vendor.plugins.database:PostgreSqlPlugin",
        ),
        reads=(
            "TLS handshake and negotiated suite on the database listener, STARTTLS where the "
            "engine offers it, plus engine banner/parameter artifacts"
        ),
        cannot_claim=(
            "a handshake proves what the listener negotiated for that connection, not what the "
            "engine supports or what a client requires; no data-at-rest or TDE inspection"
        ),
        gaps=(
            "no Oracle TNS or DB2 LUW probe",
            "no tablespace/TDE encryption read",
        ),
    ),
    Surface(
        id="network_device",
        label="Network devices and load balancers",
        planes=("NETWORK",),
        kind=KIND_LIVE_PROBE,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "network_scanner.probing.ssh_kex:probe_ssh_kex_offer",
            "network_scanner.probing.cipher_probe:probe_weak_ciphers",
            "universal_vendor.plugins.network:CiscoPlugin",
        ),
        reads=(
            "SSH KEX/host-key algorithms, TLS cipher suites and protocol floors on management "
            "and data-plane listeners, plus vendor banner/config artifacts"
        ),
        cannot_claim=(
            "only endpoints inside an approved scope are probed; an unprobed device is "
            "NOT_OBSERVED, and a management-plane read says nothing about the data plane"
        ),
        gaps=(
            "no SNMPv3 USM/crypto read",
            "no device configuration archive diffing",
        ),
    ),
    Surface(
        id="vpn_ipsec",
        label="VPN / IPsec gateways",
        planes=("NETWORK",),
        kind=KIND_LIVE_PROBE,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "network_scanner.probing.ipsec_probe:summarize_proposals",
            "network_scanner.probing.ipsec_probe:classify_esp",
        ),
        reads=(
            "IKEv1/IKEv2 SA proposals offered by the gateway (encryption, PRF, integrity, DH "
            "group) and ESP proposals, classified for post-quantum exposure"
        ),
        cannot_claim=(
            "a proposal set is what the gateway offers, not what a tunnel negotiated, and no "
            "pre-shared-key or certificate identity is established"
        ),
        gaps=(
            "no tunnel-level (established SA) capture",
            "no IKE identity/auth-method enumeration",
        ),
    ),
    Surface(
        id="pki",
        label="PKI and certificate inventory",
        planes=("PKI",),
        kind=KIND_LIVE_CONTROL_PLANE,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "api.estate_discovery:collect_pki",
            "universal_vendor.plugins.pki:HashiCorpVaultPkiPlugin",
        ),
        reads=(
            "certificate metadata from the inventory: subject, issuer, key algorithm and size, "
            "validity, revocation and CT-log presence"
        ),
        cannot_claim=(
            "public certificate metadata only — private keys are never read, and a certificate "
            "that was never ingested is NOT_OBSERVED"
        ),
        gaps=(
            "no CA hierarchy traversal from the root",
            "no OCSP/CRL freshness probe",
        ),
    ),
    Surface(
        id="code_static",
        label="Application source code",
        planes=("STATIC",),
        kind=KIND_STATIC_ANALYSIS,
        maturity=MATURITY_PARTIAL,
        detectors=(
            "scanner.parsers.tree_sitter_scanner:scan_tree_sitter_root",
            "scanner.parsers.config_crypto_parser:parse_config_file",
        ),
        reads=(
            "algorithm and library use in Java, Python, JavaScript/TypeScript, Go, Rust, C/C++, "
            "C#, PHP, Ruby, Kotlin, Swift and build/config files"
        ),
        cannot_claim=(
            "a static hit proves the algorithm is present in code, not that it runs; dynamic "
            "dispatch, reflection and generated code are under-reported"
        ),
        gaps=(
            "no binary or image layer analysis at this surface",
            "no dependency-resolution for vendored copies",
        ),
    ),
    Surface(
        id="runtime",
        label="Runtime crypto activity",
        planes=("RUNTIME",),
        kind=KIND_LIVE_PROBE,
        maturity=MATURITY_PARTIAL,
        detectors=("runtime.core.collector:collect",),
        reads="stored runtime crypto events: process, library and algorithm actually invoked",
        cannot_claim=(
            "only processes inside an approved runtime scope; unattributed evidence stays "
            "unattributed and is never folded into an asset"
        ),
        gaps=(
            "no eBPF/uprobe capture in this build",
            "no per-syscall key-material observation (by policy never)",
        ),
    ),
    Surface(
        id="legacy_import",
        label="Legacy and mainframe platforms",
        planes=("STATIC", "CMDB"),
        kind=KIND_IMPORT,
        maturity=MATURITY_IMPORT_ONLY,
        detectors=(
            "scanner.parsers.cobol_parser:parse_cobol_file",
            "scanner.parsers.pli_parser:parse_pli_file",
            "scanner.parsers.rpg_parser:parse_rpg_file",
        ),
        reads=(
            "COBOL, PL/I, RPG and NATURAL sources exported by the platform team, plus the CMDB "
            "record of the platform itself"
        ),
        cannot_claim=(
            "an export is a snapshot the bank chose to share: a mainframe that was not exported "
            "is NOT_OBSERVED, and ICSF/crypto hardware state is not read at all"
        ),
        gaps=(
            "no ICSF/CSFKEYS read",
            "no CICS/IMS runtime crypto capture",
        ),
    ),
    Surface(
        id="vendor_declared",
        label="Vendor crypto declarations",
        planes=("VENDOR",),
        kind=KIND_DECLARATION,
        maturity=MATURITY_DECLARED_ONLY,
        detectors=("universal_vendor.registry:PluginRegistry",),
        reads="vendor-declared algorithms, protocols and PQC support per product",
        cannot_claim=(
            "a declaration is never proof of use: a product can support PQC and still be "
            "configured with RSA-2048, and silence is not absence"
        ),
        gaps=("no independent verification of a vendor claim against an appliance",),
    ),
    Surface(
        id="cmdb",
        label="CMDB / system of record",
        planes=("CMDB",),
        kind=KIND_IMPORT,
        maturity=MATURITY_IMPORT_ONLY,
        detectors=(
            "api.estate_cmdb:collect_cmdb",
            "universal_vendor.plugins.identity:OktaPlugin",
        ),
        reads="ServiceNow servers, business services, applications and relationships",
        cannot_claim=(
            "CMDB records are declared (IMPORTED): ownership and existence, never cryptography "
            "in use"
        ),
        gaps=("no reconciliation against observed assets beyond the twin's conflict rules",),
        config="api.estate_cmdb:cmdb_config",
    ),
)

SURFACE_INDEX: dict[str, Surface] = {surface.id: surface for surface in SURFACES}


class UnknownSurface(KeyError):
    """Raised when a caller asks for a surface that is not in the registry."""


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #
def resolve_detector(ref: str) -> dict[str, Any]:
    """Resolve ``"module:attribute"`` by import — the registry's own fact-check.

    Import failures are data, not exceptions: a detector that no longer exists is
    exactly what the registry must report rather than assume.
    """
    module_name, _, attribute = ref.partition(":")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - any import failure is a "absent" answer
        return {"ref": ref, "present": False, "reason": f"{type(exc).__name__}: {exc}"}
    if not attribute:
        return {"ref": ref, "present": True, "reason": None}
    if not hasattr(module, attribute):
        return {"ref": ref, "present": False, "reason": "attribute missing from module"}
    return {"ref": ref, "present": True, "reason": None}


def configuration(surface: Surface, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Can *this* deployment ask the source right now?

    The plane's own resolver decides; this module only interprets the answer.
    ``UNKNOWN`` is used when the resolver itself failed for a reason that is not
    "not configured" — never silently reported as ``NOT_CONFIGURED``.
    """
    if not surface.config:
        return {"state": CONFIGURED, "reason": "no external credentials are required"}
    env = dict(os.environ if environ is None else environ)
    module_name, _, attribute = surface.config.partition(":")
    try:
        module = importlib.import_module(module_name)
        resolver: Callable[..., Any] = getattr(module, attribute)
    except Exception as exc:  # noqa: BLE001
        return {"state": CONFIGURATION_UNKNOWN, "reason": f"config resolver unavailable ({exc})"}
    try:
        resolver(env)
    except Exception as exc:  # noqa: BLE001 - PlaneNotConfigured and friends
        not_configured = type(exc).__name__ == "PlaneNotConfigured"
        return {
            "state": NOT_CONFIGURED if not_configured else CONFIGURATION_UNKNOWN,
            "reason": str(exc) or type(exc).__name__,
        }
    return {"state": CONFIGURED, "reason": "resolved from this deployment's configuration"}


def _observed(surface: Surface, collectors: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    """What the newest run collected from this surface's planes."""
    if collectors is None:
        return {
            "state": "NOT_OBSERVED",
            "planes": list(surface.planes),
            "reason": "no estate discovery run is stored for this tenant",
        }
    by_plane = {str(row.get("plane")): row for row in collectors}
    rows = [by_plane[plane] for plane in surface.planes if plane in by_plane]
    if not rows:
        return {
            "state": "NOT_OBSERVED",
            "planes": list(surface.planes),
            "reason": "the last run did not attempt this surface's plane(s)",
        }
    collected = sum(int(row.get("collected") or 0) for row in rows)
    statuses = [str(row.get("status") or "UNKNOWN") for row in rows]
    if all(status == "NOT_ATTEMPTED" for status in statuses):
        state = "NOT_ATTEMPTED"
    elif all(status == "FAILED" for status in statuses):
        state = "FAILED"
    elif any(status == "FAILED" for status in statuses):
        state = "PARTIAL"
    elif all(status == "COMPLETE" for status in statuses):
        state = "COMPLETE"
    else:
        state = "PARTIAL"
    reasons = [str(row.get("reason") or "") for row in rows if row.get("reason")]
    return {
        "state": state,
        "planes": list(surface.planes),
        "statuses": dict(zip(surface.planes, statuses)),
        "collected": collected,
        "reason": "; ".join(reasons) or None,
    }


def row(surface: Surface, *, environ: Mapping[str, str] | None = None,
        collectors: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """One surface as the API reports it."""
    detectors = [resolve_detector(ref) for ref in surface.detectors]
    present = [d for d in detectors if d["present"]]
    maturity = surface.maturity
    notes: list[str] = []
    if not present:
        maturity = MATURITY_NOT_IMPLEMENTED
        notes.append("no detector for this surface resolved in this build")
    elif len(present) < len(detectors):
        notes.append(
            f"{len(detectors) - len(present)} of {len(detectors)} declared detector(s) are absent"
        )
    return {
        "id": surface.id,
        "label": surface.label,
        "planes": list(surface.planes),
        "kind": surface.kind,
        "kind_meaning": KIND_MEANING[surface.kind],
        "maturity": maturity,
        "maturity_ceiling": surface.maturity,
        "maturity_meaning": MATURITY_MEANING[maturity],
        "declared_maturity": surface.maturity,
        "reads": surface.reads,
        "cannot_claim": surface.cannot_claim,
        "gaps": list(surface.gaps),
        "detectors": detectors,
        "configuration": configuration(surface, environ),
        "observed": _observed(surface, collectors),
        "notes": notes,
    }


def claim(rows: Sequence[Mapping[str, Any]]) -> str:
    """The sentence the product may print, derived from the rows themselves."""
    live = sum(1 for r in rows if r["kind"] in (KIND_LIVE_CONTROL_PLANE, KIND_LIVE_PROBE))
    code = sum(1 for r in rows if r["kind"] == KIND_STATIC_ANALYSIS)
    artifact = sum(1 for r in rows if r["kind"] == KIND_ARTIFACT_PARSER)
    declared = sum(1 for r in rows if r["kind"] in (KIND_IMPORT, KIND_DECLARATION))
    absent = sum(1 for r in rows if r["maturity"] == MATURITY_NOT_IMPLEMENTED)
    return (
        f"{len(rows)} cryptographic surfaces are modelled: {live} read from a live source, "
        f"{code} by static analysis, {artifact} from operator-supplied artifacts and "
        f"{declared} only from imports or declarations"
        + (f"; {absent} have no detector in this build" if absent else "")
        + ". Coverage is evidence-driven and expands per collector — no surface is claimed complete."
    )


def registry(*, environ: Mapping[str, str] | None = None,
             collectors: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """The whole matrix: rows, rollup, and the sentence that may be printed."""
    rows = [row(surface, environ=environ, collectors=collectors) for surface in SURFACES]
    by_maturity = {state: 0 for state in MATURITIES}
    by_kind = {kind: 0 for kind in KINDS}
    for item in rows:
        by_maturity[item["maturity"]] = by_maturity.get(item["maturity"], 0) + 1
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
    configured = sum(
        1 for item in rows
        if item["configuration"]["state"] == CONFIGURED and SURFACE_INDEX[item["id"]].config
    )
    unused_credentials = sum(1 for item in rows if SURFACE_INDEX[item["id"]].config is None)
    observed = sum(1 for item in rows if item["observed"]["state"] in ("COMPLETE", "PARTIAL"))
    return {
        "schema": SCHEMA,
        "surfaces": rows,
        "rollup": {
            "surfaces": len(rows),
            "by_maturity": by_maturity,
            "by_kind": by_kind,
            "credentials_resolved": configured,
            "no_credentials_needed": unused_credentials,
            "observed_in_last_run": observed,
        },
        "kinds": {kind: KIND_MEANING[kind] for kind in KINDS},
        "maturities": {state: MATURITY_MEANING[state] for state in MATURITIES},
        "claim": claim(rows),
        "note": (
            "maturity is the ceiling of what this build's collector can establish on that "
            "surface, not a score; configuration and observation are separate axes and "
            "'not observed' is never rendered as zero coverage. MEASURED is reserved for a "
            "surface whose collector declares no gap — none does today, which is the honest "
            "state of the work rather than a missing row"
        ),
    }


def surface(surface_id: str, *, environ: Mapping[str, str] | None = None,
            collectors: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """One surface by id, with the same resolution rules."""
    try:
        found = SURFACE_INDEX[surface_id]
    except KeyError as exc:
        raise UnknownSurface(surface_id) from exc
    return row(found, environ=environ, collectors=collectors)


__all__ = [
    "SCHEMA",
    "KINDS",
    "KIND_MEANING",
    "MATURITIES",
    "MATURITY_MEANING",
    "SURFACES",
    "SURFACE_INDEX",
    "Surface",
    "UnknownSurface",
    "claim",
    "configuration",
    "registry",
    "resolve_detector",
    "row",
    "surface",
]
