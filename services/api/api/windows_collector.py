"""Windows crypto collection — what exists, what it establishes, what is missing.

Windows is not at Linux parity, and the honest way to say so is layer by layer
rather than with one adjective. A Windows host's crypto is spread across seven
independent places, and the collectors in this build reach some of them:

| layer                         | what it is                          | reached here |
|-------------------------------|-------------------------------------|--------------|
| service/process inventory     | SCM + process list (the "candidate")| yes (substrate) |
| listening sockets             | GetExtendedTcpTable / UDP           | yes |
| machine + user certificate stores | CryptoAPI certificate contexts  | yes (public cert only) |
| CNG provider registration     | BCryptEnumAlgorithms/Providers      | yes (registration) |
| CAPI default provider         | CryptGetDefaultProvider             | yes |
| TPM presence                  | TBS device                          | yes (presence) |
| Schannel per-connection policy| registry `SCHANNEL\\Protocols`, event log | **no** |
| Schannel/CNG call events      | ETW providers, per-connection trace | **no** |
| AD CS, Kerberos enctypes      | LSA policy, KDC registry            | **no** |

Crucially, everything the Windows candidate reads is **substrate**: which
providers are registered, which certificates are bound, which services run. None
of it is an invocation. "The CNG provider is registered" and "TLS 1.2 with
ECDHE-RSA-AES256-GCM-SHA384 was used on this connection" are as different on
Windows as "OpenSSL installed" and "AES-256 executed" are on Linux.

This module is the registry for that statement. Every layer resolves its own
detectors by import, so a missing module degrades the layer by itself.
"""

from __future__ import annotations

from typing import Any, Mapping

from api.estate_surfaces import resolve_detector

SCHEMA = "cryptoscan.windows-collector/1"

PRESENT = "PRESENT"
PARTIAL = "PARTIAL"
ABSENT = "ABSENT"

STATES: tuple[str, ...] = (PRESENT, PARTIAL, ABSENT)

STATE_MEANING: dict[str, str] = {
    PRESENT: "a collector on the Windows host reads this layer",
    PARTIAL: "a collector exists but reads only part of what the layer holds",
    ABSENT: "nothing in this build reads this layer on Windows",
}

#: what a layer's evidence can establish, strongest last
SUBSTRATE = "SUBSTRATE"
CONFIGURATION = "CONFIGURATION"
INVOCATION = "INVOCATION"

ESTABLISHES_MEANING: dict[str, str] = {
    SUBSTRATE: "the thing exists or runs — nothing about which crypto it used",
    CONFIGURATION: "what the host is configured or registered to do",
    INVOCATION: "a cryptographic operation was observed happening",
}


class Layer:
    __slots__ = (
        "id", "label", "state", "establishes", "producers",
        "reads", "cannot_claim", "gaps", "requires",
    )

    def __init__(
        self,
        *,
        id: str,
        label: str,
        state: str,
        establishes: str,
        producers: tuple[str, ...],
        reads: str,
        cannot_claim: str,
        gaps: tuple[str, ...] = (),
        requires: str | None = None,
    ) -> None:
        if state not in STATES:
            raise ValueError(f"unknown state {state!r}")
        if establishes not in ESTABLISHES_MEANING:
            raise ValueError(f"unknown evidence class {establishes!r}")
        self.id = id
        self.label = label
        self.state = state
        self.establishes = establishes
        self.producers = producers
        self.reads = reads
        self.cannot_claim = cannot_claim
        self.gaps = gaps
        self.requires = requires


LAYERS: tuple[Layer, ...] = (
    Layer(
        id="service_inventory",
        label="Service and process inventory (SCM)",
        state=PARTIAL,
        establishes=SUBSTRATE,
        producers=(
            "inventory.windows_runtime:query_status",
            "inventory.windows_runtime:collect_service",
            "inventory.windows_runtime:collect_os_version",
        ),
        reads=(
            "the service control manager's view of a service: state, start type, and the affected "
            "process — plus host OS version"
        ),
        cannot_claim=(
            "SCM tells us a service runs. It does not tell us what crypto that service performs, "
            "which library it loads, or whether it calls CNG, CAPI or a bundled OpenSSL. The "
            "candidate approach is a map of where crypto could be, not evidence of crypto in use"
        ),
        gaps=(
            "no per-process module/loaded-library enumeration (the Windows equivalent of /proc/pid/maps)",
            "no service-level crypto policy read",
        ),
        requires="a Windows host the inventory agent can run on, with service-query rights",
    ),
    Layer(
        id="listeners",
        label="Listening sockets",
        state=PARTIAL,
        establishes=SUBSTRATE,
        producers=("inventory.windows_listeners:collect_listeners",),
        reads="IPv4/IPv6 listening endpoints and owning process id (GetExtendedTcpTable path)",
        cannot_claim=(
            "a listening socket is an endpoint, not a protocol. It says nothing about what TLS "
            "version the listener requires or which certificates it presents"
        ),
        gaps=("no Schannel-side inspection of what a listener negotiates",),
        requires="a Windows host the inventory agent can run on",
    ),
    Layer(
        id="certificate_stores",
        label="Machine and user certificate stores",
        state=PARTIAL,
        establishes=CONFIGURATION,
        producers=(
            "inventory.windows_certificates:read_certificate",
            "inventory.windows_certificates:collect_certificate",
        ),
        reads=(
            "one exact local public certificate: DER binding, SHA-256 identity and store locator "
            "(SHA-1 is used only as the native locator, never as a crypto assertion)"
        ),
        cannot_claim=(
            "public certificate material only. Private keys and CNG key containers are never read, "
            "and enumerating a whole store is a qualification gate — the candidate reads a named "
            "certificate"
        ),
        gaps=(
            "no machine-store enumeration (named certificate only)",
            "no private-key or key-container inspection, by policy",
            "no auto-enrolment / renewal policy read",
        ),
        requires="a Windows host the inventory agent can run on",
    ),
    Layer(
        id="cng_registration",
        label="CNG provider and algorithm registration",
        state=PARTIAL,
        establishes=CONFIGURATION,
        producers=("inventory.windows_cng:collect_registration",),
        reads=(
            "the registered CNG interfaces, image and provider records: which algorithm providers "
            "exist on this host and where their implementations come from"
        ),
        cannot_claim=(
            "registration is availability. Every Windows host registers AES; that says nothing about "
            "whether AES-GCM was used, with which key size, by which process"
        ),
        gaps=(
            "no per-algorithm property/flags read",
            "no measurement of which provider serviced a call",
        ),
        requires="a Windows host the inventory agent can run on",
    ),
    Layer(
        id="capi_default_provider",
        label="CryptoAPI default provider",
        state=PARTIAL,
        establishes=CONFIGURATION,
        producers=("inventory.windows_capi:collect_default_provider",),
        reads="the machine's default CryptoAPI provider type and name",
        cannot_claim=(
            "the default provider is where an application *would* go. Applications that name a "
            "provider explicitly bypass it entirely"
        ),
        gaps=("no per-application provider choice observation",),
        requires="a Windows host the inventory agent can run on",
    ),
    Layer(
        id="tpm",
        label="TPM / platform crypto device",
        state=PARTIAL,
        establishes=SUBSTRATE,
        producers=("inventory.windows_tpm:collect_device",),
        reads="whether a TPM device is present and its reported identity",
        cannot_claim=(
            "presence only. Key hierarchies, attestation state and which operations are bound to "
            "the TPM are not read"
        ),
        gaps=("no TPM key-hierarchy or attestation read",),
        requires="a Windows host the inventory agent can run on",
    ),
    Layer(
        id="images",
        label="Installed software and images",
        state=PARTIAL,
        establishes=SUBSTRATE,
        producers=("inventory.windows_images:collect_images",),
        reads="installed image/product records used to attribute software to the host",
        cannot_claim=(
            "an installed product is not a loaded library, and a loaded library is not a call"
        ),
        gaps=("no version-to-CVE or version-to-crypto-API mapping at this layer",),
        requires="a Windows host the inventory agent can run on",
    ),
    Layer(
        id="schannel_policy",
        label="Schannel protocol and cipher policy",
        state=PARTIAL,
        establishes=CONFIGURATION,
        producers=(
            "inventory.windows_schannel:evaluate",
            "inventory.windows_schannel:collect",
        ),
        reads=(
            "the host's Schannel policy from the registry: per protocol and role, whether it is "
            "explicitly enabled, explicitly disabled, disabled-by-default, or left on Windows' "
            "default — plus the configured cipher-suite order and the versions still offered"
        ),
        cannot_claim=(
            "this is policy, not use. An enabled protocol is permitted, not negotiated, and a host "
            "with no policy keys is on Windows' built-in defaults, which this build deliberately "
            "does not restate as a floor. What any application actually negotiated remains "
            "NOT_OBSERVED — that is the Schannel/CNG ETW gap below"
        ),
        gaps=(
            "no IIS/HTTP.sys binding-to-certificate map",
            "no per-application Schannel settings (an app can pin its own version)",
            "no Windows-version-specific default policy reproduced",
        ),
        requires="a registry read on the Windows host",
    ),
    Layer(
        id="schannel_events",
        label="Schannel and CNG operation events (ETW)",
        state=ABSENT,
        establishes=INVOCATION,
        producers=(),
        reads="nothing. No ETW consumer ships for the Schannel or CNG providers",
        cannot_claim=(
            "this is the Windows invocation gap. Until ETW (or a per-connection trace) is consumed, "
            "no Windows process's crypto use is *observed* — only its environment is described"
        ),
        gaps=(
            "no Microsoft-Windows-Schannel-Events consumer",
            "no Microsoft-Windows-Crypto-* provider consumption",
            "no per-connection negotiated-suite trace",
        ),
        requires="ETW session rights on the Windows host (not implemented)",
    ),
    Layer(
        id="dotnet_clr",
        label=".NET / CLR crypto calls",
        state=ABSENT,
        establishes=INVOCATION,
        producers=(),
        reads="nothing. No CLR profiler, EventPipe session or DiagnosticSource listener ships",
        cannot_claim=(
            "a .NET application's System.Security.Cryptography use is invisible to this build, and "
            "the runtime-depth matrix says the same thing under `dotnet_windows`"
        ),
        gaps=("no EventPipe/DiagnosticSource listener", "no CLR profiler attachment"),
        requires="CLR instrumentation (not implemented)",
    ),
    Layer(
        id="ad_cs_kerberos",
        label="AD CS, Kerberos enctypes and LSA policy",
        state=ABSENT,
        establishes=CONFIGURATION,
        producers=(),
        reads="nothing. Domain-level crypto policy is not read from a Windows host or a domain controller",
        cannot_claim=(
            "a bank's Kerberos enctype policy and certificate-template crypto are frequently the "
            "largest Windows findings, and this platform does not read either"
        ),
        gaps=(
            "no msDS-SupportedEncryptionTypes read",
            "no certificate-template algorithm read from AD CS",
            "no LSA authentication-policy read",
        ),
        requires="domain credentials and directory access (not implemented)",
    ),
)

LAYER_INDEX = {layer.id: layer for layer in LAYERS}


def _row(layer: Layer) -> dict[str, Any]:
    producers = [{"ref": ref, **resolve_detector(ref)} for ref in layer.producers]
    present = [item for item in producers if item["present"]]
    state = layer.state
    notes: list[str] = []
    if state != ABSENT and not present:
        state = ABSENT
        notes.append("no declared collector for this layer is present in this build")
    return {
        "id": layer.id,
        "label": layer.label,
        "state": state,
        "declared_state": layer.state,
        "state_meaning": STATE_MEANING[state],
        "establishes": layer.establishes,
        "establishes_meaning": ESTABLISHES_MEANING[layer.establishes],
        "producers": producers,
        "producers_present": len(present),
        "reads": layer.reads,
        "cannot_claim": layer.cannot_claim,
        "gaps": list(layer.gaps),
        "requires": layer.requires,
        "notes": notes,
    }


def registry(measured: Mapping[str, Any] | None = None) -> dict[str, Any]:
    rows = [_row(layer) for layer in LAYERS]
    by_state: dict[str, int] = {state: 0 for state in STATES}
    by_evidence: dict[str, int] = {key: 0 for key in ESTABLISHES_MEANING}
    for row in rows:
        by_state[row["state"]] = by_state.get(row["state"], 0) + 1
        by_evidence[row["establishes"]] = by_evidence.get(row["establishes"], 0) + 1
    invocation = [
        row["id"] for row in rows if row["establishes"] == INVOCATION and row["state"] != ABSENT
    ]
    return {
        "schema": SCHEMA,
        "layers": rows,
        "states": list(STATES),
        "state_meaning": STATE_MEANING,
        "evidence_classes": dict(ESTABLISHES_MEANING),
        "rollup": {
            "layers": len(rows),
            "by_state": by_state,
            "by_evidence": by_evidence,
            "invocation_layers": len(invocation),
            "substrate_layers": by_evidence.get(SUBSTRATE, 0),
        },
        "measured": dict(measured) if measured is not None else None,
        "verdict": {
            "complete_collector": bool(invocation),
            "answer": "NO" if not invocation else "YES",
            "reason": (
                "every layer this build reaches on Windows reads substrate or configuration — "
                "registered providers, bound certificates, running services, listening sockets. "
                "Not one layer observes a cryptographic operation, and the two layers that would "
                "(Schannel/CNG ETW and CLR instrumentation) are absent. Calling this a Windows "
                "cryptographic collector would be exactly the overclaim the platform forbids"
                if not invocation
                else "at least one layer observes operations"
            ),
        },
        "claim": (
            "a Windows substrate collector: it maps where crypto could be on a Windows host. It "
            "does not observe Windows crypto in use, and no screen should imply that it does"
        ),
        "note": (
            "the candidates run on the Windows host through the inventory agent; the Linux control "
            "plane reads their output. A host the agent cannot run on is NOT_OBSERVED"
        ),
    }


__all__ = [
    "ABSENT",
    "CONFIGURATION",
    "INVOCATION",
    "LAYERS",
    "LAYER_INDEX",
    "PARTIAL",
    "PRESENT",
    "SCHEMA",
    "STATES",
    "SUBSTRATE",
    "registry",
]
