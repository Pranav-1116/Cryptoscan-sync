"""Which collector families this build actually reaches — measured, not claimed.

The vision names twenty families (Windows, Linux, Kubernetes, cloud, HSM, KMS, PKI,
databases, load balancers, API gateways, VPN, network devices, message queues,
service mesh, storage, backup, legacy platforms, vendor products, containers, and
the runtime observer). A register of those families is only useful if a family
cannot *call itself* shipped: the failure mode is a page, a docstring or a spec
saying "Kubernetes collector" while nothing in the tree ever asks a cluster.

So every row names the **modules and entrypoints** that would have to exist, and the
status is computed by importing them:

``SHIPPED``
    every declared entrypoint imports and is callable. The row still carries its
    stated limit — a live collector that only reads configuration is shipped and
    shallow, and the two are different statements.
``PARTIAL``
    some entrypoints resolve; the missing ones are named in ``missing``.
``ABSENT``
    none resolve. The row carries a ``reason``; an absent family without a reason
    fails the build rather than passing as an empty box.

Two more columns keep the register honest against the rest of the product:

``input``
    ``LIVE`` (talks to the system over its own API/protocol), ``INJECTED`` (parses
    config, exports or text the operator supplies — no collection), ``STORED``
    (reads evidence another collector already wrote). An ``INJECTED`` family is
    real code and is *not* a production collector: nothing goes and gets it.
``evidence``
    the strongest evidence type the family can produce, using the estate graph's own
    vocabulary. ``CONFIGURED`` is a declaration and never becomes observed use.

Nothing here is a score. The counts are counts of rows in each state.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Iterable

SCHEMA = "cryptoscan.collector-families/1"

SHIPPED = "SHIPPED"
PARTIAL = "PARTIAL"
ABSENT = "ABSENT"

LIVE = "LIVE"
INJECTED = "INJECTED"
STORED = "STORED"

#: whose estate the collector reads. "PLATFORM" means it collects this product's own
#: runtime, not the customer's estate — a bank's backup appliances need BACKUP/ESTATE,
#: and CryptoScan protecting its own database does not supply it.
ESTATE = "ESTATE"
PLATFORM = "PLATFORM"

#: evidence types, weakest claim first, in the estate graph's vocabulary
CONFIGURED = "CONFIGURED"
STATIC_OBSERVED = "STATIC_OBSERVED"
NETWORK_ACTIVE_OBSERVED = "NETWORK_ACTIVE_OBSERVED"
NETWORK_PASSIVE_OBSERVED = "NETWORK_PASSIVE_OBSERVED"
AUDIT_OBSERVED = "AUDIT_OBSERVED"
RUNTIME_OBSERVED = "RUNTIME_OBSERVED"

#: rank used only to compare claimed depth against produced depth — never a score
EVIDENCE_RANK: dict[str, int] = {
    CONFIGURED: 1,
    STATIC_OBSERVED: 2,
    NETWORK_PASSIVE_OBSERVED: 3,
    NETWORK_ACTIVE_OBSERVED: 4,
    AUDIT_OBSERVED: 5,
    RUNTIME_OBSERVED: 6,
}


@dataclass(frozen=True)
class Family:
    """One collector family: what would prove it, and what it would prove."""

    id: str
    label: str
    #: (module, attribute) pairs; ALL must resolve for SHIPPED
    entrypoints: tuple[tuple[str, str], ...]
    input: str
    evidence: str
    reads: str
    limit: str
    scope: str = ESTATE
    reason: str | None = None
    #: families the vision names but this build does not reach yet
    note: str | None = None

    def measured(self, importer: Any = None) -> dict[str, Any]:
        """Status computed by importing, never by trusting ``self``."""
        load = importer or importlib.import_module
        resolved: list[str] = []
        missing: list[str] = []
        for module, attribute in self.entrypoints:
            try:
                loaded = load(module)
            except Exception as exc:  # noqa: BLE001 — an unimportable entrypoint is the finding
                missing.append(f"{module}.{attribute} ({type(exc).__name__})")
                continue
            target = getattr(loaded, attribute, None)
            if target is None or not callable(target):
                missing.append(f"{module}.{attribute} (not callable)")
                continue
            resolved.append(f"{module}.{attribute}")
        if not missing:
            status = SHIPPED
        elif resolved:
            status = PARTIAL
        else:
            status = ABSENT
        # "production" is a claim about unattended collection, and it needs both: code
        # that exists AND input nobody has to hand over. A parser that only runs when an
        # operator supplies config is real code and is not a production collector.
        production = status == SHIPPED and self.input == LIVE and self.scope == ESTATE
        return {
            "id": self.id,
            "label": self.label,
            "status": status,
            "production": production,
            "input": self.input,
            "scope": self.scope,
            "evidence": self.evidence,
            "reads": self.reads,
            "limit": self.limit,
            "reason": self.reason,
            "note": self.note,
            "entrypoints": resolved,
            "missing": missing,
        }


#: The twenty families the vision names, in the order it names them, plus the two
#: this build reaches under its own names (containers, runtime).
FAMILIES: tuple[Family, ...] = (
    Family(
        id="WINDOWS",
        label="Windows",
        entrypoints=(
            ("inventory.windows_capi", "collect_default_provider"),
            ("inventory.windows_schannel", "collect"),
            ("inventory.windows_tpm", "collect_device"),
        ),
        input=LIVE,
        evidence=STATIC_OBSERVED,
        reads="CNG/CAPI providers, SCHANNEL registry, TPM presence, certificate stores, listeners, images",
        limit=(
            "per-host, run on the server itself: it reads what the host is configured with and can "
            "use, which is not the same as what a process used"
        ),
    ),
    Family(
        id="LINUX",
        label="Linux breadth",
        entrypoints=(
            ("inventory.linux_packages", "dpkg_status"),
            ("inventory.rpm_metadata", "rpm_header"),
            ("inventory.linux_runtime", "kernel_fd"),
        ),
        input=LIVE,
        evidence=STATIC_OBSERVED,
        reads="package crypto (OpenSSL/GnuTLS/NSS), rpm signature metadata, linked TLS libraries, listeners",
        limit=(
            "installed and linked is not executed: the executable-to-library map is a static "
            "observation, and only the runtime agent turns it into call-level use"
        ),
    ),
    Family(
        id="CONTAINERS",
        label="Containers / OCI",
        entrypoints=(
            ("inventory.oci_image", "collect_image"),
            ("inventory.oci_runtime", "collect_runtime"),
            ("inventory.oci_evidence", "collect_oci"),
        ),
        input=LIVE,
        evidence=STATIC_OBSERVED,
        reads="image layers and packages, the runtime's own config, OCI labels and annotations",
        limit=(
            "the image is not the running container: a digest-pinned image says what could run, "
            "and the container's TLS is observed at runtime or on the wire"
        ),
    ),
    Family(
        id="KUBERNETES",
        label="Kubernetes",
        entrypoints=(("api.estate_kubernetes", "collect_kubernetes"),),
        input=LIVE,
        evidence=CONFIGURED,
        reads="namespaces, ingresses (TLS blocks), services, pods, container images",
        limit=(
            "read-only and configuration only: an Ingress TLS block is a declaration of intent, "
            "and secrets are never read"
        ),
    ),
    Family(
        id="CLOUD",
        label="Cloud control plane",
        entrypoints=(("api.estate_cloud", "collect_cloud"),),
        input=LIVE,
        evidence=CONFIGURED,
        reads="AWS ELBv2/ACM/RDS/KMS/API Gateway, Azure and GCP equivalents",
        limit=(
            "a listener policy or key spec is what the service allows, not what a client "
            "negotiated with it"
        ),
    ),
    Family(
        id="HSM",
        label="HSM",
        entrypoints=(("api.hsm_usage", "collect_hsm_usage"),),
        input=LIVE,
        evidence=AUDIT_OBSERVED,
        reads="KMIP Locate and GetAttributes: key state, attributes, usage counters",
        limit=(
            "metadata only: key material is never read, and a zero usage counter means 'not "
            "counted', not 'unused'"
        ),
    ),
    Family(
        id="KMS",
        label="KMS",
        entrypoints=(("api.estate_kms", "collect_kms_usage"),),
        input=LIVE,
        evidence=AUDIT_OBSERVED,
        reads="the provider's own audit trail (CloudTrail and equivalents) for key use",
        limit=(
            "an audit trail covers its retention window only: a key last used before it is "
            "NOT_OBSERVED, never 'unused'"
        ),
    ),
    Family(
        id="PKI",
        label="PKI",
        entrypoints=(
            ("inventory.tls_session", "probe_session"),
            ("network_scanner.enterprise.cert_intel", "usage_tags"),
        ),
        input=LIVE,
        evidence=NETWORK_ACTIVE_OBSERVED,
        reads="certificate chains on the wire, expiry, key size, signature algorithm, usage tags",
        limit=(
            "public certificate metadata only — never private keys — and a certificate that is "
            "served is not a CA that is trusted"
        ),
    ),
    Family(
        id="DATABASES",
        label="Databases",
        entrypoints=(("network_scanner.probing.db_probe", "probe_database"),),
        input=LIVE,
        evidence=NETWORK_ACTIVE_OBSERVED,
        reads="the transport handshake: TLS support, version floor, cipher, engine-specific refusal",
        limit=(
            "transport crypto only: data-at-rest encryption (TDE) and column encryption are not "
            "visible in a handshake and stay UNKNOWN"
        ),
    ),
    Family(
        id="LOAD_BALANCERS",
        label="Load balancers",
        entrypoints=(("network_scanner.enterprise.firewall_lb", "discover_termination_profiles"),),
        input=INJECTED,
        evidence=CONFIGURED,
        reads="vendor config/API records: termination profiles, cipher policy, certificates, backends",
        limit=(
            "no collector fetches the records: profiles are parsed from data the operator "
            "supplies, so this is a parser and a model, not a production collector"
        ),
    ),
    Family(
        id="API_GATEWAYS",
        label="API gateways",
        entrypoints=(("cloud_scanner.aws.scanners", "scan_apigateway"),),
        input=LIVE,
        evidence=CONFIGURED,
        reads="AWS API Gateway domain names, TLS policy and mutual-TLS settings",
        limit=(
            "cloud gateways only: an on-premises gateway (APIM, Kong, Apigee) has no reader here"
        ),
    ),
    Family(
        id="VPN",
        label="VPN / IPsec",
        entrypoints=(("network_scanner.probing.ipsec_probe", "extract_sa_from_response"),),
        input=LIVE,
        evidence=NETWORK_ACTIVE_OBSERVED,
        reads="the IKE offer: encryption, PRF, integrity and DH transforms proposed",
        limit=(
            "an offer is a proposal, not a negotiated session: a responder that proposes 3DES may "
            "still refuse it, and the SA is not observable from here"
        ),
    ),
    Family(
        id="NETWORK_DEVICES",
        label="Network devices",
        entrypoints=(
            ("network_scanner.enterprise.vendors.cisco", "parse_tls_config"),
            ("network_scanner.enterprise.vendors.cisco", "parse_ikev2_proposals"),
        ),
        input=INJECTED,
        evidence=CONFIGURED,
        reads="iOS/IOS-XE/NX-OS running-config text: TLS, IKEv1/IKEv2, IPsec, SSH, certificates",
        limit=(
            "config text is supplied by the operator or by a backup export; nothing here logs "
            "into a device, so 'the config says' is the strongest claim"
        ),
    ),
    Family(
        id="MESSAGE_QUEUES",
        label="Message queues",
        entrypoints=(("ot_scanner.protocols.mqtt", "analyze"),),
        input=INJECTED,
        evidence=NETWORK_PASSIVE_OBSERVED,
        reads="an already-collected record for an MQTT endpoint (port, TLS flag, cipher)",
        limit=(
            "no broker collector is shipped: this reads one record the network sweep already "
            "produced, and AMQP, Kafka, RabbitMQ and IBM MQ have no reader at all"
        ),
        reason=(
            "the gap is a collector, not a parser: nothing logs into or queries a broker's own "
            "API, so a broker's TLS version, ciphers and certificates are only visible as a "
            "generic endpoint"
        ),
    ),
    Family(
        id="SERVICE_MESH",
        label="Service mesh",
        entrypoints=(("network_scanner.discovery.service_mesh_discoverer", "discover_mesh_endpoints"),),
        input=LIVE,
        evidence=CONFIGURED,
        reads="mesh control-plane endpoints (Istio/Istio-cni, Prometheus scrape targets)",
        limit=(
            "endpoint discovery, not mesh policy: mTLS mode and workload certificates are read "
            "from the mesh API only where the deployment exposes it"
        ),
    ),
    Family(
        id="STORAGE",
        label="Storage",
        entrypoints=(
            ("cloud_scanner.aws.scanners", "scan_ebs"),
            ("cloud_scanner.aws.scanners", "scan_s3"),
        ),
        input=LIVE,
        evidence=CONFIGURED,
        reads="AWS EBS volume encryption and S3 bucket encryption/default-KMS settings",
        limit=(
            "cloud block/object storage only: a SAN, NAS or on-prem object store has no reader, "
            "and encryption-at-rest is a configuration claim about the service"
        ),
    ),
    Family(
        id="BACKUP",
        label="Backup",
        entrypoints=(
            ("governance.backup", "create_backup"),
            ("governance.backup_jobs", "PgDumpBackend"),
        ),
        input=LIVE,
        evidence=CONFIGURED,
        reads="this platform's own encrypted, signed backups of its databases (pg_dump/neo4j-admin)",
        scope=PLATFORM,
        limit=(
            "it protects CryptoScan's database, not the bank's backup estate: a bank's backup "
            "appliance, tape crypto or DR vault has no collector here"
        ),
    ),
    Family(
        id="LEGACY",
        label="Legacy platforms",
        entrypoints=(
            ("cbom.mainframe", "normalize_racdcert_rich"),
            ("scanner.parsers.cobol_parser", "parse_cobol_file"),
        ),
        input=INJECTED,
        evidence=STATIC_OBSERVED,
        reads="RACF RACDCERT listings, COBOL source crypto calls (mainframe and AS/400 source)",
        limit=(
            "static and export-based: a RACDCERT listing is an export and COBOL source is source, "
            "so this is presence in code and keyrings, never a running CICS region's crypto"
        ),
    ),
    Family(
        id="VENDOR",
        label="Vendor products",
        entrypoints=(
            ("universal_vendor.registry", "PluginRegistry"),
            ("universal_vendor.detection", "UniversalVendorDetectionEngine"),
        ),
        input=INJECTED,
        evidence=CONFIGURED,
        reads="vendor plugin declarations and product signatures",
        limit=(
            "plugin framework plus signatures: a vendor is recognised from what it exposes, and "
            "its internal crypto is a declaration unless a live connector exists"
        ),
    ),
    Family(
        id="RUNTIME",
        label="Runtime observer",
        entrypoints=(
            ("api.estate_runtime_edges", "build"),
            ("runtime.agent.crypto_events", "observations_from_trace"),
        ),
        input=LIVE,
        evidence=RUNTIME_OBSERVED,
        reads="traced EVP_* calls in a process under an approved scope: operation, algorithm, mode, key size",
        limit=(
            "call-level only where an LD_PRELOAD shim over libcrypto fits: a Go runtime, a static "
            "Rust binary and a JVM's own provider are library or configuration evidence"
        ),
    ),
)


def _row(family: Family, importer: Any = None) -> dict[str, Any]:
    return family.measured(importer)


def register(*, importer: Any = None, families: Iterable[Family] | None = None) -> dict[str, Any]:
    """The whole matrix, with every status computed from the code."""
    rows = [_row(family, importer) for family in (families or FAMILIES)]
    counts = {state: sum(1 for row in rows if row["status"] == state)
              for state in (SHIPPED, PARTIAL, ABSENT)}
    by_input = {kind: sum(1 for row in rows if row["input"] == kind)
                for kind in (LIVE, INJECTED, STORED)}
    return {
        "schema": SCHEMA,
        "families": rows,
        "counts": counts,
        "by_input": by_input,
        "claim": (
            "status is computed by importing each family's entrypoints, so a family cannot be "
            "reported shipped without code behind it; SHIPPED says code exists, and each row's "
            "limit says how far it reaches. This is not a coverage or maturity score."
        ),
        "production": sum(1 for row in rows if row["production"]),
        "production_gap": [row["id"] for row in rows if not row["production"]],
        "production_gap_note": (
            "families that are ABSENT, PARTIAL, reachable only by parsing data an operator "
            "supplies, or that collect this platform rather than the estate: for these, no "
            "scheduled collection of the customer's estate runs unattended"
        ),
    }
