"""TechBOM as a projection: typed technology assets, evidence-backed relationships.

The estate already has SBOM, CBOM, HBOM, NBOM, VBOM and the certificate layer, and
:mod:`cbom.technology_bom` already materializes them as **layers of one state**. What that
materializer cannot answer is the question this module exists for:

    what technology exists, where it is, how it is connected, who owns it, what
    cryptography it depends on, and what evidence proves each relationship?

A TechBOM is not ``SBOM + CBOM + HBOM + NBOM + VBOM`` concatenated. It is a **graph of
typed assets whose edges are claims**, and the difference between the two is where every
one of the review's objections lives:

* **co-occurrence is not a relationship.** "Payments API" and "HSM-01" appearing in one
  scan is not ``Payments API → USES_HSM → HSM-01``. A claim with no basis, or a basis of
  proximity, is refused by name — not down-weighted, refused — because a graph that
  quietly accepts proximity edges is a graph nobody can audit;
* **an edge can never be stronger than its evidence.** A vendor datasheet is
  ``VENDOR_DECLARED``, an imported CMDB row is ``IMPORTED``, an agent poll is
  ``CONFIGURED``, a packet capture is ``OBSERVED``. Asking for a stronger class than the
  basis supports is refused, and downstream consumers read the class rather than the
  relation;
* **the layers do not stand in for each other.** A certificate presented by an endpoint
  is not a statement about the application's crypto library; an SBOM is not the runtime;
  a network hop does not prove what is inside the process. Those are type rules, not
  policy prose: ``APPLICATION → CERTIFICATE`` is ``PRESENTS`` and never
  ``USES_ALGORITHM``, and an algorithm is reached through the key that carries it;
* **this is a projection, not a second twin.** :func:`build` takes a canonical estate and
  :func:`from_document` refuses a TechBOM as input, so there is no path by which a
  TechBOM becomes the source that produces the next TechBOM.

Identity is two-part on purpose: ``key`` is content-addressed
(``kind:name:environment``) and survives renumbering, while ``id`` is the readable
``TECH-APP-001`` an operator quotes in a ticket. A snapshot assigns ids deterministically,
so the same estate always produces the same ids and a *changed* estate renumbers — which
is why nothing downstream may key on ``id``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Any

SCHEMA = "cryptoscan.techbom/1"
ESTATE_SCHEMA = "cryptoscan.techbom-estate/1"

# --------------------------------------------------------------------------- #
# Confidence — one ladder, printed with every claim
# --------------------------------------------------------------------------- #

OBSERVED = "OBSERVED"
#: an observation taken off the wire rather than out of an agent. It is an observation all
#: the same, and it is kept apart so a packet says what a packet can prove (review hbom 4).
NETWORK_OBSERVED = "NETWORK_OBSERVED"
#: something watched a running process rather than a socket. A TLS handshake on the wire
#: says nothing about the cipher the application used inside its own process, so the two
#: observations are separate classes (review nbom 7).
RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
CONFIGURED = "CONFIGURED"
IMPORTED = "IMPORTED"
VENDOR_DECLARED = "VENDOR_DECLARED"
#: what a device says it *can* do. Below anything that was read from the device, above an
#: import, because a capability list is still a statement about the device itself.
CAPABILITY = "CAPABILITY"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"

CONFIDENCE: dict[str, int] = {
    OBSERVED: 5,
    NETWORK_OBSERVED: 5,
    RUNTIME_OBSERVED: 5,
    CONFIGURED: 4,
    CAPABILITY: 3,
    IMPORTED: 3,
    VENDOR_DECLARED: 3,
    INFERRED: 2,
    UNKNOWN: 1,
}

#: a dependency path is *proven* only when something saw or read the device itself.
#: IMPORTED, VENDOR_DECLARED and INFERRED are claims about a claim: they are walked, and
#: they are reported as possibilities rather than as blast radius.
PROVEN: frozenset[str] = frozenset({OBSERVED, NETWORK_OBSERVED, RUNTIME_OBSERVED,
                                   CONFIGURED})

#: every basis a claim may cite, and the strongest class it can support. A basis that is
#: not here is refused rather than guessed, and ``co-occurrence`` is deliberately absent:
#: it is not a basis, it is the absence of one.
BASES: dict[str, str] = {
    "packet-capture": OBSERVED,
    "passive-capture": NETWORK_OBSERVED,
    "capability-list": CAPABILITY,
    "runtime-probe": OBSERVED,
    "process-trace": OBSERVED,
    "agent-inventory": CONFIGURED,
    "config-parse": CONFIGURED,
    "api-poll": CONFIGURED,
    "sbom-import": IMPORTED,
    "cmdb-import": IMPORTED,
    "ticket-import": IMPORTED,
    "vendor-datasheet": VENDOR_DECLARED,
    "vendor-portal": VENDOR_DECLARED,
    "operator-registration": IMPORTED,
    "code-analysis": CONFIGURED,
    "scan-manifest": CONFIGURED,
    "name-match": INFERRED,
    "dependency-graph": INFERRED,
    # how a network endpoint is tied to the thing behind it (review nbom 2). None of
    # these is a name comparison: each is a record that says which backend listens.
    "dns-resolution": CONFIGURED,
    "sni-header": NETWORK_OBSERVED,
    "deployment-metadata": CONFIGURED,
    "kubernetes-ingress": CONFIGURED,
    "api-gateway-config": CONFIGURED,
    "load-balancer-config": CONFIGURED,
    "service-registry": CONFIGURED,
    "mesh-config": CONFIGURED,
    "database-config": CONFIGURED,
    "vpn-config": CONFIGURED,
    "tls-handshake": NETWORK_OBSERVED,
    "ssh-banner": NETWORK_OBSERVED,
    "runtime-observation": RUNTIME_OBSERVED,
}

#: bases that look like evidence and are not. Named so the refusal can quote the reason.
NOT_A_BASIS: dict[str, str] = {
    "co-occurrence": "two assets in one scan is proximity, not a relationship",
    "same-scan": "a shared scan says when something was seen, not how it connects",
    "proximity": "being on the same network segment connects nothing by itself",
    "name-similarity": "a similar name is not an identity match",
    "assumption": "an assumption with no rule behind it is not a claim",
}

# --------------------------------------------------------------------------- #
# Asset types and the relations that may join them
# --------------------------------------------------------------------------- #

ASSET_TYPES: tuple[str, ...] = (
    # business + software
    "BUSINESS_SYSTEM", "APPLICATION", "SERVICE", "CONTAINER", "IMAGE", "PACKAGE",
    "CRYPTO_LIBRARY", "CRYPTO_ASSET",
    # network
    "NETWORK_ENDPOINT", "WAF", "LOAD_BALANCER", "API_GATEWAY", "SERVICE_MESH",
    "CERTIFICATE", "CERTIFICATE_AUTHORITY", "PUBLIC_KEY", "ALGORITHM",
    # the named things a network observation lands on (review nbom 1–3, 13–14)
    "CIPHER_SUITE", "SSH_SERVICE", "VPN_GATEWAY", "IPSEC_TUNNEL",
    # keys and hardware
    "HSM", "KMS", "KEY_REFERENCE", "FIRMWARE", "CRYPTO_CAPABILITY",
    "HOST", "VM", "PHYSICAL_SERVER", "TPM",
    # hardware components — the device is not one opaque row (review hbom 1)
    "CPU", "MEMORY", "MOTHERBOARD", "BIOS", "NIC", "STORAGE", "RAID_CONTROLLER",
    "GPU", "PCI_DEVICE", "CRYPTO_ACCELERATOR", "SMART_CARD", "SECURITY_APPLIANCE",
    "HSM_CLUSTER", "HSM_PARTITION", "DISK",
    # controls that see the traffic, and the policy that limits it (guide 171)
    "IDS", "IPS", "RATE_LIMIT",
    # physical and virtual platforms
    "FIREWALL", "NETWORK_SEGMENT", "HYPERVISOR", "OS", "KUBERNETES_NODE",
    "CLOUD_ACCOUNT", "CLOUD_REGION", "CLOUD_INSTANCE",
    # evidence and vendor lifecycle
    "EVIDENCE", "VULNERABILITY",
    # vendor
    "VENDOR", "VENDOR_PRODUCT",
    # runtime deployment identity
    "SOURCE", "BUILD", "ARTIFACT", "SBOM", "DEPLOYMENT", "POD", "PROCESS",
    "DATABASE",
)

#: the readable id prefix per kind
PREFIX: dict[str, str] = {
    "BUSINESS_SYSTEM": "SYS", "APPLICATION": "APP", "SERVICE": "SVC",
    "CONTAINER": "CTR", "IMAGE": "IMG", "PACKAGE": "PKG",
    "CRYPTO_LIBRARY": "LIB", "CRYPTO_ASSET": "CRY", "NETWORK_ENDPOINT": "EP",
    "LOAD_BALANCER": "LB", "API_GATEWAY": "GW", "SERVICE_MESH": "MESH",
    "WAF": "WAF", "CERTIFICATE": "CERT",
    "CERTIFICATE_AUTHORITY": "CA", "PUBLIC_KEY": "KEY", "ALGORITHM": "ALG",
    "HSM": "HSM", "KMS": "KMS", "KEY_REFERENCE": "KREF", "FIRMWARE": "FW",
    "CRYPTO_CAPABILITY": "CAP", "HOST": "HOST", "VM": "VM",
    "PHYSICAL_SERVER": "SRV", "TPM": "TPM", "VENDOR": "VENDOR",
    "VENDOR_PRODUCT": "PROD", "SOURCE": "SRC", "BUILD": "BUILD", "ARTIFACT": "ART",
    "SBOM": "SBOM", "DEPLOYMENT": "DEP", "POD": "POD", "PROCESS": "PROC",
    "DATABASE": "DB",
    "CIPHER_SUITE": "SUITE", "SSH_SERVICE": "SSH", "VPN_GATEWAY": "VPN",
    "IPSEC_TUNNEL": "TUN",
    "CPU": "CPU", "MEMORY": "MEM", "MOTHERBOARD": "MB", "BIOS": "BIOS", "NIC": "NIC",
    "STORAGE": "STG", "RAID_CONTROLLER": "RAID", "GPU": "GPU", "PCI_DEVICE": "PCI",
    "CRYPTO_ACCELERATOR": "ACCEL", "SMART_CARD": "SCARD",
    "SECURITY_APPLIANCE": "APPL", "HSM_CLUSTER": "HSMC", "HSM_PARTITION": "PART",
    "DISK": "DISK", "FIREWALL": "FW", "NETWORK_SEGMENT": "SEG",
    "IDS": "IDS", "IPS": "IPS", "RATE_LIMIT": "RL",
    "HYPERVISOR": "HYP", "OS": "OS", "KUBERNETES_NODE": "NODE",
    "CLOUD_ACCOUNT": "ACCT", "CLOUD_REGION": "REGION", "CLOUD_INSTANCE": "INST",
    "EVIDENCE": "EVID", "VULNERABILITY": "VULN",
}

#: relation -> (allowed source kinds, allowed target kinds, chain)
RELATIONS: dict[str, dict[str, Any]] = {
    # business → software
    "CONTAINS": {"from": ("BUSINESS_SYSTEM",), "to": ("APPLICATION",), "chain": "SOFTWARE"},
    "PROVIDES": {"from": ("APPLICATION",), "to": ("SERVICE",), "chain": "SOFTWARE"},
    "RUNS": {"from": ("SERVICE", "PHYSICAL_SERVER", "HOST", "VM", "OS",
                      "KUBERNETES_NODE", "HYPERVISOR", "CLOUD_INSTANCE"),
             "to": ("CONTAINER", "APPLICATION", "SERVICE", "POD", "PROCESS"),
             "chain": "SOFTWARE"},
    "FROM_IMAGE": {"from": ("CONTAINER",), "to": ("IMAGE",), "chain": "SOFTWARE"},
    "SHIPS": {"from": ("IMAGE",), "to": ("PACKAGE",), "chain": "SOFTWARE"},
    "LINKS": {"from": ("PACKAGE",), "to": ("CRYPTO_LIBRARY",), "chain": "SOFTWARE"},
    "PROVIDES_ALGORITHM": {"from": ("CRYPTO_LIBRARY",), "to": ("CRYPTO_ASSET",),
                           "chain": "SOFTWARE"},
    "USES_CRYPTO": {"from": ("APPLICATION", "SERVICE", "PROCESS", "CIPHER_SUITE",
                             "CERTIFICATE", "PUBLIC_KEY", "SSH_SERVICE", "IPSEC_TUNNEL"),
                    "to": ("CRYPTO_ASSET",), "chain": "SOFTWARE"},
    "STORES_IN": {"from": ("APPLICATION", "SERVICE"), "to": ("DATABASE",),
                  "chain": "SOFTWARE"},
    "OWNS": {"from": ("BUSINESS_SYSTEM",),
             "to": ("APPLICATION", "SERVICE", "CONTAINER", "DATABASE", "CRYPTO_ASSET",
                    "CRYPTO_LIBRARY", "HOST", "HSM", "KMS", "NETWORK_ENDPOINT",
                    "LOAD_BALANCER", "WAF", "API_GATEWAY", "SERVICE_MESH",
                    "CERTIFICATE", "FIRMWARE", "VENDOR_PRODUCT", "VENDOR",
                    "KEY_REFERENCE", "VM", "PHYSICAL_SERVER"),
             "chain": "SOFTWARE"},
    "DEPENDS_ON": {"from": ("BUSINESS_SYSTEM", "APPLICATION", "SERVICE", "PACKAGE",
                            "CRYPTO_LIBRARY"),
                   "to": ("BUSINESS_SYSTEM", "APPLICATION", "SERVICE", "PACKAGE",
                          "CRYPTO_LIBRARY"),
                   "chain": "SOFTWARE"},
    "FOUND_ON": {"from": ("CRYPTO_ASSET",), "to": ("HOST", "APPLICATION", "HOST"),
                 "chain": "HARDWARE"},
    # network path
    "EXPOSES": {"from": ("APPLICATION", "API_GATEWAY", "SERVICE", "SERVICE_MESH"),
                "to": ("NETWORK_ENDPOINT",), "chain": "NETWORK"},
    "PROTECTED_BY": {"from": ("NETWORK_ENDPOINT", "APPLICATION", "NETWORK_SEGMENT",
                              "CRYPTO_ASSET"),
                     "to": ("WAF", "FIREWALL", "SECURITY_APPLIANCE", "HSM", "KMS", "TPM",
                            "IPS"),
                     "chain": "NETWORK"},
    "FRONTED_BY": {"from": ("NETWORK_ENDPOINT",), "to": ("LOAD_BALANCER",),
                   "chain": "NETWORK"},
    #: an inline IPS is a hop like any other intermediary, in and out (guide 171)
    "FORWARDS_TO": {"from": ("FIREWALL", "WAF", "LOAD_BALANCER", "API_GATEWAY",
                             "SERVICE_MESH", "NETWORK_ENDPOINT", "IPS"),
                    "to": ("WAF", "LOAD_BALANCER", "API_GATEWAY", "SERVICE_MESH",
                           "NETWORK_ENDPOINT", "IPS"),
                    "chain": "NETWORK"},
    "ATTACHED_TO": {"from": ("NIC", "CRYPTO_ACCELERATOR"),
                    "to": ("NETWORK_ENDPOINT", "NETWORK_SEGMENT"), "chain": "NETWORK"},
    "ROUTES_TO": {"from": ("API_GATEWAY", "SERVICE_MESH", "NETWORK_ENDPOINT",
                           "LOAD_BALANCER"),
                  "to": ("APPLICATION", "SERVICE", "DATABASE"), "chain": "NETWORK"},
    "PRESENTS": {"from": ("NETWORK_ENDPOINT", "LOAD_BALANCER", "API_GATEWAY", "WAF",
                          "SERVICE_MESH", "DATABASE"),
                 "to": ("CERTIFICATE",), "chain": "NETWORK"},
    # certificate → key → algorithm → issuer
    "CONTAINS_KEY": {"from": ("CERTIFICATE",), "to": ("PUBLIC_KEY",), "chain": "CERTIFICATE"},
    "USES_ALGORITHM": {"from": ("PUBLIC_KEY", "CRYPTO_ASSET"), "to": ("ALGORITHM",),
                       "chain": "CERTIFICATE"},
    "ISSUED_BY": {"from": ("CERTIFICATE",), "to": ("CERTIFICATE_AUTHORITY",),
                  "chain": "CERTIFICATE"},
    "SIGNED_BY": {"from": ("CERTIFICATE_AUTHORITY",), "to": ("CERTIFICATE_AUTHORITY",),
                  "chain": "CERTIFICATE"},
    "KEY_HELD_BY": {"from": ("CERTIFICATE_AUTHORITY",), "to": ("HSM", "KMS"),
                    "chain": "CERTIFICATE"},
    "HOLDS_CERTIFICATE": {"from": ("HSM", "KMS", "TPM"), "to": ("CERTIFICATE",),
                          "chain": "CERTIFICATE"},
    # keys and hardware
    "USES_HSM": {"from": ("APPLICATION", "SERVICE", "PROCESS", "LOAD_BALANCER",
                          "API_GATEWAY", "FIREWALL", "SECURITY_APPLIANCE", "DATABASE"),
                 "to": ("HSM", "KMS"), "chain": "KEYS"},
    "HAS_MODEL": {"from": ("HSM", "LOAD_BALANCER", "WAF", "API_GATEWAY", "SERVICE_MESH",
                           "DATABASE", "VPN_GATEWAY", "PHYSICAL_SERVER", "NIC", "GPU",
                           "CRYPTO_ACCELERATOR", "FIREWALL", "IDS", "IPS",
                           "SECURITY_APPLIANCE", "CPU", "STORAGE", "RAID_CONTROLLER",
                           "SMART_CARD", "TPM"),
                  "to": ("VENDOR_PRODUCT",), "chain": "VENDOR"},
    "HOLDS_KEY": {"from": ("HSM", "KMS"), "to": ("KEY_REFERENCE",), "chain": "KEYS"},
    "RUNS_FIRMWARE": {"from": ("HSM", "LOAD_BALANCER", "WAF", "API_GATEWAY", "FIREWALL",
                               "IDS", "IPS", "VPN_GATEWAY",
                               "DATABASE", "SERVICE_MESH", "PHYSICAL_SERVER", "TPM", "NIC",
                               "STORAGE",
                               "RAID_CONTROLLER", "GPU", "CRYPTO_ACCELERATOR",
                               "SECURITY_APPLIANCE", "SMART_CARD"),
                      "to": ("FIRMWARE",), "chain": "HARDWARE"},
    "RUNS_BIOS": {"from": ("PHYSICAL_SERVER", "HOST"), "to": ("BIOS",),
                  "chain": "HARDWARE"},
    # a datasheet can say a device supports an algorithm; only a probe can say it
    # performed the operation there (RELATION_BASIS_CEILING keeps the two apart)
    "SUPPORTS": {"from": ("FIRMWARE", "HSM", "TPM", "CRYPTO_ACCELERATOR", "SMART_CARD",
                          "BIOS", "NETWORK_ENDPOINT", "LOAD_BALANCER", "API_GATEWAY", "WAF",
                          "SERVICE_MESH", "DATABASE", "SSH_SERVICE", "VPN_GATEWAY",
                          "IPSEC_TUNNEL", "OS", "VENDOR_PRODUCT", "IDS", "IPS"),
                 "to": ("CRYPTO_CAPABILITY", "CIPHER_SUITE", "ALGORITHM"),
                 "chain": "NETWORK"},
    "PERFORMS": {"from": ("HSM", "CRYPTO_ACCELERATOR", "TPM"),
                 "to": ("CRYPTO_CAPABILITY",), "chain": "HARDWARE"},
    "IMPLEMENTS": {"from": ("CRYPTO_CAPABILITY",), "to": ("ALGORITHM",),
                   "chain": "CERTIFICATE"},
    # the device is a tree, not a row (review hbom 1, 2)
    "HAS_COMPONENT": {"from": ("PHYSICAL_SERVER", "HOST", "VM", "HYPERVISOR",
                               "KUBERNETES_NODE", "CLOUD_INSTANCE", "SECURITY_APPLIANCE"),
                      "to": ("CPU", "MEMORY", "MOTHERBOARD", "NIC", "STORAGE",
                             "RAID_CONTROLLER", "GPU", "PCI_DEVICE",
                             "CRYPTO_ACCELERATOR", "TPM", "DISK", "SMART_CARD", "HSM",
                             "BIOS"),
                      "chain": "HARDWARE"},
    "HAS_PARTITION": {"from": ("HSM",), "to": ("HSM_PARTITION",), "chain": "HARDWARE"},
    "MEMBER_OF": {"from": ("HSM", "HSM_PARTITION"), "to": ("HSM_CLUSTER",),
                  "chain": "HARDWARE"},
    "PEERS_WITH": {"from": ("HSM",), "to": ("HSM",), "chain": "HARDWARE"},
    "SERVES": {"from": ("HSM", "HSM_PARTITION", "KMS"), "to": ("APPLICATION",),
               "chain": "KEYS"},
    # hardware lifecycle and evidence (review hbom 8, 13)
    "HAS_VULNERABILITY": {"from": ("FIRMWARE", "BIOS", "OS"), "to": ("VULNERABILITY",),
                          "chain": "HARDWARE"},
    "EVIDENCED_BY": {"from": ("NETWORK_ENDPOINT", "CIPHER_SUITE", "SSH_SERVICE",
                             "IPSEC_TUNNEL", "VPN_GATEWAY", "DATABASE",
                             "PHYSICAL_SERVER", "HOST", "VM", "HSM", "TPM", "CPU",
                              "MEMORY", "MOTHERBOARD", "BIOS", "NIC", "STORAGE",
                              "RAID_CONTROLLER", "GPU", "PCI_DEVICE",
                              "CRYPTO_ACCELERATOR", "SMART_CARD", "SECURITY_APPLIANCE",
                              "HSM_CLUSTER", "HSM_PARTITION", "DISK", "FIRMWARE",
                              "FIREWALL", "NETWORK_SEGMENT", "HYPERVISOR", "OS",
                              "KUBERNETES_NODE", "CLOUD_ACCOUNT", "CLOUD_REGION",
                              "CLOUD_INSTANCE"),
                     "to": ("EVIDENCE",), "chain": "HARDWARE"},
    # infrastructure
    "SCHEDULED_ON": {"from": ("CONTAINER", "POD"),
                     "to": ("HOST", "KUBERNETES_NODE", "VM", "CLOUD_INSTANCE"),
                     "chain": "HARDWARE"},
    "HOSTED_ON": {"from": ("HOST",), "to": ("VM",), "chain": "HARDWARE"},
    "RUNS_ON": {"from": ("VM", "PROCESS", "APPLICATION", "SERVICE", "HYPERVISOR",
                         "KUBERNETES_NODE", "OS", "LOAD_BALANCER", "WAF", "API_GATEWAY",
                         "SERVICE_MESH", "DATABASE", "VPN_GATEWAY", "SSH_SERVICE"),
                "to": ("PHYSICAL_SERVER", "HOST", "VM", "KUBERNETES_NODE",
                       "CLOUD_INSTANCE", "HYPERVISOR"),
                "chain": "HARDWARE"},
    # virtual and cloud platforms (review hbom 11, 12)
    "RUNS_HYPERVISOR": {"from": ("PHYSICAL_SERVER",), "to": ("HYPERVISOR",),
                        "chain": "HARDWARE"},
    "HOSTS_OS": {"from": ("VM", "PHYSICAL_SERVER", "CLOUD_INSTANCE"), "to": ("OS",),
                 "chain": "HARDWARE"},
    "RUNS_APPLICATION": {"from": ("OS", "KUBERNETES_NODE", "HOST", "CLOUD_INSTANCE",
                                  "PROCESS", "SERVICE"),
                         "to": ("APPLICATION",), "chain": "SOFTWARE"},
    "IN_REGION": {"from": ("CLOUD_INSTANCE",), "to": ("CLOUD_REGION",),
                  "chain": "HARDWARE"},
    "IN_ACCOUNT": {"from": ("CLOUD_REGION", "CLOUD_INSTANCE"), "to": ("CLOUD_ACCOUNT",),
                   "chain": "HARDWARE"},
    "CARRIES": {"from": ("PHYSICAL_SERVER",), "to": ("TPM",), "chain": "HARDWARE"},
    # vendor
    "EMBEDS": {"from": ("APPLICATION", "IMAGE", "SERVICE"), "to": ("VENDOR_PRODUCT",),
               "chain": "VENDOR"},
    "SUPPLIED_BY": {"from": ("VENDOR_PRODUCT", "HSM", "LOAD_BALANCER", "WAF", "API_GATEWAY",
                             "DATABASE", "VPN_GATEWAY", "HOST", "FIRMWARE", "TPM", "VM",
                             "PHYSICAL_SERVER", "CPU", "MEMORY", "MOTHERBOARD", "BIOS",
                             "NIC", "STORAGE", "RAID_CONTROLLER", "GPU", "PCI_DEVICE",
                             "CRYPTO_ACCELERATOR", "SMART_CARD", "SECURITY_APPLIANCE",
                             "FIREWALL"),
                    "to": ("VENDOR",), "chain": "VENDOR"},
    # runtime deployment identity
    "BUILT_INTO": {"from": ("SOURCE",), "to": ("BUILD",), "chain": "RUNTIME"},
    "PRODUCES": {"from": ("BUILD",), "to": ("ARTIFACT",), "chain": "RUNTIME"},
    "DESCRIBED_BY": {"from": ("ARTIFACT",), "to": ("SBOM",), "chain": "RUNTIME"},
    "PACKAGED_AS": {"from": ("ARTIFACT",), "to": ("IMAGE",), "chain": "RUNTIME"},
    "DEPLOYED_AS": {"from": ("IMAGE",), "to": ("DEPLOYMENT",), "chain": "RUNTIME"},
    "SCHEDULES": {"from": ("DEPLOYMENT",), "to": ("POD",), "chain": "RUNTIME"},
    "RUNS_PROCESS": {"from": ("POD",), "to": ("PROCESS",), "chain": "RUNTIME"},
    # --- network dependencies: who listens, who routes, who terminates TLS -----------
    #: the port belongs to the endpoint; the device that owns it says so here, rather
    #: than every consumer guessing from the IP.
    "LISTENS_ON": {"from": ("APPLICATION", "SERVICE", "LOAD_BALANCER", "API_GATEWAY", "WAF",
                            "SERVICE_MESH", "DATABASE", "SSH_SERVICE", "VPN_GATEWAY",
                            "IPSEC_TUNNEL", "HSM", "KMS", "FIREWALL"),
                   "to": ("NETWORK_ENDPOINT",), "chain": "NETWORK"},
    #: what a listener will speak. Config and a capability list may say *supported*; only
    #: a handshake can say *negotiated*, which is why NEGOTIATES has a floor.
    "NEGOTIATES": {"from": ("NETWORK_ENDPOINT", "SSH_SERVICE", "IPSEC_TUNNEL"),
                   "to": ("CIPHER_SUITE", "CRYPTO_ASSET", "ALGORITHM", "CERTIFICATE"),
                   "chain": "NETWORK"},
    #: the three ways TLS crosses an intermediary — three different crypto graphs.
    "TERMINATES_TLS": {"from": ("NETWORK_ENDPOINT",), "to": ("NETWORK_ENDPOINT",),
                       "chain": "NETWORK"},
    "RE_ENCRYPTS": {"from": ("NETWORK_ENDPOINT",), "to": ("NETWORK_ENDPOINT",),
                    "chain": "NETWORK"},
    "PASSTHROUGH": {"from": ("NETWORK_ENDPOINT",), "to": ("NETWORK_ENDPOINT",),
                    "chain": "NETWORK"},
    #: an IPS *in the path* protects; an IDS is not in the tuple on purpose — it sees a
    #: copy of the traffic and cannot drop a packet it never carried (guide 171).
    "PROTECTS": {"from": ("WAF", "FIREWALL", "SECURITY_APPLIANCE", "SERVICE_MESH", "IPS"),
                 "to": ("APPLICATION", "SERVICE", "NETWORK_ENDPOINT", "DATABASE",
                        "NETWORK_SEGMENT"), "chain": "NETWORK"},
    #: what a control *sees*. Not a forwarding relation: a tap inspects a copy, and a
    #: route that does not cross it is still a route (guide 171).
    "INSPECTS": {"from": ("IDS", "IPS", "FIREWALL", "SECURITY_APPLIANCE", "WAF"),
                 "to": ("NETWORK_SEGMENT", "NETWORK_ENDPOINT", "SERVICE", "APPLICATION",
                        "DATABASE"), "chain": "NETWORK"},
    #: a device that enforces a rate-limit policy, and what that policy applies to
    "ENFORCES": {"from": ("WAF", "FIREWALL", "API_GATEWAY", "LOAD_BALANCER", "SERVICE_MESH",
                          "IPS", "NETWORK_ENDPOINT"),
                 "to": ("RATE_LIMIT",), "chain": "NETWORK"},
    "LIMITS": {"from": ("RATE_LIMIT",),
               "to": ("NETWORK_ENDPOINT", "SERVICE", "APPLICATION", "DATABASE"),
               "chain": "NETWORK"},
    "AUTHENTICATES": {"from": ("SERVICE_MESH", "API_GATEWAY", "WAF"),
                      "to": ("APPLICATION", "SERVICE", "DATABASE"), "chain": "NETWORK"},
    "USES_CERTIFICATE": {"from": ("NETWORK_ENDPOINT", "APPLICATION", "SERVICE", "PROCESS",
                                  "LOAD_BALANCER", "API_GATEWAY", "WAF", "SERVICE_MESH",
                                  "DATABASE", "SSH_SERVICE"),
                         "to": ("CERTIFICATE",), "chain": "NETWORK"},
    "USES_KMS": {"from": ("APPLICATION", "SERVICE", "PROCESS", "DATABASE", "LOAD_BALANCER"),
                 "to": ("KMS",), "chain": "KEYS"},
    "USES_KEY": {"from": ("APPLICATION", "SERVICE", "PROCESS", "DATABASE", "LOAD_BALANCER"),
                 "to": ("KEY_REFERENCE",), "chain": "KEYS"},
    "SIGNED_WITH": {"from": ("CERTIFICATE",), "to": ("ALGORITHM",), "chain": "CERTIFICATE"},
    #: a sidecar does the TLS, not the application: the handshake belongs to the proxy
    "PROXY_FOR": {"from": ("PROCESS", "SERVICE", "CONTAINER"),
                  "to": ("APPLICATION", "SERVICE"), "chain": "NETWORK"},
    "CONNECTS_TO": {"from": ("NETWORK_ENDPOINT", "APPLICATION", "SERVICE", "LOAD_BALANCER",
                             "API_GATEWAY", "WAF", "SERVICE_MESH", "DATABASE", "PROCESS",
                             "HOST", "VM", "CLOUD_INSTANCE"),
                    "to": ("NETWORK_ENDPOINT", "APPLICATION", "SERVICE", "LOAD_BALANCER",
                           "API_GATEWAY", "WAF", "SERVICE_MESH", "DATABASE", "HOST", "VM",
                           "HSM", "KMS", "CLOUD_INSTANCE"),
                    "chain": "NETWORK"},
    "TUNNELS_TO": {"from": ("IPSEC_TUNNEL", "VPN_GATEWAY"),
                   "to": ("NETWORK_SEGMENT", "NETWORK_ENDPOINT", "VPN_GATEWAY"),
                   "chain": "NETWORK"},
    "LOADS": {"from": ("PROCESS",), "to": ("CRYPTO_LIBRARY",), "chain": "RUNTIME"},
}

#: relations that need a class *at least* this strong. A datasheet may say an HSM
#: **supports** RSA — that is a capability claim and ``VENDOR_DECLARED`` is honest — but
#: only something that read the device or watched it can say the operation **performed**
#: there. This is the review's "capability ≠ use", as a rule rather than as prose.
RELATION_MIN_CONFIDENCE: dict[str, str] = {
    "PERFORMS": CONFIGURED,
    #: a load balancer's or a tunnel's configuration is a record of what it *will* use, so
    #: CONFIGURED is enough to say "negotiated" about a policy. It is not enough to say it
    #: about a *session*: `nbom_graph.negotiated()` raises this floor to an observation,
    #: because a session is not a policy (review nbom 6).
    "NEGOTIATES": CONFIGURED,
    #: how TLS crosses a device is read from its configuration, not guessed from a route
    "TERMINATES_TLS": CONFIGURED,
    "RE_ENCRYPTS": CONFIGURED,
    "PASSTHROUGH": CONFIGURED,
    "RUNS_FIRMWARE": IMPORTED,
    "EVIDENCED_BY": IMPORTED,
}

#: evidence classes a crypto-asset relation may carry, kept apart on purpose (review 9)
CRYPTO_EVIDENCE: tuple[str, ...] = ("RUNTIME_OBSERVED", "NETWORK_OBSERVED",
                                   "STATIC_OBSERVED", "CERTIFICATE_OBSERVED", "CONFIGURED")

#: which bases may evidence which crypto-asset class. A runtime observation, a static
#: manifest row and a certificate's key are different claims about different things.
CRYPTO_EVIDENCE_BASIS: dict[str, set[str]] = {
    "RUNTIME_OBSERVED": {"runtime-probe", "process-trace", "packet-capture",
                         "runtime-observation"},
    #: a cipher suite read off a handshake is a network observation of that suite's parts
    "NETWORK_OBSERVED": {"tls-handshake", "packet-capture", "passive-capture", "ssh-banner"},
    "STATIC_OBSERVED": {"sbom-import", "config-parse", "cmdb-import"},
    "CERTIFICATE_OBSERVED": {"packet-capture", "api-poll", "config-parse"},
    "CONFIGURED": {"config-parse", "agent-inventory", "api-poll"},
}

#: algorithms whose exposure a quantum computer changes. Symmetric ciphers are not here.
QUANTUM_SENSITIVE = ("RSA", "ECDSA", "ECDH", "DH", "DSA", "X25519", "P-256", "P-384",
                     "SHA-1", "SHA1", "MD5", "3DES")

#: kinds that make a PQC migration expensive when they appear on a path
PQC_BLOCKER_KINDS = ("HSM", "FIRMWARE", "VENDOR_PRODUCT", "TPM")

NOT_PROVEN = [
    "that a relationship exists because two assets exist: an edge is only in this "
    "document when something said so, and the basis is printed beside it",
    "that a declared edge is deployed: IMPORTED and VENDOR_DECLARED are kept as they are "
    "and are not counted as proven paths in a blast radius",
    "what is inside a running process: a certificate on an endpoint is not the "
    "application's crypto library, and the model never joins them",
    "that the estate is complete: the completeness block states the denominator and the "
    "reason for every gap, and an unmeasured layer is UNMEASURED, not zero",
    "that ids are permanent: `id` is readable and renumbers when the estate changes, so "
    "anything durable must key on `key`",
]


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())


def _key(kind: str, name: str, environment: str) -> str:
    return f"{kind}:{_norm(name).lower()}:{_norm(environment).lower() or 'unknown'}"


def _digest(text: str, length: int = 10) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def _ref(kind: str, name: str, environment: str = "PRODUCTION") -> str:
    """The reference form a claim uses, so a caller never has to compute an id."""
    return _key(kind, name, environment)


class ClaimRefused(ValueError):
    """A refusal with a code: the reason is prose, the code is what code reads."""

    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _refused(code: str, subject: Any, reason: str) -> dict[str, Any]:
    return {"code": code, "subject": subject, "reason": reason}


def _quantum_sensitive(algorithm: Any) -> bool:
    text = str(algorithm or "").upper()
    return any(token in text for token in QUANTUM_SENSITIVE)


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #

def asset(kind: Any, name: Any, *, environment: Any = "PRODUCTION", version: Any = None,
          owner: Any = None, location: Any = None, status: Any = "ACTIVE",
          first_seen: Any = None, last_seen: Any = None, source: Any = None,
          evidence_ids: Iterable[Any] | None = None, **attributes: Any) -> dict[str, Any]:
    """One technology asset, before the estate assigns it a readable id.

    An asset without evidence is a claim, so at least one evidence id is required: the
    asset model must not be the one place where a fact arrives unbacked.
    """
    kind_text = str(kind or "").strip().upper()
    if kind_text not in ASSET_TYPES:
        raise ClaimRefused("UNKNOWN_KIND",
                           f"{kind_text or '(none)'} is not a technology asset type")
    name_text = _norm(name)
    if not name_text:
        raise ClaimRefused("MISSING_NAME", f"a {kind_text} needs a name")
    environment_text = _norm(environment).upper() or "PRODUCTION"
    evidence = [_norm(value) for value in (evidence_ids or []) if _norm(value)]
    if not evidence:
        raise ClaimRefused("ASSET_WITHOUT_EVIDENCE",
                           f"{name_text}: an asset with no evidence id is a claim, not "
                           "an asset")
    body = {
        "kind": kind_text,
        "name": name_text,
        "key": _key(kind_text, name_text, environment_text),
        "environment": environment_text,
        "version": _norm(version) or None,
        "owner": _norm(owner) or None,
        "location": _norm(location) or None,
        "status": _norm(status).upper() or "ACTIVE",
        "first_seen": _norm(first_seen) or None,
        "last_seen": _norm(last_seen) or None,
        "source": _norm(source) or None,
        "evidence_ids": evidence,
        "attributes": {key: value for key, value in attributes.items()
                       if value not in (None, "")},
    }
    return body


# --------------------------------------------------------------------------- #
# Claims (relationships)
# --------------------------------------------------------------------------- #

def claim(source: Any, relation: Any, target: Any, *, basis: Any,
          evidence_ids: Iterable[Any] | None = None, source_system: Any = None,
          confidence: Any = None, rule: Any = None, note: Any = None,
          observed_at: Any = None, first_seen: Any = None, last_seen: Any = None,
          **facts: Any) -> dict[str, Any]:
    """A relationship, as a claim that carries its own basis and class.

    ``confidence`` may lower the class a basis supports (a runtime probe of a *shared*
    library can be reported as a ``CONFIGURED`` use, for instance) but never raise it —
    raising is refused here and again in :func:`build` when the estate is assembled.

    ``observed_at`` / ``first_seen`` / ``last_seen`` and any remaining keyword (a
    ``protocol``, a ``port``, a ``vlan``) are kept on the edge as **facts**: a network
    dependency that does not say which port it was read from is a drawing, not a record.
    """
    relation_text = str(relation or "").strip().upper()
    if relation_text not in RELATIONS:
        raise ClaimRefused("UNKNOWN_RELATION",
                           f"{relation_text or '(none)'} is not a technology relation")
    basis_text = _norm(basis).lower()
    if not basis_text:
        raise ClaimRefused("NO_BASIS",
                           "a claim needs a basis; without one it is an assumption")
    if basis_text in NOT_A_BASIS:
        raise ClaimRefused("CO_OCCURRENCE_NOT_EVIDENCE",
                           f"{basis_text} is not evidence: {NOT_A_BASIS[basis_text]}")
    if basis_text not in BASES:
        raise ClaimRefused("UNKNOWN_BASIS",
                           f"{basis_text} is not a basis this model can classify")
    ceiling = BASES[basis_text]
    claimed = str(confidence or ceiling).strip().upper()
    if claimed not in CONFIDENCE:
        raise ClaimRefused("UNKNOWN_CONFIDENCE",
                           f"{claimed} is not a confidence class")
    if CONFIDENCE[claimed] > CONFIDENCE[ceiling]:
        raise ClaimRefused(
            "CLAIM_STRONGER_THAN_EVIDENCE",
            f"{basis_text} supports at most {ceiling}, and the claim asks for {claimed}; "
            "an edge may never be stronger than its evidence")
    evidence = [_norm(value) for value in (evidence_ids or []) if _norm(value)]
    if not evidence:
        raise ClaimRefused("CLAIM_WITHOUT_EVIDENCE",
                           f"{relation_text}: a claim needs an evidence id, not just a "
                           "basis name")
    if claimed == INFERRED and not _norm(rule):
        raise ClaimRefused("INFERENCE_WITHOUT_RULE",
                           "an INFERRED claim must name the rule it uses, so the "
                           "inference can be argued with")
    return {
        "from": _norm(source),
        "relation": relation_text,
        "to": _norm(target),
        "basis": basis_text,
        "confidence": claimed,
        "evidence_ids": evidence,
        "source_system": _norm(source_system) or None,
        "rule": _norm(rule) or None,
        "note": _norm(note) or None,
        "observed_at": _norm(observed_at) or None,
        "first_seen": _norm(first_seen) or None,
        "last_seen": _norm(last_seen) or None,
        "facts": {str(key): value for key, value in facts.items()
                  if value not in (None, "", [], {})},
        "chain": RELATIONS[relation_text]["chain"],
    }


def check_types(relation: Any, source_kind: Any, target_kind: Any) -> tuple[bool, str]:
    """Whether a relation may join these two kinds — the layer boundary, as a rule."""
    relation_text = str(relation or "").strip().upper()
    spec = RELATIONS.get(relation_text)
    if not spec:
        return False, f"{relation_text or '(none)'} is not a technology relation"
    source_text = str(source_kind or "").strip().upper()
    target_text = str(target_kind or "").strip().upper()
    if source_text not in spec["from"]:
        return False, (f"{relation_text} starts at {', '.join(spec['from'])}, not "
                       f"{source_text or '(none)'}")
    if target_text not in spec["to"]:
        return False, (f"{relation_text} ends at {', '.join(spec['to'])}, not "
                       f"{target_text or '(none)'}")
    return True, ""


# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #

#: the top-level keys :func:`asset` owns. Anything else on an estate row is an attribute,
#: because a caller describing an asset should not have to nest the interesting part.
_ASSET_FIELDS = frozenset({"kind", "name", "environment", "version", "owner", "location",
                           "status", "first_seen", "last_seen", "source", "evidence_ids",
                           "attributes", "key", "id", "digest"})


def build(estate: Mapping[str, Any]) -> dict[str, Any]:
    """Canonical estate → TechBOM. Ids are assigned here and nowhere else."""
    if not isinstance(estate, Mapping) or estate.get("schema") != ESTATE_SCHEMA:
        raise ValueError(f"build() takes a {ESTATE_SCHEMA} document, not a projection; "
                         "a TechBOM is never its own input")
    refusals: list[dict[str, Any]] = []
    assets: dict[str, dict[str, Any]] = {}
    for raw in estate.get("assets") or []:
        try:
            row = asset(
                raw.get("kind"), raw.get("name"),
                environment=raw.get("environment") or estate.get("environment")
                or "PRODUCTION",
                version=raw.get("version"), owner=raw.get("owner"),
                location=raw.get("location"), status=raw.get("status"),
                first_seen=raw.get("first_seen"), last_seen=raw.get("last_seen"),
                source=raw.get("source"), evidence_ids=raw.get("evidence_ids"),
                **{**(raw.get("attributes") or {}),
                   **{key: value for key, value in raw.items()
                      if key not in _ASSET_FIELDS}},
            )
        except ClaimRefused as exc:
            refusals.append(_refused(exc.code, raw.get("name") or raw, exc.reason))
            continue
        if row["key"] in assets:
            refusals.append(_refused(
                "DUPLICATE_ASSET", row["key"],
                f"{row['name']} is described twice for {row['environment']}; the first "
                "description is kept and the second is refused rather than merged"))
            continue
        assets[row["key"]] = row

    # readable ids, assigned deterministically: same estate, same ids
    ordered = sorted(assets.values(), key=lambda row: (row["kind"], row["key"]))
    counter: dict[str, int] = {}
    for row in ordered:
        prefix = PREFIX.get(row["kind"], "TECH")
        counter[prefix] = counter.get(prefix, 0) + 1
        row["id"] = f"TECH-{prefix}-{counter[prefix]:03d}"
        row["digest"] = _digest(row["key"])

    claims: list[dict[str, Any]] = []
    for raw in estate.get("claims") or []:
        try:
            row = claim(
                raw.get("from"), raw.get("relation"), raw.get("to"),
                basis=raw.get("basis"), evidence_ids=raw.get("evidence_ids"),
                source_system=raw.get("source_system"),
                confidence=raw.get("confidence"), rule=raw.get("rule"),
                note=raw.get("note"), observed_at=raw.get("observed_at"),
                first_seen=raw.get("first_seen"), last_seen=raw.get("last_seen"),
                **(raw.get("facts") or {}),
            )
        except ClaimRefused as exc:
            refusals.append(_refused(exc.code, raw, exc.reason))
            continue
        source_key, source_code = _resolve(row["from"], assets)
        target_key, target_code = _resolve(row["to"], assets)
        if not source_key or not target_key:
            code = source_code or target_code
            missing = row["from"] if not source_key else row["to"]
            if code == "AMBIGUOUS_REF":
                reason = (f"{row['relation']} names {missing}, which two or more assets in "
                          "this estate share; qualify it by kind, as "
                          "`KIND:name:environment`, instead of letting the first match "
                          "decide")
            else:
                reason = (f"{row['relation']} names {missing}, which no asset in this "
                          "estate declares; an edge to an undeclared node is refused, "
                          "not invented")
            refusals.append(_refused(code, missing, reason))
            continue
        ok, reason = check_types(row["relation"], assets[source_key]["kind"],
                                 assets[target_key]["kind"])
        if not ok:
            refusals.append(_refused(
                "TYPE_MISMATCH", f"{row['from']} {row['relation']} {row['to']}", reason))
            continue
        floor = RELATION_MIN_CONFIDENCE.get(row["relation"])
        if floor and CONFIDENCE[row["confidence"]] < CONFIDENCE[floor]:
            refusals.append(_refused(
                "CLAIM_WEAKER_THAN_RELATION_REQUIRES",
                f"{row['from']} {row['relation']} {row['to']}",
                f"{row['relation']} says something happened at the device, and "
                f"{row['basis']} supports only {row['confidence']}; it needs at least "
                f"{floor}, or it is a capability claim and belongs on SUPPORTS"))
            continue
        if row["relation"] == "USES_CRYPTO":
            # review 9: a runtime hit, a manifest row and a certificate key are three
            # different claims, so an edge may not be evidenced by a basis from another
            # class — a certificate never proves what a process linked against.
            declared = str(assets[target_key]["attributes"].get("evidence_type") or "")
            allowed = CRYPTO_EVIDENCE_BASIS.get(declared)
            if allowed and row["basis"] not in allowed:
                refusals.append(_refused(
                    "EVIDENCE_CLASS_MISMATCH",
                    f"{row['from']} USES_CRYPTO {row['to']}",
                    f"the crypto asset is {declared}, and {row['basis']} is evidence of "
                    f"{', '.join(sorted(allowed))}; the three classes stay apart"))
                continue
        row["from_key"] = source_key
        row["to_key"] = target_key
        row["from_id"] = assets[source_key]["id"]
        row["to_id"] = assets[target_key]["id"]
        row["id"] = f"EDGE-{_digest(source_key + row['relation'] + target_key, 8)}"
        # the same edge from the same basis is the same edge: a second copy would double
        # every route and every count that walks it, without adding a fact
        twin = next((item for item in claims
                     if item["from_key"] == source_key and item["to_key"] == target_key
                     and item["relation"] == row["relation"]
                     and item["basis"] == row["basis"]), None)
        if twin is not None:
            twin["evidence_ids"] = sorted(set(twin["evidence_ids"])
                                          | set(row["evidence_ids"]))
            continue
        claims.append(row)

    counts: dict[str, int] = {}
    for row in assets.values():
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
    chain_counts: dict[str, int] = {}
    for row in claims:
        chain_counts[row["chain"]] = chain_counts.get(row["chain"], 0) + 1
    unproven = [row["id"] for row in claims if row["confidence"] not in PROVEN]
    return {
        "schema": SCHEMA,
        "projection": True,
        "source_of_truth": "CANONICAL_ESTATE",
        "derived_from": estate.get("estate_id"),
        "environment": estate.get("environment") or "PRODUCTION",
        "assets": sorted(assets.values(), key=lambda row: row["id"]),
        "by_key": assets,
        "claims": sorted(claims, key=lambda row: row["id"]),
        "refusals": refusals,
        "counts": dict(sorted(counts.items())),
        "claim_counts": dict(sorted(chain_counts.items())),
        "unproven_edges": unproven,
        "completeness": completeness(assets.values(), estate.get("expected") or {},
                                    estate.get("gaps") or []),
        "statement": (
            f"{len(assets)} technology asset(s) across {len(counts)} kind(s) and "
            f"{len(claims)} evidenced relationship(s); "
            f"{len(unproven)} edge(s) not proven; "
            f"{len(refusals)} claim(s) refused"),
        "not_proven": list(NOT_PROVEN),
    }


def _resolve(reference: str, assets: Mapping[str, dict[str, Any]]) -> tuple[str | None, str]:
    """A reference is a key, an id, or an unambiguous name — never a guess."""
    text = _norm(reference)
    if text in assets:
        return text, ""
    lowered = text.lower()
    for key in assets:
        if key.lower() == lowered:
            return key, ""
    for key, row in assets.items():
        if row["id"].lower() == lowered:
            return key, ""
    matches = [key for key, row in assets.items() if row["name"].lower() == lowered]
    if len(matches) == 1:
        return matches[0], ""
    if len(matches) > 1:
        return None, "AMBIGUOUS_REF"
    return None, "UNKNOWN_REF"


# --------------------------------------------------------------------------- #
# Completeness — the denominator, always
# --------------------------------------------------------------------------- #

def completeness(assets: Iterable[Mapping[str, Any]], expected: Mapping[str, Any],
                 gaps: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Observed against expected, per kind, with a verdict and the stated reasons.

    ``expected`` maps a kind to the number the estate *should* hold (from authorisation
    and the scan plan). A kind with no expected number is ``UNMEASURED`` — not complete,
    not zero — because a count nobody can divide by is not coverage.
    """
    observed: dict[str, int] = {}
    for row in assets:
        kind = str(row.get("kind") or "").upper()
        observed[kind] = observed.get(kind, 0) + 1
    rows: list[dict[str, Any]] = []
    for kind in sorted({*observed, *{str(k).upper() for k in expected}}):
        seen = observed.get(kind, 0)
        total = expected.get(kind, expected.get(kind.lower(), None))
        if total is None:
            rows.append({"kind": kind, "observed": seen, "expected": None,
                         "coverage": None, "verdict": "UNMEASURED"})
            continue
        total = int(total)
        coverage = 1.0 if total <= 0 else min(seen / total, 1.0)
        verdict = ("COMPLETE" if seen >= total else
                   "OVER" if seen > total else
                   "PARTIAL" if seen else "MISSING")
        rows.append({"kind": kind, "observed": seen, "expected": total,
                     "coverage": round(coverage, 4), "verdict": verdict})
    stated = [{"kind": str(row.get("kind") or "").upper(),
               "reason": _norm(row.get("reason")) or "no reason given"}
              for row in (gaps or [])]
    if any(row["verdict"] in {"PARTIAL", "MISSING"} for row in rows):
        overall = "PARTIAL"
    elif any(row["verdict"] == "UNMEASURED" for row in rows):
        overall = "UNMEASURED"
    elif not rows:
        overall = "UNMEASURED"
    else:
        overall = "COMPLETE"
    missing = [row for row in rows if row["verdict"] in {"PARTIAL", "MISSING"}]
    return {
        "rows": rows,
        "overall": overall,
        "gaps": stated,
        "unmeasured": [row["kind"] for row in rows if row["verdict"] == "UNMEASURED"],
        "statement": (
            f"{overall}: {len([r for r in rows if r['verdict'] == 'COMPLETE'])} kind(s) "
            f"complete, {len(missing)} short, {len(stated)} stated gap(s), "
            f"{len([r for r in rows if r['verdict'] == 'UNMEASURED'])} unmeasured"),
        "rationale": ("an overall verdict of COMPLETE means every kind with an expected "
                      "number met it; a kind with no expected number is UNMEASURED and "
                      "never counts as complete"),
    }


# --------------------------------------------------------------------------- #
# Cross-BOM reconciliation — conflicts are preserved, never resolved silently
# --------------------------------------------------------------------------- #

def reconcile(observations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Same asset, same attribute, several sources → agree, or say CONFLICT.

    Consensus is not verification: four sources repeating one imported value agree with
    each other and with nothing else, so the block reports ``sources`` and the strongest
    class it saw rather than a winner.
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in observations or []:
        attribute = _norm(row.get("attribute")).lower()
        subject = _norm(row.get("subject"))
        if not subject or not attribute:
            continue
        basis = _norm(row.get("basis")).lower()
        if basis in NOT_A_BASIS or basis not in BASES:
            groups.setdefault((subject, attribute), []).append({
                "value": _norm(row.get("value")), "source": _norm(row.get("source")),
                "basis": basis or "unknown", "confidence": UNKNOWN,
                "rejected_basis": True})
            continue
        groups.setdefault((subject, attribute), []).append({
            "value": _norm(row.get("value")),
            "source": _norm(row.get("source")) or "unstated",
            "basis": basis,
            "confidence": BASES[basis],
            "evidence_ids": [_norm(v) for v in (row.get("evidence_ids") or [])],
        })
    findings: list[dict[str, Any]] = []
    for (subject, attribute), rows in sorted(groups.items()):
        values = sorted({row["value"] for row in rows})
        strongest = max(rows, key=lambda row: CONFIDENCE[row["confidence"]])
        entry = {
            "subject": subject,
            "attribute": attribute,
            "status": "CONFLICT" if len(values) > 1 else "AGREE",
            "values": values,
            "sources": len(rows),
            "strongest": strongest["confidence"],
            "resolution": ("UNRESOLVED" if len(values) > 1 else "NOT_NEEDED"),
            "observations": rows,
        }
        if len(values) > 1:
            entry["statement"] = (
                f"{subject} {attribute}: {len(values)} values across {len(rows)} "
                "source(s) — kept as a conflict, because choosing one would hide which "
                "layer disagrees")
        else:
            entry["statement"] = (
                f"{subject} {attribute}: {values[0]} from {len(rows)} source(s); "
                "agreement is not verification")
        findings.append(entry)
    conflicts = [row for row in findings if row["status"] == "CONFLICT"]
    return {
        "schema": SCHEMA,
        "findings": findings,
        "conflicts": conflicts,
        "statement": (f"{len(findings)} reconciled attribute(s), {len(conflicts)} "
                      "in conflict and left unresolved"),
        "not_proven": [
            "which of two conflicting values is deployed: resolving that needs a probe at "
            "the place the value matters, and this module will not pick a winner",
            "that agreement means correctness: several layers reading one import agree "
            "with the import",
        ],
    }


# --------------------------------------------------------------------------- #
# Blast radius
# --------------------------------------------------------------------------- #

def blast_radius(bom: Mapping[str, Any], *, query: Any, include_declared: bool = True,
                 max_hops: int = 8) -> dict[str, Any]:
    """Who depends on this asset or algorithm, and how strongly the path is proven."""
    if not isinstance(bom, Mapping) or bom.get("schema") != SCHEMA:
        raise ValueError(f"blast_radius() takes a {SCHEMA} document")
    text = _norm(query)
    if not text:
        raise ValueError("a blast radius needs something to start from")
    assets = bom.get("by_key") or {}
    seeds = [key for key, row in assets.items()
             if row["name"].lower() == text.lower()
             or row["id"].lower() == text.lower()
             or text.lower() in {str(value).lower()
                                 for value in row["attributes"].values()}
             or row["name"].lower().startswith(text.lower())]
    if not seeds:
        return {"schema": SCHEMA, "query": text, "seeds": [], "reachable": [],
                "impacts": {}, "possible": [], "statement":
                f"nothing in this TechBOM matches {text}"}
    inbound: dict[str, list[dict[str, Any]]] = {}
    for row in bom.get("claims") or []:
        if not include_declared and row["confidence"] not in PROVEN:
            continue
        inbound.setdefault(row["to_key"], []).append(row)
    seen: dict[str, int] = {key: 0 for key in seeds}
    frontier = list(seeds)
    # the seeds are what the question is *about*, so they are not listed as dependents
    proven: set[str] = set()
    possible: set[str] = set()
    used: list[dict[str, Any]] = []
    steps = 0
    while frontier and steps < max_hops:
        steps += 1
        next_frontier: list[str] = []
        for key in frontier:
            for edge in inbound.get(key, []):
                source = edge["from_key"]
                if source in seen:
                    continue
                seen[source] = steps
                used.append(edge)
                # a node reached through an inference is itself only a possibility, and
                # so is everything above it: the model under-claims rather than
                # reporting a declared edge as a proven dependency path.
                if key in possible or edge["confidence"] not in PROVEN:
                    possible.add(source)
                else:
                    proven.add(source)
                next_frontier.append(source)
        frontier = next_frontier
    reachable = sorted(proven, key=lambda key: (assets[key]["kind"], assets[key]["id"]))
    impacts: dict[str, list[str]] = {}
    for key in reachable:
        impacts.setdefault(assets[key]["kind"], []).append(assets[key]["id"])
    systems = impacts.get("BUSINESS_SYSTEM", [])
    crypto = [assets[key] for key in reachable if assets[key]["kind"] == "CRYPTO_ASSET"]
    blockers: list[dict[str, Any]] = []
    for key in [*seeds, *reachable]:
        row = assets[key]
        if row["kind"] in PQC_BLOCKER_KINDS:
            blockers.append({"asset": row["id"], "kind": row["kind"], "name": row["name"],
                             "detail": ("a migration that replaces an algorithm on this "
                                        "path has to change this device or its firmware")})
    sensitive = [{"asset": row["id"], "algorithm": row["name"]}
                 for row in crypto if _quantum_sensitive(row["name"])]
    proven_ids = {assets[k]["id"] for k in proven}
    return {
        "schema": SCHEMA,
        "query": text,
        "seeds": [assets[key]["id"] for key in seeds],
        "reachable": [{"id": assets[key]["id"], "kind": assets[key]["kind"],
                       "name": assets[key]["name"], "hops": seen[key],
                       "proven": assets[key]["id"] in proven_ids}
                      for key in reachable],
        "impacts": {kind: ids for kind, ids in sorted(impacts.items())},
        "systems": systems,
        "network_paths": sorted({row["id"] for row in used
                                 if row["chain"] == "NETWORK"}),
        "crypto_assets": [row["id"] for row in crypto],
        "quantum_sensitive": sensitive,
        "pqc_blockers": blockers,
        "possible": sorted(assets[key]["id"] for key in possible),
        "edges_used": len(used),
        "statement": (
            f"{text}: {len(reachable)} dependent asset(s) across {len(impacts)} kind(s), "
            f"{len(systems)} business system(s), {len(blockers)} migration blocker(s)"
            + (f"; {len(possible)} reachable only through an inference"
               if possible else "")
            + (f"; {len(sensitive)} quantum-sensitive algorithm(s)"
               if sensitive else "")),
        "not_proven": [
            "that a dependency is exclusive: the graph holds the relationships the "
            "sources asserted, and a path nobody recorded is missing, not absent",
            "that a downstream asset is affected in practice: reachability is exposure, "
            "and impact needs the owner's assessment",
        ],
    }


# --------------------------------------------------------------------------- #
# Time — technology version changes, not just asset churn
# --------------------------------------------------------------------------- #

#: how a kind's change is named in the drift feed
CHANGE_BY_KIND: dict[str, str] = {
    "CRYPTO_ASSET": "CRYPTO_CHANGED",
    "CRYPTO_LIBRARY": "CRYPTO_CHANGED",
    "CERTIFICATE": "CERTIFICATE_CHANGED",
    "CERTIFICATE_AUTHORITY": "CERTIFICATE_CHANGED",
    "PUBLIC_KEY": "CERTIFICATE_CHANGED",
    "HSM": "HARDWARE_CHANGED",
    "FIRMWARE": "HARDWARE_CHANGED",
    "PHYSICAL_SERVER": "HARDWARE_CHANGED",
    "HOST": "HARDWARE_CHANGED",
    "VM": "HARDWARE_CHANGED",
    "TPM": "HARDWARE_CHANGED",
    "VENDOR": "VENDOR_CHANGED",
    "VENDOR_PRODUCT": "VENDOR_CHANGED",
    "NETWORK_ENDPOINT": "NETWORK_CHANGED",
    "LOAD_BALANCER": "NETWORK_CHANGED",
    "API_GATEWAY": "NETWORK_CHANGED",
    "DEPLOYMENT": "DEPLOYMENT_CHANGED",
    "POD": "DEPLOYMENT_CHANGED",
    "PROCESS": "DEPLOYMENT_CHANGED",
    "IMAGE": "DEPLOYMENT_CHANGED",
    "PACKAGE": "SBOM_CHANGED",
    "APPLICATION": "SBOM_CHANGED",
    "SERVICE": "SBOM_CHANGED",
    "CONTAINER": "SBOM_CHANGED",
    "SBOM": "SBOM_CHANGED",
    "SOURCE": "SBOM_CHANGED",
    "BUILD": "SBOM_CHANGED",
    "ARTIFACT": "SBOM_CHANGED",
}


def diff(previous: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    """Two TechBOM snapshots → typed change events, including version changes."""
    for name, doc in (("previous", previous), ("current", current)):
        if not isinstance(doc, Mapping) or doc.get("schema") != SCHEMA:
            raise ValueError(f"{name} is not a {SCHEMA} document")
    before = previous.get("by_key") or {}
    after = current.get("by_key") or {}
    events: list[dict[str, Any]] = []

    for key in sorted(set(after) - set(before)):
        row = after[key]
        events.append({"change": "ASSET_ADDED", "category": CHANGE_BY_KIND.get(
            row["kind"], "TECHNOLOGY_CHANGED"), "subject": row["id"], "asset": row["key"],
            "detail": f"{row['name']} {row['version'] or ''}".strip()})
    for key in sorted(set(before) - set(after)):
        row = before[key]
        events.append({"change": "ASSET_REMOVED", "category": CHANGE_BY_KIND.get(
            row["kind"], "TECHNOLOGY_CHANGED"), "subject": row["id"], "asset": row["key"],
            "detail": f"{row['name']} {row['version'] or ''}".strip()})
    for key in sorted(set(before) & set(after)):
        old, new = before[key], after[key]
        if (old.get("version") or "") != (new.get("version") or ""):
            events.append({
                "change": "TECHNOLOGY_VERSION_CHANGED",
                "category": CHANGE_BY_KIND.get(new["kind"], "TECHNOLOGY_CHANGED"),
                "subject": new["id"], "asset": key,
                "detail": f"{new['name']}: {old.get('version') or '(none)'} → "
                          f"{new.get('version') or '(none)'}"})
        changed = sorted(name for name in set(old.get("attributes") or {}) |
                         set(new.get("attributes") or {})
                         if (old.get("attributes") or {}).get(name)
                         != (new.get("attributes") or {}).get(name))
        for name in changed:
            events.append({
                "change": "ATTRIBUTE_CHANGED",
                "category": CHANGE_BY_KIND.get(new["kind"], "TECHNOLOGY_CHANGED"),
                "subject": new["id"], "asset": key, "attribute": name,
                "detail": f"{new['name']}.{name}: "
                          f"{(old.get('attributes') or {}).get(name)} → "
                          f"{(new.get('attributes') or {}).get(name)}"})
        if (old.get("status") or "") != (new.get("status") or ""):
            events.append({"change": "STATUS_CHANGED", "category": "TECHNOLOGY_CHANGED",
                           "subject": new["id"], "asset": key,
                           "detail": f"{new['name']}: {old.get('status')} → "
                                     f"{new.get('status')}"})
    old_edges = {row["id"]: row for row in previous.get("claims") or []}
    new_edges = {row["id"]: row for row in current.get("claims") or []}
    for edge_id in sorted(set(new_edges) - set(old_edges)):
        row = new_edges[edge_id]
        events.append({"change": "RELATIONSHIP_ADDED", "category": "NETWORK_CHANGED"
                       if row["chain"] == "NETWORK" else "TECHNOLOGY_CHANGED",
                       "subject": edge_id,
                       "detail": f"{row['from']} {row['relation']} {row['to']} "
                                 f"({row['confidence']})"})
    for edge_id in sorted(set(old_edges) - set(new_edges)):
        row = old_edges[edge_id]
        events.append({"change": "RELATIONSHIP_REMOVED", "category": "NETWORK_CHANGED"
                       if row["chain"] == "NETWORK" else "TECHNOLOGY_CHANGED",
                       "subject": edge_id,
                       "detail": f"{row['from']} {row['relation']} {row['to']} "
                                 f"({row['confidence']})"})
    by_category: dict[str, int] = {}
    for event in events:
        by_category[event["category"]] = by_category.get(event["category"], 0) + 1
    return {
        "schema": SCHEMA,
        "events": events,
        "by_change": {name: sum(1 for event in events if event["change"] == name)
                      for name in sorted({event["change"] for event in events})},
        "by_category": dict(sorted(by_category.items())),
        "statement": (
            f"{len(events)} change(s) between the two snapshots"
            + (": " + ", ".join(f"{name} {count}" for name, count
                                in sorted(by_category.items())) if by_category else "")
            + ("; nothing moved" if not events else "")),
        "not_proven": [
            "why something changed: a version change is a fact about two snapshots, and "
            "an upgrade, a rollback and a scan error look identical here",
            "that a change is an improvement: 3.0.11 → 3.0.13 is a version change, and "
            "whether it is better is the vulnerability layer's question",
        ],
    }


# --------------------------------------------------------------------------- #
# Projection guard and summary
# --------------------------------------------------------------------------- #

def from_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Always refused: a TechBOM is a projection and cannot be its own source."""
    if isinstance(document, Mapping) and document.get("schema") == SCHEMA:
        raise ValueError(
            "a TechBOM is a projection of the canonical estate, not a source: feeding one "
            "back in would create a second source of truth. Build from the estate instead")
    raise ValueError("build() takes a cryptoscan.techbom-estate/1 document")


def summary(bom: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: what the estate is made of, how well it is known, what is unproven."""
    assets = bom.get("assets") or []
    claims = bom.get("claims") or []
    by_confidence: dict[str, int] = {}
    for row in claims:
        by_confidence[row["confidence"]] = by_confidence.get(row["confidence"], 0) + 1
    completeness_block = bom.get("completeness") or {}
    return {
        "schema": SCHEMA,
        "assets": len(assets),
        "relationships": len(claims),
        "by_kind": bom.get("counts") or {},
        "by_chain": bom.get("claim_counts") or {},
        "by_confidence": dict(sorted(by_confidence.items())),
        "refusals": len(bom.get("refusals") or []),
        "unproven_edges": len(bom.get("unproven_edges") or []),
        "completeness": completeness_block.get("overall"),
        "statement": bom.get("statement", ""),
        "not_proven": list(NOT_PROVEN),
    }
