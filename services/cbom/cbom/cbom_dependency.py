"""The CBOM dependency chain, from a business system down to the vendor.

A CBOM that says *"AES-256-GCM, confidence HIGH"* has collapsed eight different claims
into one line. This module keeps the chain the review draws, and keeps every edge on it
separable:

    BUSINESS SYSTEM → APPLICATION → RELEASE / ARTIFACT → PROCESS / CONTAINER
        → CRYPTO PROVIDER → CRYPTO OPERATION → ALGORITHM
        → KEY METADATA → HSM / KMS → CERTIFICATE / NETWORK → HARDWARE / VENDOR

:mod:`cbom.nbom_graph` already walks the network half of that chain, and
:mod:`cbom.usage_evidence` already classifies the evidence. What is missing is the
*software* half — releases, providers, operations, keys — and the walk that joins the two
without collapsing a hop. That is what this module adds, and it adds no second graph: the
builders return ``part()`` bundles for the same canonical estate, and every query reads the
same projection.

The rules the chain obeys, each of them a refusal rather than a convention:

* **capability is not usage.** A provider that lists AES-128, AES-192, AES-256, RSA and
  ECDSA has told you five things it *can* do. Usage is an ``INVOKES`` from a process to an
  operation somebody watched. :func:`capability_vs_usage` returns the two sets side by
  side and never merges them.
* **a static hit is not an execution.** ``EVP_DigestSignInit`` in a file is
  ``STATIC_OBSERVED``: a dependency a reader can point at, and not something that ran. It
  is not in ``PROVEN``, so it never becomes blast radius on its own.
* **an operation names its parameters.** ``AES-256`` is a name; ``ENCRYPT / AES / 256 /
  GCM`` is a dependency. The same goes for ``SIGN / RSA / 2048 / PSS / SHA-256``.
* **a key is a reference.** The key record carries a reference, size, purpose and holder,
  and :func:`cbom.nbom_graph.key_reference` refuses anything that looks like material.
* **a certificate is not the application's crypto.** The certificate chain hangs off a
  listener; the application's signing hangs off a process. They share a graph and never
  share an edge.
* **a hop is a hop.** Four hops of TLS and one signing operation are five facts, and
  :func:`crypto_hops` returns them as HOP 1..N rather than one attribute.
* **disagreement is data.** When the SBOM says 3.0.13 and the process says 3.0.11, that is
  ``CRYPTO_DEPENDENCY_CONFLICT`` with both sources kept, not a chosen value.
* **a change is a change.** A dependency that moved from RSA-2048 to RSA-3072 is
  ``CRYPTO_DEPENDENCY_CHANGED`` with the evidence before and after, not an overwrite.
* **a blocker is on the path.** RSA-2048 does not block a migration; the load balancer
  that terminates it, the HSM that holds the key and the firmware that cannot do ML-KEM
  do, and :func:`pqc_blockers` names them hop by hop.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any

from . import techbom as tb
from .nbom_graph import _resolve_one, edge_record, part

SCHEMA = "cryptoscan.cbom-dependency/1"

#: the levels of the chain the review draws, in the order it draws them.
CHAIN_LEVELS: tuple[tuple[str, str], ...] = (
    ("BUSINESS_SYSTEM", "system"),
    ("APPLICATION", "application"),
    ("RELEASE", "release"),
    ("PROCESS", "process"),
    ("CRYPTO_PROVIDER", "provider"),
    ("CRYPTO_OPERATION", "operation"),
    ("ALGORITHM", "algorithm"),
    ("KEY_REFERENCE", "key"),
    ("HSM", "key_provider"),
    ("CERTIFICATE", "certificate"),
    ("NETWORK_ENDPOINT", "endpoint"),
    ("VENDOR", "vendor"),
)

#: the kinds that fill each level. A level is a bucket, not one kind: "process" is where a
#: workload runs, which is a process, a container, a pod, a deployment or a namespace.
LEVEL_KINDS: dict[str, tuple[str, ...]] = {
    "system": ("BUSINESS_SYSTEM",),
    "application": ("APPLICATION",),
    "release": ("RELEASE", "ARTIFACT", "IMAGE", "BUILD", "SBOM"),
    "process": ("PROCESS", "CONTAINER", "POD", "DEPLOYMENT", "NAMESPACE", "CLUSTER",
                "SERVICE"),
    "provider": ("CRYPTO_PROVIDER", "CRYPTO_LIBRARY"),
    "operation": ("CRYPTO_OPERATION",),
    "algorithm": ("ALGORITHM", "CRYPTO_ASSET", "CIPHER_SUITE", "CRYPTO_CAPABILITY"),
    "key": ("KEY_REFERENCE",),
    "key_provider": ("HSM", "KMS", "TPM"),
    "certificate": ("CERTIFICATE", "CERTIFICATE_AUTHORITY", "PUBLIC_KEY"),
    "endpoint": ("NETWORK_ENDPOINT", "WAF", "LOAD_BALANCER", "API_GATEWAY", "SERVICE_MESH"),
    "hardware": ("PHYSICAL_SERVER", "HOST", "VM", "KUBERNETES_NODE", "CLOUD_INSTANCE",
                 "FIRMWARE", "CRYPTO_ACCELERATOR", "BIOS", "OS", "TPM"),
    "vendor": ("VENDOR", "VENDOR_PRODUCT"),
}

#: the relations the chain is walked along. A whitelist, on purpose: an edge that is not
#: here is a fact about the estate, but it is not a dependency, and a walk that follows it
#: would answer a question nobody asked.
CHAIN_RELATIONS: tuple[str, ...] = (
    "CONTAINS", "OWNS", "PROVIDES", "RELEASED_AS", "BUNDLES", "PACKAGED_AS", "SHIPS",
    "LINKS", "DESCRIBED_BY", "DEPLOYED_AS", "SCHEDULES", "FROM_IMAGE", "RUNS_IN",
    "RUNS_CONTAINER", "RUNS_PROCESS", "RUNS_APPLICATION", "RUNS", "MEMBER_OF_CLUSTER",
    "SCHEDULED_ON", "RUNS_ON", "LOADS", "IMPLEMENTS", "DECLARES", "INVOKES",
    "USES_CRYPTO", "USES_ALGORITHM", "USES_KEY", "USES_HSM", "USES_KMS", "USES_TPM",
    "BACKED_BY", "HAS_MODEL", "SUPPLIED_BY", "RUNS_FIRMWARE", "HOLDS_KEY",
    "USES_CERTIFICATE", "PRESENTS", "CONTAINS_KEY", "SIGNED_WITH", "ISSUED_BY",
    "SIGNED_BY", "NEGOTIATES", "LISTENS_ON", "EXPOSES", "ROUTES_TO", "FORWARDS_TO",
    "TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH", "FRONTED_BY", "PROTECTED_BY",
    "HAS_VULNERABILITY", "AFFECTS",
)

#: relations whose arrow points at the *dependent* rather than the dependency: a host
#: ``RUNS`` an application, so the application's dependency on the host is walked backwards.
#: ``PROVIDES`` is not here — an application *provides* a service and depends on it, which
#: is the same direction as the arrow.
REVERSE_RELATIONS: frozenset[str] = frozenset({"RUNS", "RUNS_APPLICATION", "RUNS_PROCESS",
                                               "RUNS_CONTAINER"})

#: the classes that mean "this is what the thing does". Everything else — capability,
#: import, vendor declaration, inference — is a statement about the thing.
USAGE_CLASSES: frozenset[str] = frozenset({tb.OBSERVED, tb.RUNTIME_OBSERVED,
                                           tb.NETWORK_OBSERVED, tb.STATIC_OBSERVED,
                                           tb.CONFIGURED})

#: layers a usage claim can come from, strongest first.
USAGE_LAYERS: tuple[tuple[str, str], ...] = (
    ("network", tb.NETWORK_OBSERVED),
    ("runtime", tb.RUNTIME_OBSERVED),
    ("static", tb.STATIC_OBSERVED),
    ("config", tb.CONFIGURED),
)

#: the parameters an operation is expected to name (cbom 4, 6). A block cipher without a
#: mode and a signature without a size are refused, because neither can be migrated from.
OPERATION_PARAMETERS: tuple[str, ...] = ("operation", "algorithm", "key_size", "mode",
                                         "padding", "hash", "curve", "purpose", "provider")

OPERATIONS: tuple[str, ...] = ("ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "KEY_AGREEMENT",
                               "KEY_WRAP", "KEY_UNWRAP", "HASH", "MAC", "KDF",
                               "RANDOM", "GENERATE_KEY")

#: provider families, closed. A bank's vulnerability feed groups by provider, so a
#: free-text provider name is a join that silently fails (cbom 5).
PROVIDER_FAMILIES: tuple[str, ...] = (
    "OPENSSL", "LIBRESSL", "BORINGSSL", "OPENSSL_FIPS", "JCE", "CNG", "SCHANNEL",
    "PKCS11", "GO", "RUSTCRYPTO", "NODEJS", "WOLFSSL", "MBEDTLS", "VENDOR_SDK", "KERNEL",
    "OTHER",
)

#: what a KMS answer can be, weakest to strongest (cbom 9). A KMS that *supports* RSA has
#: told you nothing about whether an application uses it.
KMS_STATES: tuple[str, ...] = ("SUPPORTED", "CONFIGURED", "REFERENCED", "ACTUALLY_USED")

#: relation -> the KMS class its basis can support. Anything below ``ACTUALLY_USED`` is
#: reported as what it is.
KMS_STATE_BY_BASIS: dict[str, str] = {
    "vendor-datasheet": "SUPPORTED", "capability-list": "SUPPORTED",
    "config-parse": "CONFIGURED", "api-poll": "CONFIGURED",
    "agent-inventory": "REFERENCED", "deployment-metadata": "REFERENCED",
    "runtime-probe": "ACTUALLY_USED", "runtime-observation": "ACTUALLY_USED",
    "process-trace": "ACTUALLY_USED", "packet-capture": "ACTUALLY_USED",
}


# --------------------------------------------------------------------------- #
# Builders: the levels the network projection does not build
# --------------------------------------------------------------------------- #

def application_release(*, application_row: Mapping[str, Any],
                        release_row: Mapping[str, Any],
                        artifacts: Iterable[Mapping[str, Any]] = (),
                        basis: Any = "agent-inventory",
                        evidence_ids: Iterable[Any] | None = None,
                        **facts: Any) -> dict[str, Any]:
    """``application → RELEASED_AS → release → BUNDLES → artifact`` (cbom 2, 23).

    A release is the level a change record names, so "RSA-2048 is used" and "the version
    deployed on Tuesday is 2.4.1" are statements about different nodes and can be kept
    apart. An application with no release is an application whose artifact is *unknown*,
    which is a gap, not an absence.
    """
    rows = list(artifacts)
    claims = [tb.claim(application_row["name"], "RELEASED_AS", release_row["name"],
                       basis=basis, evidence_ids=evidence_ids, **facts)]
    claims.extend(tb.claim(release_row["name"], "BUNDLES", row["name"], basis=basis,
                           evidence_ids=evidence_ids, **facts) for row in rows)
    return part(application_row, release_row, *rows, claims=claims)


def deployment(*, image_row: Mapping[str, Any], deployment_row: Mapping[str, Any],
               pods: Iterable[Mapping[str, Any]] = (),
               containers: Iterable[Mapping[str, Any]] = (),
               namespace_row: Mapping[str, Any] | None = None,
               cluster_row: Mapping[str, Any] | None = None,
               node_row: Mapping[str, Any] | None = None,
               basis: Any = "deployment-metadata",
               evidence_ids: Iterable[Any] | None = None,
               **facts: Any) -> dict[str, Any]:
    """``image → DEPLOYED_AS → deployment → SCHEDULES → pod → container → namespace``.

    The Kubernetes walk of cbom 16/17, stopping where the platform can see: a cluster the
    estate knows nothing about is reported as a cluster and not invented as a node. Each
    edge carries its own basis, because "the image exists" and "the pod ran" are different
    observations even when they come from the same API.
    """
    pod_rows = list(pods)
    container_rows = list(containers)
    claims = [tb.claim(image_row["name"], "DEPLOYED_AS", deployment_row["name"],
                       basis=basis, evidence_ids=evidence_ids, **facts)]
    for pod in pod_rows:
        claims.append(tb.claim(deployment_row["name"], "SCHEDULES", pod["name"],
                               basis=basis, evidence_ids=evidence_ids, **facts))
        for container in container_rows:
            claims.append(tb.claim(pod["name"], "RUNS_CONTAINER", container["name"],
                                   basis=basis, evidence_ids=evidence_ids, **facts))
    for container in container_rows:
        claims.append(tb.claim(container["name"], "FROM_IMAGE", image_row["name"],
                               basis=basis, evidence_ids=evidence_ids, **facts))
    if namespace_row is not None:
        claims.append(tb.claim(deployment_row["name"], "RUNS_IN", namespace_row["name"],
                               basis=basis, evidence_ids=evidence_ids, **facts))
    if cluster_row is not None and namespace_row is not None:
        claims.append(tb.claim(namespace_row["name"], "MEMBER_OF_CLUSTER",
                               cluster_row["name"], basis=basis,
                               evidence_ids=evidence_ids, **facts))
    if node_row is not None:
        for pod in pod_rows:
            claims.append(tb.claim(pod["name"], "SCHEDULED_ON", node_row["name"],
                                   basis=basis, evidence_ids=evidence_ids, **facts))
    return part(image_row, deployment_row, *pod_rows, *container_rows, namespace_row,
                cluster_row, node_row, claims=claims)


def provider(*, name: Any, family: Any, version: Any = None,
             library_row: Mapping[str, Any] | None = None,
             file_name: Any = None, vendor: Any = None,
             supports: Iterable[Mapping[str, Any]] = (),
             capabilities: Iterable[Mapping[str, Any]] = (),
             process_row: Mapping[str, Any] | None = None,
             provider_row: Mapping[str, Any] | None = None,
             basis: Any = "runtime-probe",
             evidence_ids: Iterable[Any] | None = None,
             **attributes: Any) -> dict[str, Any]:
    """``process → LOADS → provider → SUPPORTS / IMPLEMENTS → algorithm`` (cbom 5).

    The provider is the node a vulnerability feed names — ``OpenSSL 3.0.11``,
    ``BoringSSL``, ``JCE``, ``.NET CNG``, ``PKCS#11``, ``Go crypto/tls``,
    ``RustCrypto``, a vendor SDK.

    Capabilities are **nodes** (:func:`capability`), not a list on the provider, because
    ``SUPPORTS`` is a different statement from ``IMPLEMENTS``: a capability says *this
    provider lists AES-256-GCM*, and the ``IMPLEMENTS`` edge off it says *and here is the
    algorithm that means*. Five capabilities and one observed operation then reads as five
    capability nodes and one usage, which is the arithmetic the review asks for.

    ``supports`` keeps the shorter form — a provider pointing straight at an algorithm —
    for an estate that has no capability rows yet. ``process_row`` is ``LOADS``, because
    that is the strongest thing a runtime probe can say about a library: this process has
    it mapped.
    """
    family_text = str(family or "").strip().upper().replace(" ", "_").replace("-", "_")
    if family_text not in PROVIDER_FAMILIES:
        raise tb.ClaimRefused(
            "UNKNOWN_PROVIDER_FAMILY",
            f"{family or '(none)'} is not a crypto provider family; expected one of "
            f"{', '.join(PROVIDER_FAMILIES)}")
    row = provider_row if provider_row is not None else tb.asset(
        "CRYPTO_PROVIDER", name, version=version, evidence_ids=evidence_ids,
        family=family_text, provider_file=file_name, vendor=vendor,
        library=library_row["name"] if library_row else None, **attributes)
    if row["name"] != tb._norm(name):
        raise tb.ClaimRefused(
            "PROVIDER_ROW_MISMATCH",
            f"the row given for {row['name']} was offered as {name}; a provider is one "
            "identity, and a rename here would silently split its capabilities")
    assets: list[Mapping[str, Any]] = [row]
    claims: list[dict[str, Any]] = []
    if library_row is not None:
        assets.append(library_row)
    for algorithm_row in supports:
        assets.append(algorithm_row)
        claims.append(tb.claim(name, "SUPPORTS", algorithm_row["name"],
                               basis="capability-list", evidence_ids=evidence_ids))
        claims.append(tb.claim(name, "IMPLEMENTS", algorithm_row["name"], basis=basis,
                               evidence_ids=evidence_ids))
    for capability_row in capabilities:
        assets.append(capability_row)
        claims.append(tb.claim(name, "SUPPORTS", capability_row["name"],
                               basis="capability-list", evidence_ids=evidence_ids))
    if process_row is not None:
        assets.append(process_row)
        claims.append(tb.claim(process_row["name"], "LOADS", name, basis=basis,
                               evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


def capability(*, provider_row: Mapping[str, Any], algorithm_row: Mapping[str, Any],
               key_size: Any = None, mode: Any = None, purpose: Any = None,
               basis: Any = "capability-list",
               evidence_ids: Iterable[Any] | None = None,
               **attributes: Any) -> dict[str, Any]:
    """``provider → SUPPORTS → capability → IMPLEMENTS → algorithm`` (cbom 2, 20).

    The capability is the unit a datasheet actually states: *this provider can do AES-256
    in GCM mode*, and separately *that AES-256 is this algorithm node*. Keeping the two
    apart is what lets :func:`capability_vs_usage` subtract usage from capability and get
    an answer rather than a guess.

    The capability is named ``provider:algorithm`` so that a graph with two providers, or
    one algorithm listed at two sizes, never has to guess which statement a name refers
    to.
    """
    label = f"{provider_row['name']}:{algorithm_row['name']}"
    row = tb.asset("CRYPTO_CAPABILITY", label, evidence_ids=evidence_ids,
                   algorithm=algorithm_row["name"], key_size=key_size, mode=mode,
                   purpose=purpose, provider=provider_row["name"], **attributes)
    return part(provider_row, algorithm_row, row, claims=[
        tb.claim(provider_row["name"], "SUPPORTS", label, basis=basis,
                 evidence_ids=evidence_ids),
        tb.claim(label, "IMPLEMENTS", algorithm_row["name"], basis=basis,
                 evidence_ids=evidence_ids),
    ])


def _require_parameters(operation_text: str, facts: Mapping[str, Any]) -> None:
    if facts.get("algorithm") in (None, ""):
        raise tb.ClaimRefused(
            "OPERATION_WITHOUT_ALGORITHM",
            "an operation without an algorithm is a verb; the chain stops here")
    family = str(facts.get("algorithm_family") or facts.get("algorithm")).upper()
    if operation_text in ("ENCRYPT", "DECRYPT") and family in ("AES", "SM4", "CAMELLIA",
                                                              "ARIA", "3DES", "DES") \
            and not facts.get("mode"):
        raise tb.ClaimRefused(
            "BLOCK_CIPHER_WITHOUT_MODE",
            f"{facts['algorithm']} is a block cipher and the operation names no mode; "
            "AES without GCM/CBC/CTR is not a dependency anyone can migrate")
    if operation_text in ("SIGN", "VERIFY") and family in ("RSA", "ECDSA", "ED25519",
                                                          "DSA", "SM2") \
            and not facts.get("key_size") and not facts.get("curve"):
        raise tb.ClaimRefused(
            "SIGNATURE_WITHOUT_SIZE",
            f"{facts['algorithm']} signing with no key size or curve is a name, not a "
            "dependency: RSA-2048 and RSA-3072 are different migrations")


def runtime_operation(*, name: Any, process_row: Mapping[str, Any],
                      operation: Any, algorithm_row: Mapping[str, Any],
                      application_row: Mapping[str, Any] | None = None,
                      provider_row: Mapping[str, Any] | None = None,
                      key_row: Mapping[str, Any] | None = None,
                      key_size: Any = None, mode: Any = None, padding: Any = None,
                      hash_name: Any = None, curve: Any = None, purpose: Any = None,
                      parameters: Mapping[str, Any] | None = None,
                      basis: Any = "runtime-observation",
                      observed_at: Any = None, first_seen: Any = None,
                      last_seen: Any = None,
                      evidence_ids: Iterable[Any] | None = None,
                      **extra: Any) -> dict[str, Any]:
    """``process → INVOKES → operation → algorithm / key / provider`` (cbom 4, 6).

    The operation is the only node that can say *what was actually done*:
    ``SIGN / RSA / 2048 / PSS / SHA-256``, ``ENCRYPT / AES / 256 / GCM``. It hangs off a
    *process*, not off the application, because that is what a runtime observation is: this
    PID invoked this function with this key at this instant.

    ``extra`` may carry anything the probe knows, but the fields in
    :data:`OPERATION_PARAMETERS` are the ones a reader can rely on — and the ones the
    migration engine reads.
    """
    operation_text = str(operation or "").strip().upper()
    if operation_text not in OPERATIONS:
        raise tb.ClaimRefused(
            "UNKNOWN_OPERATION",
            f"{operation or '(none)'} is not a crypto operation this model names; "
            f"expected one of {', '.join(OPERATIONS)}")
    facts: dict[str, Any] = {**(parameters or {})}
    family = (algorithm_row.get("attributes") or {}).get("family")
    for field, value in (("algorithm", algorithm_row["name"]),
                         ("algorithm_family", family), ("key_size", key_size),
                         ("mode", mode), ("padding", padding), ("hash", hash_name),
                         ("curve", curve), ("purpose", purpose),
                         ("provider", provider_row["name"] if provider_row else None)):
        if value not in (None, ""):
            facts[field] = value
    facts["operation"] = operation_text
    _require_parameters(operation_text, facts)
    row = tb.asset("CRYPTO_OPERATION", name, evidence_ids=evidence_ids, **facts)
    assets: list[Mapping[str, Any]] = [row, process_row, algorithm_row]
    stamp = {"observed_at": observed_at, "first_seen": first_seen,
             "last_seen": last_seen}
    claims = [
        tb.claim(process_row["name"], "INVOKES", name, basis=basis,
                 evidence_ids=evidence_ids, operation=operation_text, **stamp),
        tb.claim(name, "USES_ALGORITHM", algorithm_row["name"], basis=basis,
                 evidence_ids=evidence_ids, operation=operation_text, **stamp),
    ]
    if application_row is not None:
        assets.append(application_row)
        claims.append(tb.claim(process_row["name"], "RUNS_APPLICATION",
                               application_row["name"], basis=basis,
                               evidence_ids=evidence_ids, pid=extra.get("pid")))
    if provider_row is not None:
        # IMPLEMENTS belongs to the provider and to one basis: a second copy here would
        # report the same implementation twice at two different classes
        assets.append(provider_row)
        claims.append(tb.claim(process_row["name"], "LOADS", provider_row["name"],
                               basis=basis, evidence_ids=evidence_ids))
    if key_row is not None:
        assets.append(key_row)
        claims.append(tb.claim(name, "USES_KEY", key_row["name"], basis=basis,
                               evidence_ids=evidence_ids, operation=operation_text))
        if provider_row is not None and provider_row.get("kind") in ("HSM", "KMS", "TPM"):
            # the operation *ran at* the holder: this is the claim that separates "the
            # HSM supports RSA" from "the application used the HSM for RSA" (cbom 8)
            claims.append(tb.claim(name, "BACKED_BY", provider_row["name"], basis=basis,
                                   evidence_ids=evidence_ids, operation=operation_text))
    return part(*assets, claims=claims)


def key_binding(*, operation_row: Mapping[str, Any], key_row: Mapping[str, Any],
                holder_row: Mapping[str, Any] | None = None,
                basis: Any = "api-poll",
                evidence_ids: Iterable[Any] | None = None) -> dict[str, Any]:
    """``operation → USES_KEY → key ← HOLDS_KEY ← HSM/KMS/TPM`` (cbom 7, 8, 9).

    Two claims, deliberately separate: the operation *uses* a key, and the holder *holds*
    it. ``BACKED_BY`` is added only when the operation ran at the holder, which is the
    difference between "the HSM supports RSA" and "the application used the HSM for RSA".

    Only metadata crosses this edge. :func:`cbom.nbom_graph.key_reference` refuses
    material, so a key record is a reference, its algorithm, its size, its purpose and its
    holder — never the key.
    """
    assets: list[Mapping[str, Any]] = [operation_row, key_row]
    claims = [tb.claim(operation_row["name"], "USES_KEY", key_row["name"], basis=basis,
                       evidence_ids=evidence_ids)]
    if holder_row is not None:
        if holder_row.get("kind") not in ("HSM", "KMS", "TPM"):
            raise tb.ClaimRefused(
                "NOT_A_KEY_PROVIDER",
                f"{holder_row.get('name')} ({holder_row.get('kind')}) is not a key "
                "provider; an application that holds its own key is a different claim")
        assets.append(holder_row)
        claims.append(tb.claim(holder_row["name"], "HOLDS_KEY", key_row["name"],
                               basis=basis, evidence_ids=evidence_ids))
        claims.append(tb.claim(operation_row["name"], "BACKED_BY", holder_row["name"],
                               basis=basis, evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


def static_dependency(*, application_row: Mapping[str, Any], source_file: Any,
                      api: Any, algorithm_row: Mapping[str, Any], line: Any = None,
                      basis: Any = "source-analysis",
                      evidence_ids: Iterable[Any] | None = None,
                      observed_at: Any = None, first_seen: Any = None,
                      last_seen: Any = None,
                      **attributes: Any) -> dict[str, Any]:
    """``application → USES_CRYPTO → source file → DECLARES → crypto call → algorithm``.

    The review's third point, and the reason ``STATIC_OBSERVED`` exists. The dependency is
    real — somebody can open the file and point at the line — and it is not an execution.
    ``STATIC_OBSERVED`` is deliberately absent from ``PROVEN``, so a code hit never becomes
    blast radius on its own; it is a dependency a migration has to plan for, not one that
    has been observed happening.

    The file is a node because an evidence id cannot name a line, and the call is a
    ``CRYPTO_ASSET`` because that is the kind a source file may declare.
    """
    if basis not in tb.BASES or tb.BASES[basis] != tb.STATIC_OBSERVED:
        raise tb.ClaimRefused(
            "NOT_STATIC_EVIDENCE",
            f"{basis} is not a static-analysis basis; a source hit is STATIC_OBSERVED and "
            "is never promoted by naming it something else")
    file_row = tb.asset("SOURCE", source_file, evidence_ids=evidence_ids,
                        evidence_type=tb.STATIC_OBSERVED, **attributes)
    call_row = tb.asset("CRYPTO_ASSET", f"{source_file}:{api}", evidence_ids=evidence_ids,
                        api=str(api), file=str(source_file), line=line,
                        evidence_type=tb.STATIC_OBSERVED, **attributes)
    stamp = {"observed_at": observed_at, "first_seen": first_seen,
             "last_seen": last_seen}
    return part(application_row, file_row, call_row, algorithm_row, claims=[
        tb.claim(application_row["name"], "USES_CRYPTO", call_row["name"], basis=basis,
                 evidence_ids=evidence_ids, file=str(source_file), line=line, **stamp),
        tb.claim(file_row["name"], "DECLARES", call_row["name"], basis=basis,
                 evidence_ids=evidence_ids, line=line, **stamp),
        tb.claim(call_row["name"], "USES_ALGORITHM", algorithm_row["name"], basis=basis,
                 evidence_ids=evidence_ids, line=line, **stamp),
    ])


def network_binding(*, endpoint_row: Mapping[str, Any], suite_row: Mapping[str, Any],
                    parts: Mapping[str, Mapping[str, Any]] | Iterable[Mapping[str, Any]] = (),
                    certificate_row: Mapping[str, Any] | None = None,
                    application_row: Mapping[str, Any] | None = None,
                    basis: Any = "tls-handshake", observed_at: Any = None,
                    evidence_ids: Iterable[Any] | None = None) -> dict[str, Any]:
    """``application → EXPOSES → endpoint → NEGOTIATES → suite → USES_CRYPTO → parts``.

    The suite is decomposed, because ``TLS_AES_256_GCM_SHA384`` is four crypto
    dependencies wearing one name. A certificate presented here belongs to the *listener*
    and is never joined to the application's own signing, which is the fourth rule.
    """
    role_rows: list[Mapping[str, Any]] = list(parts.values()) if isinstance(parts, Mapping) \
        else list(parts)
    claims = [tb.claim(endpoint_row["name"], "NEGOTIATES", suite_row["name"],
                       basis=basis, evidence_ids=evidence_ids, observed_at=observed_at,
                       protocol="TLS")]
    for role_row in role_rows:
        claims.append(tb.claim(suite_row["name"], "USES_CRYPTO", role_row["name"],
                               basis=basis, evidence_ids=evidence_ids,
                               role=(parts.get(role_row["name"]) if isinstance(parts, Mapping)
                                     else None)))
    assets: list[Mapping[str, Any]] = [endpoint_row, suite_row, *role_rows]
    if certificate_row is not None:
        assets.append(certificate_row)
        claims.append(tb.claim(endpoint_row["name"], "PRESENTS", certificate_row["name"],
                               basis=basis, evidence_ids=evidence_ids,
                               observed_at=observed_at))
    if application_row is not None:
        assets.append(application_row)
        claims.append(tb.claim(application_row["name"], "EXPOSES", endpoint_row["name"],
                               basis="deployment-metadata", evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


def vendor_chain(*, device_row: Mapping[str, Any], vendor_row: Mapping[str, Any],
                 firmware_row: Mapping[str, Any] | None = None,
                 product_row: Mapping[str, Any] | None = None,
                 basis: Any = "api-poll",
                 datasheet_basis: Any = "vendor-datasheet",
                 evidence_ids: Iterable[Any] | None = None,
                 **facts: Any) -> dict[str, Any]:
    """``device → SUPPLIED_BY → vendor`` and ``device → RUNS_FIRMWARE → firmware`` (cbom 14).

    A vendor firmware advisory names a *vendor* and a *version*. It maps to assets only if
    the assets carry both: the device is supplied by that vendor, and the firmware it runs
    is a node with a version on it. A device whose firmware is unknown is the gap a
    firmware audit exists to close, and it is reported as unknown rather than assumed
    patched.
    """
    claims = [tb.claim(device_row["name"], "SUPPLIED_BY", vendor_row["name"], basis=basis,
                       evidence_ids=evidence_ids, **facts)]
    assets: list[Mapping[str, Any]] = [device_row, vendor_row]
    if firmware_row is not None:
        assets.append(firmware_row)
        claims.append(tb.claim(device_row["name"], "RUNS_FIRMWARE", firmware_row["name"],
                               basis=basis, evidence_ids=evidence_ids, **facts))
    if product_row is not None:
        assets.append(product_row)
        claims.append(tb.claim(device_row["name"], "HAS_MODEL", product_row["name"],
                               basis=datasheet_basis, evidence_ids=evidence_ids))
        claims.append(tb.claim(product_row["name"], "SUPPLIED_BY", vendor_row["name"],
                               basis=datasheet_basis, evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


# --------------------------------------------------------------------------- #
# Queries: the chain, in both directions and at full length
# --------------------------------------------------------------------------- #

def levels(bom: Mapping[str, Any]) -> dict[str, Any]:
    """How many nodes sit at each level — the shape of the chain, not its content."""
    counts: dict[str, int] = {}
    for _, name in CHAIN_LEVELS:
        counts[name] = sum(1 for row in bom["assets"] if row["kind"] in LEVEL_KINDS[name])
    counts["hardware"] = sum(1 for row in bom["assets"]
                             if row["kind"] in LEVEL_KINDS["hardware"])
    return counts


def chain(bom: Mapping[str, Any], *, query: Any, max_depth: int = 8) -> dict[str, Any]:
    """The dependency chain around one node, walked down and up.

    *Down* is "what this depends on" — application → release → process → provider →
    operation → algorithm → key → HSM → certificate/network → hardware → vendor. *Up* is
    "what depends on this", which is the direction a bank asks in when it says *which
    business systems depend on RSA-2048*.

    A walk stops where the estate stops. A level with no rows is reported as empty, because
    a gap in the chain is a finding and filling it with an inference is how a chain starts
    to lie.
    """
    start = _resolve_one(bom, query)
    down = _walk(bom, start, max_depth=max_depth)
    up = _walk(bom, start, max_depth=max_depth, reverse=True)
    return {
        "query": str(query),
        "node": _brief(bom["by_key"][start]),
        "down": down["levels"],
        "up": up["levels"],
        "edges": down["edges"],
        "statement": (f"{bom['by_key'][start]['name']}: down {down['statement']}; "
                      f"up {up['statement']}"),
        "not_proven": ["that every level exists: a chain stops where the estate stops, and "
                       "an empty level is reported as a gap rather than filled with a guess"],
    }


def _walk(bom: Mapping[str, Any], start: str, *, max_depth: int,
          reverse: bool = False) -> dict[str, Any]:
    buckets: dict[str, dict[str, dict[str, Any]]] = {}
    edges: list[dict[str, Any]] = []
    seen: set[str] = {start}
    frontier: list[tuple[str, int]] = [(start, 0)]
    while frontier:
        key, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["relation"] not in CHAIN_RELATIONS:
                continue
            dependent, dependency = _sides(claim)
            if not reverse and dependent != key:
                continue
            if reverse and dependency != key:
                continue
            neighbour = dependency if not reverse else dependent
            if neighbour in seen or neighbour not in bom["by_key"]:
                continue
            seen.add(neighbour)
            row = bom["by_key"][neighbour]
            bucket = _bucket(row["kind"])
            if bucket:
                buckets.setdefault(bucket, {})[neighbour] = {
                    **_brief(row), "class": claim["confidence"],
                    "relation": claim["relation"],
                    "evidence_id": (claim.get("evidence_ids") or [None])[0]}
                edges.append({"source": claim["from"], "relationship": claim["relation"],
                              "target": claim["to"], "class": claim["confidence"],
                              "basis": claim["basis"], "evidence_id":
                              (claim.get("evidence_ids") or [None])[0]})
            frontier.append((neighbour, depth + 1))
    ordered = {name: sorted(rows.values(), key=lambda item: item["id"] or item["key"])
               for _, name in CHAIN_LEVELS if (rows := buckets.get(name))}
    return {
        "levels": ordered,
        "edges": sorted(edges, key=lambda row: (row["relationship"], row["source"],
                                                row["target"])),
        "statement": " → ".join(f"{len(rows)} {name}" for name, rows in ordered.items())
        or "nothing",
    }


def _sides(claim: Mapping[str, Any]) -> tuple[str, str]:
    """(dependent, dependency), read off the arrow and corrected where it points the other way."""
    if claim["relation"] in REVERSE_RELATIONS:
        return claim["to_key"], claim["from_key"]
    return claim["from_key"], claim["to_key"]


def _bucket(kind: str) -> str | None:
    for bucket, kinds in LEVEL_KINDS.items():
        if kind in kinds:
            return bucket
    return None


def _brief(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"key": row["key"], "id": row.get("id"), "kind": row["kind"],
            "name": row["name"], "attributes": dict(row.get("attributes") or {})}


def capability_vs_usage(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """The two sets the review says must never be merged (cbom 1, 5, 20).

    *Capability* is what a provider lists. *Usage* is an operation with a class of its own.
    A provider with five capabilities and one observed operation has five capabilities and
    one usage; a report that says "uses AES-128" because AES-128 was on the list is wrong
    by construction, and this function exists so that no caller has to remember it.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    # a capability node names a statement; the algorithms it implements are what the two
    # sets can be compared on. Both are reported: nodes for a reader, algorithms for the
    # arithmetic.
    nodes: dict[str, set[str]] = {}
    for claim in bom["claims"]:
        if claim["from_key"] != key or claim["relation"] != "SUPPORTS":
            continue
        target = bom["by_key"][claim["to_key"]]
        if target["kind"] == "CRYPTO_CAPABILITY":
            implementations = {bom["by_key"][inner["to_key"]]["name"]
                               for inner in bom["claims"]
                               if inner["from_key"] == target["key"]
                               and inner["relation"] == "IMPLEMENTS"}
            nodes[target["name"]] = implementations or {target["name"]}
        else:
            nodes[target["name"]] = {target["name"]}
    capabilities = sorted({name for names in nodes.values() for name in names})
    used: dict[str, set[str]] = {}
    for claim in bom["claims"]:
        if claim["relation"] != "USES_ALGORITHM":
            continue
        source = bom["by_key"][claim["from_key"]]
        if source["kind"] == "CRYPTO_OPERATION":
            provider = (source["attributes"] or {}).get("provider")
            if provider and provider != row["name"]:
                continue
            if not provider and not any(other["relation"] == "INVOKES"
                                        and other["to_key"] == claim["from_key"]
                                        for other in bom["claims"]):
                continue
        elif claim["from_key"] != key:
            continue
        used.setdefault(bom["by_key"][claim["to_key"]]["name"], set()).add(
            claim["confidence"])
    layers = sorted({layer for classes in used.values() for layer, klass in USAGE_LAYERS
                     if klass in classes})
    unused = sorted(set(capabilities) - set(used))
    unlisted = sorted(set(used) - set(capabilities))
    return {
        "provider": row["name"],
        "capability": capabilities,
        "capability_nodes": {name: sorted(names) for name, names in sorted(nodes.items())},
        "usage": {name: sorted(classes) for name, classes in sorted(used.items())},
        "capability_not_used": unused,
        "used_not_capable": unlisted,
        "layers": layers,
        "statement": (f"{row['name']}: {len(capabilities)} capability(ies), "
                      f"{len(used)} observed use(s) from {len(layers)} layer(s)"
                      + (f", {len(unused)} listed and never used" if unused else "")
                      + (f", {len(unlisted)} used without being listed" if unlisted else "")),
        "rule": ("a capability is what the provider says it can do; usage is an operation "
                 "with an evidence class, and one never becomes the other"),
    }


def crypto_hops(hops: Iterable[Mapping[str, Any]], *,
                final_operation: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The multi-hop dependency, one row per hop (cbom 12).

    ``client → LB (TLS1.3, AES-256-GCM)``, ``LB → gateway (TLS1.2, AES-128-GCM)``,
    ``gateway → mesh (mTLS, AES-256-GCM)``, ``application → HSM (RSA-2048 PSS signing)``.
    Collapsing that into "the application uses AES-256" is how a migration plan misses the
    legacy hop that actually blocks it.
    """
    rows: list[dict[str, Any]] = []
    for index, hop in enumerate(hops, start=1):
        missing = [field for field in ("source", "target") if not hop.get(field)]
        if missing:
            raise tb.ClaimRefused(
                "HOP_WITHOUT_FACTS",
                f"hop {index} does not name {', '.join(missing)}; a hop is a fact about one "
                "boundary, and an unnamed boundary is a gap in the path")
        rows.append({
            "hop": index, "source": str(hop["source"]), "target": str(hop["target"]),
            "mode": str(hop.get("mode") or "TLS").upper(),
            "tls_version": hop.get("tls_version"),
            "suite": hop.get("suite"),
            "crypto": list(hop.get("crypto") or []),
            "evidence_id": hop.get("evidence_id"),
            "class": str(hop.get("class") or tb.NETWORK_OBSERVED).upper(),
        })
    if final_operation is not None:
        attributes = dict(final_operation.get("attributes") or final_operation)
        rows.append({
            "hop": len(rows) + 1,
            "source": str(attributes.get("process") or attributes.get("application")
                          or "application"),
            "target": str(attributes.get("provider") or attributes.get("holder") or "HSM"),
            "mode": str(attributes.get("operation") or "OPERATION").upper(),
            "tls_version": None,
            "suite": attributes.get("algorithm"),
            "crypto": [value for value in (attributes.get("algorithm"),
                                           attributes.get("hash")) if value],
            "evidence_id": attributes.get("evidence_id"),
            "class": str(attributes.get("class") or tb.RUNTIME_OBSERVED).upper(),
        })
    weakest = min((row["class"] for row in rows),
                  key=lambda name: tb.CONFIDENCE.get(name, 1)) if rows else tb.UNKNOWN
    return {
        "hops": rows,
        "count": len(rows),
        "weakest": weakest,
        "proven": bool(rows) and all(row["class"] in tb.PROVEN for row in rows),
        "statement": (f"{len(rows)} hop(s): " + " → ".join(
            f"{row['source']} → {row['target']} "
            f"({row['tls_version'] or row['mode']}"
            f"{'/' + str(row['suite']) if row['suite'] else ''})"
            for row in rows)) if rows else "no hop was evidenced",
        "not_proven": ["that a request takes every hop at once: the graph holds the hops "
                       "that were evidenced, and a request takes one path"],
    }


#: the relations a request crosses on its way through the estate. A hop is one boundary,
#: and the walk follows these only — a certificate does not carry traffic.
HOP_RELATIONS: tuple[str, ...] = ("FORWARDS_TO", "TERMINATES_TLS", "RE_ENCRYPTS",
                                  "PASSTHROUGH", "ROUTES_TO")


def endpoint_hops(bom: Mapping[str, Any], *, query: Any, max_hops: int = 8) -> dict[str, Any]:
    """The hops a listener's traffic takes, as HOP 1..N (cbom 11, 12).

    The walk is a walk: ``client → LB → gateway → application`` is three hops and three
    suites, and a report that names only the first one is a report that has missed the
    legacy hop nobody wrote down.
    """
    key = _resolve_one(bom, query)
    hops: list[dict[str, Any]] = []
    seen: set[str] = {key}
    frontier: list[str] = [key]
    while frontier and len(hops) < max_hops:
        current = frontier.pop(0)
        for claim in bom["claims"]:
            if claim["from_key"] != current or claim["relation"] not in HOP_RELATIONS:
                continue
            source = bom["by_key"][current]
            suite = next((bom["by_key"][other["to_key"]]["name"] for other in bom["claims"]
                          if other["from_key"] == current
                          and other["relation"] == "NEGOTIATES"), None)
            hops.append({
                "source": source["name"], "target": bom["by_key"][claim["to_key"]]["name"],
                "mode": claim["relation"],
                "tls_version": (source["attributes"].get("tls") or {}).get("version"),
                "suite": suite, "crypto": [suite] if suite else [],
                "evidence_id": (claim.get("evidence_ids") or [None])[0],
                "class": claim["confidence"]})
            if claim["to_key"] not in seen:
                seen.add(claim["to_key"])
                frontier.append(claim["to_key"])
    block = crypto_hops(hops)
    return {"endpoint": bom["by_key"][key]["name"], **block}


def systems_depending_on(bom: Mapping[str, Any], *, algorithm: Any,
                         include_static: bool = True,
                         coverage: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """*Which business systems depend on RSA-2048?* — asked of the chain (cbom 18).

    A business system is named only when an evidenced edge path reaches it. With
    ``include_static=False`` the answer is the stricter one — which systems *ran* it —
    because a static hit is a dependency and not an execution.

    ``coverage`` is the denominator from :func:`cbom.usage_evidence.coverage` or
    :func:`cbom.nbom_graph.coverage`. Pass it and the answer stops being a total: *one
    system depends on RSA-2048, among the twelve of seventy applications inspected* is a
    different sentence from *the bank has one*.
    """
    target = _resolve_one(bom, algorithm)
    rows: list[dict[str, Any]] = []
    for application in bom["assets"]:
        if application["kind"] != "APPLICATION":
            continue
        found = _reach(bom, application["key"], target, include_static=include_static)
        if found is None:
            continue
        rows.append({"application": application["name"],
                     "application_id": application.get("id"),
                     "systems": found["systems"], "path": found["path"],
                     "classes": found["classes"], "weakest": found["weakest"]})
    systems = sorted({name for row in rows for name in row["systems"]})
    bounded = ""
    quotable = True
    if coverage:
        inspected = coverage.get("systems_inspected", coverage.get("observed",
                                                                  coverage.get("successful")))
        total = coverage.get("systems_total", coverage.get("expected"))
        quotable = bool(coverage.get("quotable_as_total", False))
        bounded = (f", among {inspected} of {total} applications inspected"
                   if total is not None else "")
    return {
        "algorithm": bom["by_key"][target]["name"],
        "applications": sorted(rows, key=lambda row: row["application"]),
        "systems": systems,
        "coverage": dict(coverage) if coverage else None,
        "quotable_as_total": quotable,
        "statement": ((f"{len(systems)} business system(s) depend on "
                       f"{bom['by_key'][target]['name']} through {len(rows)} application(s)"
                       + bounded) if rows else
                      f"no application reaches {bom['by_key'][target]['name']}" + bounded),
        "not_proven": ["that this is every system: the answer is bounded by the "
                       "applications that were inspected, and coverage says how many those "
                       "were"],
    }


def _reach(bom: Mapping[str, Any], start: str, target: str, *,
           include_static: bool) -> dict[str, Any] | None:
    queue: list[tuple[str, list[str]]] = [(start, [start])]
    seen: set[str] = {start}
    while queue:
        key, path = queue.pop(0)
        if key == target:
            classes = {claim["confidence"] for claim in bom["claims"]
                       if claim["relation"] in CHAIN_RELATIONS
                       and claim["from_key"] in path and claim["to_key"] in path}
            if not include_static and tb.STATIC_OBSERVED in classes:
                return None
            systems = [bom["by_key"][node]["name"] for node in path
                       if bom["by_key"][node]["kind"] == "BUSINESS_SYSTEM"]
            if not systems:
                # the system owns the application at the top of the path: that edge is the
                # answer a bank asks for, and it is one hop beyond where the walk started
                systems = [bom["by_key"][claim["from_key"]]["name"]
                           for claim in bom["claims"]
                           if claim["relation"] in ("CONTAINS", "OWNS")
                           and claim["to_key"] in path]
            return {"systems": sorted(set(systems)),
                    "path": [bom["by_key"][node]["name"] for node in path],
                    "classes": sorted(classes),
                    "weakest": min(classes, key=lambda name: tb.CONFIDENCE.get(name, 1))
                    if classes else tb.UNKNOWN}
        for claim in bom["claims"]:
            if claim["relation"] not in CHAIN_RELATIONS:
                continue
            if not include_static and claim["confidence"] == tb.STATIC_OBSERVED:
                continue
            dependent, dependency = _sides(claim)
            if dependent != key:
                continue
            step = dependency
            if step in seen:
                continue
            seen.add(step)
            queue.append((step, [*path, step]))
    return None


# --------------------------------------------------------------------------- #
# Impact: an advisory is a question about assets, not about a version string
# --------------------------------------------------------------------------- #

#: the kinds an advisory has to land on before it is actionable
IMPACT_KINDS: tuple[str, ...] = ("PROCESS", "APPLICATION", "SERVICE", "BUSINESS_SYSTEM",
                                 "NETWORK_ENDPOINT", "LOAD_BALANCER", "WAF", "API_GATEWAY",
                                 "SERVICE_MESH", "DATABASE", "HOST", "VM", "PHYSICAL_SERVER",
                                 "KUBERNETES_NODE", "HSM", "KMS", "TPM", "KEY_REFERENCE",
                                 "CRYPTO_OPERATION", "FIRMWARE", "VENDOR_PRODUCT", "VENDOR")

#: the kinds that count as the device an advisory is served against
DEVICE_KINDS: tuple[str, ...] = ("LOAD_BALANCER", "WAF", "API_GATEWAY", "SERVICE_MESH",
                                 "DATABASE", "FIREWALL", "PHYSICAL_SERVER", "HOST", "HSM",
                                 "TPM")


#: relations an impact walk follows *forward* from a node it has reached: a device owns
#: its listener, a listener presents its certificate. An advisory that stops at the device
#: names a box; one that crosses the surface names the applications behind it.
SURFACE_RELATIONS: tuple[str, ...] = ("LISTENS_ON", "PRESENTS", "NEGOTIATES",
                                      "USES_CERTIFICATE", "RUNS_FIRMWARE", "HAS_MODEL",
                                      "SUPPLIED_BY", "ROUTES_TO")


def _dependents(bom: Mapping[str, Any], key: str, *, max_depth: int = 6,
                follow: Iterable[str] = ()) -> list[tuple[Mapping[str, Any], Mapping[str, Any], int]]:
    """Everything that depends on this node, nearest first.

    One direction only — the dependent side of each edge — because "what does this
    advisory affect" is a question about who relies on the thing, not about everything
    within six hops of it.
    """
    out: list[tuple[Mapping[str, Any], Mapping[str, Any], int]] = []
    visited: set[str] = {key}
    frontier: list[tuple[str, int]] = [(key, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["relation"] not in CHAIN_RELATIONS:
                continue
            dependent, dependency = _sides(claim)
            steps: list[str] = []
            if dependency == current:
                steps.append(dependent)
            if claim["relation"] in follow and claim["from_key"] == current:
                steps.append(claim["to_key"])
            for step in steps:
                if step in visited or step not in bom["by_key"]:
                    continue
                visited.add(step)
                out.append((bom["by_key"][step], claim, depth + 1))
                frontier.append((step, depth + 1))
    return out


def provider_impact(bom: Mapping[str, Any], *, query: Any,
                    version: Any = None) -> dict[str, Any]:
    """*This OpenSSL version is affected* → which processes, applications and systems (cbom 5).

    A provider is only a useful node if an advisory against it maps to assets. The walk is
    the dependent direction from the provider — the processes that load it, the
    applications those processes run, the systems that own them — plus every operation
    whose parameters name it, which is the difference between "the library is present" and
    "this signing call used it".

    ``version`` is what the advisory names. When the estate records something else the
    result says so: an inventory that disagrees with an advisory is a gap in the inventory,
    not an all-clear.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    if row["kind"] not in ("CRYPTO_PROVIDER", "CRYPTO_LIBRARY"):
        raise tb.ClaimRefused(
            "NOT_A_PROVIDER",
            f"{row['name']} ({row['kind']}) is not a crypto provider or library; an advisory "
            "against an algorithm is a different question")
    dependents = _dependents(bom, key)
    by_kind: dict[str, list[str]] = {}
    for node, _claim, _depth in dependents:
        if node["kind"] in IMPACT_KINDS:
            by_kind.setdefault(node["kind"], []).append(node["name"])
    operations = sorted({asset["name"] for asset in bom["assets"]
                         if asset["kind"] == "CRYPTO_OPERATION"
                         and (asset["attributes"] or {}).get("provider") == row["name"]})
    recorded = row.get("version")
    matches = version is None or not recorded or str(recorded) == str(version)
    affected = {kind: sorted(set(names)) for kind, names in sorted(by_kind.items())}
    applications = affected.get("APPLICATION", [])
    systems = affected.get("BUSINESS_SYSTEM", [])
    return {
        "query": str(query), "provider": row["name"], "recorded_version": recorded,
        "advisory_version": str(version) if version is not None else None,
        "version_matches": matches,
        "affected": affected, "operations": operations,
        "counts": {"processes": len(affected.get("PROCESS", [])),
                   "applications": len(applications), "systems": len(systems),
                   "operations": len(operations)},
        "statement": (f"{row['name']}"
                      + (f" {recorded}" if recorded else "")
                      + (f" vs advisory {version}" if version is not None else "")
                      + ("" if matches else " — VERSION MISMATCH, the inventory disagrees")
                      + f": {len(affected.get('PROCESS', []))} process(es), "
                        f"{len(applications)} application(s), {len(systems)} business "
                        f"system(s), {len(operations)} operation(s) affected"),
        "not_proven": ["that every affected asset was discovered: the answer is bounded by "
                       "the applications that were inspected",
                       "that the version the inventory records is the version running: a "
                       "process map and an SBOM can disagree, and that disagreement is "
                       "reported as a conflict rather than resolved here"],
    }


def advisory_impact(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """*Vendor firmware advisory* → the devices, listeners and applications behind it (cbom 14).

    A CVE against a vendor's firmware is a fact about a version. It becomes an operational
    fact only when the graph can walk firmware → device → listener → application → business
    system, and each hop is an edge somebody can re-read. An estate that never recorded the
    firmware version is reported as unrecorded, not as unaffected.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    if row["kind"] == "VULNERABILITY":
        firmwares = [bom["by_key"][claim["from_key"]] for claim in bom["claims"]
                     if claim["to_key"] == key and claim["relation"] == "HAS_VULNERABILITY"]
    elif row["kind"] in ("FIRMWARE", "VENDOR_PRODUCT", "VENDOR"):
        firmwares = [row]
    else:
        raise tb.ClaimRefused(
            "NOT_AN_ADVISORY",
            f"{row['name']} ({row['kind']}) is not a vulnerability, a firmware or a vendor "
            "product; an advisory against a service is a different question")
    findings: list[dict[str, Any]] = []
    for firmware in firmwares:
        dependents = _dependents(bom, firmware["key"], follow=SURFACE_RELATIONS)
        levels: dict[str, list[str]] = {}
        for node, _claim, _depth in dependents:
            if node["kind"] in IMPACT_KINDS:
                levels.setdefault(node["kind"], []).append(node["name"])
        device_keys = {node["key"] for node, _claim, _depth in dependents
                       if node["kind"] in DEVICE_KINDS}
        devices = sorted({bom["by_key"][device_key]["name"] for device_key in device_keys})
        # the vendor behind each affected device: the party a bank has to call
        vendors = sorted({bom["by_key"][claim["to_key"]]["name"] for claim in bom["claims"]
                          if claim["relation"] == "SUPPLIED_BY"
                          and claim["from_key"] in device_keys})
        findings.append({
            "vulnerability": row["name"] if row["kind"] == "VULNERABILITY" else None,
            "firmware": firmware["name"], "firmware_version": firmware.get("version"),
            "devices": devices, "vendors": vendors,
            "endpoints": sorted(set(levels.get("NETWORK_ENDPOINT", []))),
            "applications": sorted(set(levels.get("APPLICATION", []))),
            "systems": sorted(set(levels.get("BUSINESS_SYSTEM", [])))})
    total = sum(len(finding["applications"]) for finding in findings)
    return {
        "query": str(query), "findings": findings, "count": len(findings),
        "applications_affected": total,
        "statement": (f"{row['name']}: {len(findings)} firmware record(s), "
                      f"{sum(len(f['devices']) for f in findings)} device(s), "
                      f"{total} application(s) behind them" if findings else
                      f"{row['name']}: no firmware in the estate is affected"),
        "not_proven": ["that a device is exploitable: this maps an advisory to the assets "
                       "that depend on the affected firmware, and exploitability belongs to "
                       "vulnerability management",
                       "that the firmware record is current: a device with no firmware "
                       "version recorded is a gap, and it is reported as one"],
    }


# --------------------------------------------------------------------------- #
# Conflict, change, coverage
# --------------------------------------------------------------------------- #

def dependency_conflicts(bom: Mapping[str, Any]) -> dict[str, Any]:
    """Sources that disagree about one dependency, kept apart (cbom 21).

    Two kinds matter. A **version** conflict is when the SBOM, the process map and the
    agent inventory each name a different version of the provider — the SVB case. A
    **layer** conflict is when a process was seen using one algorithm statically and
    another at runtime. Both are ``CRYPTO_DEPENDENCY_CONFLICT`` and neither is resolved by
    picking the newest claim: the disagreement *is* the finding.
    """
    findings: list[dict[str, Any]] = []
    for row in bom["assets"]:
        claims = (row["attributes"] or {}).get("version_claims") or []
        values = {str(claim.get("value")) for claim in claims}
        if len(values) > 1:
            findings.append({
                "code": "CRYPTO_DEPENDENCY_CONFLICT", "kind": "VERSION",
                "asset": row["name"], "asset_id": row.get("id"), "field": "version",
                "values": sorted(values),
                "sources": [{key: claim.get(key) for key in
                             ("source", "value", "class", "evidence_id")}
                            for claim in claims],
                "reason": "the sources disagree about which version is deployed; the "
                          "disagreement is the finding, not the newest value"})
    by_process: dict[str, dict[str, set[str]]] = {}
    for claim in bom["claims"]:
        if claim["relation"] != "USES_ALGORITHM":
            continue
        if bom["by_key"][claim["from_key"]]["kind"] != "CRYPTO_OPERATION":
            continue
        owner = next((other for other in bom["claims"]
                      if other["relation"] == "INVOKES"
                      and other["to_key"] == claim["from_key"]), None)
        if owner is None:
            continue
        by_process.setdefault(bom["by_key"][owner["from_key"]]["name"], {}) \
            .setdefault(claim["confidence"], set()).add(
                bom["by_key"][claim["to_key"]]["name"])
    for process, layers in sorted(by_process.items()):
        observed = {layer: sorted(names) for layer, names in layers.items()
                    if layer in USAGE_CLASSES}
        values = {name for names in observed.values() for name in names}
        if len(observed) > 1 and len(values) > 1:
            findings.append({
                "code": "CRYPTO_DEPENDENCY_CONFLICT", "kind": "LAYER",
                "process": process, "layers": observed,
                "reason": "two layers saw two different algorithms; collapsing them would "
                          "report one dependency where the estate has two"})
    kinds = sorted({row["kind"] for row in findings})
    return {
        "findings": findings,
        "counts": {kind: sum(1 for row in findings if row["kind"] == kind)
                   for kind in kinds},
        "statement": (f"{len(findings)} dependency conflict(s)"
                      + (f": {', '.join(f'{count} {kind}' for kind, count in sorted({k: sum(1 for r in findings if r['kind'] == k) for k in kinds}.items()))}"
                         if findings else "")),
        "rule": ("a conflict keeps every source; a CBOM that resolves it by precedence has "
                 "thrown away the one fact worth reporting"),
    }


def dependency_changes(previous: Mapping[str, Any], current: Mapping[str, Any], *,
                       detected_at: Any = None) -> dict[str, Any]:
    """What moved between two projections, with the evidence on both sides (cbom 22).

    ``CRYPTO_DEPENDENCY_CHANGED`` carries ``previous``, ``current``, ``evidence_before``
    and ``evidence_after``, because "RSA-2048 became RSA-3072" is only usable if the two
    observations behind it can be re-read.
    """
    before = _dependency_map(previous)
    after = _dependency_map(current)
    changes = [{"code": "CRYPTO_DEPENDENCY_CHANGED", "dependency": key,
                "previous": before[key]["value"], "current": after[key]["value"],
                "evidence_before": before[key]["evidence_id"],
                "evidence_after": after[key]["evidence_id"],
                "class_before": before[key]["class"], "class_after": after[key]["class"],
                "detected_at": detected_at}
               for key in sorted(set(before) & set(after))
               if before[key]["value"] != after[key]["value"]]
    removed = [{"code": "CRYPTO_DEPENDENCY_REMOVED", "dependency": key,
                "previous": before[key]["value"],
                "evidence_before": before[key]["evidence_id"],
                "detected_at": detected_at}
               for key in sorted(set(before) - set(after))]
    added = [{"code": "CRYPTO_DEPENDENCY_ADDED", "dependency": key,
              "current": after[key]["value"], "evidence_after": after[key]["evidence_id"],
              "detected_at": detected_at}
             for key in sorted(set(after) - set(before))]
    return {
        "changes": changes, "added": added, "removed": removed,
        "counts": {"CHANGED": len(changes), "ADDED": len(added), "REMOVED": len(removed)},
        "statement": (f"{len(changes)} changed, {len(added)} added, {len(removed)} removed")
        + ("" if changes else "; nothing in the chain moved"),
        "rule": ("a dependency that stops being observed is superseded, not deleted: what "
                 "the estate used to depend on is part of the answer"),
    }


def _dependency_map(bom: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for claim in bom.get("claims") or []:
        if claim["relation"] not in ("USES_ALGORITHM", "USES_CRYPTO", "LOADS"):
            continue
        # a process loading two libraries is two dependencies, so a `LOADS` edge is keyed
        # by its target; an operation has one algorithm, so that edge is keyed by its actor
        name = (f"{claim['from']} {claim['relation']} {claim['to']}"
                if claim["relation"] == "LOADS" else
                f"{claim['from']} {claim['relation']}")
        entry = {
            "value": claim["to"],
            "evidence_id": (claim.get("evidence_ids") or [None])[0],
            "evidence_ids": list(claim.get("evidence_ids") or []),
            "class": claim["confidence"],
            "edge": claim["id"],
            "observed_at": claim.get("observed_at"),
            "first_seen": claim.get("first_seen"),
            "last_seen": claim.get("last_seen")}
        previous = rows.get(name)
        if previous is None:
            rows[name] = entry
            continue
        # the same dependency described by two layers is one dependency, and the entry
        # kept is the *strongest* statement about it — a static scan must not overwrite a
        # runtime observation just because it was read later. Both evidence ids survive.
        entry["evidence_ids"] = sorted(set(previous["evidence_ids"])
                                       | set(entry["evidence_ids"]))
        if tb.CONFIDENCE[entry["class"]] > tb.CONFIDENCE[previous["class"]]:
            rows[name] = entry
        else:
            previous["evidence_ids"] = entry["evidence_ids"]
    return rows


#: the six states a dependency edge can be in (cbom 23). ``REMOVED`` and ``SUPERSEDED``
#: are states, not deletions: what the estate used to depend on is part of the answer.
LIFECYCLE_STATES: tuple[str, ...] = ("FIRST_SEEN", "ACTIVE", "CHANGED", "SUPERSEDED",
                                     "REMOVED", "UNKNOWN")


def dependency_lifecycle(current: Mapping[str, Any], *,
                         previous: Mapping[str, Any] | None = None,
                         reference: Any = None) -> dict[str, Any]:
    """Every dependency edge with a state, and nothing dropped for being old (cbom 23).

    With one projection the state comes from the edge's own record: no timestamps is
    ``UNKNOWN`` — which is not the same as active — one sighting is ``FIRST_SEEN``, a
    ``last_seen`` before the reference is ``CHANGED``, anything else is ``ACTIVE``.

    With two projections the vocabulary gains the two states only comparison produces. An
    edge that now names a *different* target is ``SUPERSEDED``: the old row is kept beside
    the new one, because "we stopped depending on libcrypto.so.1.1" is a finding and a
    deletion is not. An edge pointing at the same target at a different class is
    ``CHANGED``. An edge that is gone is ``REMOVED``, still carrying its last value and
    evidence id.
    """
    after = _dependency_map(current)
    rows: list[dict[str, Any]] = []
    superseded: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    if previous is None:
        for name, entry in sorted(after.items()):
            rows.append({"dependency": name, "state": _lifecycle_state(entry, reference),
                         "value": entry["value"], "previous": None,
                         "class": entry["class"], "evidence_id": entry["evidence_id"],
                         "edge": entry["edge"]})
    else:
        before = _dependency_map(previous)
        for name in sorted(set(before) | set(after)):
            old, new = before.get(name), after.get(name)
            if old is None and new is not None:
                state = "FIRST_SEEN"
            elif new is None and old is not None:
                removed.append({"dependency": name, "previous": old["value"],
                                "evidence_before": old["evidence_id"], "edge": old["edge"]})
                rows.append({"dependency": name, "state": "REMOVED", "value": None,
                             "previous": old["value"], "class": old["class"],
                             "evidence_id": old["evidence_id"], "edge": old["edge"]})
                continue
            elif old["value"] != new["value"]:
                state = "SUPERSEDED"
                superseded.append({"dependency": name, "previous": old["value"],
                                   "current": new["value"],
                                   "evidence_before": old["evidence_id"],
                                   "evidence_after": new["evidence_id"]})
            elif old["class"] != new["class"]:
                state = "CHANGED"
            else:
                state = _lifecycle_state(new, reference)
            rows.append({"dependency": name, "state": state,
                         "value": (new or old)["value"],
                         "previous": old["value"] if old else None,
                         "class": (new or old)["class"],
                         "evidence_id": (new or old)["evidence_id"],
                         "edge": (new or old)["edge"]})
    counts = {state: sum(1 for row in rows if row["state"] == state)
              for state in LIFECYCLE_STATES}
    counts = {state: count for state, count in counts.items() if count}
    return {
        "states": {row["dependency"]: row["state"] for row in rows},
        "rows": rows,
        "counts": counts,
        "superseded": superseded,
        "removed": removed,
        "reference": reference,
        "statement": (f"{len(rows)} dependency edge(s): "
                      + ", ".join(f"{state} {count}" for state, count in counts.items())
                      if rows else "no dependency edge was recorded"),
        "rule": ("SUPERSEDED and REMOVED are states, not deletions: an edge that stopped "
                 "being observed is kept with its last value and the evidence that said so"),
    }


def _lifecycle_state(entry: Mapping[str, Any], reference: Any) -> str:
    first = entry.get("first_seen")
    last = entry.get("last_seen") or entry.get("observed_at")
    if not first and not last:
        return "UNKNOWN"
    if first and last and first == last:
        return "FIRST_SEEN"
    if reference and last and str(last) < str(reference):
        return "CHANGED"
    return "ACTIVE"


#: the state a KMS answer sits at, from the class of the evidence behind it. A datasheet
#: is SUPPORTED, a config file is CONFIGURED, an inventory row is REFERENCED and only an
#: observation is ACTUALLY_USED.


def kms_state(*, basis: Any = None, confidence: Any = None) -> str:
    """Which of the four answers this evidence supports (cbom 9)."""
    state = KMS_STATE_BY_BASIS.get(str(basis or "").strip().lower())
    if state:
        return state
    klass = str(confidence or "").strip().upper()
    if klass == tb.RUNTIME_OBSERVED or klass == tb.OBSERVED:
        return "ACTUALLY_USED"
    if klass == tb.CONFIGURED:
        return "CONFIGURED"
    if klass == tb.IMPORTED:
        return "REFERENCED"
    return "SUPPORTED"


def kms_evidence(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """A KMS and what the estate can actually say about it (cbom 9).

    Four answers, and the strongest one wins the headline: ``SUPPORTED`` (a datasheet),
    ``CONFIGURED`` (a policy file names it), ``REFERENCED`` (an inventory row points at
    it), ``ACTUALLY_USED`` (an operation ran there). A KMS with three capabilities and one
    configured key is reported as configured, because that is the strongest thing anything
    said.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    if row["kind"] not in ("KMS", "HSM", "TPM"):
        raise tb.ClaimRefused(
            "NOT_A_KEY_PROVIDER",
            f"{row['name']} ({row['kind']}) is not a key provider; a KMS answer is about a "
            "KMS, an HSM or a TPM")
    answers: list[dict[str, Any]] = []
    for claim in bom["claims"]:
        if claim["from_key"] != key and claim["to_key"] != key:
            continue
        if claim["relation"] not in ("USES_KMS", "USES_HSM", "BACKED_BY", "HOLDS_KEY",
                                     "SUPPORTS", "PERFORMS"):
            continue
        answers.append({
            "relation": claim["relation"],
            "source": bom["by_key"][claim["from_key"]]["name"] if claim["from_key"] != key
            else row["name"],
            "target": bom["by_key"][claim["to_key"]]["name"] if claim["to_key"] != key
            else row["name"],
            "basis": claim["basis"], "class": claim["confidence"],
            "state": kms_state(basis=claim["basis"], confidence=claim["confidence"]),
            "evidence_id": (claim.get("evidence_ids") or [None])[0]})
    order = {state: index for index, state in enumerate(KMS_STATES)}
    strongest = max((answer["state"] for answer in answers),
                    key=lambda state: order[state]) if answers else "SUPPORTED"
    return {
        "query": str(query), "provider": row["name"], "kind": row["kind"],
        "state": strongest, "answers": answers,
        "states_present": sorted({answer["state"] for answer in answers},
                                 key=lambda state: order[state]),
        "statement": (f"{row['name']}: {len(answers)} answer(s), strongest "
                      f"{strongest} — " + ", ".join(sorted({answer['state']
                                                            for answer in answers},
                                                           key=lambda state: order[state]))
                      if answers else f"{row['name']}: nothing in the estate speaks for it"),
        "rule": ("SUPPORTED is a datasheet, CONFIGURED is a policy, REFERENCED is an "
                 "inventory row and ACTUALLY_USED is an operation; only the last one is use"),
    }


# --------------------------------------------------------------------------- #
# PQC: the blocker is on the path, not on the algorithm
# --------------------------------------------------------------------------- #

#: the nodes a PQC migration has to change when it reaches them. A vendor product is here
#: because its firmware is, and a firmware is here because it cannot be patched by the bank.
PQC_PATH_KINDS: tuple[str, ...] = ("CERTIFICATE", "NETWORK_ENDPOINT", "LOAD_BALANCER",
                                   "FIREWALL", "HOST", "PHYSICAL_SERVER",
                                   "KUBERNETES_NODE", "CRYPTO_LIBRARY",
                                   "WAF", "API_GATEWAY", "SERVICE_MESH", "DATABASE", "HSM",
                                   "KMS", "TPM", "KEY_REFERENCE", "FIRMWARE",
                                   "VENDOR_PRODUCT", "CRYPTO_ACCELERATOR", "SMART_CARD")

#: the levels whose *own* dependencies are on the migration path: an operation's key and
#: key store, a listener's certificate, a device's firmware. Without this the blocker list
#: names the operation and stops, which is exactly the answer that is not actionable.
PQC_EXPAND_KINDS: tuple[str, ...] = ("CRYPTO_OPERATION", "PROCESS", "APPLICATION",
                                     "NETWORK_ENDPOINT", "LOAD_BALANCER", "WAF",
                                     "API_GATEWAY", "SERVICE_MESH", "DATABASE")

PQC_OWNER_RELATIONS: tuple[str, ...] = ("LISTENS_ON", "FRONTED_BY", "PROTECTED_BY")

PQC_EXPAND_RELATIONS: tuple[str, ...] = ("USES_KEY", "BACKED_BY", "USES_HSM", "USES_TPM",
                                         "HOLDS_KEY", "PRESENTS", "RUNS_FIRMWARE",
                                         "SUPPLIED_BY", "HAS_MODEL", "USES_CERTIFICATE",
                                         "CONTAINS_KEY", "EXPOSES", "LISTENS_ON")


def pqc_blockers(bom: Mapping[str, Any], *, query: Any, max_depth: int = 8) -> dict[str, Any]:
    """Why *this* dependency cannot migrate, named hop by hop (cbom 25).

    ``RSA-2048`` is not the blocker. The certificate that carries it is, the load balancer
    that terminates it is, the HSM that holds the key is, and the firmware that cannot do
    ML-KEM is. The walk therefore follows the *dependent* direction — who depends on this
    algorithm — and then, from each operation, listener and device it reaches, the
    dependencies that a migration would have to re-provision: the key, its holder, the
    certificate, the firmware.

    What it deliberately does not do is follow every edge outward: that finds the AES key
    three hops away and calls it an RSA blocker, which is how a blocker list stops being
    read.
    """
    start = _resolve_one(bom, query)
    row = bom["by_key"][start]
    sensitive = any(token in row["name"].upper() for token in tb.QUANTUM_SENSITIVE)
    blockers: list[dict[str, Any]] = []
    if sensitive:
        blockers.append({"kind": "ALGORITHM", "name": row["name"], "class": tb.CONFIGURED,
                         "relation": None, "reached_by": "self",
                         "reason": "the algorithm itself is quantum-sensitive"})
    visited: set[str] = {start}
    frontier: list[tuple[str, int]] = [(start, 0)]
    while frontier:
        key, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        expand = bom["by_key"][key]["kind"] in PQC_EXPAND_KINDS
        for claim in bom["claims"]:
            if claim["relation"] not in CHAIN_RELATIONS:
                continue
            dependent, dependency = _sides(claim)
            steps: list[tuple[str, str]] = []
            if dependency == key:
                # who depends on this: the direction the dependency actually points
                steps.append((dependent, "depends"))
            if expand and claim["from_key"] == key \
                    and claim["relation"] in PQC_EXPAND_RELATIONS:
                # what this very node needs re-provisioned: its key, holder, certificate
                steps.append((claim["to_key"], "uses"))
            if expand and claim["from_key"] == key and claim["relation"] in HOP_RELATIONS:
                # the next listener on the path, and the device that owns it
                steps.append((claim["to_key"], "hop"))
            if expand and claim["to_key"] == key and claim["relation"] in PQC_OWNER_RELATIONS:
                # the device a listener belongs to: its firmware is the migration blocker
                steps.append((claim["from_key"], "runs_on"))
            for neighbour, why in steps:
                if neighbour in visited or neighbour not in bom["by_key"]:
                    continue
                visited.add(neighbour)
                target = bom["by_key"][neighbour]
                if target["kind"] in PQC_PATH_KINDS:
                    blockers.append(_blocker(bom, target, claim, why))
                frontier.append((neighbour, depth + 1))
    kinds = sorted({entry["kind"] for entry in blockers})
    return {
        "query": str(query), "algorithm": row["name"], "sensitive": sensitive,
        "blockers": blockers, "kinds": kinds, "count": len(blockers),
        "statement": (f"{row['name']}: {len(blockers)} blocker(s) on the chain — "
                      + ", ".join(kinds)) if blockers else
                     f"{row['name']}: no blocker was evidenced on the chain",
        "rule": ("a PQC blocker is a property of the path, not of the algorithm: the "
                 "algorithm is the thing being migrated, and the path is why it is hard"),
        "not_proven": ["that the device cannot be upgraded: the blocker is a fact about the "
                       "device, and the upgrade path is a vendor question"],
    }


def _blocker(bom: Mapping[str, Any], node: Mapping[str, Any], claim: Mapping[str, Any],
             why: str) -> dict[str, Any]:
    reasons = {
        "CERTIFICATE": ("the certificate carries the key exchange and the signature that a "
                        "migration has to replace"),
        "NETWORK_ENDPOINT": ("this listener negotiates the suite, and a listener is the hop "
                             "a client actually meets"),
        "KEY_REFERENCE": ("the key has to be re-issued and every consumer of the reference "
                          "re-pointed"),
        "FIRMWARE": "the firmware has to support ML-KEM before the device can negotiate it",
        "VENDOR_PRODUCT": "the product's crypto is the vendor's to change, not the bank's",
    }
    entry: dict[str, Any] = {
        "kind": node["kind"], "name": node["name"], "class": claim["confidence"],
        "relation": claim["relation"], "reached_by": why,
        "reason": reasons.get(node["kind"],
                              "a migration that moves this algorithm has to change this "
                              "device, its firmware or its key store"),
    }
    if node["kind"] == "NETWORK_ENDPOINT":
        entry["suites"] = sorted({bom["by_key"][other["to_key"]]["name"]
                                  for other in bom["claims"]
                                  if other["from_key"] == node["key"]
                                  and other["relation"] == "NEGOTIATES"})
    return entry


# --------------------------------------------------------------------------- #
# Evidence: every edge carries nine fields
# --------------------------------------------------------------------------- #

#: the fields the review asks every edge to carry (cbom 19). ``collector`` and
#: ``collector_version`` are printed when an evidence record exists and left null when it
#: does not — an edge must never borrow a collector from a neighbour.
EDGE_FIELDS: tuple[str, ...] = ("source", "target", "relationship", "basis", "confidence",
                               "evidence_id", "evidence_type", "observed_at", "first_seen",
                               "last_seen")


#: the six fields an edge cannot be read without. An edge missing one of these is a
#: drawing, and it is listed rather than counted.
REQUIRED_EDGE_FIELDS: tuple[str, ...] = ("source", "target", "relationship", "basis",
                                         "confidence", "evidence_id")


def evidence_audit(bom: Mapping[str, Any]) -> dict[str, Any]:
    """Dependency edges against the ten fields the review names (cbom 19).

    The honest report is two numbers, not one. **Structural** completeness — source,
    target, relationship, basis, class, evidence id — is what makes an edge readable, and
    every edge in a built projection has it by construction. **Full** completeness adds
    ``evidence_type``, ``observed_at``, ``first_seen``, ``last_seen`` and the collector,
    and an estate supplies those unevenly: a claim built from a configuration parse has a
    basis but no observation time, and inventing one is the fabrication this module exists
    to avoid.

    So the audit counts per field and publishes the shortfall. "58 of 58 complete" over
    four empty columns is not an audit, it is a slogan.
    """
    rows = [edge_record(bom, claim) for claim in bom.get("claims") or []
            if claim["relation"] in CHAIN_RELATIONS]
    coverage = {field: sum(1 for row in rows if row.get(field) not in (None, "", []))
                for field in EDGE_FIELDS}
    structural = [row["id"] for row in rows
                  if any(row.get(field) in (None, "", [])
                         for field in REQUIRED_EDGE_FIELDS)]
    fully = {row["id"] for row in rows
             if all(row.get(field) not in (None, "", []) for field in EDGE_FIELDS)}
    collected = [row for row in rows if row["collector"]]
    sparse = [f"{field} {coverage[field]}/{len(rows)}" for field in EDGE_FIELDS
              if coverage[field] < len(rows)]
    return {
        "edges": rows, "count": len(rows),
        "structural": len(rows) - len(structural), "incomplete": structural,
        "fully_recorded": len(fully),
        "sparse_edges": sorted({row["id"] for row in rows} - fully),
        "field_coverage": coverage, "missing_fields": sparse,
        "with_collector": len(collected),
        "collectors": sorted({row["collector"] for row in collected}),
        "statement": (f"{len(rows)} dependency edge(s): {len(rows) - len(structural)} carry "
                      f"all six structural fields, {len(fully)} carry all ten; "
                      f"{len(collected)} name a collector"
                      + (f"; short on {', '.join(sparse)}" if sparse else "")),
        "rule": ("an edge without a basis, a class and an evidence id is a drawing; a field "
                 "the estate did not supply is reported as a shortfall, never backfilled "
                 "from a neighbour"),
    }


def digest(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


NOT_PROVEN = [
    "that a business system depends on an algorithm because both exist: every answer here "
    "walks an edge, and each edge prints the basis that put it there",
    "that a static hit is an execution: STATIC_OBSERVED is a dependency and is not in "
    "PROVEN, so it never becomes blast radius on its own",
    "that a provider's capability list is usage: the two sets are returned side by side and "
    "never merged",
    "that a certificate is the application's crypto: the certificate chain hangs off a "
    "listener and the application's operations hang off a process",
    "that a conflict has a winner: both sources are kept and a human decides, because a "
    "precedence rule that silently picks one is the loss this module exists to prevent",
]
