"""Live collection: real upstream payloads → the inventory the chain is built from.

Guide 176 proved the chain comes out of a gathered inventory. What was still missing was the
gathering: everything up to now was a fixture shaped like a store. This module is the live
half — one collector per transport, each turning the payload a real system returns into
inventory rows, with three rules that make the difference between *collected* and *asserted*:

* **the transport decides the class.** A git API answer is a JSON document over HTTP; it is
  ``CONFIGURED`` at most, never ``OBSERVED``. Only a probe — a process trace, a packet
  capture — can produce an ``OBSERVED`` row, and only the collector that ran the probe may
  say so. A Kubernetes deployment read from the API server is ``deployment-metadata``
  (``CONFIGURED``), because the manifest is what was asked for and what is running is a
  different question.
* **identity comes from the immutable field.** A commit is a sha, an image is a digest, a
  component is a purl at a version with its hash. A branch name, a tag and a version range
  are collected and kept as *attributes*, and a collector that has nothing else refuses the
  row rather than minting an identity from something that moves.
* **every row carries the evidence reference that produced it.** ``git:<repo>@<sha>``,
  ``oci:<image>@<digest>``, ``k8s:<cluster>/<namespace>/<name>``, ``probe:<host>:<pid>``,
  ``sbom:<document>#<purl>``. A row with no reference is refused here, so the store never has
  to decide what to do with one.

Then :func:`collect` merges the results into one inventory, refusing to let two transports
overwrite each other, and :func:`assemble` runs it all the way to a built chain:

    payloads → collect() → sbom_supply.from_inventory() → techbom.build() → the chain

Freshness is part of the model, not a footnote: a payload carries ``collected_at``, and a
row read three days ago is a fact about three days ago. :func:`freshness` measures it and
marks the transport stale — the rows are still imported, because a stale fact is better than
no fact, as long as nobody calls it live.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from . import sbom_supply as supply
from . import techbom as tb

SCHEMA = "cryptoscan.sbom-collector/1"

#: the transports this module knows, and the strongest class each can support. The value is
#: a *ceiling*: a collector may report lower, never higher, and the ceiling is a property of
#: the transport rather than of the code that parses it.
TRANSPORTS: dict[str, str] = {
    "git": "api-poll",
    "ci": "api-poll",
    "registry": "api-poll",
    "kubernetes": "deployment-metadata",
    "process": "process-trace",
    "host": "agent-inventory",
    "sbom": "sbom-import",
    "scan": "binary-scan",
    "cmdb": "cmdb-import",
}

#: the transports that may produce an ``OBSERVED`` row. Everything else is a document.
PROBE_TRANSPORTS: frozenset[str] = frozenset({"process"})

#: how long a read stays *live*. A day is the review's own cadence for a deployment snapshot;
#: a collector may ask for longer, and the freshness report says what it asked for.
STALE_AFTER_HOURS = 24


class Refused(Exception):
    """A payload this collector will not turn into rows."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _norm(value: Any) -> str:
    return tb._norm(value)


def _class_of(transport: str) -> str:
    return tb.BASES.get(TRANSPORTS.get(transport, "cmdb-import"), tb.IMPORTED)


def _digest_like(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text or text in ("latest", "main", "master", "head"):
        return False
    if ":" in text:
        algorithm, _, remainder = text.partition(":")
        return algorithm in ("sha256", "sha384", "sha512") and len(remainder) >= 16
    return len(text) >= 32 and all(char in "0123456789abcdef" for char in text)


def _split_coordinate(coordinate: Any, version: Any = None) -> tuple[str, str]:
    """``pkg:generic/openssl@3.0.13`` → (``pkg:generic/openssl``, ``3.0.13``).

    A component's identity is its coordinate *without* the version: the version is a layer
    that three transports report differently, and the chain keeps those layers apart. Merging
    on the versioned purl would turn one component into three components and lose the
    version conflict that is the finding.
    """
    text = _norm(coordinate)
    declared = _norm(version)
    if text.startswith("pkg:") and "@" in text:
        head, _, tail = text.rpartition("@")
        if head and tail and "/" in head:
            return head, tail
    return text, declared


def _stamp(body: Mapping[str, Any], collected_at: Any) -> Any:
    """The explicit timestamp if one was given, otherwise the timestamp the payload carries."""
    return collected_at or body.get("collected_at") or body.get("read_at") or None


def _row(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in (None, "", [], {})}


class _Collector:
    """One transport, and the rows it produced."""

    def __init__(self, transport: str, *, collected_at: Any = None,
                 subject: Any = None) -> None:
        if transport not in TRANSPORTS:
            raise Refused("UNKNOWN_TRANSPORT",
                          f"{transport or '(none)'} is not a transport this platform reads; "
                          f"expected one of {', '.join(sorted(TRANSPORTS))}")
        self.transport = transport
        self.basis = TRANSPORTS[transport]
        self.evidence_class = _class_of(transport)
        self.collected_at = collected_at
        self.subject = _norm(subject)
        self.rows: dict[str, list[dict[str, Any]]] = {}
        self.refusals: list[dict[str, Any]] = []

    # -- recording --------------------------------------------------------- #

    def add(self, section: str, row: Mapping[str, Any]) -> dict[str, Any]:
        self.rows.setdefault(section, []).append(dict(row))
        return self.rows[section][-1]

    def refuse(self, code: str, subject: Any, reason: Any) -> None:
        self.refusals.append({"code": code, "transport": self.transport,
                              "subject": str(subject or "(none)"), "reason": str(reason)})

    # -- the answer -------------------------------------------------------- #

    def result(self, *, rule: str) -> dict[str, Any]:
        counts = {section: len(rows) for section, rows in sorted(self.rows.items())}
        return {
            "schema": SCHEMA,
            "collector": self.transport,
            "transport": self.transport,
            "basis": self.basis,
            "class": self.evidence_class,
            "observed": self.evidence_class == tb.OBSERVED,
            "collected_at": self.collected_at,
            "subject": self.subject or None,
            "rows": self.rows,
            "counts": counts,
            "refusals": self.refusals,
            "statement": (f"{self.transport}: {sum(counts.values())} row(s) across "
                          f"{len(counts)} section(s) at {self.evidence_class}"
                          + (f"; {len(self.refusals)} refusal(s)" if self.refusals else "")),
            "rule": rule,
        }


# --------------------------------------------------------------------------- #
# git — repository and commit
# --------------------------------------------------------------------------- #

def from_git(payload: Mapping[str, Any] | None, *, collected_at: Any = None
             ) -> dict[str, Any]:
    """``repository + [commits]`` from a git host's API answer.

    A repository is identified by its full name; a commit by its sha. A *branch* is stored on
    the commit as an attribute, never as the commit's identity, because a branch name is a
    pointer that moves and the guide's whole point is that the chain must not move underneath
    a remediation.
    """
    body = payload if isinstance(payload, Mapping) else {}
    collected_at = _stamp(body, collected_at)
    repository = body.get("repository") if isinstance(body.get("repository"), Mapping) else body
    collector = _Collector("git", collected_at=collected_at,
                           subject=_norm(repository.get("full_name"))
                           or _norm(repository.get("name")))
    name = _norm(repository.get("full_name")) or _norm(repository.get("name"))
    if not name:
        collector.refuse("NO_IDENTITY", repository.get("url"),
                         "a git answer with no repository name or full_name cannot be placed: "
                         "a URL alone is a location, not an identity")
    else:
        collector.add("repositories", _row(
            name=name, url=repository.get("url") or repository.get("html_url"),
            vcs="git", default_branch=repository.get("default_branch"),
            applications=[_norm(item) for item in (repository.get("applications") or [])],
            basis=collector.basis, evidence_ref=f"git:{name}",
            collected_at=collected_at))

    for commit in body.get("commits") or []:
        if not isinstance(commit, Mapping):
            continue
        sha = _norm(commit.get("sha")) or _norm(commit.get("id"))
        if len(sha) < 7:
            collector.refuse(
                "MUTABLE_IDENTITY", sha or commit.get("ref") or commit.get("branch"),
                "a commit is named by its sha; a branch or tag name points at a commit that "
                "will not be the same commit tomorrow")
            continue
        collector.add("commits", _row(
            sha=sha, repository=name or None, author=commit.get("author"),
            committed_at=commit.get("committed_at") or commit.get("date"),
            message=commit.get("message"), branch=commit.get("branch"),
            basis=collector.basis, evidence_ref=f"git:{name or 'repository'}@{sha}",
            collected_at=collected_at))
    return collector.result(rule="a commit is a sha and a branch is a pointer: only the sha "
                                 "may anchor a provenance chain")


# --------------------------------------------------------------------------- #
# CI — build and artifact
# --------------------------------------------------------------------------- #

def from_ci(payload: Mapping[str, Any] | None, *, collected_at: Any = None
            ) -> dict[str, Any]:
    """``build + [artifacts]`` from a pipeline run.

    A build names the commit it built. An artifact names the build that produced it *and* a
    digest: a CI artefact identified by ``payments-api.jar`` is a filename, and a filename is
    overwritten on the next run.
    """
    body = payload if isinstance(payload, Mapping) else {}
    collected_at = _stamp(body, collected_at)
    run = body.get("build") if isinstance(body.get("build"), Mapping) else body
    name = (_norm(run.get("name")) or _norm(run.get("id"))
            or _norm(body.get("build_id")) or _norm(body.get("number")))
    collector = _Collector("ci", collected_at=collected_at, subject=name)
    if not name:
        collector.refuse("NO_IDENTITY", body.get("pipeline"),
                         "a pipeline answer with no build name or id cannot anchor an "
                         "artifact: the number is the identity")
    else:
        collector.add("builds", _row(
            name=name, commit=_norm(run.get("commit")) or _norm(body.get("commit")),
            repository=_norm(run.get("repository")),
            pipeline=run.get("pipeline") or body.get("pipeline"),
            status=run.get("status") or body.get("status") or "SUCCESS",
            started_at=run.get("started_at"), basis=collector.basis,
            evidence_ref=f"ci:{name}", collected_at=collected_at))

    for artifact in body.get("artifacts") or []:
        if not isinstance(artifact, Mapping):
            continue
        artifact_name = _norm(artifact.get("name")) or _norm(artifact.get("path"))
        digest = _norm(artifact.get("digest")) or _norm(artifact.get("sha256"))
        if not _digest_like(digest):
            collector.refuse(
                "ARTIFACT_WITHOUT_DIGEST", artifact_name,
                "the pipeline reports a name and no digest: a jar called "
                f"{artifact_name or '(unnamed)'} is overwritten on the next build, so it "
                "cannot anchor an SBOM")
            continue
        collector.add("artifacts", _row(
            name=artifact_name, digest=digest, build=name or None,
            kind=artifact.get("kind") or "BINARY", size=artifact.get("size"),
            basis=collector.basis,
            evidence_ref=f"ci:{name or 'build'}:{digest}", collected_at=collected_at))
    return collector.result(rule="an artifact anchors on a digest that the build produced; a "
                                 "filename is a label and is refused as an identity")


# --------------------------------------------------------------------------- #
# registry — the image and its layers
# --------------------------------------------------------------------------- #

def from_registry(payload: Mapping[str, Any] | None, *, collected_at: Any = None
                  ) -> dict[str, Any]:
    """``image + [layers]`` from an OCI manifest answer.

    The digest is the identity and the tag is recorded beside it, because a deployment that
    says ``payments-api:4.2.1`` has told you a name and the registry has told you which bytes
    that name currently means — and the two are not the same fact.
    """
    body = payload if isinstance(payload, Mapping) else {}
    collected_at = _stamp(body, collected_at)
    image = body.get("image") if isinstance(body.get("image"), Mapping) else body
    name = _norm(image.get("repository")) or _norm(image.get("name"))
    tag = _norm(image.get("tag")) or _norm(body.get("tag"))
    digest = _norm(image.get("digest")) or _norm(body.get("digest"))
    reference = f"{name}:{tag}" if name and tag else name
    collector = _Collector("registry", collected_at=collected_at, subject=reference)
    if not name:
        collector.refuse("NO_IDENTITY", image.get("digest"),
                         "a manifest with no repository name cannot be placed")
        return collector.result(rule="a registry answers with a digest; the tag is a pointer")
    if not _digest_like(digest):
        collector.refuse(
            "IMAGE_WITHOUT_DIGEST", reference,
            "the registry returned a tag and no digest: a tag is re-pushable, so an image "
            "identified by one would silently change under the deployment that names it")
        return collector.result(rule="a registry answers with a digest; the tag is a pointer")

    collector.add("images", _row(
        name=reference or digest, digest=digest, tag=tag,
        layers=[f"layer:{_short(layer)}" for layer in _layer_digests(body)],
        base=body.get("base"), basis=collector.basis,
        evidence_ref=f"oci:{name}@{digest}", collected_at=collected_at))
    for layer in _layers(body):
        collector.add("layers", _row(
            name=f"layer:{_short(layer['digest'])}", digest=layer["digest"],
            image=reference or None, base=body.get("base"),
            packages=[_norm(item) for item in (layer.get("packages") or [])],
            media_type=layer.get("media_type"), size=layer.get("size"),
            basis=collector.basis,
            evidence_ref=f"oci:{name}@{layer['digest']}", collected_at=collected_at))
    return collector.result(rule="the image digest anchors the layers; a layer is a digest and "
                                 "a size, not a name")


def _layers(body: Mapping[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for layer in body.get("layers") or []:
        if isinstance(layer, Mapping):
            digest = _norm(layer.get("digest"))
            if digest:
                found.append({**layer, "digest": digest})
        elif _digest_like(layer):
            found.append({"digest": _norm(layer)})
    return found


def _layer_digests(body: Mapping[str, Any]) -> list[str]:
    return [layer["digest"] for layer in _layers(body)]


def _short(digest: Any) -> str:
    text = str(digest or "")
    _, _, tail = text.partition(":")
    return (tail or text)[:12]


# --------------------------------------------------------------------------- #
# Kubernetes — deployment, pod, node
# --------------------------------------------------------------------------- #

def from_kubernetes(payload: Mapping[str, Any] | None, *, collected_at: Any = None
                    ) -> dict[str, Any]:
    """``deployments`` from the objects a cluster API returns.

    This is ``deployment-metadata``: a Deployment says what *should* run. What does run is a
    pod, and what is *loaded* in it is a process — so this collector stops at the pod and
    says so, rather than promoting a manifest into a runtime observation.
    """
    body = payload if isinstance(payload, Mapping) else {}
    collected_at = _stamp(body, collected_at)
    cluster = _norm(body.get("cluster")) or "cluster"
    collector = _Collector("kubernetes", collected_at=collected_at, subject=cluster)
    # a node's inventory answer names the physical host a pod sits on. It is *not* emitted
    # as a second host asset: the pod already carries it, and two rows for one server is a
    # duplicate rather than a richer record.
    nodes = {_norm(node.get("name")): node for node in (body.get("nodes") or [])
             if isinstance(node, Mapping) and _norm(node.get("name"))}

    for deployment in body.get("deployments") or []:
        if not isinstance(deployment, Mapping):
            continue
        name = _norm(deployment.get("name"))
        namespace = _norm(deployment.get("namespace")) or "default"
        image = _norm(deployment.get("image"))
        if not name:
            collector.refuse("NO_IDENTITY", deployment.get("image"),
                             "a Deployment object with no name cannot be placed")
            continue
        if not image:
            collector.refuse("DEPLOYMENT_WITHOUT_IMAGE", name,
                             "the Deployment names no image, so nothing in it can reach a "
                             "component")
            continue
        pods = []
        for pod in deployment.get("pods") or []:
            if not isinstance(pod, Mapping):
                continue
            pod_name = _norm(pod.get("name"))
            if not pod_name:
                collector.refuse("POD_WITHOUT_NAME", name,
                                 "a pod with no name cannot be referenced by a process")
                continue
            containers = []
            for container in pod.get("containers") or []:
                container_name = _norm(container if isinstance(container, str)
                                       else container.get("name"))
                if container_name:
                    containers.append(container_name)
            node_name = _norm(pod.get("node"))
            host = _norm(pod.get("host")) or _norm(
                (nodes.get(node_name) or {}).get("host"))
            pods.append(_row(
                name=pod_name, node=node_name or None, host=host or None,
                containers=containers, phase=pod.get("phase")))
        collector.add("deployments", _row(
            name=name, namespace=namespace, cluster=cluster, image=image,
            replica_set=_norm(deployment.get("replica_set")), pods=pods,
            basis=collector.basis,
            evidence_ref=f"k8s:{cluster}/{namespace}/{name}", collected_at=collected_at))
    return collector.result(rule="a Deployment says what should run; only a probe says what "
                                 "does, so this collector stops at the pod")


# --------------------------------------------------------------------------- #
# the process probe — the only collector that may say OBSERVED
# --------------------------------------------------------------------------- #

def from_process_probe(payload: Mapping[str, Any] | None, *, collected_at: Any = None
                       ) -> dict[str, Any]:
    """``processes`` and what they loaded, from a trace.

    This is the one transport that can produce an ``OBSERVED`` row, because it is the one
    that saw the kernel do it. A library version read here is a *runtime* version and keeps
    that name all the way up the chain: it never becomes the SBOM's declared version.
    """
    body = payload if isinstance(payload, Mapping) else {}
    collected_at = _stamp(body, collected_at)
    host = _norm(body.get("host"))
    collector = _Collector("process", collected_at=collected_at, subject=host)
    for process in body.get("processes") or []:
        if not isinstance(process, Mapping):
            continue
        name = _norm(process.get("name"))
        pid = process.get("pid")
        if not name:
            collector.refuse("NO_IDENTITY", pid,
                             "a process row with no name cannot be referenced; a pid alone "
                             "is reused by the kernel")
            continue
        loads: list[str] = []
        for library in process.get("libraries") or []:
            if not isinstance(library, Mapping):
                continue
            library_name = _norm(library.get("name")) or _norm(library.get("path"))
            if not library_name:
                collector.refuse("LIBRARY_WITHOUT_NAME", name,
                                 "a loaded object with no name or path cannot be placed")
                continue
            digest = _norm(library.get("sha256"))
            # a probe that says which package ships the loaded object gives the chain the
            # edge it needs: the SBOM lists the package, and the process loaded it
            coordinate, _ = _split_coordinate(
                _norm(library.get("package")) or library_name, library.get("version"))
            collector.add("software", _row(
                coordinate=coordinate, name=coordinate,
                version=library.get("version"), origin="PROBE", scope="RUNTIME",
                component_type="library" if library.get("crypto") else None,
                crypto_bearing=bool(library.get("crypto")),
                direct=False, path=library.get("path"), sha256=digest,
                mapped=library_name, basis=collector.basis,
                version_sources=([{"source": "process-map", "value": library.get("version"),
                                   "class": tb.RUNTIME_OBSERVED,
                                   "evidence_id": f"probe:{host}:{pid}"}]
                                 if library.get("version") else None),
                evidence_ref=f"probe:{host}:{pid}:{library_name}", collected_at=collected_at))
            loads.append(coordinate)
        for operation in process.get("operations") or []:
            if not isinstance(operation, Mapping):
                continue
            algorithm = _norm(operation.get("algorithm"))
            if not algorithm:
                collector.refuse("OPERATION_WITHOUT_ALGORITHM", name,
                                 "a traced operation with no algorithm is a verb: SIGN of "
                                 "what?")
                continue
            key_size = operation.get("key_size")
            library, _ = _split_coordinate(
                _norm(process.get("provider")) or _norm(operation.get("library")),
                operation.get("version"))
            collector.add("crypto", _row(
                id=f"{name}:{algorithm}:{operation.get('operation')}",
                algorithm=algorithm, key_size=key_size, family=operation.get("family"),
                mode=operation.get("mode"), curve=operation.get("curve"),
                library=library or None, operation=_norm(operation.get("operation")),
                process=name, application=_norm(process.get("application")),
                pod=_norm(process.get("pod")), hash=operation.get("hash"),
                purpose=operation.get("purpose"),
                observed_at=operation.get("observed_at") or collected_at,
                basis=collector.basis,
                evidence_ref=f"probe:{host}:{pid}:{algorithm}"
                             f":{_norm(operation.get('operation')) or 'op'}",
                collected_at=collected_at))
        collector.add("processes", _row(
            name=name, pid=pid, host=host or None,
            application=_norm(process.get("application")),
            pod=_norm(process.get("pod")), loads=loads, basis=collector.basis,
            evidence_ref=f"probe:{host}:{pid}", collected_at=collected_at))
    return collector.result(rule="a trace is the only transport that may say OBSERVED, and a "
                                 "runtime version stays a runtime version")


# --------------------------------------------------------------------------- #
# the SBOM document and the host inventory
# --------------------------------------------------------------------------- #

def from_image_scan(payload: Mapping[str, Any] | None, *, collected_at: Any = None
                    ) -> dict[str, Any]:
    """``images + software`` from an image scanner's answer (Trivy, Grype, Syft).

    A scan reads files out of the image, so its class is ``STATIC_OBSERVED`` — stronger than
    the SBOM's ``IMPORTED`` and still not a runtime observation. This is also the collector
    that says *what is installed in which image*, which is the edge that lets a component be
    found installed anywhere at all.
    """
    body = payload if isinstance(payload, Mapping) else {}
    collected_at = _stamp(body, collected_at)
    image = body.get("image") if isinstance(body.get("image"), Mapping) else body
    name = _norm(image.get("name")) or _norm(image.get("repository"))
    digest = _norm(image.get("digest"))
    collector = _Collector("scan", collected_at=collected_at, subject=name)
    if not name or not _digest_like(digest):
        collector.refuse("IMAGE_WITHOUT_DIGEST", name or digest,
                         "a scan result that does not name the image digest cannot say which "
                         "bytes it read")
        return collector.result(rule="a scanner says what is in a digest, not in a tag")
    installed: list[str] = []
    for package in body.get("packages") or []:
        if not isinstance(package, Mapping):
            continue
        package_name = _norm(package.get("name")) or _norm(package.get("coordinate"))
        version = _norm(package.get("version"))
        if not package_name or not version:
            collector.refuse("UNPINNED_PACKAGE", package_name,
                             "a package with no version cannot be compared with a manifest")
            continue
        coordinate, _ = _split_coordinate(
            _norm(package.get("coordinate")) or f"pkg:generic/{package_name}@{version}",
            version)
        collector.add("software", _row(
            coordinate=coordinate, name=package_name, version=version, origin="SCAN",
            scope=_norm(package.get("scope")).upper() or "RUNTIME",
            component_type="library" if package.get("crypto") else None,
            crypto_bearing=bool(package.get("crypto")), direct=False,
            version_sources=[{"source": "image-scan", "value": version,
                              "class": tb.STATIC_OBSERVED,
                              "evidence_id": f"scan:{name}@{digest}"}],
            basis=collector.basis,
            evidence_ref=f"scan:{name}@{digest}#{coordinate}", collected_at=collected_at))
        installed.append(coordinate)
    collector.add("images", _row(
        name=name, digest=digest, tag=image.get("tag"), installed=installed,
        basis=collector.basis, evidence_ref=f"scan:{name}@{digest}",
        collected_at=collected_at))
    return collector.result(rule="a scanner reads files: STATIC_OBSERVED, never OBSERVED")


def from_sbom(payload: Mapping[str, Any] | None, *, collected_at: Any = None
              ) -> dict[str, Any]:
    """``software + dependencies`` from a normalized SBOM component list.

    The input is the normalized model (``purl, name, version, scope, hashes, depends_on``)
    that :func:`devsecops.sbom.import_sbom` already produces from CycloneDX and SPDX, so this
    collector never re-parses a standard. A component with no version, or with a range
    instead of a version, is refused: *"openssl ^3.0"* is a manifest line, not a component.
    """
    body = payload if isinstance(payload, Mapping) else {"components": payload}
    collected_at = _stamp(body, collected_at)
    document = _norm(body.get("document")) or _norm(body.get("name")) or "sbom"
    artifact = _norm(body.get("artifact"))
    collector = _Collector("sbom", collected_at=collected_at, subject=document)
    coordinates: list[str] = []
    for component in body.get("components") or []:
        if not isinstance(component, Mapping):
            continue
        coordinate, declared = _split_coordinate(
            _norm(component.get("purl")) or _norm(component.get("name")),
            component.get("version"))
        version = _norm(component.get("version")) or declared
        if not coordinate:
            collector.refuse("NO_IDENTITY", component.get("name"),
                             "an SBOM component with neither purl nor name cannot be placed")
            continue
        if not version or version[:1] in "^~><=*":
            collector.refuse(
                "UNPINNED_VERSION", coordinate,
                "the component carries "
                f"{version or 'no version'}; a range is a manifest declaration and an SBOM "
                "that cannot say which version is in the artifact answers nothing")
            continue
        library = _norm(component.get("component_type")).lower() in ("library",
                                                                     "crypto_library")
        collector.add("software", _row(
            coordinate=coordinate, name=_norm(component.get("name")) or coordinate,
            version=version, purl=coordinate if coordinate.startswith("pkg:") else None,
            origin="SBOM", scope=_norm(component.get("scope")).upper() or "RUNTIME",
            component_type="library" if library else None,
            crypto_bearing=bool(component.get("crypto_bearing")),
            direct=bool(component.get("direct")),
            product=_norm(component.get("product")),
            version_sources=[{"source": "sbom", "value": version, "class": tb.IMPORTED,
                              "evidence_id": f"sbom:{document}#{coordinate}"}],
            basis=collector.basis,
            evidence_ref=f"sbom:{document}#{coordinate}", collected_at=collected_at))
        coordinates.append(coordinate)
        for dependency in component.get("depends_on") or []:
            collector.add("dependencies", _row(
                source=coordinate, target=_norm(dependency), type="depends_on",
                basis=collector.basis,
                evidence_ref=f"sbom:{document}#{coordinate}->{_norm(dependency)}",
                collected_at=collected_at))
    if coordinates:
        collector.add("sboms", _row(
            name=document, artifact=artifact or None, format=body.get("format")
            or "CycloneDX-1.6", tool=body.get("tool"), serial=body.get("serial"),
            generated_at=body.get("generated_at"), components=coordinates,
            basis=collector.basis, evidence_ref=f"sbom:{document}", collected_at=collected_at))
    return collector.result(rule="an SBOM states a version, not a range, and its components "
                                 "are imported at IMPORTED until a collector says otherwise")


def from_cmdb(payload: Mapping[str, Any] | None, *, collected_at: Any = None
              ) -> dict[str, Any]:
    """``applications`` and their business systems, from the CMDB.

    Every other collector names an application; this is the one that says the application
    exists. Without it a repository, a release and a process all point at a name nobody has
    registered, which is how a chain acquires an owner it cannot prove.
    """
    body = payload if isinstance(payload, Mapping) else {}
    collected_at = _stamp(body, collected_at)
    collector = _Collector("cmdb", collected_at=collected_at,
                           subject=_norm(body.get("source")) or "cmdb")
    for row in body.get("applications") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        identifier = _norm(row.get("id"))
        if not name:
            collector.refuse("NO_IDENTITY", identifier or row.get("system"),
                             "a CMDB row with no application name cannot be placed")
            continue
        collector.add("applications", _row(
            id=identifier or None, name=name, system=_norm(row.get("system")),
            owner=row.get("owner"), version=row.get("version"),
            criticality=row.get("criticality"), basis=collector.basis,
            evidence_ref=f"cmdb:{identifier or name}", collected_at=collected_at))
    return collector.result(rule="an application exists because the CMDB registers it: every "
                                 "other collector only names one")


def from_host_inventory(payload: Mapping[str, Any] | None, *, collected_at: Any = None
                        ) -> dict[str, Any]:
    """``hosts + software`` from an agent's package inventory.

    An installed package is a filesystem fact, so this is ``agent-inventory``
    (``CONFIGURED``): stronger than an SBOM's word, weaker than a process that mapped it.
    """
    body = payload if isinstance(payload, Mapping) else {}
    collected_at = _stamp(body, collected_at)
    host = _norm(body.get("host")) or _norm(body.get("asset_id"))
    collector = _Collector("host", collected_at=collected_at, subject=host)
    if not host:
        collector.refuse("NO_IDENTITY", body.get("os"),
                         "a package inventory with no host cannot be placed: the host is what "
                         "makes the list a fact about a machine")
        return collector.result(rule="installed is a filesystem fact on a named host")
    installed: list[str] = []
    for package in body.get("packages") or []:
        if not isinstance(package, Mapping):
            continue
        name = _norm(package.get("name")) or _norm(package.get("coordinate"))
        version = _norm(package.get("version"))
        if not name or not version:
            collector.refuse("UNPINNED_PACKAGE", name,
                             "an installed package with no version cannot be compared with "
                             "the SBOM's, which is the only reason to collect it")
            continue
        coordinate = f"pkg:generic/{name}"
        collector.add("software", _row(
            coordinate=coordinate, name=name, version=version, origin="SCAN",
            scope=_norm(package.get("scope")).upper() or "RUNTIME",
            component_type="library" if package.get("crypto") else None,
            crypto_bearing=bool(package.get("crypto")), arch=package.get("arch"),
            basis=collector.basis,
            evidence_ref=f"host:{host}:{coordinate}", collected_at=collected_at))
        installed.append(coordinate)
    collector.add("hosts", _row(
        name=host, type=_norm(body.get("type")).upper() or "PHYSICAL_SERVER",
        os=body.get("os"), datacenter=body.get("datacenter"), rack=body.get("rack"),
        installed=installed, basis=collector.basis, evidence_ref=f"host:{host}",
        collected_at=collected_at))
    return collector.result(rule="what is installed on a host is a filesystem fact: it is "
                                 "CONFIGURED, and it is not what the host is running")


# --------------------------------------------------------------------------- #
# Freshness, merge, and the whole chain
# --------------------------------------------------------------------------- #

def _parse(value: Any) -> datetime | None:
    text = _norm(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def freshness(result: Mapping[str, Any], *, as_of: Any = None,
              stale_after_hours: int = STALE_AFTER_HOURS) -> dict[str, Any]:
    """How old the read is, and whether it may be called live.

    The rows are not discarded when a transport is stale — a fact read yesterday is still a
    fact — but the report says which transport it came from and how old it is, so nobody
    quotes a week-old deployment snapshot as the current estate.
    """
    now = _parse(as_of) or datetime.now(timezone.utc)
    collected = _parse(result.get("collected_at"))
    if collected is None:
        return {"transport": result.get("transport"), "age_hours": None, "stale": True,
                "collected_at": result.get("collected_at"),
                "statement": (f"{result.get('transport')}: no collection timestamp, so the "
                              "read cannot be called live"),
                "rule": "a read with no timestamp is a document of unknown age"}
    age = (now - collected).total_seconds() / 3600.0
    stale = age > stale_after_hours
    return {
        "transport": result.get("transport"), "age_hours": round(age, 2), "stale": stale,
        "collected_at": result.get("collected_at"),
        "stale_after_hours": stale_after_hours,
        "statement": (f"{result.get('transport')}: read {age:.1f}h ago, "
                      + ("STALE" if stale else "LIVE")),
        "rule": "live means recently read: a stale row is imported and labelled, never "
                "silently promoted to current",
    }


#: what makes two rows the same row when two transports describe one asset, and which field
#: decides whether they agree. A disagreement on the decider is a conflict, not an update.
IDENTITY_FIELDS: dict[str, tuple[str, str]] = {
    "images": ("name", "digest"),
    "artifacts": ("name", "digest"),
    "repositories": ("name", "url"),
    "commits": ("sha", "repository"),
    "hosts": ("name", "os"),
    "processes": ("name", "pid"),
}


def collect(*results: Mapping[str, Any], as_of: Any = None,
            stale_after_hours: int = STALE_AFTER_HOURS) -> dict[str, Any]:
    """Merge collector results into one inventory, keeping their disagreements.

    Two transports describing one asset is normal — a registry and a Deployment both name the
    image. Two transports *contradicting* each other is a finding, and it is recorded rather
    than resolved by whichever arrived last: the chain below it would otherwise be built on
    an arbitrary winner.
    """
    inventory: dict[str, Any] = {"applications": [], "software": [], "dependencies": [],
                                 "supply": {}}
    for section in ("vendors", "crypto", "hardware", "certificates", "endpoints", "hosts",
                    "repositories", "commits", "builds", "artifacts", "layers", "images",
                    "releases", "sboms", "deployments", "processes"):
        inventory[section] = []
        inventory["supply"][section] = inventory[section]
    for section in ("software", "dependencies", "applications"):
        inventory["supply"][section] = inventory[section]

    seen: dict[tuple[str, str], dict[str, Any]] = {}
    conflicts: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    transports: dict[str, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, Mapping):
            continue
        transport = _norm(result.get("transport")) or _norm(result.get("collector"))
        refusals.extend(dict(row) for row in result.get("refusals") or [])
        fresh = freshness(result, as_of=as_of, stale_after_hours=stale_after_hours)
        transports[transport] = {
            "class": result.get("class"), "basis": result.get("basis"),
            "rows": sum((result.get("counts") or {}).values()),
            "refusals": len(result.get("refusals") or []),
            "freshness": fresh,
        }
        for section, rows in (result.get("rows") or {}).items():
            bucket = inventory["supply"].setdefault(section, [])
            if bucket is not inventory.get(section) and section in inventory:
                bucket = inventory[section]
            identity = IDENTITY_FIELDS.get(section)
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                if section == "software":
                    key = (section, _norm(row.get("coordinate")
                                          or row.get("name")).lower())
                    previous = seen.get(key)
                    if previous is not None:
                        _merge_versions(previous, row, transport=transport,
                                        conflicts=conflicts)
                        continue
                    stored = {**dict(row), "collector": transport}
                    seen[key] = stored
                    bucket.append(stored)
                    continue
                if identity is not None:
                    key = (section, _norm(row.get(identity[0])).lower())
                    previous = seen.get(key)
                    if previous is not None:
                        if _norm(previous.get(identity[1])).lower() == \
                                _norm(row.get(identity[1])).lower():
                            # two transports agreeing about one asset: keep both facts.
                            # A registry knows the layers and a scanner knows the packages;
                            # dropping the second row would drop half the asset.
                            _absorb(previous, row)
                            continue
                        if _norm(previous.get(identity[1])).lower() != \
                                _norm(row.get(identity[1])).lower():
                            conflicts.append({
                                "code": "COLLECTOR_DISAGREEMENT", "section": section,
                                "asset": row.get(identity[0]), "field": identity[1],
                                "kept": previous.get(identity[1]),
                                "kept_from": previous.get("collector"),
                                "reported": row.get(identity[1]),
                                "reported_from": transport,
                                "reason": (f"{transport} and {previous.get('collector')} "
                                           f"disagree on {identity[1]} for "
                                           f"{row.get(identity[0])}: both are kept and neither "
                                           "overwrites the other"),
                            })
                        continue
                    stored = {**dict(row), "collector": transport}
                    seen[key] = stored
                    bucket.append(stored)
                else:
                    bucket.append({**dict(row), "collector": transport})
    for section in ("releases", "sboms"):
        inventory["supply"][section] = inventory.get(section, [])
    stale = [name for name, entry in transports.items() if entry["freshness"]["stale"]]
    return {
        "schema": SCHEMA,
        "inventory": inventory,
        "transports": transports,
        "conflicts": conflicts,
        "refusals": refusals,
        "counts": {
            "transports": len(transports),
            "rows": sum(entry["rows"] for entry in transports.values()),
            "conflicts": len(conflicts),
            "refusals": len(refusals),
            "stale": len(stale),
        },
        "statement": (f"{sum(entry['rows'] for entry in transports.values())} row(s) from "
                      f"{len(transports)} transport(s)"
                      + (f"; {len(conflicts)} disagreement(s) kept" if conflicts else "")
                      + (f"; {len(refusals)} refusal(s)" if refusals else "")
                      + (f"; {len(stale)} stale transport(s): {', '.join(sorted(stale))}"
                         if stale else "")),
        "rule": ("a transport may only claim the class it can support, and two transports "
                 "that disagree are a finding rather than a last-write-wins"),
    }


def _absorb(previous: dict[str, Any], row: Mapping[str, Any]) -> None:
    """Fold an agreeing row into the one already kept: lists union, blanks are filled."""
    for key, value in row.items():
        if key == "collector":
            continue
        current = previous.get(key)
        if isinstance(current, list) and isinstance(value, list):
            merged = list(current)
            for item in value:
                if item not in merged:
                    merged.append(item)
            previous[key] = merged
        elif current in (None, "", [], {}) and value not in (None, "", [], {}):
            previous[key] = value


def _merge_versions(previous: dict[str, Any], row: Mapping[str, Any], *, transport: str,
                    conflicts: list[dict[str, Any]]) -> None:
    """One component, several version observations: keep them all, name the strongest.

    An SBOM says 3.0.13 and a probe says 3.0.11 loaded. That is not a disagreement to
    resolve — it is two layers of one component, and collapsing it into a winner would
    destroy the finding the chain exists to publish.
    """
    sources = list(previous.get("version_sources") or [])
    known = {(entry.get("source"), entry.get("value")) for entry in sources}
    for entry in row.get("version_sources") or []:
        if (entry.get("source"), entry.get("value")) not in known:
            sources.append(dict(entry))
    previous["version_sources"] = sources
    previous["crypto_bearing"] = bool(previous.get("crypto_bearing")
                                      or row.get("crypto_bearing"))
    previous["direct"] = bool(previous.get("direct") or row.get("direct"))
    previous["component_type"] = previous.get("component_type") or row.get("component_type")
    declared = next((entry for entry in sources
                     if str(entry.get("source") or "").lower() in
                     ("sbom", "manifest", "lockfile")), None)
    ranked = sorted(sources, key=lambda entry: -tb.CONFIDENCE.get(
        str(entry.get("class") or tb.IMPORTED).upper(), 0))
    chosen = declared or (ranked[0] if ranked else None)
    if chosen:
        previous["version"] = chosen.get("value") or previous.get("version")
    previous.setdefault("also_reported_by", [])
    if transport not in previous["also_reported_by"]:
        previous["also_reported_by"].append(transport)
    digests = {_norm(entry.get("sha256")) for entry in
               (previous, row) if _norm(entry.get("sha256"))}
    if len(digests) > 1:
        conflicts.append({
            "code": "COLLECTOR_DISAGREEMENT", "section": "software",
            "asset": previous.get("coordinate"), "field": "sha256",
            "kept": previous.get("sha256"), "kept_from": previous.get("collector"),
            "reported": row.get("sha256"), "reported_from": transport,
            "reason": (f"{transport} and {previous.get('collector')} read different bytes for "
                       f"{previous.get('coordinate')}: both are kept"),
        })


def assemble(*results: Mapping[str, Any], as_of: Any = None,
             environment: Any = "PRODUCTION", estate_id: Any = None,
             stale_after_hours: int = STALE_AFTER_HOURS) -> dict[str, Any]:
    """Payloads → one inventory → one estate → one chain, with every report attached."""
    from . import sbom_dependency as sd  # noqa: PLC0415 — avoids a circular import at load

    collected = collect(*results, as_of=as_of, stale_after_hours=stale_after_hours)
    built = supply.from_inventory(collected["inventory"], environment=environment,
                                  estate_id=estate_id)
    bom = tb.build(built["estate"])
    levels = sd.levels(bom)
    return {
        "schema": SCHEMA,
        "collected": collected,
        "supply": built,
        "bom": bom,
        "levels": levels,
        "statement": (f"{collected['statement']}; {len(bom['assets'])} asset(s) and "
                      f"{len(bom['claims'])} claim(s) in the chain, "
                      + ", ".join(f"{name} {count}" for name, count in levels.items() if count)),
        "rule": ("live collection ends in a built projection, not in a JSON dump: a collector "
                 "that cannot be walked to a business system has collected nothing yet"),
    }


def fingerprint(payload: Any) -> str:
    """A stable short hash of a payload, so an evidence reference can name what was read."""
    text = repr(sorted(payload.items())) if isinstance(payload, Mapping) else repr(payload)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def collectors() -> dict[str, Any]:
    """The registry: transport → collector, in the order a bank's systems are read."""
    return {
        "git": from_git, "ci": from_ci, "registry": from_registry,
        "kubernetes": from_kubernetes, "process": from_process_probe,
        "sbom": from_sbom, "scan": from_image_scan, "host": from_host_inventory,
        "cmdb": from_cmdb,
    }


def collect_all(payloads: Iterable[Mapping[str, Any]], *, as_of: Any = None) -> list[Any]:
    """Read every payload with the collector its ``transport`` names, refusing the rest."""
    registry = collectors()
    results: list[Any] = []
    for payload in payloads:
        if not isinstance(payload, Mapping):
            continue
        transport = _norm(payload.get("transport")).lower()
        collector = registry.get(transport)
        if collector is None:
            outcomes = _Collector("git")  # a valid collector only to record the refusal
            outcomes.transport = transport or "(none)"
            outcomes.refuse("UNKNOWN_TRANSPORT", transport,
                            f"{transport or '(none)'} has no collector; the payload is not "
                            "read and the inventory is missing a transport")
            results.append({"schema": SCHEMA, "collector": transport, "transport": transport,
                            "basis": None, "class": None, "collected_at": None,
                            "rows": {}, "counts": {},
                            "refusals": outcomes.refusals,
                            "statement": f"{transport or '(none)'}: not collected",
                            "rule": "an unknown transport is refused by name"})
            continue
        results.append(collector(payload, collected_at=payload.get("collected_at") or as_of))
    return results
