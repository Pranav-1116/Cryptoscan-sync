"""The supply chain as the *store* knows it: an inventory → the twelve levels.

Guide 175 built the chain the review draws — business system → application → repository →
commit → build → artifact → image → deployment → pod / VM / host → process → component →
crypto capability — and built it from a fixture. A chain that only exists in a harness is a
demonstration; this module is the bridge from the inventory the platform already gathers to
that chain, so production gets the same levels.

The hard part is not the field names, it is the same one :mod:`cbom.techbom_estate` has:

* **a stored row is not an observation.** A row saying ``image payments-api:4.2.1 was
  deployed`` is the residue of a deployment controller's API answer read back through a
  database. Calling that ``OBSERVED`` would poison every dependency drawn from it, so each
  section maps to the weakest basis its provenance supports
  (:data:`BASIS_BY_SECTION`), and a row may only be stronger than that if it carries its
  own ``basis`` — and even then only through the whitelist below.
* **a row with no evidence reference is skipped, by name.** An asset with no evidence id is
  a claim, and this build refuses to place one.
* **nothing is joined by name.** A build names its own commit column, an artifact names its
  own build column, a layer names its packages. Where a reference is missing the edge is
  missing: a chain with a guessed hop is worse than a chain with a gap, because the gap is
  visible and the guess is not.
* **the classes travel.** ``inventory → estate → techbom.build`` keeps the class each edge
  was given, so ``sbom_dependency``'s readers (a transitive dependency, a state, a version
  layer) answer on the same graph the bank's own rows produced.

The inventory shape this reads::

    {
      "applications": [{"id", "name", "system", "version"}],
      "software":     [{"coordinate", "name", "version", "origin", "scope", "direct",
                        "component_type", "crypto_bearing", "declared_in",
                        "version_sources": [{"source", "value", "class", "evidence_id"}]}],
      "dependencies": [{"source", "target", "type"}],
      "supply": {
        "repositories": [{"name", "url", "applications", "default_branch"}],
        "commits":      [{"sha", "repository", "author", "committed_at"}],
        "builds":       [{"name", "commit", "repository", "pipeline", "status"}],
        "artifacts":    [{"name", "digest", "build", "kind", "size"}],
        "layers":       [{"name", "image", "base", "packages": [...]}],
        "images":       [{"name", "digest", "artifact", "tag", "base", "layers": [...]}],
        "releases":     [{"name", "application", "version", "artifact"}],
        "sboms":        [{"name", "artifact", "format", "tool", "serial", "components": [...]}],
        "deployments":  [{"name", "image", "namespace", "cluster", "pods": [...]}],
        "processes":    [{"name", "pid", "application", "host", "loads": [...]}]
      }
    }

Every section is optional: an inventory with no ``supply`` block produces the levels it can
and reports the rest as gaps rather than as empty answers.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from . import cbom_dependency as cd
from . import nbom_graph as n
from . import sbom_dependency as sd
from . import techbom as tb
from .nbom_graph import part

SCHEMA = "cryptoscan.sbom-supply/1"

#: the class a section's rows support when the row does not carry a stronger basis. A
#: manifest is not a filesystem, a deployment controller's answer is not a syscall, and a
#: scan row is not a runtime observation.
BASIS_BY_SECTION: dict[str, str] = {
    "repositories": "api-poll",
    "commits": "api-poll",
    "builds": "api-poll",
    "artifacts": "agent-inventory",
    "layers": "sbom-import",
    "images": "agent-inventory",
    "releases": "api-poll",
    "sboms": "sbom-import",
    "deployments": "deployment-metadata",
    "processes": "process-trace",
    "software": "sbom-import",
    "applications": "cmdb-import",
    "dependencies": "sbom-import",
    "crypto": "capability-list",
    "vendors": "vendor-datasheet",
    "hardware": "cmdb-import",
    "certificates": "cmdb-import",
    "endpoints": "config-parse",
}

#: the asset kind a hardware row becomes, by the type it declares
HARDWARE_KINDS: dict[str, str] = {"HSM": "HSM", "TPM": "TPM", "CPU": "CPU", "KMS": "KMS",
                                  "HOST": "HOST", "SERVER": "PHYSICAL_SERVER"}

#: the bases a *stored row* may ask for on its own. The probe bases are absent on purpose:
#: a row read back through a database cannot make a syscall, so a store that claims
#: ``runtime-probe`` on a stored row is claiming a collector's work in the collector's name.
STORED_BASES: frozenset[str] = frozenset({
    "api-poll", "agent-inventory", "cmdb-import", "deployment-metadata", "sbom-import",
    "scan-manifest", "vendor-datasheet", "code-analysis", "operator-registration",
    "capability-list", "dependency-graph", "config-parse",
})

#: the bases that only a probe may claim. A stored row may still carry one — a process trace
#: is a real thing that happened — but only when it hands over the collector's own evidence
#: reference, because the class then belongs to the collector and not to this adapter.
PROBE_BASES: frozenset[str] = frozenset({
    "runtime-probe", "process-trace", "runtime-observation", "packet-capture",
    "tls-handshake", "passive-capture",
})


def _explicit_evidence(row: Mapping[str, Any]) -> bool:
    for key in ("evidence_ref", "evidence_id", "evidence_ids", "evidence_links"):
        value = row.get(key)
        if isinstance(value, (list, tuple, set)) and any(_norm(item) for item in value):
            return True
        if not isinstance(value, (list, tuple, set)) and _norm(value):
            return True
    return False


def _norm(value: Any) -> str:
    return tb._norm(value)


def _skip(skipped: list[dict[str, Any]], kind: Any, subject: Any, reason: Any,
          *, code: Any = None) -> None:
    skipped.append({"kind": str(kind or "ROW"), "subject": str(subject or "(none)"),
                    "code": code, "reason": str(reason)})


def _evidence(row: Mapping[str, Any], kind: str, identifier: Any = None) -> list[str]:
    """The evidence a stored row carries: its references, or its own identifier."""
    found: list[str] = []
    for key in ("evidence_ref", "evidence_id", "evidence_ids", "evidence_links"):
        value = row.get(key)
        if isinstance(value, (list, tuple, set)):
            found.extend(_norm(item) for item in value if _norm(item))
        elif _norm(value):
            found.append(_norm(value))
    reference = _norm(identifier) or _norm(row.get("id")) or _norm(row.get("name"))
    if reference:
        found.append(f"{kind.lower()}:{reference}")
    return sorted(dict.fromkeys(found))


def _basis(row: Mapping[str, Any], section: str, skipped: list[dict[str, Any]],
           subject: Any) -> str | None:
    """The class this row supports, or ``None`` when it cannot be given one honestly."""
    default = BASIS_BY_SECTION.get(section, "cmdb-import")
    asked = _norm(row.get("basis") or row.get("source_basis")).lower()
    if not asked:
        return default
    if asked in PROBE_BASES and asked in tb.BASES:
        if _explicit_evidence(row):
            return asked
        _skip(skipped, section, subject,
              f"it asks for {asked!r}, which only a probe may claim, and hands over no "
              "collector evidence reference: the class would be this adapter's, not the "
              "collector's", code="PROBE_BASIS_WITHOUT_EVIDENCE")
        return None
    if asked in STORED_BASES and asked in tb.BASES:
        return asked
    _skip(skipped, section, subject,
          f"its basis {asked!r} is not one a stored row can claim; expected one of a "
          "collector that ran, and a stored row cannot claim a probe", code="UNKNOWN_BASIS")
    return None


def _place(builder: Any, skipped: list[dict[str, Any]], subject_kind: str, subject: Any,
           /, **kwargs: Any) -> dict[str, Any] | None:
    """Run a builder, turning its refusal into a reported skip rather than an exception."""
    try:
        return builder(**kwargs)
    except tb.ClaimRefused as exc:
        _skip(skipped, subject_kind, subject, str(exc), code=exc.code)
        return None


def from_inventory(inventory: Mapping[str, Any] | None, *, environment: Any = None,
                   estate_id: Any = None, expected: Mapping[str, int] | None = None,
                   gaps: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """One gathered inventory → an estate document for ``build()``, plus what was skipped."""
    inv = inventory if isinstance(inventory, Mapping) else {}
    environment_text = (_norm(environment) or _norm(inv.get("environment"))
                        or "PRODUCTION").upper()
    estate_text = _norm(estate_id) or "sbom-supply:" + environment_text.lower()
    supply = inv.get("supply") if isinstance(inv.get("supply"), Mapping) else {}

    parts: list[Any] = []
    skipped: list[dict[str, Any]] = []
    placed: dict[str, int] = {}
    rows_by_name: dict[str, dict[str, Any]] = {}
    placed_assets: list[str] = []

    def count(section: str) -> None:
        placed[section] = placed.get(section, 0) + 1

    def remember(row: Mapping[str, Any], *, section: str) -> None:
        count(section)
        name = _norm(row.get("name")) or _norm(row.get("coordinate"))
        if name:
            rows_by_name[name] = row

    def rows(section: str) -> list[Mapping[str, Any]]:
        found = supply.get(section)
        if not isinstance(found, list):
            found = inv.get(section)
        if not isinstance(found, list):
            return []
        return [row for row in found if isinstance(row, Mapping)]

    # ---- business system → application ------------------------------------ #
    applications: dict[str, dict[str, Any]] = {}
    systems: dict[str, dict[str, Any]] = {}
    for row in inv.get("applications") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        subject = name or row.get("id")
        evidence = _evidence(row, "system")
        if not name or not evidence:
            _skip(skipped, "APPLICATION", subject,
                  "a row with no name or no evidence reference is a claim, not an asset")
            continue
        basis = _basis(row, "applications", skipped, subject)
        if basis is None:
            continue
        application = n.service_of(name=name, kind="APPLICATION", version=row.get("version"),
                                      owner=row.get("owner"), evidence_ids=evidence)
        applications[name] = application
        remember(row, section="applications")
        placed_assets.append(name)
        block: list[Any] = [application]
        system = _norm(row.get("system"))
        if system:
            if system not in systems:
                systems[system] = n.service_of(name=system, kind="BUSINESS_SYSTEM",
                                               evidence_ids=evidence)
                block.append(systems[system])
                placed_assets.append(system)
            block.append(part(claims=[tb.claim(system, "CONTAINS", name, basis="cmdb-import",
                                               evidence_ids=evidence)]))
        parts.append(part(*block))

    # ---- software components ---------------------------------------------- #
    components: dict[str, dict[str, Any]] = {}
    for row in inv.get("software") or []:
        if not isinstance(row, Mapping):
            continue
        coordinate = _norm(row.get("coordinate")) or _norm(row.get("name"))
        evidence = _evidence(row, "software", coordinate)
        if not coordinate or not evidence:
            _skip(skipped, "COMPONENT", coordinate or row.get("name"),
                  "a software row with no coordinate or no evidence reference cannot be "
                  "placed as a component")
            continue
        basis = _basis(row, "software", skipped, coordinate)
        if basis is None:
            continue
        scope = _norm(row.get("scope")).upper() or "RUNTIME"
        version_sources = [claim for claim in (row.get("version_sources") or [])
                           if isinstance(claim, Mapping)]
        library = _norm(row.get("component_type")).lower() in ("library", "crypto_library")
        if library:
            # a crypto library is a different kind from a package: a process loads it and
            # the SBOM's own list does not contain it
            asset = tb.asset("CRYPTO_LIBRARY", coordinate, version=row.get("version"),
                             scope=scope, direct=bool(row.get("direct")),
                             crypto_capable=bool(row.get("crypto_bearing")),
                             version_claims=version_sources, evidence_ids=evidence)
            block = part(asset)
        else:
            block = sd.component(name=coordinate, version=row.get("version"),
                                 purl=row.get("purl"), scope=scope,
                                 crypto=bool(row.get("crypto_bearing")),
                                 direct=bool(row.get("direct")),
                                 evidence_ids=evidence, version_claims=version_sources)
        components[coordinate] = {"row": row, "part": block, "basis": basis,
                                 "scope": scope, "name": coordinate}
        product = _norm(row.get("product"))
        if product:
            parts.append(part(claims=[tb.claim(coordinate, "PRODUCT_OF", product,
                                               basis=basis, evidence_ids=evidence)]))
        remember(row, section="software")
        placed_assets.append(coordinate)
        parts.append(block)

    # ---- software edges ---------------------------------------------------- #
    for edge in inv.get("dependencies") or []:
        if not isinstance(edge, Mapping):
            continue
        source, target = _norm(edge.get("source")), _norm(edge.get("target"))
        if source not in components or target not in components:
            _skip(skipped, "DEPENDENCY", f"{source} → {target}",
                  "one end of the edge is not a component this inventory holds; an edge to "
                  "an undeclared node is refused rather than invented")
            continue
        evidence = _evidence(edge, "dependency", f"{source}->{target}")
        basis = _basis(edge, "dependencies", skipped, f"{source} → {target}")
        if basis is None:
            continue
        kind = _norm(edge.get("type")).lower()
        if kind in ("contains", "contains_package", "ships"):
            parts.append(part(claims=[tb.claim(source, "SHIPS", target, basis=basis,
                                               evidence_ids=evidence)]))
        else:
            parts.append(part(claims=[tb.claim(
                source, "DEPENDS_ON", target, basis=basis, evidence_ids=evidence,
                scope=components[target]["scope"], dependency_kind="TRANSITIVE")]))
        count("dependencies")

    # ---- repository → commit → build → artifact ---------------------------- #
    repositories: dict[str, Any] = {}
    for row in rows("repositories"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "repository", name or row.get("url"))
        basis = _basis(row, "repositories", skipped, name)
        if not name or not evidence or basis is None:
            _skip(skipped, "REPOSITORY", name or row.get("url"),
                  "a repository row with no name or no evidence reference cannot be placed")
            continue
        applications_here = [_norm(item) for item in (row.get("applications") or [])]
        unknown = [name_ for name_ in applications_here if name_ not in applications]
        for name_ in unknown:
            _skip(skipped, "REPOSITORY", f"{name} → {name_}",
                  "the repository names an application this inventory does not hold")
        block = sd.source_repository(
            name=name, url=row.get("url"), vcs=row.get("vcs") or "git",
            default_branch=row.get("default_branch") or "main",
            application_rows=[applications[name_] for name_ in applications_here
                              if name_ in applications],
            basis=basis, evidence_ids=evidence)
        repositories[name] = block["assets"][0]
        remember(row, section="repositories")
        placed_assets.append(name)
        parts.append(block)

    commits: dict[str, Any] = {}
    for row in rows("commits"):
        sha = _norm(row.get("sha"))
        evidence = _evidence(row, "commit", sha)
        basis = _basis(row, "commits", skipped, sha)
        if basis is None:
            continue
        block = _place(sd.commit, skipped, "COMMIT", sha, sha=sha, author=row.get("author"),
                       committed_at=row.get("committed_at"), message=row.get("message"),
                       evidence_ids=evidence)
        if block is None:
            continue
        commits[sha] = block
        remember(row, section="commits")
        placed_assets.append(sha)
        parts.append(part(block))
        repository = _norm(row.get("repository"))
        if repository and repository in repositories:
            parts.append(part(claims=[tb.claim(
                repository, "AT_COMMIT", sha, basis=basis, evidence_ids=evidence)]))
        elif repository:
            _skip(skipped, "COMMIT", f"{sha} → {repository}",
                  "the commit names a repository this inventory does not hold")

    builds: dict[str, Any] = {}
    for row in rows("builds"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "build", name)
        basis = _basis(row, "builds", skipped, name)
        if not name or not evidence or basis is None:
            _skip(skipped, "BUILD", name,
                  "a build row with no name or no evidence reference cannot be placed")
            continue
        commit_name = _norm(row.get("commit"))
        block = sd.build(name=name, commit_row=commits.get(commit_name),
                         repository_row=repositories.get(_norm(row.get("repository"))),
                         pipeline=row.get("pipeline"), started_at=row.get("started_at"),
                         status=row.get("status") or "SUCCESS", basis=basis,
                         evidence_ids=evidence)
        if commit_name and commit_name not in commits:
            _skip(skipped, "BUILD", f"{name} → {commit_name}",
                  "the build names a commit this inventory does not hold, so its provenance "
                  "stops here instead of being guessed")
        builds[name] = block["assets"][0]
        remember(row, section="builds")
        placed_assets.append(name)
        parts.append(block)

    artifacts: dict[str, Any] = {}
    for row in rows("artifacts"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "artifact", name)
        basis = _basis(row, "artifacts", skipped, name)
        if basis is None:
            continue
        block = _place(sd.artifact, skipped, "ARTIFACT", name, name=name,
                       digest_value=row.get("digest"), build_row=builds.get(
                           _norm(row.get("build"))),
                       kind=row.get("kind") or "BINARY", size=row.get("size"),
                       basis=basis, evidence_ids=evidence)
        if block is None:
            continue
        artifacts[name] = block["assets"][0]
        remember(row, section="artifacts")
        placed_assets.append(name)
        parts.append(block)

    # ---- layers → image ---------------------------------------------------- #
    layers: dict[str, Any] = {}
    for row in rows("layers"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "layer", name)
        basis = _basis(row, "layers", skipped, name)
        if not name or not evidence or basis is None:
            _skip(skipped, "LAYER", name,
                  "a layer row with no name or no evidence reference cannot be placed")
            continue
        packages = [components[_norm(item)]["part"] for item in (row.get("packages") or [])
                    if _norm(item) in components]
        for item in (row.get("packages") or []):
            if _norm(item) not in components:
                _skip(skipped, "LAYER", f"{name} ships {_norm(item)}",
                      "the layer names a package this inventory does not hold")
        layers[name] = sd.layer(name=name, base=row.get("base"), packages=packages,
                                evidence_ids=evidence)
        remember(row, section="layers")
        placed_assets.append(name)
        parts.append(layers[name])

    images: dict[str, Any] = {}
    for row in rows("images"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "image", name)
        basis = _basis(row, "images", skipped, name)
        if basis is None:
            continue
        block = _place(sd.image, skipped, "IMAGE", name, name=name,
                       digest_value=row.get("digest"),
                       artifact_row=artifacts.get(_norm(row.get("artifact"))),
                       tag=row.get("tag"), base=row.get("base"),
                       layers=[layers[_norm(item)] for item in (row.get("layers") or [])
                               if _norm(item) in layers],
                       basis=basis, evidence_ids=evidence)
        if block is None:
            continue
        images[name] = block["assets"][0]
        remember(row, section="images")
        placed_assets.append(name)
        parts.append(block)
        installed = [tb.claim(_norm(item), "INSTALLED_IN", name, basis="sbom-import",
                              evidence_ids=evidence)
                     for item in (row.get("installed") or []) if _norm(item) in components]
        if installed:
            parts.append(part(claims=installed))

    # ---- release: the hop that makes an SBOM owned -------------------------- #
    for row in rows("releases"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "release", name)
        basis = _basis(row, "releases", skipped, name)
        if not name or not evidence or basis is None:
            _skip(skipped, "RELEASE", name,
                  "a release row with no name or no evidence reference cannot be placed")
            continue
        application_name = _norm(row.get("application"))
        artifact_name = _norm(row.get("artifact"))
        if application_name not in applications:
            _skip(skipped, "RELEASE", f"{name} → {application_name}",
                  "the release names an application this inventory does not hold")
            continue
        if artifact_name not in artifacts:
            _skip(skipped, "RELEASE", f"{name} → {artifact_name}",
                  "the release names an artifact this inventory does not hold")
            continue
        release_row = tb.asset("RELEASE", name, version=row.get("version"),
                               channel=row.get("channel") or "PRODUCTION",
                               evidence_ids=evidence)
        parts.append(part(release_row, claims=[
            tb.claim(application_name, "RELEASED_AS", name, basis=basis,
                     evidence_ids=evidence),
            tb.claim(name, "BUNDLES", artifact_name, basis=basis,
                     evidence_ids=evidence)]))
        remember(row, section="releases")
        placed_assets.append(name)

    # ---- SBOM --------------------------------------------------------------- #
    sboms: dict[str, Any] = {}
    for row in rows("sboms"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "sbom", name)
        basis = _basis(row, "sboms", skipped, name)
        if basis is None:
            continue
        listed = [_norm(item) for item in (row.get("components") or [])]
        components_here = [components[item]["part"] for item in listed
                           if item in components]
        for item in listed:
            if item not in components:
                _skip(skipped, "SBOM", f"{name} lists {item}",
                      "the SBOM lists a component this inventory does not hold; the list is "
                      "not a place to invent a package")
        block = _place(sd.sbom, skipped, "SBOM", name, name=name,
                       artifact_row=artifacts.get(_norm(row.get("artifact"))),
                       components=components_here,
                       sbom_format=row.get("format") or "CycloneDX-1.6",
                       tool=row.get("tool"), generated_at=row.get("generated_at"),
                       serial=row.get("serial"), evidence_ids=evidence)
        if block is None:
            continue
        sboms[name] = block["assets"][0]
        remember(row, section="sboms")
        placed_assets.append(name)
        parts.append(block)

    # ---- deployment → replica set → pod → container → node → host ---------- #
    for row in rows("deployments"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "deployment", name)
        basis = _basis(row, "deployments", skipped, name)
        image_name = _norm(row.get("image"))
        if not name or not evidence or basis is None:
            _skip(skipped, "DEPLOYMENT", name,
                  "a deployment row with no name or no evidence reference cannot be placed")
            continue
        if image_name not in images:
            _skip(skipped, "DEPLOYMENT", f"{name} → {image_name}",
                  "the deployment names an image this inventory does not hold")
            continue
        deployment_row = tb.asset("DEPLOYMENT", name, evidence_ids=evidence,
                                  namespace=row.get("namespace"))
        claims: list[dict[str, Any]] = [
            tb.claim(image_name, "DEPLOYED_AS", name, basis=basis, evidence_ids=evidence)]
        block: list[Any] = [deployment_row]
        namespace = _norm(row.get("namespace"))
        if namespace:
            block.append(tb.asset("NAMESPACE", namespace, evidence_ids=evidence))
            claims.append(tb.claim(name, "RUNS_IN", namespace, basis=basis,
                                   evidence_ids=evidence))
        cluster = _norm(row.get("cluster"))
        if cluster and namespace:
            block.append(tb.asset("CLUSTER", cluster, evidence_ids=evidence))
            claims.append(tb.claim(namespace, "MEMBER_OF_CLUSTER", cluster, basis=basis,
                                   evidence_ids=evidence))
        replica_set = _norm(row.get("replica_set"))
        if replica_set:
            block.append(tb.asset("REPLICA_SET", replica_set, evidence_ids=evidence))
            claims.append(tb.claim(name, "MANAGES", replica_set, basis=basis,
                                   evidence_ids=evidence))
        for pod in row.get("pods") or []:
            if not isinstance(pod, Mapping):
                continue
            pod_name = _norm(pod.get("name"))
            if not pod_name:
                _skip(skipped, "POD", name, "a pod row with no name cannot be referenced")
                continue
            block.append(tb.asset("POD", pod_name, evidence_ids=evidence))
            scheduler = replica_set or name
            claims.append(tb.claim(scheduler, "SCHEDULES", pod_name, basis=basis,
                                   evidence_ids=evidence))
            for container in pod.get("containers") or []:
                container_name = _norm(container if isinstance(container, str)
                                       else container.get("name"))
                if not container_name:
                    continue
                block.append(tb.asset("CONTAINER", container_name, evidence_ids=evidence))
                claims.append(tb.claim(pod_name, "RUNS_CONTAINER", container_name,
                                       basis=basis, evidence_ids=evidence))
                claims.append(tb.claim(container_name, "FROM_IMAGE", image_name,
                                       basis=basis, evidence_ids=evidence))
            node = _norm(pod.get("node"))
            if node:
                block.append(tb.asset("KUBERNETES_NODE", node, evidence_ids=evidence))
                claims.append(tb.claim(pod_name, "SCHEDULED_ON", node, basis=basis,
                                       evidence_ids=evidence))
                host = _norm(pod.get("host"))
                if host:
                    block.append(tb.asset("PHYSICAL_SERVER", host, evidence_ids=evidence))
                    claims.append(tb.claim(node, "RUNS_ON", host, basis=basis,
                                           evidence_ids=evidence))
        count("deployments")
        remember(row, section="deployments")
        placed_assets.append(name)
        parts.append(part(*block, claims=claims))

    # ---- process → what it loads → what it runs ---------------------------- #
    for row in rows("processes"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "process", name or row.get("pid"))
        basis = _basis(row, "processes", skipped, name)
        if not name or not evidence or basis is None:
            _skip(skipped, "PROCESS", name,
                  "a process row with no name or no evidence reference cannot be placed")
            continue
        process_row = tb.asset("PROCESS", name, pid=row.get("pid"), evidence_ids=evidence)
        claims = []
        application_name = _norm(row.get("application"))
        if application_name in applications:
            claims.append(tb.claim(name, "RUNS_APPLICATION", application_name, basis=basis,
                                   evidence_ids=evidence))
        elif application_name:
            _skip(skipped, "PROCESS", f"{name} → {application_name}",
                  "the process names an application this inventory does not hold")
        for loaded in row.get("loads") or []:
            loaded_name = _norm(loaded)
            if loaded_name not in components:
                _skip(skipped, "PROCESS", f"{name} loads {loaded_name}",
                      "the process loads something this inventory does not hold")
                continue
            claims.append(tb.claim(name, "LOADS", loaded_name, basis=basis,
                                   evidence_ids=evidence))
        pod_name = _norm(row.get("pod"))
        if pod_name:
            claims.append(tb.claim(pod_name, "RUNS_PROCESS", name, basis=basis,
                                   evidence_ids=evidence))
        elif _norm(row.get("container")):
            _skip(skipped, "PROCESS", f"{name} in {_norm(row.get('container'))}",
                  "the row places the process in a container, and RUNS_PROCESS starts at a "
                  "pod: the container is a level the store did not record")
        host = _norm(row.get("host"))
        if host:
            claims.append(tb.claim(name, "RUNS_ON", host, basis=basis,
                                   evidence_ids=evidence))
        count("processes")
        remember(row, section="processes")
        placed_assets.append(name)
        parts.append(part(process_row, claims=claims))

    # ---- crypto: the SBOM's capability handoff, from rows rather than from prose ----- #
    algorithms: dict[str, Any] = {}
    processes: dict[str, Any] = {}
    for block in parts:
        for row in block.get("assets") or []:
            if row.get("kind") == "PROCESS":
                processes[row["name"]] = row
    for row in rows("crypto"):
        algorithm_name = _norm(row.get("algorithm"))
        key_size = row.get("key_size")
        label = f"{algorithm_name}-{key_size}" if algorithm_name and key_size else algorithm_name
        evidence = _evidence(row, "crypto", row.get("id") or label)
        basis = _basis(row, "crypto", skipped, label)
        if not label or not evidence or basis is None:
            _skip(skipped, "CRYPTO", label,
                  "a crypto row with no algorithm or no evidence reference cannot be placed")
            continue
        algorithm = n.algorithm(name=label, family=row.get("family") or algorithm_name,
                                key_size=key_size, mode=row.get("mode"),
                                curve=row.get("curve"), evidence_ids=evidence)
        algorithms[label] = algorithm
        parts.append(part(algorithm))
        library_name = _norm(row.get("library"))
        library_row = None
        if library_name:
            if library_name in components:
                library_row = components[library_name]["part"]["assets"][0]
            else:
                library_row = tb.asset("CRYPTO_LIBRARY", library_name, evidence_ids=evidence,
                                       crypto_capable=True)
                components[library_name] = {"row": row, "part": part(library_row),
                                            "basis": basis, "scope": "RUNTIME",
                                            "name": library_name}
                parts.append(part(library_row))
        if library_row is not None:
            capability = _place(cd.capability, skipped, "CRYPTO", label,
                                provider_row=library_row, algorithm_row=algorithm,
                                key_size=key_size, mode=row.get("mode"),
                                basis=basis, evidence_ids=evidence)
            if capability is not None:
                parts.append(capability)
        operation = _norm(row.get("operation"))
        process_name = _norm(row.get("process"))
        if operation and process_name in processes:
            application_name = _norm(row.get("application"))
            run = _place(cd.runtime_operation, skipped, "CRYPTO", label,
                         name=f"{operation}-{process_name}", process_row=processes[process_name],
                         operation=operation, algorithm_row=algorithm,
                         application_row=applications.get(application_name),
                         provider_row=library_row, key_size=key_size, mode=row.get("mode"),
                         hash_name=row.get("hash"), purpose=row.get("purpose"),
                         basis="process-trace", observed_at=row.get("observed_at"),
                         evidence_ids=evidence)
            if run is not None:
                parts.append(run)
        elif operation:
            _skip(skipped, "CRYPTO", f"{label} {operation}",
                  "the row records an operation on a process this inventory does not hold; "
                  "an operation without its process is a verb")
        count("crypto")
        remember(row, section="crypto")
        placed_assets.append(label)

    for row in rows("vendors"):
        vendor_name = _norm(row.get("name"))
        product_name = _norm(row.get("product"))
        evidence = _evidence(row, "vendor", vendor_name)
        basis = _basis(row, "vendors", skipped, vendor_name)
        if not vendor_name or not evidence or basis is None:
            _skip(skipped, "VENDOR", vendor_name,
                  "a vendor row with no name or no evidence reference cannot be placed")
            continue
        vendor_row = tb.asset("VENDOR", vendor_name, lifecycle=row.get("lifecycle"),
                              risk_level=row.get("risk_level"),
                              crypto_capability=row.get("crypto_capability"),
                              evidence_ids=evidence)
        parts.append(part(vendor_row))
        if product_name:
            product_row = tb.asset("VENDOR_PRODUCT", product_name,
                                   version=row.get("version"),
                                   lifecycle=row.get("lifecycle"), evidence_ids=evidence)
            parts.append(part(product_row, claims=[
                tb.claim(product_name, "SUPPLIED_BY", vendor_name, basis="vendor-datasheet",
                         evidence_ids=evidence)]))
        count("vendors")
        remember(row, section="vendors")
        placed_assets.append(vendor_name)

    # ---- hardware, certificates and endpoints: what the crypto sits on ------------- #
    for row in rows("hardware"):
        name = _norm(row.get("name"))
        declared = _norm(row.get("type")).upper()
        kind = HARDWARE_KINDS.get(declared, "HOST")
        evidence = _evidence(row, "hardware", name)
        basis = _basis(row, "hardware", skipped, name)
        if not name or not evidence or basis is None:
            _skip(skipped, "HARDWARE", name,
                  "a hardware row with no name or no evidence reference cannot be placed")
            continue
        device = tb.asset(kind, name, model=row.get("model"),
                          manufacturer=row.get("manufacturer"),
                          version=row.get("firmware"),
                          crypto_capabilities=row.get("crypto_capabilities"),
                          evidence_ids=evidence)
        parts.append(part(device))
        for algorithm_name in row.get("algorithms") or []:
            label = _norm(algorithm_name)
            if label not in algorithms:
                _skip(skipped, "HARDWARE", f"{name} supports {label}",
                      "the device names an algorithm this inventory does not hold")
                continue
            parts.append(part(claims=[tb.claim(name, "SUPPORTS", label, basis=basis,
                                               evidence_ids=evidence)]))
        count("hardware")
        remember(row, section="hardware")
        placed_assets.append(name)

    endpoints_named = {_norm(row.get("name")) for row in rows("endpoints")
                       if _norm(row.get("name"))}
    for row in rows("certificates"):
        name = _norm(row.get("name")) or _norm(row.get("subject"))
        evidence = _evidence(row, "certificate", name or row.get("fingerprint"))
        basis = _basis(row, "certificates", skipped, name)
        if not name or not evidence or basis is None:
            _skip(skipped, "CERTIFICATE", name,
                  "a certificate row with no name or no evidence reference cannot be placed")
            continue
        certificate = n.certificate(name=name, subject=row.get("subject") or name,
                                    issuer=row.get("issuer"),
                                    signature_algorithm=row.get("signature_algorithm"),
                                    not_after=row.get("not_after"), evidence_ids=evidence)
        parts.append(part(certificate))
        signature = _norm(row.get("signature_algorithm"))
        for label in (signature, _norm(row.get("key_algorithm"))):
            if label and label in algorithms:
                parts.append(part(claims=[tb.claim(name, "SIGNED_WITH", label, basis=basis,
                                                   evidence_ids=evidence)]))
        endpoint_name = _norm(row.get("endpoint"))
        if endpoint_name and endpoint_name in endpoints_named:
            parts.append(part(claims=[tb.claim(endpoint_name, "PRESENTS", name, basis=basis,
                                               evidence_ids=evidence)]))
        count("certificates")
        remember(row, section="certificates")
        placed_assets.append(name)

    for row in rows("endpoints"):
        name = _norm(row.get("name"))
        evidence = _evidence(row, "endpoint", name)
        basis = _basis(row, "endpoints", skipped, name)
        if not name or not evidence or basis is None:
            _skip(skipped, "ENDPOINT", name,
                  "an endpoint row with no name or no evidence reference cannot be placed")
            continue
        endpoint_row = n.endpoint(host=row.get("host") or name, port=row.get("port") or 443,
                                  name=name, tls=row.get("tls"), evidence_ids=evidence)
        parts.append(part(endpoint_row))
        owner = _norm(row.get("application"))
        claims = []
        if owner in applications:
            claims.append(tb.claim(owner, "EXPOSES", name, basis=basis,
                                   evidence_ids=evidence))
        suite = _norm(row.get("suite"))
        block: list[Any] = [endpoint_row]
        if suite:
            suite_row = n.cipher_suite(name=suite, tls_version=row.get("tls_version") or "1.3",
                                       bulk=row.get("algorithm"), evidence_ids=evidence)
            block.append(suite_row)
            claims.append(tb.claim(name, "NEGOTIATES", suite, basis=basis,
                                   evidence_ids=evidence))
            label = _norm(row.get("algorithm"))
            if label in algorithms:
                # a suite uses a *crypto asset*, which is what carries the algorithm
                bulk = tb.asset("CRYPTO_ASSET", f"suite:{suite}", algorithm=label,
                                evidence_ids=evidence)
                block.append(bulk)
                claims.append(tb.claim(suite, "USES_CRYPTO", bulk["name"], basis=basis,
                                       evidence_ids=evidence, role="bulk"))
                claims.append(tb.claim(bulk["name"], "USES_ALGORITHM", label, basis=basis,
                                       evidence_ids=evidence))
            elif label:
                _skip(skipped, "ENDPOINT", f"{name} negotiates {label}",
                      "the endpoint names an algorithm this inventory does not hold")
        parts.append(part(*block, claims=claims))
        count("endpoints")
        remember(row, section="endpoints")
        placed_assets.append(name)

    estate = n.estate(*parts, estate_id=estate_text, environment=environment_text,
                         expected=dict(expected or {}),
                         gaps=[dict(row) for row in (gaps or [])])
    estate["source"] = {
        "kind": "INVENTORY",
        "note": ("read from the stored inventory: every asset and edge here is the residue "
                 "of a collection that already happened, so none of it is OBSERVED on this "
                 "read"),
    }
    levels_covered = sorted({part_["kind"] for part_ in estate["assets"]})
    return {
        "schema": SCHEMA,
        "estate": estate,
        "assets": len(estate["assets"]),
        "claims": len(estate["claims"]),
        "placed": dict(sorted(placed.items())),
        "kinds": levels_covered,
        "skipped": skipped,
        "statement": (
            f"{len(estate['assets'])} asset(s) and {len(estate['claims'])} claim(s) read from "
            f"the inventory, across {len(levels_covered)} kind(s)"
            + (f"; {len(skipped)} row(s) skipped with a reason" if skipped else "")
            + "; every class here is IMPORTED, CONFIGURED or VENDOR_DECLARED, because a "
              "stored row is not an observation"),
        "not_proven": [
            "that a stored row is still true: a row records what a collector saw when it "
            "ran, and the estate may have changed since",
            "that the chain is complete: a level with no rows is a gap in the inventory, and "
            "it is reported rather than filled",
            "that two records with one name are one asset: identity is resolved through a "
            "digest, a repository or a namespace, never through a string",
        ],
    }
