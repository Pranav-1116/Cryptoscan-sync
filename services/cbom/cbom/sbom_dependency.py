"""The SBOM dependency chain, from the business system down to a crypto capability.

An SBOM that lists ``OpenSSL 3.0.13`` has answered one question (*what is in the box*) and
none of the questions a bank actually asks: which application owns it, which commit built
it, which image carries it, whether it was ever loaded, and which business system is exposed
when it is patched. This module keeps the chain the review draws and makes each step a node
with an edge of its own::

    BUSINESS SYSTEM → APPLICATION → SOURCE REPOSITORY → COMMIT → BUILD
        → ARTIFACT → CONTAINER IMAGE → DEPLOYMENT → POD / VM / HOST → PROCESS
        → SOFTWARE COMPONENT → CRYPTO CAPABILITY

The rules the chain obeys, each a refusal rather than a convention:

* **an artifact has an identity, not a tag.** A row with only ``payments-api:latest`` cannot
  anchor a dependency, because the tag will point at something else tomorrow;
  :func:`image` and :func:`artifact` refuse to build one, and :func:`artifact_identity`
  refuses to bind an SBOM to it after the fact (``TAG_ONLY_IDENTITY``).
* **declared, installed, loaded and used are four facts.** An SBOM says what is *in* the
  artifact, an image says what is *installed*, a process map says what is *loaded* and a
  runtime probe says what *ran*. :func:`component_states` returns six states side by side
  and never promotes one into another.
* **a version disagreement is data.** SBOM 3.0.13 and runtime 3.0.11 are both true;
  :func:`version_layers` keeps ``DECLARED_VERSION``, ``IMAGE_VERSION``, ``RUNTIME_VERSION``
  and ``VENDOR_VERSION`` apart and reports ``DEPENDENCY_VERSION_CONFLICT``.
* **direct is not transitive.** :func:`dependency_tree` derives directness from the graph —
  what the SBOM lists is direct, what is only reachable through another component is
  transitive — and prints the path, because *"OpenSSL is a transitive dependency through
  payments-sdk"* is a remediation plan and *"Payments API uses OpenSSL"* is not.
* **the SBOM does not decide PQC.** Capabilities are capabilities;
  :func:`pqc_handoff` hands them to the CBOM with the rule attached rather than promoting a
  listed algorithm into a migration candidate.
* **identity is evidence, not a name.** ``payments-api``, ``payments_api`` and
  ``payment-service`` are three names; :func:`canonical_identity` resolves them only through
  a shared artifact digest, repository or image digest, and refuses to merge on a name
  (``NAME_ONLY_IDENTITY``).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any

from . import techbom as tb
from .nbom_graph import _resolve_one, part

SCHEMA = "cryptoscan.sbom-dependency/1"

#: the review's chain, in the order it draws it, as (kind at the level, level name).
SUPPLY_LEVELS: tuple[tuple[str, str], ...] = (
    ("BUSINESS_SYSTEM", "system"),
    ("APPLICATION", "application"),
    ("REPOSITORY", "repository"),
    ("COMMIT", "commit"),
    ("BUILD", "build"),
    ("ARTIFACT", "artifact"),
    ("IMAGE", "image"),
    ("DEPLOYMENT", "deployment"),
    ("POD", "pod"),
    ("PROCESS", "process"),
    ("PACKAGE", "component"),
    ("CRYPTO_CAPABILITY", "capability"),
)

#: the kinds that fill each level. A level is a bucket: "artifact" is the thing a build
#: produced and the record that describes it, and "component" is a package or the library
#: inside it.
LEVEL_KINDS: dict[str, tuple[str, ...]] = {
    "system": ("BUSINESS_SYSTEM",),
    "application": ("APPLICATION", "SERVICE"),
    "repository": ("REPOSITORY",),
    "commit": ("COMMIT",),
    "build": ("BUILD",),
    "artifact": ("ARTIFACT", "RELEASE", "SBOM"),
    "image": ("IMAGE", "IMAGE_LAYER"),
    "deployment": ("DEPLOYMENT", "REPLICA_SET", "NAMESPACE", "CLUSTER"),
    "pod": ("POD", "CONTAINER"),
    "process": ("PROCESS",),
    "component": ("PACKAGE", "CRYPTO_LIBRARY", "CRYPTO_PROVIDER"),
    "capability": ("CRYPTO_CAPABILITY", "CRYPTO_OPERATION", "ALGORITHM"),
}

#: the relations the supply chain is walked along. A whitelist: an edge that is not here is
#: still a fact about the estate, but following it would answer a question nobody asked.
SUPPLY_RELATIONS: tuple[str, ...] = (
    "CONTAINS", "PROVIDES", "TRACKED_IN", "AT_COMMIT", "BUILT_FROM", "BUILT_INTO",
    "PRODUCES", "DESCRIBED_BY", "BUNDLES", "PACKAGED_AS", "HAS_LAYER", "SHIPS",
    "INSTALLED_IN", "LISTS", "DEPENDS_ON", "DEPLOYED_AS", "MANAGES", "SCHEDULES",
    "RUNS_IN", "MEMBER_OF_CLUSTER", "RUNS_CONTAINER", "FROM_IMAGE", "RUNS_PROCESS",
    "LOADS", "LINKS", "RUNS_APPLICATION", "RELEASED_AS", "PRODUCT_OF", "SUPPLIED_BY",
    "HAS_VULNERABILITY", "IMPLEMENTS", "SUPPORTS", "USES_ALGORITHM", "INVOKES",
    "SCHEDULED_ON", "RUNS_ON", "RUNS",
)

#: the six states a component can be in (cbom 6 of the SBOM review). They are not a ladder
#: and they are not exclusive: a component is routinely present in the SBOM, installed in
#: the image, never loaded, and used anyway through a statically linked copy.
COMPONENT_STATES: tuple[str, ...] = ("SBOM_PRESENT", "INSTALLED", "LOADED", "CONFIGURED",
                                     "STATIC_REFERENCED", "RUNTIME_USED")

#: the deployment questions, in the weakest-to-strongest order a bank asks them.
DEPLOYMENT_STATES: tuple[str, ...] = ("EXISTS", "INSTALLED", "DEPLOYED", "RUNNING",
                                      "LOADED")

#: the scopes a dependency can be declared in. ``BUILD`` is on the list because a compiler
#: dependency is real; it is not on the list of scopes that can carry production risk.
SCOPES: tuple[str, ...] = ("PRODUCTION", "RUNTIME", "TEST", "DEV", "BUILD", "OPTIONAL",
                           "PROVIDED", "TRANSITIVE")

#: the scopes that put a component in front of a customer.
PRODUCTION_SCOPES: frozenset[str] = frozenset({"PRODUCTION", "RUNTIME"})

#: the layers a version can be declared in, and the ``source`` names that select them.
VERSION_LAYERS: tuple[str, ...] = ("DECLARED_VERSION", "IMAGE_VERSION", "RUNTIME_VERSION",
                                   "VENDOR_VERSION")

VERSION_LAYER_BY_SOURCE: dict[str, str] = {
    "sbom": "DECLARED_VERSION", "manifest": "DECLARED_VERSION", "lockfile": "DECLARED_VERSION",
    "image": "IMAGE_VERSION", "image-scan": "IMAGE_VERSION", "image-digest": "IMAGE_VERSION",
    "runtime": "RUNTIME_VERSION", "process-map": "RUNTIME_VERSION",
    "process-trace": "RUNTIME_VERSION", "loaded-library": "RUNTIME_VERSION",
    "vendor": "VENDOR_VERSION", "vendor-portal": "VENDOR_VERSION",
    "advisory": "VENDOR_VERSION",
}

#: what a capability's evidence amounts to, strongest first. The vocabulary is the review's
#: (point 8): CAPABILITY, STATIC_OBSERVED, CONFIGURED, RUNTIME_OBSERVED, NETWORK_OBSERVED,
#: IMPORTED, VENDOR_DECLARED, UNKNOWN.
EVIDENCE_TYPES: tuple[str, ...] = ("CAPABILITY", "STATIC_OBSERVED", "CONFIGURED",
                                   "RUNTIME_OBSERVED", "NETWORK_OBSERVED", "IMPORTED",
                                   "VENDOR_DECLARED", "UNKNOWN")

#: the model's confidence classes, in the review's evidence-type vocabulary. ``OBSERVED`` is
#: a runtime observation that did not say which collector made it; it does not become
#: ``CAPABILITY`` on the way through.
CLASS_TO_EVIDENCE: dict[str, str] = {
    tb.OBSERVED: "RUNTIME_OBSERVED",
    tb.RUNTIME_OBSERVED: "RUNTIME_OBSERVED",
    tb.NETWORK_OBSERVED: "NETWORK_OBSERVED",
    tb.STATIC_OBSERVED: "STATIC_OBSERVED",
    tb.CONFIGURED: "CONFIGURED",
    tb.CAPABILITY: "CAPABILITY",
    tb.IMPORTED: "IMPORTED",
    tb.VENDOR_DECLARED: "VENDOR_DECLARED",
    tb.INFERRED: "UNKNOWN",
    tb.UNKNOWN: "UNKNOWN",
}

#: the evidence types that corroborate a capability — a listed algorithm plus one of these
#: is a usage candidate, and a listed algorithm alone is a datasheet.
PROVEN_EVIDENCE: frozenset[str] = frozenset({"RUNTIME_OBSERVED", "NETWORK_OBSERVED"})

#: an SBOM that lists a component inside this many hops of a production application counts
#: as production surface; beyond it, the path is printed and the caller decides.
PRODUCTION_REACH = 6


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

#: the kinds a container relation may end at. A component's part also carries the vendor
#: product behind it, and *that* is not a thing an SBOM lists or a layer ships.
CONTAINED_KINDS: tuple[str, ...] = ("PACKAGE", "CRYPTO_LIBRARY")


def _parts(items: Iterable[Any]) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]]]:
    """Rows and the claims that came with them.

    A builder returns ``part(rows, claims)``, and the claims are half the fact: a layer that
    ships a package and loses its ``SHIPS`` edge on the way to the image has been counted
    and not recorded. Every builder here therefore accepts a row *or* a part.
    """
    rows: list[Mapping[str, Any]] = []
    claims: list[dict[str, Any]] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, Mapping) and "assets" in item:
            rows.extend(item["assets"])
            claims.extend(item.get("claims") or [])
            continue
        rows.append(item)
    return rows, claims


def digest(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _brief(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"name": row["name"], "kind": row["kind"], "id": row["id"],
            "key": row["key"], "version": row.get("version")}


def _refused(code: str, reason: str) -> tb.ClaimRefused:
    return tb.ClaimRefused(code, reason)


def _looks_like_digest(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith("sha256:") and len(text.split(":", 1)[1]) >= 12


def _sides(bom: Mapping[str, Any], claim: Mapping[str, Any]) -> tuple[str, str]:
    """(dependent, dependency) after a relation that points at its *host* is reversed."""
    if claim["relation"] in ("RUNS", "RUNS_APPLICATION", "RUNS_PROCESS", "RUNS_CONTAINER",
                             "SCHEDULES", "MANAGES"):
        return claim["to_key"], claim["from_key"]
    return claim["from_key"], claim["to_key"]


# --------------------------------------------------------------------------- #
# Builders: the levels above and inside the artifact
# --------------------------------------------------------------------------- #

def source_repository(*, name: Any, url: Any = None, vcs: Any = "git",
                      application_rows: Iterable[Mapping[str, Any]] = (),
                      commit_row: Mapping[str, Any] | None = None,
                      default_branch: Any = "main", basis: Any = "api-poll",
                      evidence_ids: Iterable[Any] | None = None,
                      **attributes: Any) -> dict[str, Any]:
    """``application → TRACKED_IN → repository → AT_COMMIT → commit`` (sbom 1, 2).

    A repository is a node because "which repository" and "which commit in it" are two
    questions with different lifetimes: the repository outlives the release, and the commit
    is the only thing that can answer *which revision produced this SBOM*.
    """
    row = tb.asset("REPOSITORY", name, url=url, vcs=str(vcs).upper(),
                   default_branch=default_branch, evidence_ids=evidence_ids, **attributes)
    assets: list[Mapping[str, Any]] = [row]
    claims: list[dict[str, Any]] = []
    for application_row in application_rows:
        assets.append(application_row)
        claims.append(tb.claim(application_row["name"], "TRACKED_IN", row["name"],
                               basis=basis, evidence_ids=evidence_ids))
    if commit_row is not None:
        assets.append(commit_row)
        claims.append(tb.claim(row["name"], "AT_COMMIT", commit_row["name"], basis=basis,
                               evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


def commit(*, sha: Any, repository: Any = None, author: Any = None,
           committed_at: Any = None, message: Any = None,
           evidence_ids: Iterable[Any] | None = None, **attributes: Any) -> dict[str, Any]:
    """One revision, named by its sha. A commit without a sha is a branch, not a revision."""
    text = tb._norm(sha)
    if len(text) < 7:
        raise _refused("COMMIT_WITHOUT_SHA",
                       f"{sha or '(none)'} is not a revision: a commit is a sha, and a "
                       "branch name moves")
    return tb.asset("COMMIT", text, sha=text, repository=repository, author=author,
                    committed_at=committed_at, message=message,
                    evidence_ids=evidence_ids, **attributes)


def build(*, name: Any, commit_row: Mapping[str, Any] | None = None,
          repository_row: Mapping[str, Any] | None = None,
          artifact_rows: Iterable[Mapping[str, Any]] = (),
          pipeline: Any = None, started_at: Any = None, status: Any = "SUCCESS",
          basis: Any = "api-poll", evidence_ids: Iterable[Any] | None = None,
          **attributes: Any) -> dict[str, Any]:
    """``build → BUILT_FROM → commit`` and ``build → PRODUCES → artifact`` (sbom 2).

    The pipeline is an attribute rather than a node: what a remediation needs is *which
    build* and *which commit*, and a pipeline name on its own re-runs.
    """
    row = tb.asset("BUILD", name, pipeline=pipeline, started_at=started_at,
                   status=status, evidence_ids=evidence_ids, **attributes)
    assets: list[Mapping[str, Any]] = [row]
    claims: list[dict[str, Any]] = []
    if commit_row is not None:
        assets.append(commit_row)
        claims.append(tb.claim(row["name"], "BUILT_FROM", commit_row["name"], basis=basis,
                               evidence_ids=evidence_ids))
    if repository_row is not None:
        assets.append(repository_row)
        claims.append(tb.claim(row["name"], "TRACKED_IN", repository_row["name"],
                               basis=basis, evidence_ids=evidence_ids))
    artifact_entries, artifact_claims = _parts(artifact_rows)
    for artifact_row in artifact_entries:
        assets.append(artifact_row)
        if artifact_row["kind"] != "ARTIFACT":
            continue
        claims.append(tb.claim(row["name"], "PRODUCES", artifact_row["name"], basis=basis,
                               evidence_ids=evidence_ids))
    claims.extend(artifact_claims)
    return part(*assets, claims=claims)


def artifact(*, name: Any, digest_value: Any = None, build_row: Mapping[str, Any] | None = None,
             sbom_row: Mapping[str, Any] | None = None, kind: Any = "BINARY",
             size: Any = None, basis: Any = "agent-inventory",
             evidence_ids: Iterable[Any] | None = None, **attributes: Any) -> dict[str, Any]:
    """An artifact bound to the digest that identifies it (sbom 2, 3).

    A tag is not an identity. Refusing here is cheaper than discovering in a year that
    ``payments-api:latest`` referred to four different builds.
    """
    if not _looks_like_digest(digest_value):
        raise _refused(
            "ARTIFACT_WITHOUT_DIGEST",
            f"{name}: an artifact dependency binds to a digest, not a name; "
            f"{digest_value or '(none)'} is not one")
    row = tb.asset("ARTIFACT", name, digest=str(digest_value), artifact_kind=str(kind),
                   size=size, evidence_ids=evidence_ids, **attributes)
    assets: list[Mapping[str, Any]] = [row]
    claims: list[dict[str, Any]] = []
    if build_row is not None:
        assets.append(build_row)
        claims.append(tb.claim(build_row["name"], "PRODUCES", row["name"], basis=basis,
                               evidence_ids=evidence_ids))
    if sbom_row is not None:
        assets.append(sbom_row)
        claims.append(tb.claim(row["name"], "DESCRIBED_BY", sbom_row["name"],
                               basis="sbom-import", evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


def image(*, name: Any, digest_value: Any = None, artifact_row: Mapping[str, Any] | None = None,
          tag: Any = None, base: Any = None, layers: Iterable[Mapping[str, Any]] = (),
          basis: Any = "agent-inventory", evidence_ids: Iterable[Any] | None = None,
          **attributes: Any) -> dict[str, Any]:
    """``artifact → PACKAGED_AS → image → HAS_LAYER → layer`` (sbom 3, 9).

    The image digest is the anchor a deployment actually names, which is why it may not be
    replaced by a tag.
    """
    if not _looks_like_digest(digest_value):
        raise _refused(
            "IMAGE_WITHOUT_DIGEST",
            f"{name}: a deployment names an image digest; a tag such as {tag or name} can be "
            "re-pushed, so the dependency would silently move")
    row = tb.asset("IMAGE", name, digest=str(digest_value), tag=tag, base_image=base,
                   evidence_ids=evidence_ids, **attributes)
    assets: list[Mapping[str, Any]] = [row]
    claims: list[dict[str, Any]] = []
    if artifact_row is not None:
        assets.append(artifact_row)
        claims.append(tb.claim(artifact_row["name"], "PACKAGED_AS", row["name"], basis=basis,
                               evidence_ids=evidence_ids))
    layer_rows, layer_claims = _parts(layers)
    for layer_row in layer_rows:
        assets.append(layer_row)
        if layer_row["kind"] != "IMAGE_LAYER":
            continue
        claims.append(tb.claim(row["name"], "HAS_LAYER", layer_row["name"],
                               basis="sbom-import", evidence_ids=evidence_ids))
    claims.extend(layer_claims)
    return part(*assets, claims=claims)


def layer(*, name: Any, base: Any = None, packages: Iterable[Mapping[str, Any]] = (),
          evidence_ids: Iterable[Any] | None = None, **attributes: Any) -> dict[str, Any]:
    """One image layer and the packages it delivers (sbom 9)."""
    row = tb.asset("IMAGE_LAYER", name, base_image=base, evidence_ids=evidence_ids,
                   **attributes)
    assets: list[Mapping[str, Any]] = [row]
    claims: list[dict[str, Any]] = []
    package_rows, package_claims = _parts(packages)
    for package_row in package_rows:
        assets.append(package_row)
        if package_row["kind"] not in CONTAINED_KINDS:
            continue
        claims.append(tb.claim(row["name"], "SHIPS", package_row["name"], basis="sbom-import",
                               evidence_ids=evidence_ids))
    claims.extend(package_claims)
    return part(*assets, claims=claims)


def sbom(*, name: Any, artifact_row: Mapping[str, Any] | None = None,
         components: Iterable[Mapping[str, Any]] = (), sbom_format: Any = "CycloneDX-1.6",
         tool: Any = None, generated_at: Any = None, serial: Any = None,
         evidence_ids: Iterable[Any] | None = None, **attributes: Any) -> dict[str, Any]:
    """``artifact → DESCRIBED_BY → SBOM → LISTS → component`` (sbom 1, 12).

    What an SBOM lists is a *component*, and the difference between "listed" and "installed"
    is the difference between a document and a machine.
    """
    row = tb.asset("SBOM", name, sbom_format=str(sbom_format), tool=tool,
                   generated_at=generated_at, serial=serial, evidence_ids=evidence_ids,
                   **attributes)
    assets: list[Mapping[str, Any]] = [row]
    claims: list[dict[str, Any]] = []
    if artifact_row is not None:
        assets.append(artifact_row)
        claims.append(tb.claim(artifact_row["name"], "DESCRIBED_BY", row["name"],
                               basis="sbom-import", evidence_ids=evidence_ids))
    component_rows, component_claims = _parts(components)
    for component_row in component_rows:
        assets.append(component_row)
        if component_row["kind"] not in CONTAINED_KINDS:
            continue
        claims.append(tb.claim(row["name"], "LISTS", component_row["name"],
                               basis="sbom-import", evidence_ids=evidence_ids))
    claims.extend(component_claims)
    return part(*assets, claims=claims)


def component(*, name: Any, version: Any = None, purl: Any = None, scope: Any = "RUNTIME",
              product_row: Mapping[str, Any] | None = None,
              depends_on: Iterable[Mapping[str, Any]] = (), crypto: bool = False,
              direct: bool = False,
              dependency_basis: Any = "sbom-import",
              evidence_ids: Iterable[Any] | None = None, **attributes: Any) -> dict[str, Any]:
    """A software component, with the scope it was declared in (sbom 12, 13, 14).

    ``scope`` is not decoration. A component in ``BUILD`` scope never runs, and a report
    that adds it to the production surface overstates the estate by exactly one compiler.
    """
    scope_text = str(scope or "").strip().upper()
    if scope_text not in SCOPES:
        raise _refused("UNKNOWN_SCOPE",
                       f"{scope or '(none)'} is not a dependency scope; expected one of "
                       f"{', '.join(SCOPES)}")
    #: ``direct`` is what the application's own manifest asked for. An SBOM is a flat list
    #: of everything that ended up in the artifact, so the flat list cannot answer "direct
    #: or transitive" — the manifest can, and the difference is what a remediation plans.
    row = tb.asset("PACKAGE", name, version=version, purl=purl, scope=scope_text,
                   crypto_capable=bool(crypto), direct=bool(direct),
                   evidence_ids=evidence_ids, **attributes)
    assets: list[Mapping[str, Any]] = [row]
    claims: list[dict[str, Any]] = []
    if product_row is not None:
        assets.append(product_row)
        claims.append(tb.claim(row["name"], "PRODUCT_OF", product_row["name"],
                               basis="sbom-import", evidence_ids=evidence_ids))
    dependency_rows, dependency_claims = _parts(depends_on)
    for other in dependency_rows:
        other_scope = tb._norm((other["attributes"] or {}).get("scope")
                               or scope_text).upper()
        assets.append(other)
        if other["kind"] not in CONTAINED_KINDS:
            continue
        claims.append(tb.claim(row["name"], "DEPENDS_ON", other["name"],
                               basis=dependency_basis, evidence_ids=evidence_ids,
                               scope=other_scope, dependency_kind="TRANSITIVE"))
    claims.extend(dependency_claims)
    return part(*assets, claims=claims)


# --------------------------------------------------------------------------- #
# The chain, read off the built projection
# --------------------------------------------------------------------------- #

def levels(bom: Mapping[str, Any]) -> dict[str, int]:
    """How many nodes sit at each level of the supply chain."""
    return {name: sum(1 for row in bom["assets"] if row["kind"] in LEVEL_KINDS[name])
            for _, name in SUPPLY_LEVELS}


def _walk(bom: Mapping[str, Any], start: str, *, max_depth: int = 10,
          reverse: bool = False) -> dict[str, Any]:
    buckets: dict[str, dict[str, dict[str, Any]]] = {name: {} for _, name in SUPPLY_LEVELS}
    edges: list[dict[str, Any]] = []
    seen: set[str] = {start}
    frontier: list[tuple[str, int]] = [(start, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["relation"] not in SUPPLY_RELATIONS:
                continue
            if reverse:
                if claim["to_key"] != current:
                    continue
                neighbour = claim["from_key"]
            else:
                if claim["from_key"] != current:
                    continue
                neighbour = claim["to_key"]
            if neighbour in seen or neighbour not in bom["by_key"]:
                continue
            seen.add(neighbour)
            row = bom["by_key"][neighbour]
            for _, name in SUPPLY_LEVELS:
                if row["kind"] in LEVEL_KINDS[name]:
                    buckets[name][row["key"]] = _brief(row)
                    break
            edges.append({"source": bom["by_key"][current]["name"],
                          "relation": claim["relation"], "target": row["name"],
                          "class": claim["confidence"]})
            frontier.append((neighbour, depth + 1))
    return {"levels": {name: list(rows.values()) for name, rows in buckets.items()},
            "edges": edges,
            "statement": ", ".join(f"{name} {len(rows)}"
                                   for name, rows in buckets.items() if rows)}


def supply_chain(bom: Mapping[str, Any], *, query: Any, max_depth: int = 10
                 ) -> dict[str, Any]:
    """The supply chain around one node, walked down and up (sbom 1, 28)."""
    start = _resolve_one(bom, query)
    down = _walk(bom, start, max_depth=max_depth)
    up = _walk(bom, start, max_depth=max_depth, reverse=True)
    return {
        "query": str(query), "node": _brief(bom["by_key"][start]),
        "down": down["levels"], "up": up["levels"], "edges": down["edges"],
        "statement": (f"{bom['by_key'][start]['name']}: down {down['statement'] or 'nothing'}; "
                      f"up {up['statement'] or 'nothing'}"),
        "not_proven": ["that the chain is complete: a level with no rows is a gap in the "
                       "evidence, and it is printed rather than filled"],
    }


def _owners(bom: Mapping[str, Any], start: str, *, max_depth: int = 10
            ) -> list[dict[str, Any]]:
    """Every application that reaches a node, with the path that reaches it."""
    found: list[dict[str, Any]] = []
    seen: set[str] = {start}
    frontier: list[tuple[str, list[str], int]] = [(start, [], 0)]
    while frontier:
        current, path, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["relation"] not in SUPPLY_RELATIONS:
                continue
            if claim["to_key"] != current:
                continue
            neighbour = claim["from_key"]
            row = bom["by_key"].get(neighbour)
            if row is None or neighbour in seen:
                continue
            seen.add(neighbour)
            step = [*path, f"{row['name']} {claim['relation']} "
                           f"{bom['by_key'][current]['name']}"]
            if row["kind"] in ("APPLICATION", "SERVICE"):
                found.append({"application": row["name"], "kind": row["kind"],
                              "path": list(reversed(step)),
                              "class": claim["confidence"]})
            frontier.append((neighbour, step, depth + 1))
    return found


def component_owners(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """*Which application actually owns this component?* (sbom 1).

    The answer is a walk, not a join on a name: an SBOM lists a component, an artifact is
    described by that SBOM, a release bundles the artifact and an application is released as
    the release. An owner is reported only when that path exists.
    """
    start = _resolve_one(bom, query)
    row = bom["by_key"][start]
    owners = _owners(bom, start)
    names = sorted({owner["application"] for owner in owners})
    return {
        "query": str(query), "component": row["name"], "kind": row["kind"],
        "owners": owners, "applications": names,
        "statement": (f"{row['name']}: owned by {', '.join(names)}"
                      if names else
                      f"{row['name']}: no application owns it in this projection"),
        "rule": ("ownership is an evidenced path from an application to the component; a "
                 "component nobody reaches is a component nobody has deployed"),
        "not_proven": ["that the repository which produced the artifact is the one that "
                       "holds the component's own source: the SBOM joins them as data, not "
                       "as provenance"],
    }


def _kinds_in_walk(bom: Mapping[str, Any], key: str, kinds: Iterable[str], *,
                   reverse: bool = False, max_depth: int = 10) -> list[dict[str, Any]]:
    """Every reachable node of the given kinds, with the relation that reached it."""
    wanted = set(kinds)
    found: list[dict[str, Any]] = []
    seen: set[str] = {key}
    frontier: list[tuple[str, int]] = [(key, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["relation"] not in SUPPLY_RELATIONS:
                continue
            if reverse:
                if claim["to_key"] != current:
                    continue
                neighbour = claim["from_key"]
            else:
                if claim["from_key"] != current:
                    continue
                neighbour = claim["to_key"]
            if neighbour in seen or neighbour not in bom["by_key"]:
                continue
            seen.add(neighbour)
            row = bom["by_key"][neighbour]
            if row["kind"] in wanted:
                found.append({**_brief(row), "reached_by": claim["relation"]})
            frontier.append((neighbour, depth + 1))
    return found


def image_chain(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """``image → layer → package → library → process``, with the digest as the anchor (sbom 9).

    The layering matters for remediation: a package that arrives in the base layer is fixed
    by rebuilding the base image, and one the application adds is fixed by rebuilding the
    application.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    if row["kind"] not in ("IMAGE", "IMAGE_LAYER"):
        raise _refused("NOT_AN_IMAGE", f"{row['name']} ({row['kind']}) is not an image")
    layers = [entry for entry in _kinds_in_walk(bom, key, ("IMAGE_LAYER",))]
    packages: dict[str, dict[str, Any]] = {}
    for claim in bom["claims"]:
        if claim["relation"] != "SHIPS":
            continue
        if claim["from_key"] != key and not any(
                claim["from_key"] == _resolve_one(bom, entry["name"]) for entry in layers):
            continue
        package = bom["by_key"][claim["to_key"]]
        packages[package["key"]] = {**_brief(package),
                                    "layer": bom["by_key"][claim["from_key"]]["name"]}
    processes = _kinds_in_walk(bom, key, ("PROCESS",), reverse=True)
    return {
        "image": row["name"], "digest": (row["attributes"] or {}).get("digest"),
        "layers": [{"name": entry["name"],
                    "base": (bom["by_key"][entry["key"]]["attributes"] or {}).get(
                        "base_image")} for entry in layers],
        "packages": sorted(packages.values(), key=lambda entry: entry["name"]),
        "processes": [entry["name"] for entry in processes],
        "statement": (f"{row['name']}@{(row['attributes'] or {}).get('digest')}: "
                      f"{len(layers)} layer(s), {len(packages)} package(s), "
                      f"{len(processes)} process(es)"),
        "rule": ("an image is an immutable digest, its layers are where packages arrive "
                 "from, and a package in a layer is installed whether or not it is loaded"),
    }


def kubernetes_chain(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """``image → deployment → replica set → pod → container → node → host`` (sbom 10).

    The ReplicaSet is on this list because it is the object a rollout names: a chain that
    jumps from a deployment straight to a pod cannot say which revision of the controller
    the pod belongs to.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    wanted = ("DEPLOYMENT", "REPLICA_SET", "POD", "CONTAINER", "KUBERNETES_NODE", "NAMESPACE",
              "CLUSTER", "HOST", "PHYSICAL_SERVER", "PROCESS")
    found = _kinds_in_walk(bom, key, wanted)
    by_kind: dict[str, list[str]] = {}
    for entry in found:
        by_kind.setdefault(entry["kind"], []).append(entry["name"])
    for names in by_kind.values():
        names.sort()
    missing = [kind for kind in ("DEPLOYMENT", "POD", "PROCESS") if not by_kind.get(kind)]
    return {
        "image": row["name"] if row["kind"] in ("IMAGE", "APPLICATION") else None,
        "kinds": by_kind, "missing": missing,
        "statement": (f"{row['name']}: " + " → ".join(
            f"{kind.lower()} {', '.join(names)}" for kind, names in sorted(by_kind.items()))
            if by_kind else f"{row['name']}: nothing runs from it in this projection"),
        "rule": ("a pod is scheduled somewhere physical: the topology joins the hardware "
                 "estate, and the HBOM reads the same nodes rather than a copy"),
    }


def host_chain(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """``application → process → host → hardware`` for a non-container workload (sbom 11, 16)."""
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    hosts = _kinds_in_walk(bom, key, ("PHYSICAL_SERVER", "HOST", "VM", "KUBERNETES_NODE"))
    hardware: list[str] = []
    for host in hosts:
        for claim in bom["claims"]:
            if claim["relation"] != "HAS_COMPONENT" or claim["from_key"] != host["key"]:
                continue
            hardware.append(bom["by_key"][claim["to_key"]]["name"])
    processes = _kinds_in_walk(bom, key, ("PROCESS",))
    components = _kinds_in_walk(bom, key, ("PACKAGE", "CRYPTO_LIBRARY"))
    return {
        "node": row["name"],
        "processes": [entry["name"] for entry in processes],
        "components": sorted({entry["name"] for entry in components}),
        "hosts": [entry["name"] for entry in hosts],
        "hardware": sorted(set(hardware)),
        "statement": (f"{row['name']}: {len(processes)} process(es), "
                      f"{len({entry['name'] for entry in components})} component(s), "
                      f"{len(hosts)} host(s), {len(set(hardware))} hardware component(s)"),
        "rule": ("a software dependency that relies on hardware crypto acceleration has a "
                 "hardware dependency, and it is the HBOM's walk rather than a second one"),
    }


def provenance(bom: Mapping[str, Any], *, artifact: Any) -> dict[str, Any]:
    """*Which exact source revision produced this SBOM?* (sbom 2).

    Repository → commit → build → artifact → SBOM, each step an edge. Where a step is
    missing it is reported missing, because a provenance chain with a guessed link is worse
    than one with a gap.
    """
    key = _resolve_one(bom, artifact)
    row = bom["by_key"][key]
    repository = commit_sha = build_name = pipeline = sbom_name = None
    build_key = None
    for claim in bom["claims"]:
        if claim["relation"] == "DESCRIBED_BY" and claim["from_key"] == key:
            sbom_name = bom["by_key"][claim["to_key"]]["name"]
        if claim["relation"] == "PRODUCES" and claim["to_key"] == key:
            build_key = claim["from_key"]
            build_name = bom["by_key"][build_key]["name"]
            pipeline = (bom["by_key"][build_key]["attributes"] or {}).get("pipeline")
    if build_key:
        for claim in bom["claims"]:
            if claim["from_key"] != build_key:
                continue
            if claim["relation"] == "BUILT_FROM":
                commit_sha = bom["by_key"][claim["to_key"]]["name"]
            if claim["relation"] == "TRACKED_IN":
                repository = bom["by_key"][claim["to_key"]]["name"]
    if repository is None and commit_sha:
        for claim in bom["claims"]:
            if claim["relation"] == "AT_COMMIT" and claim["to_key"] == _resolve_one(
                    bom, commit_sha):
                repository = bom["by_key"][claim["from_key"]]["name"]
    steps = {"repository": repository, "commit": commit_sha, "build": build_name,
             "pipeline": pipeline, "artifact": row["name"],
             "digest": (row["attributes"] or {}).get("digest"), "sbom": sbom_name}
    missing = [name for name in ("repository", "commit", "build", "sbom") if not steps[name]]
    return {
        "artifact": row["name"], "steps": steps, "missing": missing,
        "complete": not missing,
        "statement": (f"{row['name']}: "
                      + " → ".join(str(value) for value in
                                   (repository, commit_sha, build_name, sbom_name) if value)
                      if not missing else
                      f"{row['name']}: provenance is missing {', '.join(missing)}"),
        "rule": ("a provenance chain is printed with its gaps: an SBOM whose commit nobody "
                 "recorded cannot be re-built, and saying so is the finding"),
    }


def artifact_identity(bom: Mapping[str, Any], *, sbom: Any) -> dict[str, Any]:
    """What an SBOM is bound to, and whether that binding is immutable (sbom 3).

    A digest is an identity; a tag is a pointer. Binding to a pointer is refused, because
    the dependency would move the next time somebody pushes.
    """
    key = _resolve_one(bom, sbom)
    row = bom["by_key"][key]
    described = [bom["by_key"][claim["from_key"]] for claim in bom["claims"]
                 if claim["relation"] == "DESCRIBED_BY" and claim["to_key"] == key]
    if not described:
        raise _refused("SBOM_WITHOUT_ARTIFACT",
                       f"{row['name']} describes no artifact; an SBOM with no subject is a "
                       "manifest of nothing")
    subject = described[0]
    attributes = subject["attributes"] or {}
    bound = attributes.get("digest") or attributes.get("sha256")
    if not _looks_like_digest(bound):
        raise _refused(
            "TAG_ONLY_IDENTITY",
            f"{subject['name']} is bound by {attributes.get('tag') or 'a name'}, not by a "
            "digest; a tag can be re-pushed and the SBOM would silently describe another "
            "build")
    images = [bom["by_key"][claim["to_key"]] for claim in bom["claims"]
              if claim["relation"] == "PACKAGED_AS" and claim["from_key"] == subject["key"]]
    return {
        "sbom": row["name"], "artifact": subject["name"], "digest": bound,
        "immutable": True, "image": images[0]["name"] if images else None,
        "image_digest": (images[0]["attributes"] or {}).get("digest") if images else None,
        "statement": (f"{row['name']} → {subject['name']} at {bound}"
                      + (f" → {images[0]['name']} at "
                         f"{(images[0]['attributes'] or {}).get('digest')}" if images else "")),
        "rule": "an SBOM binds to an artifact digest; a tag is a pointer, and pointers move",
    }


def deployment_state(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """``COMPONENT_EXISTS`` is not ``COMPONENT_DEPLOYED`` (sbom 4, 5).

    Five questions in the order a bank asks them: is it in the SBOM, is it installed in an
    image, is that image deployed, is a process running from it, and has a process loaded
    the component itself. The strongest one that holds is the answer, and every weaker one
    that holds is printed beside it.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    states: dict[str, bool] = {state: False for state in DEPLOYMENT_STATES}
    evidence: dict[str, list[str]] = {state: [] for state in DEPLOYMENT_STATES}
    for claim in bom["claims"]:
        relation = claim["relation"]
        if relation == "LISTS" and claim["to_key"] == key:
            states["EXISTS"] = True
            evidence["EXISTS"].append(f"{bom['by_key'][claim['from_key']]['name']} lists it")
        if relation in ("INSTALLED_IN", "SHIPS") and claim["to_key"] == key:
            states["INSTALLED"] = True
            evidence["INSTALLED"].append(
                f"{bom['by_key'][claim['from_key']]['name']} ships it")
        if relation == "LOADS" and claim["to_key"] == key:
            states["LOADED"] = True
            evidence["LOADED"].append(f"{bom['by_key'][claim['from_key']]['name']} loads it")
    # a deployment is reached by walking up from the component: the image that ships it is
    # what a deployment names, and a component installed nowhere cannot be deployed
    reached = _walk(bom, key, reverse=True)
    if reached["levels"]["deployment"] and states["INSTALLED"]:
        states["DEPLOYED"] = True
        evidence["DEPLOYED"] = [row_["name"] for row_ in reached["levels"]["deployment"]]
    if reached["levels"]["process"]:
        states["RUNNING"] = True
        evidence["RUNNING"] = [row_["name"] for row_ in reached["levels"]["process"]]
    strongest = next((state for state in reversed(DEPLOYMENT_STATES) if states[state]),
                     None)
    return {
        "query": str(query), "component": row["name"], "states": states,
        "evidence": evidence, "strongest": strongest,
        "deployed": bool(states["DEPLOYED"] or states["RUNNING"]),
        "statement": (f"{row['name']}: " + (", ".join(
            f"{state}={'yes' if states[state] else 'no'}" for state in DEPLOYMENT_STATES))),
        "rule": ("existence in an SBOM is a document, installation is a filesystem and a "
                 "load is a syscall; the three are counted apart"),
    }


def component_states(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """The six states a component can be in, side by side (sbom 6).

    ``SBOM_PRESENT``, ``INSTALLED``, ``LOADED``, ``CONFIGURED``, ``STATIC_REFERENCED``,
    ``RUNTIME_USED``. They are not a ladder: a component can be present, installed, never
    loaded and used anyway through a statically linked copy, and a model with one "used"
    flag cannot say that.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    # a component's crypto is not only what points at the row: a policy that configures an
    # algorithm, a source hit that calls one and an operation that ran one all name the
    # *algorithm*, and the component reaches it through the library it links.
    algorithms = _algorithm_neighbourhood(bom, key)
    states: dict[str, bool] = {state: False for state in COMPONENT_STATES}
    evidence: dict[str, list[str]] = {state: [] for state in COMPONENT_STATES}
    for claim in bom["claims"]:
        relation = claim["relation"]
        source = bom["by_key"][claim["from_key"]]
        if claim["from_key"] in algorithms or claim["to_key"] in algorithms:
            if claim["confidence"] == tb.CONFIGURED:
                states["CONFIGURED"] = True
                evidence["CONFIGURED"].append(f"{source['name']} {relation}")
            if claim["confidence"] == tb.STATIC_OBSERVED:
                states["STATIC_REFERENCED"] = True
                evidence["STATIC_REFERENCED"].append(f"{source['name']} {relation}")
        if relation == "INVOKES" and claim["confidence"] in tb.PROVEN:
            if any(inner["from_key"] == claim["to_key"]
                   and inner["relation"] == "USES_ALGORITHM"
                   and inner["to_key"] in algorithms for inner in bom["claims"]):
                states["RUNTIME_USED"] = True
                evidence["RUNTIME_USED"].append(bom["by_key"][claim["to_key"]]["name"])
        if claim["to_key"] == key:
            if relation == "LISTS":
                states["SBOM_PRESENT"] = True
                evidence["SBOM_PRESENT"].append(source["name"])
            if relation in ("INSTALLED_IN", "SHIPS"):
                states["INSTALLED"] = True
                evidence["INSTALLED"].append(source["name"])
            if relation == "LOADS":
                states["LOADED"] = True
                evidence["LOADED"].append(source["name"])
        touches = claim["from_key"] == key or claim["to_key"] == key
        if touches and claim["confidence"] == tb.CONFIGURED and relation != "LISTS":
            states["CONFIGURED"] = True
            evidence["CONFIGURED"].append(f"{source['name']} {relation}")
        if touches and claim["confidence"] == tb.STATIC_OBSERVED:
            states["STATIC_REFERENCED"] = True
            evidence["STATIC_REFERENCED"].append(f"{source['name']} {relation}")
    present = [state for state in COMPONENT_STATES if states[state]]
    absent = [state for state in COMPONENT_STATES if not states[state]]
    return {
        "query": str(query), "component": row["name"], "states": states,
        "evidence": evidence, "present": present, "absent": absent,
        "statement": (f"{row['name']}: {', '.join(present) or 'nothing'}"
                      + (f"; not {', '.join(absent)}" if absent else "")),
        "rule": ("installed, loaded and used are three different facts; a model that "
                 "promotes one into the next has replaced a measurement with an assumption"),
    }


def _algorithm_neighbourhood(bom: Mapping[str, Any], key: str, *, max_depth: int = 4
                             ) -> set[str]:
    """The algorithm nodes a component reaches: link → library → capability → algorithm."""
    found: set[str] = set()
    seen: set[str] = {key}
    frontier: list[tuple[str, int]] = [(key, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["from_key"] != current:
                continue
            if claim["relation"] not in ("LINKS", "SUPPORTS", "IMPLEMENTS", "PROVIDES_ALGORITHM",
                                         "USES_ALGORITHM", "USES_CRYPTO"):
                continue
            neighbour = claim["to_key"]
            if neighbour in seen:
                continue
            seen.add(neighbour)
            target = bom["by_key"][neighbour]
            if target["kind"] in ("ALGORITHM", "CRYPTO_ASSET"):
                found.add(neighbour)
            frontier.append((neighbour, depth + 1))
    return found


def component_history(previous: Mapping[str, Any], current: Mapping[str, Any], *,
                      detected_at: Any = None) -> dict[str, Any]:
    """A component's version over time, with the evidence on both sides (sbom 22).

    The edge-level comparison in :mod:`cbom.cbom_dependency` answers *what the estate
    depends on* changing. This answers the SBOM question underneath it: *this component was
    3.0.11 and is now 3.0.13*, which is a different fact and has a different owner.
    """
    def versions(bom: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for row in bom["assets"]:
            if row["kind"] not in ("PACKAGE", "CRYPTO_LIBRARY"):
                continue
            claims = [claim for claim in ((row["attributes"] or {}).get("version_claims") or [])
                      if isinstance(claim, Mapping)]
            runtime = next((claim for claim in claims
                            if VERSION_LAYER_BY_SOURCE.get(
                                str(claim.get("source") or "").lower()) == "RUNTIME_VERSION"),
                           None)
            declared = next((claim for claim in claims
                             if VERSION_LAYER_BY_SOURCE.get(
                                 str(claim.get("source") or "").lower()) == "DECLARED_VERSION"),
                            None)
            rows[row["name"]] = {
                "declared": (declared or {}).get("value") or row.get("version"),
                "runtime": (runtime or {}).get("value"),
                "evidence": sorted({str(claim.get("evidence_id"))
                                    for claim in claims if claim.get("evidence_id")}),
            }
        return rows

    before, after = versions(previous), versions(current)
    changes: list[dict[str, Any]] = []
    for name in sorted(set(before) & set(after)):
        for layer in ("declared", "runtime"):
            old, new = before[name][layer], after[name][layer]
            if old and new and old != new:
                changes.append({
                    "code": "DEPENDENCY_CHANGED", "component": name, "layer": layer,
                    "previous_version": old, "current_version": new,
                    "evidence_before": (before[name]["evidence"] or [None])[0],
                    "evidence_after": (after[name]["evidence"] or [None])[0],
                    "detected_at": detected_at})
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    return {
        "changes": changes, "added": added, "removed": removed,
        "counts": {"CHANGED": len(changes), "ADDED": len(added), "REMOVED": len(removed)},
        "statement": (f"{len(changes)} component version(s) moved, {len(added)} added, "
                      f"{len(removed)} removed"
                      + ("; " + ", ".join(
                          f"{row['component']} {row['layer']} {row['previous_version']} → "
                          f"{row['current_version']}" for row in changes[:2])
                         if changes else "")),
        "rule": ("a component's version is a fact with a date: the previous version and the "
                 "evidence for both are kept, and a removed component is reported rather "
                 "than forgotten"),
    }


def version_layers(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """Four version layers, preserved (sbom 5, 21).

    An SBOM that says 3.0.13, an image scan that says 3.0.13 and a process map that says
    3.0.11 are three observations of one component. None of them overwrites another, and
    the disagreement is the finding.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    attributes = row["attributes"] or {}
    claims = [claim for claim in (attributes.get("version_claims") or [])
              if isinstance(claim, Mapping)]
    layers: dict[str, Any] = {name: None for name in VERSION_LAYERS}
    sources: dict[str, list[dict[str, Any]]] = {name: [] for name in VERSION_LAYERS}
    if row.get("version"):
        layers["DECLARED_VERSION"] = row["version"]
        sources["DECLARED_VERSION"].append({"source": "row", "value": row["version"],
                                            "class": tb.IMPORTED})
    for claim in claims:
        layer = VERSION_LAYER_BY_SOURCE.get(str(claim.get("source") or "").lower())
        if layer is None:
            raise _refused(
                "UNKNOWN_VERSION_SOURCE",
                f"{claim.get('source') or '(none)'} is not a version source; a layer has to "
                f"be one of {', '.join(sorted(set(VERSION_LAYER_BY_SOURCE)))}")
        value = tb._norm(claim.get("value"))
        sources[layer].append({"source": claim.get("source"), "value": value,
                               "class": claim.get("class") or tb.IMPORTED,
                               "evidence_id": claim.get("evidence_id")})
        if layers[layer] is None:
            layers[layer] = value
    distinct = sorted({value for value in layers.values() if value})
    conflict = len(distinct) > 1
    return {
        "query": str(query), "component": row["name"], "layers": layers,
        "sources": sources, "distinct": distinct, "conflict": conflict,
        "code": "DEPENDENCY_VERSION_CONFLICT" if conflict else None,
        "statement": (f"{row['name']}: " + ", ".join(
            f"{name}={layers[name] or '—'}" for name in VERSION_LAYERS)
            + (f" — {len(distinct)} versions, preserved" if conflict else "")),
        "rule": ("a declared version, an image version and a runtime version are three "
                 "observations; the conflict is published, not resolved"),
    }


#: who has to cite an algorithm before the citation counts as *a caller's use*. A
#: certificate that carries ECDSA, an HSM that supports it and a policy that configures it
#: are statements about the algorithm, and none of them is a statement about a caller.
CALLER_KINDS: tuple[str, ...] = ("CRYPTO_OPERATION", "SOURCE", "PROCESS", "APPLICATION",
                                 "SERVICE", "CONTAINER", "POD", "CIPHER_SUITE",
                                 "NETWORK_ENDPOINT")


def crypto_handoff(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """What a software component hands to the CBOM, and with which evidence (sbom 7, 8).

    The handoff keeps the evidence type on every row — ``CAPABILITY`` from a provider's
    list, ``IMPORTED`` from the SBOM, ``STATIC_OBSERVED`` from a source hit,
    ``RUNTIME_OBSERVED`` from a probe — because "OpenSSL supports AES-128" and "AES-128 ran"
    arrive down the same edge and must not leave the module looking alike.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    nodes = {key}
    for claim in bom["claims"]:
        if claim["relation"] in ("LINKS",) and claim["from_key"] == key:
            nodes.add(claim["to_key"])
    rows: list[dict[str, Any]] = []
    for claim in bom["claims"]:
        if claim["from_key"] not in nodes or claim["relation"] != "SUPPORTS":
            continue
        capability = bom["by_key"][claim["to_key"]]
        algorithms = [bom["by_key"][inner["to_key"]]["name"] for inner in bom["claims"]
                      if inner["from_key"] == capability["key"]
                      and inner["relation"] == "IMPLEMENTS"]
        types: set[str] = set()
        evidence: set[str] = set()
        for other in bom["claims"]:
            if other["relation"] not in ("USES_ALGORITHM", "USES_CRYPTO"):
                continue
            target = bom["by_key"][other["to_key"]]
            if target["name"] not in algorithms:
                continue
            if bom["by_key"][other["from_key"]]["kind"] not in CALLER_KINDS:
                continue
            types.add(CLASS_TO_EVIDENCE.get(other["confidence"], "UNKNOWN"))
            evidence.update(other.get("evidence_ids") or [])
        declared = {tb.CAPABILITY, tb.IMPORTED}
        if claim["basis"] == "capability-list":
            declared.add("CAPABILITY")
        if any(source["kind"] == "SBOM" for source in
               (bom["by_key"][edge["from_key"]] for edge in bom["claims"]
                if edge["to_key"] == key and edge["relation"] == "LISTS")):
            declared.add("IMPORTED")
        types |= declared
        corroborated = bool(types & PROVEN_EVIDENCE)
        rows.append({
            "capability": capability["name"], "algorithms": algorithms,
            "evidence_types": sorted(types, key=EVIDENCE_TYPES.index),
            "evidence_ids": sorted(evidence),
            "verdict": "CORROBORATED" if corroborated else "CAPABILITY_ONLY",
        })
    counts: dict[str, int] = {}
    for entry in rows:
        for name in entry["evidence_types"]:
            counts[name] = counts.get(name, 0) + 1
    return {
        "query": str(query), "component": row["name"], "rows": rows, "count": len(rows),
        "evidence_counts": dict(sorted(counts.items())),
        "corroborated": [entry["capability"] for entry in rows
                         if entry["verdict"] == "CORROBORATED"],
        "statement": (f"{row['name']}: {len(rows)} capability(ies) handed to the CBOM; "
                      f"{len([entry for entry in rows if entry['verdict'] == 'CORROBORATED'])} "
                      f"corroborated by runtime or network evidence"),
        "rule": ("the SBOM contributes capability and provenance; only a collector "
                 "contributes usage, and the type travels with the row"),
    }


def dependency_tree(bom: Mapping[str, Any], *, query: Any, max_depth: int = 8
                    ) -> dict[str, Any]:
    """Direct and transitive components, with the path that makes one transitive (sbom 12, 13).

    An SBOM is a *flat* list: it names everything that ended up in the artifact and says
    nothing about who asked for it. So directness is read from two different places —
    ``direct`` on the component is what the application's manifest declared, and the
    ``DEPENDS_ON`` walk is what arrived through somebody else. A component that is only
    listed, with no declaring manifest and no path from one, is reported as *listed only*
    rather than promoted into the direct set.
    """
    start = _resolve_one(bom, query)
    roots = _listed_components(bom, start)
    direct_roots = [key for key in roots
                    if (bom["by_key"][key]["attributes"] or {}).get("direct")]
    rows: dict[str, dict[str, Any]] = {}

    listed_by = {claim["to_key"]: claim for claim in bom["claims"]
                 if claim["relation"] in ("LISTS", "SHIPS")}

    def record(key: str, *, kind: str, path: list[str], claim: Mapping[str, Any] | None
               ) -> None:
        row = bom["by_key"][key]
        carrier = claim or listed_by.get(key)
        entry = {
            "component": row["name"], "version": row.get("version"),
            "dependency_kind": kind, "path": path,
            "scope": tb._norm((row["attributes"] or {}).get("scope") or "RUNTIME").upper(),
            "evidence_id": ((carrier.get("evidence_ids") or [None])[0] if carrier
                            else (row.get("evidence_ids") or [None])[0]),
            "basis": carrier["basis"] if carrier else "sbom-import",
            "class": carrier["confidence"] if carrier else tb.IMPORTED,
            "first_seen": carrier.get("first_seen") if carrier else None,
            "last_seen": carrier.get("last_seen") if carrier else None,
        }
        existing = rows.get(key)
        if existing is None or (existing["dependency_kind"] == "TRANSITIVE"
                                and kind == "DIRECT"):
            rows[key] = entry

    for key in direct_roots:
        record(key, kind="DIRECT", path=[bom["by_key"][key]["name"]], claim=None)
    seen: set[str] = set(direct_roots)
    frontier: list[tuple[str, list[str], int]] = [
        (key, [bom["by_key"][key]["name"]], 0) for key in direct_roots]
    while frontier:
        current, path, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["relation"] != "DEPENDS_ON" or claim["from_key"] != current:
                continue
            target = bom["by_key"][claim["to_key"]]
            record(target["key"], kind="TRANSITIVE", path=[*path, target["name"]],
                   claim=claim)
            if target["key"] in seen:
                continue
            seen.add(target["key"])
            frontier.append((target["key"], [*path, target["name"]], depth + 1))
    for key in roots:
        if key in rows:
            continue
        record(key, kind="LISTED_ONLY", path=[bom["by_key"][key]["name"]], claim=None)
    blocks = {kind: sorted((row for row in rows.values() if row["dependency_kind"] == kind),
                           key=lambda entry: entry["component"])
              for kind in ("DIRECT", "TRANSITIVE", "LISTED_ONLY")}
    through = [row for row in blocks["TRANSITIVE"] if len(row["path"]) > 1]
    return {
        "query": str(query), "node": _brief(bom["by_key"][start]),
        "direct": blocks["DIRECT"], "transitive": blocks["TRANSITIVE"],
        "listed_only": blocks["LISTED_ONLY"],
        "statement": (f"{bom['by_key'][start]['name']}: {len(blocks['DIRECT'])} direct, "
                      f"{len(blocks['TRANSITIVE'])} transitive, "
                      f"{len(blocks['LISTED_ONLY'])} listed only"
                      + (f"; {', '.join(row['component'] for row in through)} reached "
                         "through another component" if through else "")),
        "rule": ("a transitive dependency is reported with its path: the direct parent is "
                 "what a remediation upgrades, and the transitive child is what it fixes"),
    }


def _listed_components(bom: Mapping[str, Any], start: str, *, max_depth: int = 6
                       ) -> list[str]:
    """Every component an SBOM or image belonging to ``start`` lists directly."""
    reachable: set[str] = {start}
    frontier: list[tuple[str, int]] = [(start, 0)]
    forward = ("RELEASED_AS", "BUNDLES", "PACKAGED_AS", "DESCRIBED_BY", "HAS_LAYER", "SHIPS",
               "LISTS", "INSTALLED_IN", "RUNS_APPLICATION", "RUNS_PROCESS", "RUNS_CONTAINER",
               "FROM_IMAGE", "DEPLOYED_AS")
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["relation"] not in forward or claim["from_key"] != current:
                continue
            if claim["to_key"] in reachable:
                continue
            reachable.add(claim["to_key"])
            frontier.append((claim["to_key"], depth + 1))
    listed = {claim["to_key"] for claim in bom["claims"]
              if claim["relation"] in ("LISTS", "SHIPS") and claim["from_key"] in reachable}
    return sorted(key for key in listed if bom["by_key"][key]["kind"] == "PACKAGE")


def scope_report(bom: Mapping[str, Any]) -> dict[str, Any]:
    """Components by the scope they were declared in, with the production question (sbom 14)."""
    counts: dict[str, int] = {scope: 0 for scope in SCOPES}
    production: list[str] = []
    flagged: list[dict[str, Any]] = []
    for row in bom["assets"]:
        if row["kind"] != "PACKAGE":
            continue
        scope = tb._norm((row["attributes"] or {}).get("scope") or "RUNTIME").upper()
        counts[scope] = counts.get(scope, 0) + 1
        if scope in PRODUCTION_SCOPES:
            production.append(row["name"])
        elif scope == "BUILD":
            owners = _owners(bom, row["key"], max_depth=PRODUCTION_REACH)
            if owners:
                flagged.append({"component": row["name"], "scope": scope,
                                "applications": sorted({owner["application"]
                                                        for owner in owners})})
    return {
        "counts": counts, "production": sorted(production), "build_scope_in_runtime": flagged,
        "statement": (f"{sum(counts.values())} component(s) across {len([name for name, value in counts.items() if value])} "
                      f"scope(s); {len(production)} in production scope"
                      + (f"; {len(flagged)} build-scope component(s) reach a running "
                         "application" if flagged else "")),
        "rule": ("a BUILD-scope dependency never runs in production, so it is not counted as "
                 "production surface however it is named"),
    }


def canonical_identity(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """One asset, several names — resolved from evidence rather than from a string (sbom 20).

    ``payments-api``, ``payments_api``, ``payment-service`` and ``registry/payment-api`` are
    four names for one thing. This resolves them only through a shared anchor — an artifact
    digest, an image digest, a repository or a namespace — and refuses when the only thing
    the candidates share is a name (``NAME_ONLY_IDENTITY``), because a name-match merge is
    how two applications become one asset and a vulnerability gets attributed to the wrong
    team.
    """
    text = str(query or "").strip().lower()
    if not text:
        raise _refused("UNKNOWN_NODE", "an empty name resolves to nothing")
    bare = "".join(char for char in text if char.isalnum())
    candidates = [row for row in bom["assets"]
                  if row["kind"] in ("APPLICATION", "SERVICE", "PACKAGE", "IMAGE",
                                     "ARTIFACT")
                  and bare and bare in "".join(char for char in row["name"].lower()
                                               if char.isalnum())]
    if not candidates:
        raise _refused("UNKNOWN_NODE", f"{query} is not a node in this projection")
    anchors: dict[str, list[str]] = {}
    for row in candidates:
        for kind, value in _anchors(bom, row["key"]):
            anchors.setdefault(f"{kind}:{value}", []).append(row["name"])
    shared = {name: names for name, names in anchors.items() if len(set(names)) > 1}
    if not shared:
        if len(candidates) == 1:
            row = candidates[0]
            return {"query": str(query), "canonical": row["name"], "kind": row["kind"],
                    "candidates": [row["name"]], "anchors": {},
                    "statement": f"{row['name']} resolves to itself; no second name claims it",
                    "rule": "identity is an evidence anchor, never a string match"}
        raise _refused(
            "NAME_ONLY_IDENTITY",
            f"{', '.join(row['name'] for row in candidates)} share a name and no evidence "
            "anchor; merging them would attribute one team's vulnerability to another")
    applications = [row for row in candidates if row["kind"] == "APPLICATION"]
    canonical = applications[0]["name"] if applications else candidates[0]["name"]
    return {
        "query": str(query), "canonical": canonical,
        "candidates": sorted({row["name"] for row in candidates}),
        "anchors": {name: sorted(set(names)) for name, names in shared.items()},
        "statement": (f"{canonical}: {len(candidates)} record(s) joined by "
                      + ", ".join(sorted(shared)[:3])),
        "rule": ("one canonical asset, many observations: the join is a digest, a repository "
                 "or a deployment identity — never a name"),
    }


def _anchors(bom: Mapping[str, Any], key: str, *, max_depth: int = 4) -> list[tuple[str, str]]:
    """The evidence anchors a node carries or reaches: digests, repositories, namespaces."""
    anchors: list[tuple[str, str]] = []
    row = bom["by_key"][key]
    attributes = row["attributes"] or {}
    if attributes.get("digest"):
        anchors.append(("digest", str(attributes["digest"]).lower()))
    if row["kind"] == "REPOSITORY":
        anchors.append(("repository", row["name"].lower()))
    if row["kind"] == "NAMESPACE":
        anchors.append(("namespace", row["name"].lower()))
    seen: set[str] = {key}
    frontier: list[tuple[str, int]] = [(key, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for claim in bom["claims"]:
            if claim["relation"] not in SUPPLY_RELATIONS:
                continue
            if claim["from_key"] != current:
                continue
            neighbour = claim["to_key"]
            if neighbour in seen:
                continue
            seen.add(neighbour)
            other = bom["by_key"][neighbour]
            other_attributes = other["attributes"] or {}
            if other_attributes.get("digest"):
                anchors.append(("digest", str(other_attributes["digest"]).lower()))
            if other["kind"] in ("REPOSITORY", "NAMESPACE"):
                anchors.append((other["kind"].lower(), other["name"].lower()))
            frontier.append((neighbour, depth + 1))
    return anchors


def component_impact(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """``vulnerability → component → artifact → deployment → application → system`` (sbom 25).

    A CVE in a package is a fact about a file. The blast radius is the walk, and each hop is
    printed with the edge that made it, so a reader can argue with any step.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    if row["kind"] in ("VULNERABILITY", "PACKAGE", "CRYPTO_LIBRARY"):
        start = key
    else:
        raise _refused(
            "NOT_A_COMPONENT",
            f"{row['name']} ({row['kind']}) is not a component or a vulnerability; impact "
            "is asked of a component")
    reached = _walk(bom, start, reverse=True, max_depth=12)
    components = [entry["name"] for entry in reached["levels"]["component"]]
    if row["kind"] != "VULNERABILITY":
        components = [row["name"], *components]
    deployments = [entry["name"] for entry in reached["levels"]["deployment"]]
    applications = sorted({entry["name"] for entry in
                           [*reached["levels"]["application"]]})
    systems = sorted({entry["name"] for entry in reached["levels"]["system"]})
    images = [entry["name"] for entry in reached["levels"]["image"]]
    return {
        "query": str(query), "node": _brief(row), "components": sorted(set(components)),
        "images": images, "deployments": deployments, "applications": applications,
        "systems": systems,
        "statement": (f"{row['name']}: {len(set(components))} component(s), "
                      f"{len(images)} image(s), {len(deployments)} deployment(s), "
                      f"{len(applications)} application(s), {len(systems)} business "
                      f"system(s) affected"),
        "rule": ("impact is a walk from the component to the business system; a CVE that "
                 "reaches no application is still reported, as a component nobody deployed"),
    }


def remediation_plan(bom: Mapping[str, Any], *, query: Any, target_version: Any = None,
                     regression: Iterable[Any] = ()) -> dict[str, Any]:
    """What upgrading one component touches (sbom 26).

    The count is the point: *upgrade OpenSSL → 1 application → 1 business system → 1 image →
    1 process*, plus whatever else the graph says shares the component — a shared library
    reaches anything that loads it, and an HSM integration needs its own regression pass
    because the FIPS module is part of the upgrade.
    """
    key = _resolve_one(bom, query)
    row = bom["by_key"][key]
    reached = _walk(bom, key, reverse=True, max_depth=12)
    applications = sorted({entry["name"] for entry in reached["levels"]["application"]})
    systems = sorted({entry["name"] for entry in reached["levels"]["system"]})
    images = [entry["name"] for entry in reached["levels"]["image"]]
    processes = [entry["name"] for entry in reached["levels"]["process"]]
    hardware = sorted({entry["name"] for entry in reached["levels"]["deployment"]})
    shared = [claim for claim in bom["claims"]
              if claim["relation"] == "LINKS" and claim["to_key"] == key]
    return {
        "query": str(query), "component": row["name"],
        "from_version": row.get("version"), "to_version": target_version,
        "applications": applications, "systems": systems, "images": images,
        "processes": processes, "deployments": hardware,
        "shared_with": [bom["by_key"][claim["from_key"]]["name"] for claim in shared],
        "regression": sorted({str(item) for item in regression}),
        "statement": (f"upgrade {row['name']}"
                      + (f" {row.get('version')} → {target_version}"
                         if target_version else "")
                      + f": affects {len(applications)} application(s), "
                      f"{len(systems)} business system(s), {len(images)} image(s), "
                      f"{len(processes)} process(es)"
                      + (f"; regression: {', '.join(sorted({str(i) for i in regression}))}"
                         if regression else "")),
        "rule": ("a remediation is counted after the walk, so the number a change board "
                 "approves is the number of systems that change"),
    }


def sbom_coverage(bom: Mapping[str, Any], *, expected: int, inspected: int,
                  failed: int = 0, unavailable: int = 0, component: Any = None
                  ) -> dict[str, Any]:
    """A count beside its denominator (sbom 24).

    *20 OpenSSL components discovered* is a numerator. *75 of 100 applications inspected* is
    the sentence a bank can act on, and it is the one printed.
    """
    total = inspected + failed + unavailable
    if total > expected:
        raise _refused(
            "COVERAGE_EXCEEDS_EXPECTED",
            f"{total} applications were inspected, failed or were unavailable, against "
            f"{expected} expected; a denominator smaller than its parts is not a measurement")
    discovered = [row["name"] for row in bom["assets"]
                  if row["kind"] in ("PACKAGE", "CRYPTO_LIBRARY")
                  and (component is None or str(component).lower() in row["name"].lower())]
    ratio = inspected / expected if expected else 0.0
    status = "COMPLETE" if inspected == expected else ("PARTIAL" if inspected else "NONE")
    return {
        "discovered": len(discovered), "components": sorted(discovered),
        "expected": expected, "inspected": inspected, "failed": failed,
        "unavailable": unavailable, "coverage": status,
        "ratio": round(ratio, 3), "quotable_as_total": inspected == expected,
        "statement": (f"{len(discovered)} component(s) discovered; {inspected}/{expected} "
                      f"application(s) inspected ({ratio:.1%}); SBOM completeness: {status}"),
        "rule": ("a count is reported against what was inspected: 'discovered among' is a "
                 "finding, 'the bank has' is a claim nobody made"),
    }


def pqc_handoff(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """What the SBOM is allowed to say about PQC: and what it is not (sbom 27).

    A component's capability list is a *capability*. The migration decision belongs to the
    CBOM, where an operation names the algorithm it ran. This returns the sensitive
    capabilities and the observed usages separately, and refuses to merge them.
    """
    handoff = crypto_handoff(bom, query=query)
    sensitive: set[str] = set()
    for entry in handoff["rows"]:
        for name in entry["algorithms"]:
            if any(token in name.upper() for token in tb.QUANTUM_SENSITIVE):
                sensitive.add(name)
    usage: set[str] = set()
    for claim in bom["claims"]:
        if claim["relation"] != "USES_ALGORITHM" or claim["confidence"] not in tb.PROVEN:
            continue
        source = bom["by_key"][claim["from_key"]]
        if source["kind"] != "CRYPTO_OPERATION":
            continue
        target = bom["by_key"][claim["to_key"]]
        if any(token in target["name"].upper() for token in tb.QUANTUM_SENSITIVE):
            usage.add(target["name"])
    return {
        "query": str(query), "component": handoff["component"],
        "capabilities": sorted(sensitive), "observed_usage": sorted(usage),
        "statement": (f"{handoff['component']}: {len(sensitive)} quantum-sensitive "
                      f"capability(ies) and {len(usage)} observed use(s); the SBOM answers "
                      "the first and the CBOM answers the second"),
        "rule": ("the SBOM hands capability to the CBOM and never decides readiness: a listed "
                 "RSA is a question a migration asks, an observed RSA-2048 is the candidate"),
        "not_proven": ["that a capability is reachable: the component lists it, and no "
                       "collector has shown a caller using it"],
    }


def sbom_graph(bom: Mapping[str, Any]) -> dict[str, Any]:
    """The assembled supply-chain graph, as one projection (sbom 19, 28)."""
    counts: dict[str, int] = {}
    for row in bom["assets"]:
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
    relations: dict[str, int] = {}
    for claim in bom["claims"]:
        relations[claim["relation"]] = relations.get(claim["relation"], 0) + 1
    query_edges = {name: count for name, count in relations.items()
                   if name in SUPPLY_RELATIONS}
    return {
        "levels": levels(bom), "kinds": dict(sorted(counts.items())),
        "relations": dict(sorted(relations.items())), "supply_relations": len(query_edges),
        "canonical": bom.get("source_of_truth"), "second_store": False,
        "projection": "SBOM",
        "statement": (f"{sum(counts.values())} node(s) of {len(counts)} kind(s), "
                      f"{len(bom['claims'])} edge(s), {len(query_edges)} of them on the "
                      f"supply chain; projection of {bom.get('source_of_truth') or 'unknown'}, "
                      "one store"),
        "rule": ("the SBOM is a projection of the canonical estate: a second database that "
                 "agrees on the day it is loaded is a second truth waiting to disagree"),
    }
