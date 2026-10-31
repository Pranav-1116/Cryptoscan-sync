"""Follow an evidence-backed path through the estate graph — and stop where it stops.

The Digital Twin's core claim is a *chain*:

    Payment API → runs on → Container → runs on → Kubernetes
        → uses → OpenSSL → runtime observed → AES-256-GCM
        → TLS terminates at → Load Balancer → uses → HSM

One hop is easy; ``EstateGraph.assert_relationship`` already refuses an edge with
no basis or no evidence. The chain is harder, and it is where a twin usually starts
lying: it is tempting to *complete* a path with what is plausible ("the app runs
on a node in the same namespace as the HSM") or to silently skip the hop that has
no evidence, so a seven-link chain renders as six and looks whole.

The walk keeps a *frontier* — every node the path has reached — because the vision's
chain is not one linear walk. The application both runs on a container (which runs
on a cluster that uses OpenSSL) *and* terminates TLS at a load balancer that uses an
HSM. A strict single-node walk could never take the sixth hop, so the frontier is
what makes the chain expressible; every hop still records which node it started
from, so the result is auditable rather than a hand-wave.

This module walks a pattern of hops over the **established** edges only, and when
it cannot take the next hop it says exactly why:

``COMPLETE``
    every hop in the pattern was taken from an established edge.
``REFUSED_EDGE``
    the relation was attempted and the graph refused it — the reason recorded in
    ``unresolved_relationships`` is quoted (no basis, no evidence, a basis that
    cannot establish *use*, evidence the graph does not hold).
``NO_EDGE``
    nothing in the graph relates this node by the required predicate.
``NO_ASSET``
    the subject of the next hop is not in the graph at all (the previous collector
    never discovered it).
``PATTERN_EXHAUSTED``
    the walk ran out of pattern while the node still had established edges — a
    longer chain exists than the question asked for.

The output carries the evidence ids and confidence of **every** hop, so the caller
can see which link is the weakest, and a ``weakest_confidence`` for the whole path.
A chain is only as strong as its weakest hop and this returns that hop rather than
an average that hides it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .estate_graph import ASSET_TYPES, RELATIONSHIP_PREDICATES

SCHEMA = "cryptoscan.evidence-chain/1"

COMPLETE = "COMPLETE"
REFUSED_EDGE = "REFUSED_EDGE"
NO_EDGE = "NO_EDGE"
NO_ASSET = "NO_ASSET"
PATTERN_EXHAUSTED = "PATTERN_EXHAUSTED"

#: weakest-to-strongest; used to rank hops, never to compute an average
CONFIDENCE_RANK: dict[str, int] = {
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "VENDOR_DECLARED": 2,
    "IMPORTED": 2,
    "INFERRED": 1,
    "UNKNOWN": 0,
}


@dataclass(frozen=True)
class Hop:
    """One required step: a predicate, and optionally the type it must land on."""

    predicate: str
    to_type: str | None = None
    label: str | None = None

    def describe(self) -> str:
        return self.label or self.predicate


#: The vision's chain, expressed as hops. Asset types are matched when stated,
#: because ``runs_on`` from an application lands on a container *or* a VM and the
#: difference matters to the reader. The chain is walked over a *frontier* (see
#: :func:`trace`), which is why the TLS hop can leave from the application after
#: the walk has already descended to the cluster.
_USAGE: tuple[Hop, ...] = (
    Hop("runs_on", "CONTAINER", "runs on"),
    Hop("runs_on", "CLUSTER", "runs on"),
    Hop("uses_crypto_library", "LIBRARY", "uses"),
    Hop("uses_algorithm", "CRYPTO_ASSET", "runtime observed"),
)

#: A shorter, more common question: what crypto does this application actually use?
APPLICATION_CRYPTO_USAGE: tuple[Hop, ...] = _USAGE

#: The full vision chain: usage, then where TLS is terminated, then the HSM behind it.
APPLICATION_CRYPTO_PATH: tuple[Hop, ...] = _USAGE + (
    Hop("terminates_tls_for", "LOAD_BALANCER", "TLS terminates at"),
    Hop("uses", "HSM", "uses"),
)

#: Named patterns a caller may ask for by name, plus free-form hop lists.
PATTERNS: dict[str, tuple[Hop, ...]] = {
    "crypto-path": APPLICATION_CRYPTO_PATH,
    "crypto-usage": APPLICATION_CRYPTO_USAGE,
}


@dataclass
class _Walk:
    hops: list[dict[str, Any]] = field(default_factory=list)


def _sorted_edges(edges: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic order, so the same estate always renders the same chain."""
    return sorted(
        (dict(edge) for edge in edges),
        key=lambda edge: (
            str(edge.get("subject")),
            str(edge.get("predicate")),
            str(edge.get("object")),
        ),
    )


def _refusal_for(
    unresolved: Sequence[Mapping[str, Any]], subject: str, predicate: str
) -> dict[str, Any] | None:
    """The recorded reason this hop was attempted and refused, if it was."""
    for entry in unresolved:
        if str(entry.get("subject")) != subject or str(entry.get("predicate")) != predicate:
            continue
        return {
            "reason": str(entry.get("reason") or "refused without a stated reason"),
            "basis": entry.get("basis"),
            "evidence_ids": list(entry.get("evidence_ids") or []),
        }
    return None


def _name(graph: Any, asset_id: str) -> str:
    asset = graph.asset(asset_id) or {}
    return str(asset.get("name") or asset_id)


def _asset_type(graph: Any, asset_id: str) -> str | None:
    asset = graph.asset(asset_id)
    return (asset or {}).get("type")


def trace(
    graph: Any,
    start: str,
    pattern: Sequence[Hop],
    *,
    max_branches: int = 8,
) -> dict[str, Any]:
    """Follow ``pattern`` from ``start`` over established edges.

    ``graph`` is an ``EstateGraph`` (or anything offering ``relationships()``,
    ``unresolved_relationships()`` and ``asset(id)``). The return value is a
    document, not a verdict: ``status`` says where the walk stopped, ``hops``
    carries the evidence behind every step it did take, and ``stop`` explains the
    one it did not.
    """
    if graph.asset(start) is None:
        return {
            "schema": SCHEMA,
            "start": start,
            "status": NO_ASSET,
            "complete": False,
            "hops": [],
            "stop": {"at": start, "expected": pattern[0].describe() if pattern else None,
                     "reason": "the starting asset is not in the graph — nothing discovered it"},
            "rendered": str(start),
            "weakest_confidence": None,
        }

    edges = _sorted_edges(graph.relationships())
    unresolved = list(graph.unresolved_relationships())
    by_subject: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        by_subject.setdefault(str(edge.get("subject")), []).append(edge)

    walk = _Walk()
    frontier: list[str] = [start]
    current = start
    rendered = _name(graph, start)

    def finish(status: str, stop: Mapping[str, Any] | None) -> dict[str, Any]:
        confidences = [hop.get("confidence") for hop in walk.hops]
        weakest = min(
            (confidence for confidence in confidences if confidence),
            key=lambda level: CONFIDENCE_RANK.get(str(level), 0),
            default=None,
        )
        return {
            "schema": SCHEMA,
            "start": start,
            "status": status,
            "complete": status == COMPLETE,
            "hops": walk.hops,
            "stop": dict(stop) if stop else None,
            "rendered": rendered,
            "weakest_confidence": weakest,
            "hop_count": len(walk.hops),
        }

    for index, hop in enumerate(pattern, start=1):
        candidates: list[dict[str, Any]] = []
        for node in frontier:
            for edge in by_subject.get(node, []):
                if str(edge.get("predicate")) != hop.predicate:
                    continue
                if edge.get("status", "ESTABLISHED") != "ESTABLISHED":
                    continue
                if hop.to_type and _asset_type(graph, str(edge.get("object"))) != hop.to_type:
                    continue
                candidates.append(edge)
        if not candidates:
            refusal = None
            for node in frontier:
                refusal = refusal or _refusal_for(unresolved, node, hop.predicate)
            current = frontier[-1]
            if refusal is not None:
                return finish(
                    REFUSED_EDGE,
                    {
                        "at": current,
                        "expected": hop.describe(),
                        "predicate": hop.predicate,
                        "to_type": hop.to_type,
                        "reason": refusal["reason"],
                        "refused_basis": refusal["basis"],
                        "refused_evidence_ids": refusal["evidence_ids"],
                    },
                )
            sibling_predicates = sorted({
                str(edge.get("predicate"))
                for node in frontier
                for edge in by_subject.get(node, [])
            })
            return finish(
                NO_EDGE,
                {
                    "at": current,
                    "expected": hop.describe(),
                    "predicate": hop.predicate,
                    "to_type": hop.to_type,
                    "reason": (
                        "no established edge carries this hop from any node on the path so far"
                        + (f"; the path so far is related by {', '.join(sibling_predicates)}"
                           if sibling_predicates else "; the path so far is related to nothing")
                    ),
                    "available_predicates": sibling_predicates,
                },
            )
        edge = candidates[0]
        if len(candidates) > max_branches:
            # Not a failure — a statement about the shape. A node with fifty
            # algorithm edges is a different question than one with two, and the
            # caller should ask for the branch it means.
            return finish(
                PATTERN_EXHAUSTED,
                {
                    "at": current,
                    "expected": hop.describe(),
                    "predicate": hop.predicate,
                    "reason": f"{len(candidates)} established edges satisfy this hop; narrow the question",
                    "branch_count": len(candidates),
                },
            )
        subject = str(edge.get("subject"))
        target = str(edge.get("object"))
        walk.hops.append(
            {
                "index": index,
                "subject": subject,
                "predicate": str(edge.get("predicate")),
                "object": target,
                "basis": edge.get("basis"),
                "evidence_ids": list(edge.get("evidence_ids") or []),
                "confidence": edge.get("confidence"),
                "usage_state": (edge.get("attributes") or {}).get("usage_state"),
                "from_type": _asset_type(graph, subject),
                "to_type": _asset_type(graph, target),
            }
        )
        rendered += f" —{edge.get('predicate')}→ {_name(graph, target)}"
        current = target
        if target not in frontier:
            frontier.append(target)

    return finish(COMPLETE, None)


def weakest_hop(chain: Mapping[str, Any]) -> dict[str, Any] | None:
    """The hop that sets the strength of the whole chain, or None for an empty one."""
    hops = list(chain.get("hops") or [])
    if not hops:
        return None
    return min(hops, key=lambda hop: CONFIDENCE_RANK.get(str(hop.get("confidence")), 0))


def unobserved_use_hops(chain: Mapping[str, Any]) -> list[int]:
    """Indexes of the ``uses*`` hops that rest on something other than an observation.

    A chain can be complete and still be a configuration story: ``uses`` from a
    deployment manifest says the application was *told* to use a library, not that
    it did, and a PKCS#11 reference says a key *will* be used. The indexes are
    returned rather than a single flag so the caller can say *which* link is a
    configuration claim instead of condemning the whole path.
    """
    return [
        int(hop.get("index") or 0)
        for hop in chain.get("hops") or []
        if str(hop.get("predicate", "")).startswith("uses")
        and str(hop.get("basis") or "") != "RUNTIME_OBSERVATION"
    ]


def requires_observation(chain: Mapping[str, Any]) -> bool:
    """True when any hop claims *use* without an observation behind it."""
    return bool(unobserved_use_hops(chain))


def parse_pattern(text: str) -> tuple[Hop, ...]:
    """A named pattern, or a comma list of ``predicate`` / ``predicate:TYPE``.

    Free-form hops are deliberately strict: an unknown predicate or asset type is a
    ``ValueError`` at the boundary rather than a hop that silently matches nothing,
    because "no edge carries this hop" and "this hop could never exist" are
    different answers and only the caller can tell which one they meant.
    """
    key = str(text or "").strip()
    if not key:
        raise ValueError("a pattern is required; try crypto-path or crypto-usage")
    if key in PATTERNS:
        return PATTERNS[key]
    hops: list[Hop] = []
    for raw in key.split(","):
        part = raw.strip()
        if not part:
            raise ValueError("empty hop in pattern; each hop is predicate or predicate:TYPE")
        predicate, _, to_type = part.partition(":")
        predicate = predicate.strip()
        to_type = to_type.strip().upper() or None
        if predicate not in RELATIONSHIP_PREDICATES:
            raise ValueError(
                f"unknown predicate {predicate!r}; expected one of {', '.join(RELATIONSHIP_PREDICATES)}"
            )
        if to_type and to_type not in ASSET_TYPES:
            raise ValueError(
                f"unknown asset type {to_type!r}; expected one of {', '.join(ASSET_TYPES)}"
            )
        hops.append(Hop(predicate, to_type))
    return tuple(hops)


def resolve_asset(graph: Any, ref: str) -> tuple[str | None, list[dict[str, str]]]:
    """Resolve an id *or* an exact name to an asset id.

    Names are not unique on purpose (two estates may both have a "Payment API"), so
    an ambiguous name returns ``(None, candidates)`` rather than picking one. The
    caller shows the candidates; guessing here would attach a real chain to the
    wrong asset, which is the one mistake a twin must never make.
    """
    value = str(ref or "").strip()
    if not value:
        return None, []
    if graph.asset(value) is not None:
        return value, []
    matches = [
        {"asset_id": asset.get("asset_id"), "type": asset.get("type"), "name": asset.get("name")}
        for asset in sorted(graph.assets(), key=lambda item: str(item.get("asset_id")))
        if str(asset.get("name") or "") == value
    ]
    if len(matches) == 1:
        return str(matches[0]["asset_id"]), []
    return None, matches
