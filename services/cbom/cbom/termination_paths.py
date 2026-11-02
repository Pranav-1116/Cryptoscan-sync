"""TLS termination as a path: three relationships, never one attribute.

The review's item 9 draws the picture and then the consequence:

    Client ──TLS1.3 AES-256-GCM──▶ External LB
    External LB ──TLS1.2 AES-128-GCM──▶ API Gateway
    API Gateway ──TLS1.3 AES-256-GCM──▶ Payments API

Three cryptographic relationships, hop by hop. Not one:

    Payments API = AES-256

The difference matters because the middle hop is *weaker than both ends*: TLS 1.2
with AES-128-GCM inside a connection that is TLS 1.3 with AES-256-GCM on either
side. A CBOM that collapses the path into "the application uses AES-256-GCM" is
not merely imprecise — it hides the only hop a reviewer needed to see. And the
reverse mistake is just as bad: reporting the path as "AES-256-GCM, AES-128-GCM"
in one inventory tells an auditor nothing about *where* the weak suite lives.

This module keeps the path:

1. **hops are chained, not collected** — a hop whose ``from`` is another hop's
   ``to`` continues the path; a hop with no connector is a **gap**, reported
   rather than bridged by invention;
2. **each hop is one relationship** with its own TLS version, suite, algorithms
   and evidence — the endpoint of the hop it belongs to, never the terminal;
3. **a change between adjacent hops is the finding** — a version downgrade, an
   algorithm change, or the same algorithm with weaker parameters mid-path;
4. **the merged claim is refused explicitly** — :func:`merged_claim` shows what a
   naive union would say and why it describes no hop;
5. **pass-through hops are named** — a hop that tunnels TLS is ``PASSES_THROUGH``
   and its algorithms are the endpoints', not the middlebox's.

Nothing here decides whether a downgrade is *allowed*: it reports the path, and a
policy comparison is a separate, reviewable decision.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cbom import usage_collectors as uc

SCHEMA = "cryptoscan.cbom-termination-paths/1"

#: What a hop does with the connection it carries.
MODES: tuple[str, ...] = ("TERMINATES", "PASSES_THROUGH", "UNKNOWN")

#: How two adjacent hops differ.
CHANGES: tuple[str, ...] = ("TLS_VERSION_DOWNGRADE", "TLS_VERSION_UPGRADE",
                            "BULK_CIPHER_CHANGED", "SUITE_CHANGED")

_VERSION_RANK = {"1": 10, "1.0": 10, "1.1": 11, "1.2": 12, "1.3": 13}


def _version_rank(version: Any) -> int | None:
    """``TLSv1.2``, ``TLS1.2`` and ``1.2`` all rank the same; anything else is None."""
    text = str(version or "").strip().upper()
    if not text:
        return None
    for prefix in ("TLSV", "TLS"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return _VERSION_RANK.get(text.strip().lstrip("V").strip())


def suite_facts(hop: Mapping[str, Any]) -> list[dict[str, Any]]:
    suite = hop.get("cipher_suite") or (hop.get("crypto") or {}).get("cipher_suite")
    return uc.algorithms_from_cipher_suite(str(suite)) if suite else []


def _algorithms(hop: Mapping[str, Any]) -> list[str]:
    return [str(fact["algorithm"]) for fact in suite_facts(hop)]


def _bulk(hop: Mapping[str, Any]) -> list[str]:
    """The algorithms that actually protect the data on this hop.

    Comparing whole suites across TLS versions compares signatures and key
    exchanges too, so 1.3's two-name suite reads as "narrower" than 1.2's four-name
    one. The bulk cipher is the part a downgrade changes, and the part a reviewer
    is looking for.
    """
    return sorted({str(fact["algorithm"]) for fact in suite_facts(hop)
                   if str(fact.get("role") or "") == "BULK"})


def _node(name: str) -> str:
    return f"host:{name}"


def hop_row(hop: Mapping[str, Any], index: int) -> dict[str, Any]:
    """One hop as one relationship, with the facts that belong to *it*."""
    suite = hop.get("cipher_suite") or (hop.get("crypto") or {}).get("cipher_suite")
    tls_version = hop.get("tls_version") or (hop.get("crypto") or {}).get("tls_version")
    mode = str(hop.get("mode") or "").strip().upper()
    if mode not in MODES:
        mode = "PASSES_THROUGH" if hop.get("terminates") is False else "TERMINATES"
    return {
        "hop": index,
        "from": str(hop.get("from") or "").strip() or None,
        "to": str(hop.get("to") or hop.get("observed_on") or "").strip() or None,
        "observed_on": hop.get("observed_on"),
        "endpoint": hop.get("endpoint"),
        "tls_version": str(tls_version) if tls_version else None,
        "cipher_suite": str(suite) if suite else None,
        "algorithms": _algorithms(hop),
        "bulk_algorithms": _bulk(hop),
        "key_exchange": hop.get("key_exchange"),
        "certificate_ref": hop.get("certificate_ref"),
        "mode": mode,
        "evidence_ids": [str(hop.get("evidence_id"))] if hop.get("evidence_id") else [],
        "class": "NETWORK_OBSERVED",
    }


def _refuse(hop: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(hop, Mapping):
        return {"hop": index, "reason": "a hop must be an object"}
    if not str(hop.get("from") or "").strip():
        return {"hop": index, "reason": "a hop needs the node it starts from"}
    if not str(hop.get("to") or hop.get("observed_on") or "").strip():
        return {"hop": index, "reason": "a hop needs the node it reaches"}
    if not (hop.get("cipher_suite") or (hop.get("crypto") or {}).get("cipher_suite")):
        return {"hop": index, "reason": "a hop with no negotiated suite is not a "
                                        "cryptographic relationship"}
    if not hop.get("evidence_id"):
        return {"hop": index, "reason": "a hop with no evidence id cannot be shown on a path"}
    return None


def _chain(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Follow ``from``/``to`` and return the ordered chains, never bridging a gap."""
    by_source: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_source.setdefault(str(row["from"]), []).append(row)
    targets = {str(row["to"]) for row in rows}
    starts = [row for row in rows if str(row["from"]) not in targets]
    used: set[int] = set()
    paths: list[list[dict[str, Any]]] = []
    for start in sorted(starts, key=lambda row: rows.index(row)):
        chain = [start]
        used.add(rows.index(start))
        while True:
            current = chain[-1]
            candidates = [row for row in by_source.get(str(current["to"]), [])
                          if rows.index(row) not in used]
            if not candidates:
                break
            nxt = candidates[0]
            used.add(rows.index(nxt))
            chain.append(nxt)
        paths.append(chain)
    return paths


def _changes(chain: list[dict[str, Any]], path: int) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for previous, current in zip(chain, chain[1:]):
        before = _version_rank(previous.get("tls_version"))
        after = _version_rank(current.get("tls_version"))
        if before is not None and after is not None and after < before:
            changes.append({"path": path, "kind": "TLS_VERSION_DOWNGRADE",
                            "from_hop": previous["hop"], "to_hop": current["hop"],
                            "detail": (f"TLS {current['tls_version']} after "
                                       f"TLS {previous['tls_version']}")})
        elif before is not None and after is not None and after > before:
            changes.append({"path": path, "kind": "TLS_VERSION_UPGRADE",
                            "from_hop": previous["hop"], "to_hop": current["hop"],
                            "detail": (f"TLS {current['tls_version']} after "
                                       f"TLS {previous['tls_version']}")})
        came_from = set(previous.get("bulk_algorithms") or [])
        went_to = set(current.get("bulk_algorithms") or [])
        if came_from and went_to and came_from != went_to:
            changes.append({"path": path, "kind": "BULK_CIPHER_CHANGED",
                            "from_hop": previous["hop"], "to_hop": current["hop"],
                            "detail": (f"{sorted(went_to)} after {sorted(came_from)}")})
        if previous.get("cipher_suite") and current.get("cipher_suite") \
                and previous["cipher_suite"] != current["cipher_suite"] \
                and not (came_from and went_to and came_from != went_to):
            changes.append({"path": path, "kind": "SUITE_CHANGED",
                            "from_hop": previous["hop"], "to_hop": current["hop"],
                            "detail": (f"{current['cipher_suite']} after "
                                       f"{previous['cipher_suite']}")})
    return changes


def _relationship_statement(row: Mapping[str, Any]) -> str:
    version = str(row.get("tls_version") or "").strip()
    algorithms = ", ".join(row.get("algorithms") or []) or "no algorithm"
    prefix = f"TLS {version} " if version else ""
    return (f"{row['from']} → {row['to']} is its own relationship: {prefix}{algorithms}")


def build(hops: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The ordered termination path: one relationship per hop, gaps left visible."""
    refused: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for index, hop in enumerate(hops or (), start=1):
        reason = _refuse(hop, index)
        if reason is not None:
            refused.append(reason)
            continue
        rows.append(hop_row(hop, len(rows) + 1))

    paths: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    for number, chain in enumerate(_chain(rows) or [], start=1):
        path_changes = _changes(chain, number)
        changes.extend(path_changes)
        nodes = [str(chain[0]["from"])] + [str(row["to"]) for row in chain]
        row_relationships = [
            {"path": number, "hop": row["hop"], "from": row["from"], "to": row["to"],
             "tls_version": row["tls_version"], "cipher_suite": row["cipher_suite"],
             "algorithms": row["algorithms"], "mode": row["mode"],
             "evidence_ids": row["evidence_ids"],
             "terminated_at": row["to"] if row["mode"] == "TERMINATES" else None,
             "statement": _relationship_statement(row)}
            for row in chain]
        relationships.extend(row_relationships)
        paths.append({
            "path": number,
            "nodes": nodes,
            "hops": chain,
            "relationships": row_relationships,
            "changes": path_changes,
            "statement": (
                f"{len(chain)} cryptographic relationship(s) along "
                f"{' → '.join(nodes)}; each hop is a separate fact"),
        })

    # a hop that connects to nothing is not a one-hop path: its position on the path
    # is unknown, and claiming it is the whole path would be an invention
    gaps = [{"hop": row["hop"], "from": row["from"], "to": row["to"],
             "reason": ("no other recorded hop connects to this one, so its position on "
                        "the path is unknown; the chain is not invented around it")}
            for chain in _chain(rows) if len(chain) == 1 for row in chain]

    return {
        "schema": SCHEMA,
        "paths": paths,
        "relationships": relationships,
        "changes": changes,
        "downgrades": [change for change in changes
                       if change["kind"] == "TLS_VERSION_DOWNGRADE"],
        "gaps": gaps,
        "refused": refused,
        "merged": merged_claim(paths),
        "statement": (
            f"{len(relationships)} cryptographic relationship(s) across {len(paths)} path(s)"
            + (f"; {len(changes)} change(s) between adjacent hops" if changes else "")
            + (f"; {len(gaps)} hop(s) not connected to any path" if gaps else "")
            + (f"; {len(refused)} hop(s) refused" if refused else "")),
    }


def merged_claim(paths: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """What collapsing the path into one attribute would say, and why it is wrong.

    The output is deliberately a *refusal*: the union is computed so a reviewer can
    see the claim a naive tool would make, with the reason it describes no hop.
    """
    rows = list(paths)
    union: list[str] = []
    per_hop: list[list[str]] = []
    for path in rows:
        for hop in path.get("hops") or ():
            per_hop.append(list(hop.get("algorithms") or []))
            for algorithm in hop.get("algorithms") or ():
                if algorithm not in union:
                    union.append(algorithm)
    distinctive = any(len(hop) != len(union) or set(hop) != set(union) for hop in per_hop)
    return {
        "algorithms": union,
        "refused": bool(rows),
        "hops_differ": distinctive,
        "statement": (
            (f"collapsing this path would claim {', '.join(union) or 'no algorithm'} for "
             "every node on it; no hop negotiates that set, so the claim describes no hop")
            if rows else "there is no path to collapse"),
    }


def to_components(result: Mapping[str, Any]) -> dict[str, Any]:
    """One component per (path, hop, algorithm), so the weak hop stays visible."""
    components: list[dict[str, Any]] = []
    for path in result.get("paths") or []:
        for hop in path.get("hops") or []:
            for algorithm in hop.get("algorithms") or []:
                components.append({
                    "type": "cryptographic-asset",
                    "bom-ref": (f"path:{path['path']}#hop:{hop['hop']}#{algorithm}"),
                    "name": algorithm,
                    "cryptoProperties": {"assetType": "algorithm"},
                    "properties": [
                        {"name": "cryptoscan:path", "value": str(path["path"])},
                        {"name": "cryptoscan:hop", "value": str(hop["hop"])},
                        {"name": "cryptoscan:from", "value": str(hop["from"])},
                        {"name": "cryptoscan:to", "value": str(hop["to"])},
                        {"name": "cryptoscan:tls_version",
                         "value": str(hop.get("tls_version") or "")},
                        {"name": "cryptoscan:mode", "value": str(hop["mode"])},
                        {"name": "cryptoscan:observed_classes",
                         "value": "NETWORK_OBSERVED"},
                    ] + [{"name": "cryptoscan:evidence_id", "value": evidence}
                         for evidence in hop.get("evidence_ids") or []],
                })
    return {
        "schema": SCHEMA,
        "components": components,
        "statement": (
            f"{len(components)} component(s), one per path, hop and algorithm; a suite on "
            "one hop is never written as another hop's property"),
    }


def to_edges(result: Mapping[str, Any]) -> dict[str, Any]:
    """Hop-scoped edges: each hop negotiates its algorithms, and hops precede hops."""
    edges: list[dict[str, Any]] = []
    for path in result.get("paths") or []:
        hops = list(path.get("hops") or [])
        for hop in hops:
            source = f"hop:{hop['from']}→{hop['to']}"
            for algorithm in hop.get("algorithms") or []:
                edges.append({
                    "from": source, "kind": "NEGOTIATES", "to": f"algorithm:{algorithm}",
                    "path": path["path"], "hop": hop["hop"],
                    "tls_version": hop.get("tls_version"),
                    "evidence_ids": list(hop.get("evidence_ids") or []),
                    "classes": ["NETWORK_OBSERVED"], "provenance": "OBSERVED"})
        for previous, current in zip(hops, hops[1:]):
            edges.append({
                "from": f"hop:{previous['from']}→{previous['to']}",
                "kind": "PRECEDES",
                "to": f"hop:{current['from']}→{current['to']}",
                "path": path["path"],
                "evidence_ids": (list(previous.get("evidence_ids") or [])
                                 + list(current.get("evidence_ids") or [])),
                "classes": ["NETWORK_OBSERVED"], "provenance": "OBSERVED"})
    return {
        "schema": SCHEMA,
        "edges": edges,
        "statement": (
            f"{len(edges)} edge(s): every algorithm edge belongs to the hop that "
            "negotiated it, and PRECEDES keeps the order"),
    }


def summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """The one-screen answer: how many relationships, and where the path weakens."""
    paths = list(result.get("paths") or [])
    relationships = list(result.get("relationships") or [])
    downgrades = list(result.get("downgrades") or [])
    return {
        "schema": SCHEMA,
        "paths": len(paths),
        "relationships": len(relationships),
        "changes": len(result.get("changes") or []),
        "downgrades": len(downgrades),
        "weakest_hops": [
            f"path {row['path']} hop {row['to_hop']}: {row['detail']}"
            for row in downgrades],
        "gaps": len(result.get("gaps") or []),
        "refused": len(result.get("refused") or []),
        "merge_refused": bool((result.get("merged") or {}).get("refused")),
        "statement": (
            f"{len(relationships)} cryptographic relationship(s) across {len(paths)} "
            f"path(s); {len(downgrades)} version downgrade(s)"
            + ("; the path is not collapsed into one attribute"
               if (result.get("merged") or {}).get("refused") else "")),
    }
