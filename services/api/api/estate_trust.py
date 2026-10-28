"""Certificate trust paths, walked from the graph and reported as far as evidence goes (§24).

The console's Network section lists *trust paths*, and it is the one part of the estate a
flat inventory cannot answer: a certificate is only trustworthy relative to an issuer, and
that issuer relative to another, until something roots the chain. The twin has the edges
(``issued_by`` / ``signed_by``, each with evidence) and had no walk over them.

Five outcomes, and the distinctions matter more than the counts:

* **ROOTED** — the chain reaches a certificate authority the estate collected, and that
  authority claims no issuer of its own. That is a root *as far as this evidence goes*,
  which is not the same as a root the operating system trusts;
* **SELF_SIGNED** — the leaf is its own issuer. Common in internal estates, and a finding
  only because it means nobody else vouches for it;
* **BROKEN** — an issuer is named that the model cannot accept: the edge was refused for
  want of a basis or evidence, or the named issuer is an asset that cannot vouch for a
  certificate (a product, a vendor). This is the most misread state in certificate
  tooling, so the entry says what is wrong *and* what it does not prove;
* **CYCLE** — the walk returned to a node it had already visited. Reported and stopped, not
  followed forever;
* **UNKNOWN_ISSUER** — no issuer edge at all, so the chain cannot be judged. An
  unexamined chain is not a broken one.

Nothing here verifies a signature, checks an expiry date or claims a path is trusted. It
reports the shape the *evidence* describes, with the evidence ids, so an auditor can walk
the same path themselves — and the limits say exactly where the walk stops.
"""
from __future__ import annotations

from typing import Any, Mapping

SCHEMA = "cryptoscan.estate-trust-paths/1"

#: edges that mean "the subject is vouched for by the object"
ISSUER_PREDICATES = ("issued_by", "signed_by")

ROOTED = "ROOTED"
SELF_SIGNED = "SELF_SIGNED"
BROKEN = "BROKEN"
CYCLE = "CYCLE"
UNKNOWN_ISSUER = "UNKNOWN_ISSUER"

#: asset types that can sit in a chain
CHAIN_TYPES = frozenset({"CERTIFICATE", "CA"})

#: how deep a chain is walked before the walk stops and says so
MAX_DEPTH = 12


def _issuers(graph: Any) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    """Established and refused issuer edges, indexed by subject."""
    established: dict[str, list[dict[str, Any]]] = {}
    refused: dict[str, list[dict[str, Any]]] = {}
    for edge in graph.relationships():
        if str(edge.get("predicate")) not in ISSUER_PREDICATES:
            continue
        established.setdefault(str(edge.get("subject")), []).append(dict(edge))
    for edge in graph.unresolved_relationships():
        if str(edge.get("predicate")) not in ISSUER_PREDICATES:
            continue
        refused.setdefault(str(edge.get("subject")), []).append(dict(edge))
    return established, refused


def _step(asset: Mapping[str, Any] | None, edge: Mapping[str, Any] | None, *, missing: bool) -> dict[str, Any]:
    return {
        "asset_id": (asset or {}).get("asset_id") if asset else (edge or {}).get("object"),
        "asset_name": (asset or {}).get("name") if asset else None,
        "asset_type": (asset or {}).get("type") if asset else None,
        "present": not missing,
        "evidence_ids": list((edge or {}).get("evidence_ids") or []),
        "basis": (edge or {}).get("basis"),
        "confidence": (edge or {}).get("confidence"),
    }


def _walk(
    graph: Any,
    start_id: str,
    *,
    established: Mapping[str, list[dict[str, Any]]],
    refused: Mapping[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    assets = {str(asset["asset_id"]): asset for asset in graph.assets()}
    subject = start_id
    chain: list[dict[str, Any]] = [_step(assets.get(start_id), None, missing=False)]
    seen = {start_id}
    depth = 0

    while depth < MAX_DEPTH:
        depth += 1
        edges = established.get(subject) or []
        if not edges:
            break
        edge = sorted(edges, key=lambda item: str(item.get("object")))[0]
        target = str(edge.get("object"))
        target_asset = assets.get(target)
        chain.append(_step(target_asset, edge, missing=target_asset is None))
        if target == subject:
            return {"status": SELF_SIGNED, "chain": chain, "reason": (
                "this certificate names itself as its issuer: nobody else vouches for it"
            )}
        if target_asset is not None and str(target_asset.get("type")) not in CHAIN_TYPES:
            return {"status": BROKEN, "chain": chain, "reason": (
                f"{target_asset.get('name') or target} is named as the issuer, but it is a "
                f"{target_asset.get('type')}, which cannot vouch for a certificate. Either the "
                "edge is wrong or that asset was mis-typed"
            )}
        if target_asset is None:
            return {"status": BROKEN, "chain": chain, "reason": (
                f"{target} is named as an issuer but the estate holds no asset for it. That "
                "usually means the authority is outside the collected scope — it does not prove "
                "the chain is invalid, and it does not prove it is valid"
            )}
        if target in seen:
            return {"status": CYCLE, "chain": chain, "reason": (
                f"the walk returned to {target_asset.get('name') or target}; the evidence "
                "describes a loop, so no root can be reached this way"
            )}
        seen.add(target)
        subject = target

    if depth >= MAX_DEPTH:
        return {"status": UNKNOWN_ISSUER, "chain": chain, "reason": (
            f"the chain is longer than {MAX_DEPTH} links, so the walk stopped before reaching a "
            "root. The length is reported rather than a verdict on the root"
        )}

    head = chain[-1]
    if len(chain) == 1:
        refused_edges = refused.get(start_id) or []
        if refused_edges:
            return {"status": BROKEN, "chain": chain, "reason": (
                "an issuer was named, but the graph refused the edge: "
                + str(refused_edges[0].get("reason") or "no reason recorded")
            )}
        return {"status": UNKNOWN_ISSUER, "chain": chain, "reason": (
            "no issuer edge was ever asserted for this certificate, so the chain cannot be "
            "judged — an unexamined chain is not a broken one"
        )}
    if str(head.get("asset_type")) == "CA":
        return {"status": ROOTED, "chain": chain, "reason": (
            "the chain reaches a certificate authority the estate collected that claims no "
            "issuer of its own — a root as far as this evidence goes, which is not a statement "
            "about what an operating system trusts"
        )}
    return {"status": UNKNOWN_ISSUER, "chain": chain, "reason": (
        f"the deepest link is a {head.get('asset_type') or 'node of unknown type'} with no "
        "issuer edge, so this is where the evidence stops rather than a root"
    )}


def survey(graph: Any, *, limit: int = 200) -> dict[str, Any]:
    """Every certificate in the estate, walked to whatever its evidence calls a root."""
    established, refused = _issuers(graph)
    assets = list(graph.assets())
    chain_assets = [
        asset for asset in assets
        if str(asset.get("type")) in CHAIN_TYPES
    ]

    walks: list[dict[str, Any]] = []
    for asset in sorted(chain_assets, key=lambda item: str(item.get("name") or item["asset_id"])):
        asset_id = str(asset["asset_id"])
        result = _walk(graph, asset_id, established=established, refused=refused)
        walks.append(
            {
                "asset_id": asset_id,
                "asset_name": asset.get("name"),
                "asset_type": asset.get("type"),
                "status": result["status"],
                "length": len(result["chain"]),
                "chain": result["chain"],
                "reason": result["reason"],
            }
        )

    by_status: dict[str, int] = {name: 0 for name in (ROOTED, SELF_SIGNED, BROKEN, CYCLE, UNKNOWN_ISSUER)}
    for entry in walks:
        by_status[entry["status"]] += 1

    longest = max((entry["length"] for entry in walks), default=0)
    return {
        "schema": SCHEMA,
        "chains": walks[:limit],
        "count": len(walks),
        "by_status": by_status,
        "rooted_count": by_status[ROOTED],
        "broken_count": by_status[BROKEN],
        "unjudged_count": by_status[UNKNOWN_ISSUER],
        "longest_chain": longest,
        "meaning": (
            "a chain is walked from each certificate up its issuer edges until the evidence "
            "stops. Where it stops is reported, not judged: an issuer outside the collected "
            "scope and an invalid chain look the same from here and are not the same thing"
        ),
        "limits": [
            "no signature is verified, no expiry is checked and no revocation is consulted: "
            "this is the shape the evidence describes, not a validation of the certificate",
            "a BROKEN chain usually means the authority was not collected rather than that the "
            "certificate is untrusted. Both readings are in the entry, and neither is chosen "
            "for you",
            "ROOTED means the estate holds a CA claiming no issuer of its own. Whether any "
            "operating system trusts that CA is outside the evidence",
            "the walk takes one issuer per certificate (the first by id) when an asset names "
            "several, because a certificate with two issuers is a data-quality problem to "
            "chase, not two chains to average",
        ],
    }
