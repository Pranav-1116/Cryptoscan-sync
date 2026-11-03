"""Network topology as relationships that each carry their own evidence.

Review item 12 is a warning more than a feature request:

    Relationships: `CONNECTS_TO`, `ROUTES_TO`, `TERMINATES_TLS`, `RE_ENCRYPTS`,
    `PASSTHROUGH`, `PROTECTED_BY`, `USES_CERTIFICATE`, `USES_HSM`, `USES_KMS`. Every
    relationship needs `evidence_id`, `observed_at`, `source`, `confidence` — otherwise
    the topology is fiction.

A topology is the most persuasive artefact the platform produces and therefore the one
most able to lie. This module makes the lie structurally impossible:

* an edge with no evidence id is **not written** — it is listed under ``refused`` with
  the reason, including the four fields it is missing;
* an edge's ``confidence`` is derived from what the evidence can support, never
  supplied by the caller: a handshake seen by a collector is ``OBSERVED``, a certificate
  chain assembled from names is ``ASSEMBLED``, a CMDB mapping is ``DECLARED``;
* ``RE_ENCRYPTS`` and ``PASSTHROUGH`` are the two claims that are almost always wrong,
  so both have a gate. Re-encryption needs **two handshakes in one path** with
  different termination — a decrypt and a new encrypt. Passthrough needs evidence that
  the *same* session continued, which one probe cannot show, so it is only written when
  both hops carry the same session identifier from the same collector;
* a hop's TLS never becomes the application's property: ``TERMINATES_TLS`` points at the
  device that terminated it, and reaching an application needs its own edge.

The kinds are the review's nine, and no other kind is accepted.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.cbom-topology/1"

#: exactly the review's vocabulary, in its order
KINDS: tuple[str, ...] = (
    "CONNECTS_TO", "ROUTES_TO", "TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH",
    "PROTECTED_BY", "USES_CERTIFICATE", "USES_HSM", "USES_KMS",
)

#: how strong a relationship is, and what each level means
CONFIDENCE: tuple[str, ...] = ("OBSERVED", "ASSEMBLED", "DECLARED")

#: the four fields every relationship must carry, per the review
REQUIRED: tuple[str, ...] = ("evidence_id", "observed_at", "source", "confidence")

#: kinds that describe a forwarding device rather than a terminating one
FORWARDING: tuple[str, ...] = ("CONNECTS_TO", "ROUTES_TO", "PASSTHROUGH")

#: device roles that may terminate TLS, and those that may only forward
TERMINATING_ROLES: tuple[str, ...] = (
    "LOAD_BALANCER", "ADC", "REVERSE_PROXY", "API_GATEWAY", "WAF", "SERVER",
    "MAIL_GATEWAY", "VPN", "APPLIANCE", "UNKNOWN",
)

#: the two claims that need more than one observation
GATED: tuple[str, ...] = ("RE_ENCRYPTS", "PASSTHROUGH")

NOT_PROVEN = [
    "that a relationship is complete: the topology contains what was collected, and a "
    "device nobody probed is absent rather than disconnected",
    "that a `CONNECTS_TO` edge is a permitted flow: reachability observed by a scanner "
    "is not an approved firewall rule, and no policy is consulted here",
    "that `PASSTHROUGH` is decryption-free: it says the same session continued on both "
    "hops in one collector's view, which is stronger than a guess and weaker than a "
    "packet capture",
    "that a `PROTECTED_BY` edge protects anything: a WAF in front of an application is "
    "a position in a path, not a guarantee about what it inspects",
]

DEFAULT_MISSING = "no evidence id, observation time, source or confidence"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        return sorted({str(item).strip() for item in value if str(item).strip()})
    return []


def node(name: str, *, role: str = "UNKNOWN", **attributes: Any) -> dict[str, Any]:
    """A topology node: a device, an application, a system, a certificate, a key."""
    label = _text(name)
    if not label:
        raise ValueError("a topology node needs a name")
    return {
        "name": label,
        "role": str(role or "UNKNOWN").upper(),
        "attributes": {key: value for key, value in attributes.items() if value},
    }


def _confidence(claim: Mapping[str, Any], kind: str) -> str:
    """What the evidence can support — the caller does not get to choose."""
    declared = str(claim.get("confidence") or "").upper()
    classes = {str(value).upper() for value in _values(claim.get("evidence_class")
                                                       or claim.get("classes"))}
    if "NETWORK_OBSERVED" in classes or "RUNTIME_OBSERVED" in classes \
            or "HANDSHAKE" in classes:
        return "OBSERVED"
    if "DECLARED" in classes or declared == "DECLARED" or claim.get("declared"):
        return "DECLARED"
    if "ASSEMBLED" in classes or claim.get("assembled"):
        return "ASSEMBLED"
    if declared in CONFIDENCE:
        # a caller may under-claim, never over-claim
        return declared
    return "ASSEMBLED"


def _edge(claim: Mapping[str, Any], *, kind: str, source: str, target: str,
          confidence: str) -> dict[str, Any]:
    return {
        "from": source,
        "to": target,
        "kind": kind,
        "evidence_id": _text(claim.get("evidence_id")),
        "evidence_ids": _values(claim.get("evidence_ids") or claim.get("evidence_id")),
        "observed_at": _text(claim.get("observed_at")),
        "source": _text(claim.get("source") or claim.get("collector")),
        "confidence": confidence,
        "detail": _text(claim.get("detail")) or f"{source} {kind.lower()} {target}",
    }


def build(claims: Iterable[Mapping[str, Any]], *,
          nodes: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Evidence-backed claims -> a topology, with every refusal explained.

    ``claims`` are relationships somebody observed, assembled or declared:
    ``kind``, ``from``, ``to``, ``evidence_id``, ``observed_at``, ``source``, and
    optionally ``evidence_class``. `RE_ENCRYPTS` claims additionally need
    ``handshakes`` (two, in one path); `PASSTHROUGH` claims need a matching
    ``session_id`` on both hops.
    """
    edges: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for claim in claims or ():
        if not isinstance(claim, Mapping):
            refused.append({"claim": claim, "reason": "a relationship must be an object"})
            continue
        kind = str(claim.get("kind") or "").upper()
        if kind not in KINDS:
            refused.append({"claim": dict(claim),
                            "reason": (f"{kind or 'no kind'} is not one of the nine "
                                       "relationship kinds")})
            continue
        source = _text(claim.get("from"))
        target = _text(claim.get("to"))
        if not source or not target:
            refused.append({"claim": dict(claim),
                            "reason": "a relationship needs both ends"})
            continue
        # confidence is derived from the evidence class, so it is not demanded of the
        # caller; the other three cannot be derived from anything
        missing = [field for field in REQUIRED
                   if field != "confidence" and not _text(claim.get(field))]
        if missing:
            refused.append({"claim": dict(claim),
                            "reason": ("a relationship without " + ", ".join(missing)
                                       + " is fiction and is not written")})
            continue
        if kind == "RE_ENCRYPTS":
            handshakes = [row for row in claim.get("handshakes") or []
                          if isinstance(row, Mapping) and _text(row.get("evidence_id"))]
            if len(handshakes) < 2:
                refused.append({"claim": dict(claim), "reason": (
                    "re-encryption needs two handshakes in one path — a decrypt and a "
                    "new encrypt — and one hop cannot show both")})
                continue
        if kind == "PASSTHROUGH":
            if not _text(claim.get("session_id")):
                refused.append({"claim": dict(claim), "reason": (
                    "passthrough claims the same session continued, which needs the "
                    "session identifier both hops carry; a scanner sees two "
                    "handshakes and cannot tell passthrough from termination")})
                continue
        confidence = _confidence(claim, kind)
        edge = _edge(claim, kind=kind, source=source, target=target,
                     confidence=confidence)
        edge["claim_confidence"] = str(claim.get("confidence") or "").upper() or None
        edge["overclaimed"] = bool(edge["claim_confidence"] == "OBSERVED"
                                   and confidence != "OBSERVED")
        edges.append(edge)

    declared_nodes = [row for row in nodes or () if isinstance(row, Mapping)]
    names = {str(row.get("name")) for row in declared_nodes if row.get("name")}
    names |= {edge[end] for edge in edges for end in ("from", "to")}
    used_kinds: dict[str, int] = {}
    for edge in edges:
        used_kinds[edge["kind"]] = used_kinds.get(edge["kind"], 0) + 1
    return {
        "schema": SCHEMA,
        "nodes": sorted(names),
        "declared_nodes": sorted(row["name"] for row in declared_nodes
                                 if row.get("name")),
        "edges": edges,
        "refused": refused,
        "counts": dict(sorted(used_kinds.items())),
        "kinds_unused": [kind for kind in KINDS if kind not in used_kinds],
        "undeclared_nodes": sorted({edge[end] for edge in edges for end in ("from", "to")}
                                   - {str(row.get("name")) for row in declared_nodes
                                      if row.get("name")}),
        "confidence": {level: sum(1 for edge in edges
                                  if edge["confidence"] == level)
                       for level in CONFIDENCE},
        "overclaimed": [edge for edge in edges if edge["overclaimed"]],
        "statement": (
            f"{len(edges)} relationship(s) across {len(used_kinds)} kind(s) and "
            f"{len(names)} node(s)"
            + (f"; {len(refused)} claim(s) refused for carrying no evidence or needing "
               "more than one observation" if refused else "")
            + (f"; {len([e for e in edges if e['overclaimed']])} claim(s) called "
               "themselves observed with nothing observed behind them"
               if any(edge["overclaimed"] for edge in edges) else "")),
    }


def audit(topology: Mapping[str, Any], *,
          applications: Iterable[str] | None = None) -> dict[str, Any]:
    """Read the topology back and find the four ways it can still mislead."""
    if not isinstance(topology, Mapping) or topology.get("schema") != SCHEMA:
        raise ValueError(f"the topology is not a {SCHEMA} document")
    declared_apps = {str(name).strip().lower() for name in applications or ()}
    findings: list[dict[str, Any]] = []
    for edge in topology.get("edges") or []:
        for field in REQUIRED:
            if field != "confidence" and not edge.get(field):
                findings.append({"kind": "EDGE_WITHOUT_PROVENANCE", "edge": edge,
                                 "detail": f"{edge['kind']} is missing {field}"})
        if edge["kind"] in GATED and edge.get("confidence") == "DECLARED" and \
                not edge.get("session_id") and edge["kind"] == "PASSTHROUGH":
            findings.append({"kind": "GATED_CLAIM_DECLARED_ONLY", "edge": edge,
                             "detail": ("passthrough rests on a declaration; confirm it "
                                        "with the device's own session records")})
        if edge["kind"] == "TERMINATES_TLS" and edge["to"].strip().lower() in declared_apps:
            findings.append({"kind": "TLS_ATTRIBUTED_TO_AN_APPLICATION", "edge": edge,
                             "detail": ("a terminating device's TLS is not the "
                                        "application's property; the edge belongs on "
                                        "the device that terminated it")})
        if edge.get("overclaimed"):
            findings.append({"kind": "CONFIDENCE_OVERCLAIMED", "edge": edge,
                             "detail": (f"claimed {edge['claim_confidence']}, "
                                        f"supported {edge['confidence']}")})
    for node_name in topology.get("nodes") or []:
        if node_name not in set(topology.get("declared_nodes") or []):
            findings.append({"kind": "UNDECLARED_NODE", "node": node_name,
                             "detail": ("this node appears only because an edge names "
                                        "it; nothing says what it is")})
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["kind"]] = counts.get(finding["kind"], 0) + 1
    return {
        "schema": SCHEMA,
        "findings": findings,
        "counts": dict(sorted(counts.items())),
        "clean": not findings,
        "statement": (
            "the topology is internally honest: every edge carries provenance and no "
            "claim outruns its evidence" if not findings else
            f"{len(findings)} problem(s) in the topology: "
            + ", ".join(f"{count} {name.lower()}" for name, count in sorted(counts.items()))),
    }


def from_hops(hops: Iterable[Mapping[str, Any]],
              certificates: Iterable[Mapping[str, Any]] | None = None,
              keys: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Observed hops, certificates and key bindings -> claims this module can write.

    Nothing is added that the input does not support: a hop becomes `CONNECTS_TO` and
    `TERMINATES_TLS`, a certificate presentation becomes `USES_CERTIFICATE`, an HSM or
    KMS binding becomes `USES_HSM`/`USES_KMS`. `RE_ENCRYPTS` is derived only when a path
    carries two handshakes at different terminators, and `PASSTHROUGH` only when a hop
    says so with a session id.
    """
    claims: list[dict[str, Any]] = []
    for hop in hops or ():
        if not isinstance(hop, Mapping):
            continue
        source, target = _text(hop.get("from")), _text(hop.get("to") or hop.get("observed_on"))
        evidence = hop.get("evidence_id")
        if not source or not target or not evidence:
            continue
        base = {"from": source, "to": target,
                "evidence_id": evidence,
                "observed_at": hop.get("observed_at"),
                "source": hop.get("collector") or hop.get("source") or "network-probe",
                "evidence_class": "NETWORK_OBSERVED"}
        claims.append({**base, "kind": "CONNECTS_TO",
                       "detail": f"{source} opened a connection to {target}"})
        role = str(hop.get("role") or hop.get("terminator_role") or "").upper()
        if hop.get("cipher_suite") and role in TERMINATING_ROLES:
            claims.append({**base, "kind": "TERMINATES_TLS",
                           "detail": (f"{target} terminated TLS "
                                      f"{hop.get('tls_version') or ''} "
                                      f"{hop.get('cipher_suite')}").strip()})
        if hop.get("session_id") and hop.get("passthrough"):
            claims.append({**base, "kind": "PASSTHROUGH",
                           "session_id": hop.get("session_id"),
                           "detail": f"{source} → {target} forwarded one session"})
    for row in certificates or ():
        if not isinstance(row, Mapping):
            continue
        endpoint = _text(row.get("endpoint"))
        ref = _text(row.get("certificate_ref"))
        if endpoint and ref and _text(row.get("evidence_id")):
            claims.append({"kind": "USES_CERTIFICATE", "from": endpoint, "to": ref,
                           "evidence_id": row.get("evidence_id"),
                           "observed_at": row.get("observed_at"),
                           "source": row.get("source") or "network-probe",
                           "evidence_class": "NETWORK_OBSERVED",
                           "detail": f"{endpoint} presented {ref}"})
    for row in keys or ():
        if not isinstance(row, Mapping):
            continue
        host = _text(row.get("host") or row.get("from"))
        target = _text(row.get("hsm_id") or row.get("kms_id") or row.get("key_ref"))
        kind = "USES_HSM" if row.get("hsm_id") else "USES_KMS" if row.get("kms_id") else None
        if host and target and kind and _text(row.get("evidence_id")):
            claims.append({"kind": kind, "from": host, "to": target,
                           "evidence_id": row.get("evidence_id"),
                           "observed_at": row.get("observed_at"),
                           "source": row.get("source") or "kms-inventory",
                           "evidence_class": row.get("evidence_class") or "DECLARED",
                           "detail": f"{host} uses {target}"})
    return {"schema": SCHEMA, "claims": claims,
            "statement": (f"{len(claims)} relationship(s) derived from "
                          f"{len(list(hops or []))} hop(s), {len(list(certificates or []))} "
                          "certificate presentation(s) and key bindings")}


def summary(topology: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: how many relationships, of which kinds, at what confidence."""
    edges = topology.get("edges") or []
    return {
        "schema": SCHEMA,
        "nodes": len(topology.get("nodes") or []),
        "relationships": len(edges),
        "counts": topology.get("counts") or {},
        "unused_kinds": topology.get("kinds_unused") or [],
        "confidence": topology.get("confidence") or {},
        "refused": len(topology.get("refused") or []),
        "observed_share": (round(sum(1 for edge in edges
                                     if edge["confidence"] == "OBSERVED")
                                / len(edges), 2) if edges else 0.0),
        "statement": topology.get("statement", ""),
        "not_proven": list(NOT_PROVEN),
    }
