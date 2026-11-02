"""Network crypto assets: an interface fact, never an application's property.

The review's item 8 is a single sentence with a large consequence:

    if network observes ``TLS_AES_256_GCM_SHA384``, the CBOM should say
    *network crypto asset AES-256-GCM, endpoint payments.bank.example:443,
    observed on External LB, evidence NET-9281, hop Internet → External LB* —
    **not** *Payments API uses AES-256-GCM*, unless the evidence proves that.

The reason is ordinary bank architecture: client → WAF → external LB → API
gateway → payments API. A handshake seen on ``:443`` terminates at the load
balancer. The algorithms on that hop describe **the balancer's** certificate and
cipher policy; the application behind it may speak TLS 1.2 to the gateway with a
different suite entirely. Folding both into one "the application uses AES-256-GCM"
is the overclaim that makes a CBOM useless in exactly the environment it was
written for.

This module keeps the attribution the review asks for:

1. **one asset per (endpoint, algorithm)**, carrying the interface that observed
   it, the hop it belongs to, and its evidence id;
2. **no application name unless proven** — a hop terminates at an application only
   when that application is declared or the hop says so; a name is never inferred
   from a hostname;
3. **the terminator is classified, not guessed** — ``WAF``, ``LOAD_BALANCER``,
   ``API_GATEWAY``, ``REVERSE_PROXY``, ``CDN`` and ``APPLICATION``, with
   everything else ``UNKNOWN`` rather than quietly defaulting to the application;
4. **the overclaim is detectable** — :func:`audit_graph` reads a usage graph and
   reports every ``USES_CRYPTO`` edge that leans on network evidence terminating
   in front of the subject instead of at it.

A refusal is part of the answer: a handshake with no record of *where* it was
observed is refused, because "somewhere in the path" is what lets the wrong
system inherit the algorithms.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cbom import promotion as promo
from cbom import usage_collectors as uc

SCHEMA = "cryptoscan.cbom-network-assets/1"

#: Interfaces that terminate a hop *in front of* an application. An algorithm
#: observed here belongs to the interface, and to the application only on
#: separate evidence.
FRONTING_ROLES: tuple[str, ...] = (
    "CDN", "WAF", "LOAD_BALANCER", "API_GATEWAY", "REVERSE_PROXY",
)

#: Every role this module will name. Anything else is ``UNKNOWN`` — naming a hop
#: is a claim about who terminates the connection.
ROLES: tuple[str, ...] = FRONTING_ROLES + ("APPLICATION", "ENDPOINT", "UNKNOWN")

#: ``PROVEN`` means an application was declared as this hop's terminator, so the
#: asset may be attributed to it. Everything else is deliberately not attributed.
INFERENCES: tuple[str, ...] = ("PROVEN", "NOT_PROVEN")

_TOKEN_ROLES: dict[str, str] = {
    "waf": "WAF", "firewall": "WAF",
    "lb": "LOAD_BALANCER", "elb": "LOAD_BALANCER", "alb": "LOAD_BALANCER",
    "nlb": "LOAD_BALANCER", "loadbalancer": "LOAD_BALANCER",
    "balancer": "LOAD_BALANCER", "haproxy": "LOAD_BALANCER",
    "gateway": "API_GATEWAY", "apigw": "API_GATEWAY", "apim": "API_GATEWAY",
    "proxy": "REVERSE_PROXY", "envoy": "REVERSE_PROXY", "nginx": "REVERSE_PROXY",
    "cdn": "CDN", "cloudfront": "CDN", "akamai": "CDN", "fastly": "CDN",
}


def _tokens(name: str) -> list[str]:
    cleaned = "".join(char.lower() if char.isalnum() else " " for char in str(name or ""))
    return [token for token in cleaned.split() if token]


def hop_role(name: str | None, *, role: str | None = None) -> str:
    """The interface class of a hop, from an explicit role or its name.

    ``APPLICATION`` is never inferred from a name: an application is only an
    application when the caller says so. Guessing "payments-api" is the
    application and "external-lb" is not would be right most of the time and
    wrong exactly where it matters.
    """
    explicit = str(role or "").strip().upper().replace("-", "_").replace(" ", "_")
    if explicit in ROLES:
        return explicit
    for token in _tokens(name or ""):
        if token in _TOKEN_ROLES:
            return _TOKEN_ROLES[token]
    return "UNKNOWN"


def _declared_applications(applications: Iterable[str] | Mapping[str, Any] | None) -> set[str]:
    if not applications:
        return set()
    values = applications.keys() if isinstance(applications, Mapping) else applications
    return {str(value).strip().lower() for value in values if str(value).strip()}


def _normalise_application(applications: Iterable[str] | Mapping[str, Any] | None,
                           name: str) -> bool:
    return str(name or "").strip().lower() in _declared_applications(applications)


def assets(hops: Iterable[Mapping[str, Any]], *,
           applications: Iterable[str] | Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Network observations -> one attributed asset per (endpoint, algorithm).

    ``hops`` are the rows the network collector produces (or the output of
    :func:`cbom.usage_evidence.tls_paths`): ``from``, ``to``, ``endpoint``,
    ``observed_on``, ``cipher_suite``, ``tls_version``, ``evidence_id``.

    ``applications`` names the applications the estate has declared. Only a hop
    whose terminator is in that set (or which says ``role: APPLICATION``) may
    attribute an algorithm to an application; every other asset says
    ``NOT_PROVEN`` and carries no application name at all.
    """
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    refused: list[dict[str, Any]] = []
    hops_seen: list[dict[str, Any]] = []
    for hop in hops or ():
        if not isinstance(hop, Mapping):
            refused.append({"hop": hop, "reason": "a hop must be an object"})
            continue
        endpoint = str(hop.get("endpoint") or "").strip()
        if not endpoint:
            refused.append({"hop": dict(hop),
                            "reason": "a hop needs the endpoint where it was observed"})
            continue
        suite = hop.get("cipher_suite")
        facts = uc.algorithms_from_cipher_suite(suite) if suite else []
        if not facts:
            refused.append({"endpoint": endpoint,
                            "reason": "no negotiated suite, so no algorithm is attributed"})
            continue
        evidence_id = str(hop.get("evidence_id") or "").strip()
        if not evidence_id:
            refused.append({"endpoint": endpoint,
                            "reason": "the handshake has no evidence id, so the algorithm "
                                      "cannot be attributed to anything"})
            continue
        observed_on = str(hop.get("observed_on") or hop.get("to") or "").strip()
        if not observed_on:
            refused.append({"endpoint": endpoint,
                            "reason": "no interface is recorded as having observed the "
                                      "handshake; a path position is not an owner"})
            continue
        role = hop_role(observed_on, role=hop.get("role") or hop.get("kind"))
        declared = _normalise_application(applications, observed_on)
        if declared and role == "UNKNOWN":
            # the estate said this name is an application, so the hop terminates at
            # one; the role is data the caller supplied, not a guess from the name
            role = "APPLICATION"
        application = observed_on if role == "APPLICATION" or declared else None
        hop_from = str(hop.get("from") or "").strip() or None
        hop_to = str(hop.get("to") or observed_on).strip()
        hops_seen.append({"endpoint": endpoint, "observed_on": observed_on, "role": role,
                          "from": hop_from, "to": hop_to, "cipher_suite": str(suite),
                          "evidence_id": evidence_id})
        for fact in facts:
            algorithm = str(fact["algorithm"])
            key = (endpoint, algorithm)
            row = rows.get(key)
            if row is None:
                row = {
                    "algorithm": algorithm,
                    "role_in_suite": fact.get("role"),
                    "parameters": dict(fact.get("parameters") or {}),
                    "endpoint": endpoint,
                    "observed_on": observed_on,
                    "interface_role": role,
                    "hop": {"from": hop_from, "to": hop_to},
                    "hop_label": (f"{hop_from} → {hop_to}" if hop_from
                                  else f"→ {hop_to}"),
                    "cipher_suites": [str(suite)],
                    "tls_versions": [],
                    "evidence_ids": [evidence_id],
                    "class": "NETWORK_OBSERVED",
                    "attributed_to": endpoint,
                    "application": application,
                    "application_inference": ("PROVEN" if application else "NOT_PROVEN"),
                }
                if hop.get("tls_version"):
                    row["tls_versions"] = [str(hop["tls_version"])]
                rows[key] = row
                continue
            if evidence_id not in row["evidence_ids"]:
                row["evidence_ids"].append(evidence_id)
            if str(suite) not in row["cipher_suites"]:
                row["cipher_suites"].append(str(suite))
            if hop.get("tls_version") and str(hop["tls_version"]) not in row["tls_versions"]:
                row["tls_versions"].append(str(hop["tls_version"]))
            if application and not row["application"]:
                row["application"] = application
                row["application_inference"] = "PROVEN"
    ordered = sorted(rows.values(), key=lambda row: (row["endpoint"], row["algorithm"]))
    for row in ordered:
        row["tls_versions"] = sorted(row["tls_versions"])
        row["cipher_suites"] = sorted(row["cipher_suites"])
        row["evidence_ids"] = sorted(row["evidence_ids"])
        row["statement"] = (
            f"{row['algorithm']} was negotiated on {row['endpoint']} and observed on "
            f"{row['observed_on']} ({row['interface_role']}); "
            + (f"that interface is the application {row['application']}, so the asset is "
               "attributed to it"
               if row["application_inference"] == "PROVEN" else
               "it is an interface fact and is not attributed to any application"))
    unproven = [row for row in ordered if row["application_inference"] != "PROVEN"]
    return {
        "schema": SCHEMA,
        "assets": ordered,
        "hops": hops_seen,
        "refused": refused,
        "endpoints": sorted({row["endpoint"] for row in ordered}),
        "interfaces": sorted({row["observed_on"] for row in ordered}),
        "roles": dict(sorted({role: sum(1 for row in ordered
                                        if row["interface_role"] == role)
                              for role in {row["interface_role"] for row in ordered}
                              }.items())),
        "unattributed_to_an_application": len(unproven),
        "statement": (
            f"{len(ordered)} network crypto asset(s) across {len({row['endpoint'] for row in ordered})} "
            f"endpoint(s) and {len({row['observed_on'] for row in ordered})} interface(s); "
            f"{len(unproven)} not attributed to an application"
            + (f"; {len(refused)} hop(s) refused for having no owner or no evidence"
               if refused else "")),
    }


def to_components(result: Mapping[str, Any]) -> dict[str, Any]:
    """Network assets as CycloneDX components, one per endpoint **and** algorithm.

    The component is deliberately not the same object as the promoted algorithm
    asset: two endpoints negotiating the same suite are two assets with two
    evidence ids, and a document that merged them could not answer which
    interface to fix.
    """
    components: list[dict[str, Any]] = []
    for row in result.get("assets") or []:
        profile = {
            "usage": "OBSERVED",
            "confidence": "HIGH",
            "observed_classes": ["NETWORK_OBSERVED"],
            "evidence_ids": list(row.get("evidence_ids") or []),
            "asset": {"algorithm": row["algorithm"],
                      "parameters": dict(row.get("parameters") or {}),
                      "purpose": "TLS"},
        }
        component = promo.crypto_component(row["algorithm"], profile=profile)
        component["bom-ref"] = f"network:{row['endpoint']}#{row['algorithm']}"
        component["name"] = row["algorithm"]
        properties = [
            {"name": "cryptoscan:network_observed", "value": "true"},
            {"name": "cryptoscan:endpoint", "value": row["endpoint"]},
            {"name": "cryptoscan:observed_on", "value": row["observed_on"]},
            {"name": "cryptoscan:interface_role", "value": row["interface_role"]},
            {"name": "cryptoscan:hop", "value": row["hop_label"]},
            {"name": "cryptoscan:cipher_suites", "value": ",".join(row["cipher_suites"])},
            {"name": "cryptoscan:application_inference", "value": row["application_inference"]},
        ]
        if row.get("application"):
            properties.append({"name": "cryptoscan:application",
                               "value": str(row["application"])})
        component["properties"] = list(component.get("properties") or []) + properties
        components.append(component)
    return {
        "schema": SCHEMA,
        "components": components,
        "statement": (
            f"{len(components)} network component(s), one per endpoint and algorithm; "
            "an application property appears only where the evidence proves the terminator"),
    }


def audit_graph(graph: Mapping[str, Any],
                result: Mapping[str, Any]) -> dict[str, Any]:
    """Every usage edge that leans on network evidence terminating *in front of* it.

    This is the review's distinction, made checkable. ``system:estate
    --USES_CRYPTO--> algorithm:AES-256-GCM`` whose only observing class is
    ``NETWORK_OBSERVED`` and whose hop terminated at a load balancer is an
    overclaim: the balancer terminated the handshake, the application behind it
    was not observed. The audit reports it and does not rewrite it — deciding
    whether the application also uses the algorithm needs evidence, not code.
    """
    network_algorithms: dict[str, list[dict[str, Any]]] = {}
    for row in result.get("assets") or []:
        network_algorithms.setdefault(str(row["algorithm"]), []).append(row)
    overclaims: list[dict[str, Any]] = []
    checked = 0
    for edge in graph.get("edges") or ():
        if not isinstance(edge, Mapping) or str(edge.get("kind")) != "USES_CRYPTO":
            continue
        algorithm = str(edge.get("to") or "").split(":", 1)[-1]
        if algorithm not in network_algorithms:
            continue
        checked += 1
        classes = {str(value).upper()
                   for value in (edge.get("classes") or edge.get("evidence_classes") or [])}
        if classes != {"NETWORK_OBSERVED"}:
            # any other observing class is evidence about the subject itself — runtime,
            # static or configuration. Only an edge whose *whole* basis is a handshake
            # can be an overclaim.
            continue
        subject = str(edge.get("from") or "")
        subject_name = subject.split(":", 1)[-1]
        provable = [row for row in network_algorithms[algorithm]
                    if row.get("application_inference") == "PROVEN"
                    and str(row.get("application") or "").lower() == subject_name.lower()]
        if provable:
            continue
        fronts = [row for row in network_algorithms[algorithm]
                  if row.get("application_inference") != "PROVEN"]
        if not fronts:
            continue
        overclaims.append({
            "subject": subject,
            "algorithm": algorithm,
            "terminated_at": sorted({row["observed_on"] for row in fronts}),
            "interface_roles": sorted({row["interface_role"] for row in fronts}),
            "endpoints": sorted({row["endpoint"] for row in fronts}),
            "evidence_ids": sorted({evidence for row in fronts
                                    for evidence in row.get("evidence_ids") or []}),
            "reason": ("the network evidence for this algorithm terminates in front of "
                       "the subject, so it proves the interface's cipher policy and not "
                       "the subject's usage"),
        })
    return {
        "schema": SCHEMA,
        "checked_edges": checked,
        "overclaims": overclaims,
        "statement": (
            f"{len(overclaims)} overclaim(s) among {checked} network-backed USES_CRYPTO "
            "edge(s)"
            + ("; each rests on a hop that terminated in front of the subject"
               if overclaims else "")),
    }


def summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """The one-screen answer: what the network saw, and who it belongs to."""
    rows = list(result.get("assets") or [])
    unproven = [row for row in rows if row.get("application_inference") != "PROVEN"]
    return {
        "schema": SCHEMA,
        "assets": len(rows),
        "endpoints": len({row["endpoint"] for row in rows}),
        "interfaces": len({row["observed_on"] for row in rows}),
        "algorithms": sorted({row["algorithm"] for row in rows}),
        "attributed_to_an_application": len(rows) - len(unproven),
        "not_attributed": [
            f"{row['endpoint']} {row['algorithm']} @ {row['observed_on']}"
            for row in unproven
        ],
        "refused": len(result.get("refused") or []),
        "statement": (
            f"{len(rows)} network asset(s) over {len({row['endpoint'] for row in rows})} "
            f"endpoint(s); {len(rows) - len(unproven)} attributed to an application, "
            f"{len(unproven)} left with the interface that terminated them"),
    }
