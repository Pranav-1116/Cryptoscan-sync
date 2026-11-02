"""Supported, configured, negotiated: three states, three evidences.

Review item 7 is a data-model complaint, and it is right:

    SUPPORTED  → what the endpoint offered when asked
    CONFIGURED → what policy says it should do
    NEGOTIATED → what one handshake actually produced

The three are never derived from one another:

* ``NEGOTIATED TLS 1.3`` says nothing about whether TLS 1.2 is still offered —
  negotiating one protocol is not evidence about the others;
* ``SUPPORTED TLS 1.2`` says nothing about whether anything still uses it;
* ``CONFIGURED TLS 1.2+`` is a policy statement, and a policy that nobody measured
  against is a declaration, not a measurement.

So this module keeps three evidence sets per endpoint, each with its own evidence
ids, and answers the two questions a reader actually asks:

* *can we claim a protocol is disabled?* — only from a **complete** authorized
  capability enumeration in which the protocol is absent. A negotiated handshake is
  never enough, and neither is a partial enumeration: the ClientHellos that never
  ran are exactly where the old protocol is;
* *what is the minimum version?* — from configuration first, from a complete
  enumeration second, and **never** from a negotiated value, because the endpoint
  may simply have agreed to what this client offered.

SSH and IKE follow the same shape (`ADVERTISED` is the SSH name for `SUPPORTED`), so
review items 13 and 14 can feed the same model without a second vocabulary.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

SCHEMA = "cryptoscan.cbom-tls-state/1"

#: The three states. Order is the ladder of evidence strength, not of policy.
STATES: tuple[str, ...] = ("SUPPORTED", "CONFIGURED", "NEGOTIATED")

#: Other protocol vocabularies that mean the same thing.
STATE_ALIASES = {
    "ADVERTISED": "SUPPORTED",      # SSH server banner algorithm lists
    "OFFERED": "SUPPORTED",
    "ENABLED": "CONFIGURED",        # a configuration document's wording
    "POLICY": "CONFIGURED",
    "SELECTED": "NEGOTIATED",
    "IN_USE": "NEGOTIATED",
}

#: What a claim can be based on, strongest first.
BASES: tuple[str, ...] = ("CONFIGURED", "SUPPORTED_ENUMERATION", "NEGOTIATED_ONLY")

#: Protocol order, so "minimum" means something.
PROTOCOL_ORDER: tuple[str, ...] = ("SSL2", "SSL3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")

FACETS: tuple[str, ...] = ("tls_version", "cipher_suite", "group", "signature_algorithm")


def _norm(value: Any) -> str:
    text = str(value or "").strip().upper().replace(" ", "")
    text = text.replace("TLSV", "TLS").replace("SSLV", "SSL")
    if text.startswith("TLS1") and "." not in text[3:4]:
        text = f"TLS{text[3]}.{text[4:]}" if len(text) > 4 else text
    return text


def _version(value: Any) -> str | None:
    """Normalise a protocol name to the estate's vocabulary, or leave it alone."""
    raw = str(value or "").strip()
    if not raw:
        return None
    candidates = {_norm(raw), _norm(raw.replace("_", ".")), _norm(raw.replace(".", ""))}
    for candidate in candidates:
        if candidate in PROTOCOL_ORDER:
            return candidate
    text = raw.upper().replace("_", ".").replace("-", ".")
    text = text.removeprefix("TLSV").removeprefix("TLS").removeprefix("V")
    try:
        number = float(text)
    except ValueError:
        return raw
    if number >= 1.3:
        return "TLS1.3"
    if number >= 1.2:
        return "TLS1.2"
    if number >= 1.1:
        return "TLS1.1"
    if number >= 1.0:
        return "TLS1.0"
    return raw


def _state(value: Any) -> str:
    top = str(value or "").strip().upper().replace(" ", "_").replace("-", "_")
    if top in STATES:
        return top
    if top in STATE_ALIASES:
        return STATE_ALIASES[top]
    raise ValueError(
        f"state {value!r} is not one of {', '.join(STATES)} — a fact whose state is "
        "unknown cannot be sorted into one, and guessing would be the bug")


def observe(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Observation rows -> per-endpoint state sets with their evidence, or refusals.

    A row is one fact in one state::

        {"endpoint": "payments:443", "state": "NEGOTIATED", "tls_version": "1.3",
         "cipher_suite": "TLS_AES_256_GCM_SHA384", "group": "X25519",
         "evidence_id": "NET-1", "observed_at": "2026-11-02T10:00:00Z"}

    ``enumeration_complete`` on a ``SUPPORTED`` row says the enumeration tried every
    ClientHello variant the platform supports; without it the offered set is known to
    be *at least* these values and nothing can be claimed about absence.
    """
    endpoints: dict[str, dict[str, Any]] = {}
    refused: list[dict[str, Any]] = []
    for index, row in enumerate(rows or (), start=1):
        if not isinstance(row, Mapping):
            refused.append({"row": index, "reason": "an observation must be an object"})
            continue
        endpoint = str(row.get("endpoint") or row.get("host") or "").strip()
        evidence_id = str(row.get("evidence_id") or "").strip()
        try:
            state = _state(row.get("state") or row.get("class"))
        except ValueError as exc:
            refused.append({"row": index, "endpoint": endpoint or None,
                            "reason": str(exc)})
            continue
        if not endpoint:
            refused.append({"row": index, "reason": "an observation needs an endpoint"})
            continue
        if not evidence_id:
            refused.append({
                "row": index, "endpoint": endpoint, "state": state,
                "reason": (f"a {state} fact with no evidence id is a claim: the state "
                           "must be provable, not asserted")})
            continue
        facets = {facet: row.get(facet) for facet in FACETS if row.get(facet) not in (None, "")}
        if facets.get("tls_version"):
            facets["tls_version"] = _version(facets["tls_version"])
        if not facets:
            refused.append({
                "row": index, "endpoint": endpoint, "state": state,
                "reason": (f"a {state} fact with no protocol, suite, group or signature "
                           "algorithm says nothing about the endpoint")})
            continue
        entry = endpoints.setdefault(endpoint, {
            "endpoint": endpoint, "supported": [], "configured": [], "negotiated": [],
            "enumeration": {"complete": False, "evidence_ids": []},
            "last_observed_at": None,
        })
        entry[state.lower()].append({
            "state": state,
            "evidence_id": evidence_id,
            "observed_at": row.get("observed_at"),
            "source": row.get("source"),
            **facets,
        })
        if state == "SUPPORTED" and row.get("enumeration_complete") is True:
            entry["enumeration"]["complete"] = True
            if evidence_id not in entry["enumeration"]["evidence_ids"]:
                entry["enumeration"]["evidence_ids"].append(evidence_id)
        stamp = str(row.get("observed_at") or "")
        if stamp and (entry["last_observed_at"] is None or stamp > entry["last_observed_at"]):
            entry["last_observed_at"] = stamp
    results = [_endpoint(entry) for _, entry in sorted(endpoints.items())]
    return {
        "schema": SCHEMA,
        "endpoints": results,
        "refused": refused,
        "statement": (
            f"{len(results)} endpoint(s) with {sum(len(item['facts']) for item in results)} "
            f"state fact(s)"
            + (f"; {len(refused)} row(s) refused" if refused else "")
            + "; supported, configured and negotiated are kept apart"),
    }


def _endpoint(entry: Mapping[str, Any]) -> dict[str, Any]:
    supported = list(entry["supported"])
    configured = list(entry["configured"])
    negotiated = list(entry["negotiated"])
    facts = supported + configured + negotiated

    def values(rows: Iterable[Mapping[str, Any]], facet: str) -> list[str]:
        return sorted({str(row[facet]) for row in rows if row.get(facet) not in (None, "")})

    versions = {state: values(rows, "tls_version")
                for state, rows in (("SUPPORTED", supported),
                                    ("CONFIGURED", configured),
                                    ("NEGOTIATED", negotiated))}
    evidence = {state: sorted({str(row["evidence_id"]) for row in rows})
                for state, rows in (("SUPPORTED", supported),
                                    ("CONFIGURED", configured),
                                    ("NEGOTIATED", negotiated))}
    return {
        "endpoint": entry["endpoint"],
        "facts": facts,
        "supported": {"versions": versions["SUPPORTED"],
                      "suites": values(supported, "cipher_suite"),
                      "groups": values(supported, "group"),
                      "evidence_ids": evidence["SUPPORTED"]},
        "configured": {"versions": versions["CONFIGURED"],
                       "suites": values(configured, "cipher_suite"),
                       "groups": values(configured, "group"),
                       "evidence_ids": evidence["CONFIGURED"]},
        "negotiated": {"versions": versions["NEGOTIATED"],
                       "suites": values(negotiated, "cipher_suite"),
                       "groups": values(negotiated, "group"),
                       "signature_algorithms": values(negotiated, "signature_algorithm"),
                       "evidence_ids": evidence["NEGOTIATED"],
                       "observed_at": sorted({str(row["observed_at"]) for row in negotiated
                                              if row.get("observed_at")})},
        "enumeration_complete": bool(entry["enumeration"]["complete"]),
        "last_observed_at": entry["last_observed_at"],
        "statement": _statement(entry["endpoint"], versions, evidence),
    }


def _statement(endpoint: str, versions: Mapping[str, list[str]],
               evidence: Mapping[str, list[str]]) -> str:
    parts = []
    for state in STATES:
        values = versions.get(state) or []
        if values:
            parts.append(f"{state.lower()} {', '.join(values)} "
                         f"({len(evidence.get(state) or [])} evidence id(s))")
        else:
            parts.append(f"nothing {state.lower()}")
    return f"{endpoint}: " + "; ".join(parts)


def disabled(result: Mapping[str, Any], *, endpoint: str,
             version: Any) -> dict[str, Any]:
    """Can this protocol be called *disabled* on this endpoint?

    Only from a complete authorized enumeration in which it is absent. A negotiated
    handshake is not an enumeration, an incomplete enumeration cannot speak for the
    ClientHellos it never sent, and an endpoint with no enumeration at all is
    ``UNKNOWN`` rather than clean.
    """
    target = _version(version)
    item = _find(result, endpoint)
    if item is None:
        return _not_proven(endpoint, target, "UNKNOWN",
                           "the endpoint was never observed, so nothing is known about it")
    if target in [value for value in item["negotiated"]["versions"]]:
        return _not_proven(endpoint, target, "IN_USE",
                           f"{target} was negotiated, so it is not disabled")
    if target in item["supported"]["versions"]:
        return _not_proven(endpoint, target, "SUPPORTED",
                           f"{target} is still offered by the endpoint")
    if not item["supported"]["versions"] and not item["enumeration_complete"]:
        return _not_proven(
            endpoint, target, "NOT_ENUMERATED",
            ("no capability enumeration was run, so 'disabled' would be an assumption: "
             "a modern handshake is not an enumeration"))
    if not item["enumeration_complete"]:
        return _not_proven(
            endpoint, target, "ENUMERATION_INCOMPLETE",
            ("the enumeration did not try every ClientHello variant, so the protocols "
             "that were never asked about are exactly where the old one hides"))
    return {
        "endpoint": endpoint,
        "version": target,
        "state": "DISABLED_PROVEN",
        "proven": True,
        "evidence_ids": sorted({*item["supported"]["evidence_ids"],
                                *item["negotiated"]["evidence_ids"]}),
        "statement": (f"{target} is absent from a complete enumeration of {endpoint} "
                      f"({', '.join(item['supported']['versions']) or 'no protocols offered'})"),
    }


def _not_proven(endpoint: str, version: str | None, state: str, reason: str) -> dict[str, Any]:
    return {"endpoint": endpoint, "version": version, "state": state, "proven": False,
            "evidence_ids": [], "statement": f"{version or 'the protocol'} is not proven "
                                             f"disabled on {endpoint}: {reason}"}


def minimum(result: Mapping[str, Any], *, endpoint: str) -> dict[str, Any]:
    """The minimum protocol version, with the basis that lets it be claimed.

    Configuration first (a policy is a statement about intent), then a complete
    enumeration (a measurement of what is offered). A negotiated version is never a
    minimum: the endpoint agreed to what this client asked for.
    """
    item = _find(result, endpoint)
    if item is None:
        return {"endpoint": endpoint, "version": None, "basis": None,
                "claimable": False,
                "statement": f"{endpoint} was never observed, so it has no minimum"}
    configured = [value for value in item["configured"]["versions"] if value in PROTOCOL_ORDER]
    if configured:
        lowest = min(configured, key=PROTOCOL_ORDER.index)
        return {"endpoint": endpoint, "version": lowest, "basis": "CONFIGURED",
                "claimable": True,
                "evidence_ids": item["configured"]["evidence_ids"],
                "statement": (f"policy configures {lowest} as the minimum on {endpoint} "
                              f"({len(item['configured']['evidence_ids'])} evidence id(s))")}
    supported = [value for value in item["supported"]["versions"] if value in PROTOCOL_ORDER]
    if supported and item["enumeration_complete"]:
        lowest = min(supported, key=PROTOCOL_ORDER.index)
        return {"endpoint": endpoint, "version": lowest, "basis": "SUPPORTED_ENUMERATION",
                "claimable": True,
                "evidence_ids": item["supported"]["evidence_ids"],
                "statement": (f"{lowest} is the lowest protocol a complete enumeration "
                              f"offered on {endpoint}")}
    negotiated = [value for value in item["negotiated"]["versions"] if value in PROTOCOL_ORDER]
    return {"endpoint": endpoint,
            "version": min(negotiated, key=PROTOCOL_ORDER.index) if negotiated else None,
            "basis": "NEGOTIATED_ONLY", "claimable": False,
            "evidence_ids": item["negotiated"]["evidence_ids"],
            "statement": (f"{endpoint}: the only version observed was negotiated, which "
                          "describes this handshake and not the endpoint's minimum")}


def _find(result: Mapping[str, Any], endpoint: str) -> dict[str, Any] | None:
    for item in result.get("endpoints") or []:
        if str(item.get("endpoint")) == str(endpoint):
            return item
    return None


def properties(item: Mapping[str, Any]) -> list[dict[str, str]]:
    """The three states as separate namespaced properties, never merged.

    A single ``cryptoscan:tls_version`` property would force every reader to guess
    which of the three it is looking at, which is how "negotiated" becomes
    "supported" in somebody's report.
    """
    rows: list[dict[str, str]] = []
    for state in STATES:
        block = item.get(state.lower()) or {}
        for facet, key in (("versions", "tls_version"), ("suites", "cipher_suite"),
                           ("groups", "group"),
                           ("signature_algorithms", "signature_algorithm")):
            for value in block.get(facet) or []:
                rows.append({"name": f"cryptoscan:{state.lower()}_{key}", "value": str(value)})
        for evidence_id in block.get("evidence_ids") or []:
            rows.append({"name": f"cryptoscan:{state.lower()}_evidence_id",
                         "value": str(evidence_id)})
    rows.append({"name": "cryptoscan:tls_enumeration_complete",
                 "value": "true" if item.get("enumeration_complete") else "false"})
    return rows


def attach(document: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    """Write the per-endpoint state properties into an NBOM's endpoint components."""
    by_endpoint = {str(item["endpoint"]): item for item in result.get("endpoints") or []}
    output = dict(document)
    components = []
    for component in output.get("components") or []:
        name = str(component.get("name") or "")
        item = by_endpoint.get(name)
        if item is None:
            components.append(component)
            continue
        metadata = dict(component)
        existing = list(metadata.get("properties") or [])
        metadata["properties"] = existing + properties(item)
        components.append(metadata)
    output["components"] = components
    return output


def summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """What the model knows, and what it explicitly refuses to conclude."""
    endpoints = list(result.get("endpoints") or [])
    enumerated = [item for item in endpoints if item["enumeration_complete"]]
    negotiated_only = [item["endpoint"] for item in endpoints
                       if item["negotiated"]["versions"]
                       and not item["supported"]["versions"]]
    return {
        "schema": SCHEMA,
        "endpoints": len(endpoints),
        "enumerated": len(enumerated),
        "negotiated_only": negotiated_only,
        "refused": len(result.get("refused") or []),
        "statement": (
            f"{len(endpoints)} endpoint(s); {len(enumerated)} with a complete capability "
            f"enumeration"
            + (f"; {len(negotiated_only)} observed only by negotiation, so nothing may be "
               "claimed about what else they support" if negotiated_only else "")
            + (f"; {len(result.get('refused') or [])} fact(s) refused" if result.get("refused")
               else "")),
    }
