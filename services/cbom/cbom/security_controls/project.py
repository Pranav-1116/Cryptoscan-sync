"""Collector output → canonical estate → TechBOM, with every refusal kept.

This is where the layer meets the Digital Twin. Four rules, each one a check rather than a
convention:

* **identity is canonical.** ``KIND:name:environment`` is the key, so a firewall's ``INTERNET``
  and a segment row's ``INTERNET`` are one node and two collectors cannot create two;
* **every edge is typed.** The relation must exist in :data:`cbom.techbom.RELATIONS` and the
  two kinds must be legal for it. An illegal pairing is refused *by name* — a firewall that
  claims to present a certificate is a finding about what the device reports, not a reason to
  widen the model;
* **an edge to an undeclared node is refused**, not created. A relationship that points at a
  name nobody inventoried is how a graph quietly becomes a drawing;
* **evidence survives.** Assets and claims carry the collector's evidence ids, and a claim
  with none never reaches this function because the collector refused it first.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from cbom import techbom

from .base import CONFIGURED, ControlRefused, _norm, digest

#: a few fact names are already parameters of ``techbom.claim`` (a firewall's ``rule`` is a
#: fact about the edge, and ``rule`` on a claim is the inference rule). Renaming on the way in
#: is cheaper, and clearer, than teaching the graph a second meaning for one word.
FACT_RENAMES: dict[str, str] = {"rule": "rule_id", "source": "source_ref",
                                "target": "target_ref", "note": "device_note"}


def _asset_row(asset: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "kind": asset["kind"],
        "name": asset["name"],
        "environment": asset.get("environment") or "PRODUCTION",
        "version": asset.get("version"),
        "location": asset.get("location"),
        "source": asset.get("vendor") or asset.get("control"),
        "evidence_ids": [asset["evidence_id"]],
        "attributes": dict(asset.get("attributes") or {}),
    }


def project(collectors: Iterable[Any], *, environment: str = "PRODUCTION",
            build: bool = True) -> dict[str, Any]:
    """Assemble everything the given collectors saw into one estate and one TechBOM."""
    assets: dict[str, dict[str, Any]] = {}
    claims: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    crypto: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    redactions: list[dict[str, Any]] = []
    evidence: set[str] = set()
    health: list[dict[str, Any]] = []

    def refuse(code: str, subject: Any, reason: str, source: Any = None) -> None:
        refusals.append({"code": code, "subject": _norm(subject),
                         "source": source, "reason": reason})

    for collector in collectors:
        require_collector(collector)
        snapshot = collector.snapshot()
        control = getattr(collector, "control", None)
        for asset in snapshot.get("assets") or []:
            row = _asset_row(asset)
            key = techbom._key(row["kind"], row["name"], row["environment"])
            existing = assets.get(key)
            if existing is not None:
                existing["evidence_ids"] = sorted(set(existing["evidence_ids"])
                                                  | set(row["evidence_ids"]))
                continue
            assets[key] = row
        for item in snapshot.get("crypto") or []:
            crypto.append({**item, "control": control})
        for event in snapshot.get("events") or []:
            events.append({**event, "control": control})
        for claim in snapshot.get("relationships") or []:
            claims.append({**claim, "control": control})
        for item in snapshot.get("refusals") or []:
            refusals.append(item)
        for item in snapshot.get("redactions") or []:
            redactions.append(item)
        for item in snapshot.get("evidence") or []:
            evidence.add(item["evidence_id"])
        if snapshot.get("health"):
            health.append(snapshot["health"])

    by_name: dict[str, list[str]] = {}
    for key, row in assets.items():
        by_name.setdefault(row["name"], []).append(key)

    def resolve(reference: str) -> tuple[str | None, str]:
        name = _norm(reference)
        if ":" in name:
            parts = name.split(":")
            if len(parts) == 3:
                key = techbom._key(parts[0], parts[1], parts[2])
                return (key, "") if key in assets else (None, "UNKNOWN_REF")
        found = by_name.get(name) or []
        if len(found) == 1:
            return found[0], ""
        if len(found) > 1:
            return None, "AMBIGUOUS_REF"
        return None, "UNKNOWN_REF"

    accepted: list[dict[str, Any]] = []
    for claim in claims:
        subject = f"{claim['from']} {claim['relation']} {claim['to']}"
        source_key, source_code = resolve(claim["from"])
        target_key, target_code = resolve(claim["to"])
        if not source_key:
            missing = claim["from"]
            refuse(source_code or "UNKNOWN_REF", missing,
                   f"{claim['relation']} starts at {missing}, which no collector declares; "
                   "an edge to an undeclared node is refused rather than invented",
                   claim.get("control"))
            continue
        if not target_key:
            missing = claim["to"]
            refuse(target_code or "UNKNOWN_REF", missing,
                   f"{claim['relation']} ends at {missing}, which no collector declares; "
                   "the projection does not create the node to make the edge legal",
                   claim.get("control"))
            continue
        ok, reason = techbom.check_types(claim["relation"], assets[source_key]["kind"],
                                         assets[target_key]["kind"])
        if not ok:
            refuse("NO_LEGAL_RELATION", subject,
                   f"{reason}; the device reports it and the model has no such edge, so it "
                   "is a finding about the integration rather than a new relation",
                   claim.get("control"))
            continue
        if not claim.get("evidence_ids"):
            refuse("RELATIONSHIP_WITHOUT_EVIDENCE", subject,
                   "a claim without an evidence id is a drawing", claim.get("control"))
            continue
        accepted.append({
            "from": f"{assets[source_key]['kind']}:{assets[source_key]['name']}:"
                    f"{assets[source_key]['environment']}",
            "relation": claim["relation"],
            "to": f"{assets[target_key]['kind']}:{assets[target_key]['name']}:"
                  f"{assets[target_key]['environment']}",
            "basis": claim.get("basis") or "config-parse",
            "confidence": claim.get("confidence"),
            "evidence_ids": list(claim["evidence_ids"]),
            "source_system": claim.get("control"),
            "observed_at": claim.get("observed_at"),
            "facts": {FACT_RENAMES.get(str(key), str(key)): value
                      for key, value in (claim.get("facts") or {}).items()},
        })

    # crypto metadata is attached to its asset, so a TLS profile is a property of a node
    # rather than a node of its own; the certificate it presents is a node, because the
    # estate needs to reason about expiry and algorithm across every presenter
    for row in crypto:
        key, _ = resolve(row.get("asset") or "")
        if not key:
            continue
        assets[key].setdefault("attributes", {}).update({
            claim_key: value for claim_key, value in {
                "tls_version": row.get("tls_version"),
                "cipher_suites": row.get("cipher_suites"),
                "key_exchange": row.get("key_exchange"),
                "sni": row.get("sni"),
                "alpn": row.get("alpn"),
            }.items() if value not in (None, "", [], {})
        })
        certificate = row.get("certificate")
        if not isinstance(certificate, Mapping):
            continue
        name = _norm(certificate.get("subject") or certificate.get("fingerprint_sha256")
                     or certificate.get("name"))
        if not name:
            continue
        cert_key = techbom._key("CERTIFICATE", name, environment)
        if cert_key not in assets:
            assets[cert_key] = {
                "kind": "CERTIFICATE",
                "name": name,
                "environment": environment,
                "version": None,
                "location": None,
                "source": row.get("vendor"),
                "evidence_ids": [row["evidence_id"]],
                "attributes": {claim_key: value for claim_key, value in {
                    "issuer": certificate.get("issuer"),
                    "key_algorithm": certificate.get("public_key_algorithm"),
                    "key_size": certificate.get("public_key_size"),
                    "not_after": certificate.get("not_after"),
                    "fingerprint_sha256": certificate.get("fingerprint_sha256"),
                    "self_signed": certificate.get("is_self_signed"),
                }.items() if value not in (None, "", [], {})},
            }
        else:
            assets[cert_key]["evidence_ids"] = sorted(
                set(assets[cert_key]["evidence_ids"]) | {row["evidence_id"]})
        by_name.setdefault(name, []).append(cert_key)
        claim = {
            "from": f"{assets[key]['kind']}:{assets[key]['name']}:"
                    f"{assets[key]['environment']}",
            "relation": "USES_CERTIFICATE",
            "to": f"CERTIFICATE:{name}:{environment}",
            "basis": "config-parse",
            "confidence": CONFIGURED,
            "evidence_ids": [row["evidence_id"]],
            "source_system": row.get("control"),
            "facts": {"tls_version": row.get("tls_version")},
        }
        ok, reason = techbom.check_types("USES_CERTIFICATE", assets[key]["kind"],
                                         "CERTIFICATE")
        if ok:
            accepted.append(claim)
        else:
            refuse("NO_LEGAL_RELATION",
                   f"{assets[key]['name']} USES_CERTIFICATE {name}",
                   f"{reason}; the control reports a certificate and the model has no edge "
                   "from that kind to a certificate", row.get("control"))

    result: dict[str, Any] = {
        "schema": techbom.ESTATE_SCHEMA,
        "environment": environment,
        "assets": list(assets.values()),
        "claims": accepted,
        "crypto": crypto,
        "events": events,
        "refusals": refusals,
        "redactions": redactions,
        "health": health,
        "summary": {
            "collectors": len(list(health)),
            "assets": len(assets),
            "claims": len(accepted),
            "refusals": len(refusals),
            "redactions": len(redactions),
            "evidence": len(evidence),
            "crypto_rows": len(crypto),
            "events": len(events),
            "asset_kinds": _counts(row["kind"] for row in assets.values()),
            "relation_counts": _counts(row["relation"] for row in accepted),
        },
    }
    if build:
        result["techbom"] = techbom.build({
            "schema": techbom.ESTATE_SCHEMA,
            "environment": environment,
            "assets": result["assets"],
            "claims": accepted,
        })
        result["document"] = result["techbom"]
        result["graph_refusals"] = result["techbom"]["refusals"]
        result["digest"] = digest([row["evidence_ids"] for row in accepted], 16)
    return result


def _counts(values: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items()))


def require_collector(candidate: Any) -> Any:
    """A small guard so a projection cannot be handed something that only looks like one."""
    if not hasattr(candidate, "snapshot"):
        raise ControlRefused(
            "NOT_A_COLLECTOR",
            f"{type(candidate).__name__} does not implement the six-verb contract; a "
            "projection takes collectors, not payloads")
    return candidate
