"""What a CBOM asset can claim, and what the evidence actually proves.

A CBOM that says ``AES-256-GCM, confidence HIGH`` has collapsed eight different
claims into one line. This module keeps them apart:

* **capability** — the component *can* do this (OpenSSL supports AES). A library
  that supports an algorithm is not an application that calls it.
* **static / config / runtime / network** — somebody observed the operation in
  that layer, and each observation carries its own id.
* **imported / vendor-declared / inferred** — somebody *said so*. These are
  evidence, but they can never be promoted to an observation. An imported CBOM
  stays ``IMPORTED`` until this platform observes it; a vendor's declaration stays
  ``VENDOR_DECLARED``. Promotion without evidence is spoofing.

Confidence is then computed deterministically from the classes present — never
guessed, never model-generated — and the answer ships with the reason, so the
console can show *why* an asset is ``HIGH``.

The same discipline applies to TLS: a load balancer terminating TLS 1.3 in front
of an application that talks TLS 1.2 to a gateway is three relationships, not one
``AES-256`` attribute on the application. :func:`tls_paths` returns the hops, not
a verdict.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.cbom-usage-evidence/1"

#: The review's evidence vocabulary, in strength order for the observing half.
EVIDENCE_CLASSES: tuple[str, ...] = (
    "OBSERVED",
    "STATIC_OBSERVED",
    "RUNTIME_OBSERVED",
    "NETWORK_OBSERVED",
    "CONFIGURED",
    "IMPORTED",
    "VENDOR_DECLARED",
    "INFERRED",
    "UNKNOWN",
)

#: Classes that mean "this platform, or something authoritative, saw it happen".
OBSERVING_CLASSES: frozenset[str] = frozenset({
    "OBSERVED", "STATIC_OBSERVED", "RUNTIME_OBSERVED", "NETWORK_OBSERVED", "CONFIGURED",
})

#: Classes that are a claim rather than an observation. They may create a
#: *capability*, and they may never create usage.
DECLARED_CLASSES: frozenset[str] = frozenset({
    "IMPORTED", "VENDOR_DECLARED", "INFERRED", "UNKNOWN",
})

#: Which layer an observation reports, and which class it is allowed to earn.
#: A collector's own name is deliberately not enough: ``hsm`` says *where*, and
#: the caller still has to say whether it saw capability, configuration or an
#: operation.
LAYER_CLASSES: dict[str, str] = {
    "static": "STATIC_OBSERVED",
    "source": "STATIC_OBSERVED",
    "config": "CONFIGURED",
    "configuration": "CONFIGURED",
    "runtime": "RUNTIME_OBSERVED",
    "process": "RUNTIME_OBSERVED",
    "network": "NETWORK_OBSERVED",
    "tls": "NETWORK_OBSERVED",
    "certificate": "NETWORK_OBSERVED",
    "sbom": "IMPORTED",
    "imported": "IMPORTED",
    "import": "IMPORTED",
    "upload": "IMPORTED",
    "document": "IMPORTED",
    "cyclonedx": "IMPORTED",
    "spdx": "IMPORTED",
    "container": "OBSERVED",
    "artifact": "OBSERVED",
    "vendor": "VENDOR_DECLARED",
    "vendor_declaration": "VENDOR_DECLARED",
}

#: HSM/KMS answers are three different things and only the last is usage.
HSM_EVIDENCE: dict[str, str] = {
    "CAPABILITY": "VENDOR_DECLARED",     # the module supports RSA-4096
    "CONFIGURED_KEY": "CONFIGURED",      # a key exists in the partition
    "OPERATION": "RUNTIME_OBSERVED",     # a SIGN/RECRYPT actually happened
}

CONFIDENCE_LEVELS: tuple[str, ...] = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "VERY_HIGH")

#: Purposes the review asked for, as a closed vocabulary. ``purpose`` is what
#: makes a migration answer actionable: "AES-256" is not a finding, "AES-256 for
#: DATA_AT_REST" is.
PURPOSES: tuple[str, ...] = (
    "ENCRYPTION", "DECRYPTION", "SIGNATURE", "VERIFICATION", "KEY_AGREEMENT",
    "KEY_WRAPPING", "HASHING", "MAC", "KDF", "TLS", "MTLS", "SSH", "VPN",
    "DATABASE_TLS", "DATABASE_TDE", "BACKUP_ENCRYPTION", "TOKEN_SIGNING",
    "PAYMENT_SIGNING", "HSM_OPERATION", "KMS_OPERATION", "DATA_AT_REST",
)

#: Fields a key record may carry. Everything else is refused, and any field that
#: looks like key material is refused whatever it is called.
KEY_METADATA_FIELDS: tuple[str, ...] = (
    "key_ref", "algorithm", "key_size", "curve", "purpose", "usage", "key_type",
    "provider", "location", "hsm_id", "kms_id", "created_at", "rotated_at", "status",
    "certificate_ref", "owner", "application", "system", "evidence_id",
)

#: Substrings that mean "somebody is trying to store secret material in a CBOM".
SECRET_MARKERS: tuple[str, ...] = (
    "private", "secret", "password", "passphrase", "pin", "material", "key_bytes",
    "session_key", "plaintext", "ciphertext", "token_value", "seed",
)


class EvidenceRefused(ValueError):
    """An evidence event that cannot be trusted, or must not be stored."""


def _norm_class(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if text in EVIDENCE_CLASSES else None


def _evidence_id(event: Mapping[str, Any]) -> str:
    return str(event.get("evidence_id") or event.get("id") or "").strip()


def normalize_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """One evidence event, or a refusal.

    Three refusals matter here, and each of them is a blocker from the review:

    * a class outside the vocabulary is not silently mapped to ``UNKNOWN``;
    * a *declared* class that claims to be an observation (``source: runtime``
      with ``class: IMPORTED``) keeps its class — the weaker one — and says so;
    * an observing event with no evidence id is refused, because an observation
      nobody can point at is a rumour with a timestamp.

    The class and the origin must also agree, in **both** directions: a declared
    event that claims to be an observation keeps its declared class, and an event
    that claims an observation while naming an imported or vendor-declared origin
    is downgraded to that origin. An imported CBOM that says ``RUNTIME_OBSERVED``
    is the review's first security blocker, and the class string is not evidence.
    """
    if not isinstance(event, Mapping):
        raise EvidenceRefused("an evidence event must be an object")
    declared = _norm_class(event.get("class") or event.get("evidence_class"))
    layer = str(event.get("layer") or event.get("source") or "").strip().lower()
    implied = LAYER_CLASSES.get(layer)
    klass = declared or implied
    if klass is None:
        raise EvidenceRefused(
            f"{event.get('class')!r} is not an evidence class; expected one of "
            f"{', '.join(EVIDENCE_CLASSES)}")
    downgrades: list[str] = []
    if declared in DECLARED_CLASSES and implied in OBSERVING_CLASSES:
        klass = declared
        downgrades.append(
            f"{layer} claims {implied}, but the event is {declared}; it cannot become an "
            "observation without independent evidence")
    elif implied in DECLARED_CLASSES and declared in OBSERVING_CLASSES:
        # the other direction, and the one an imported document takes: the event *says*
        # it was observed, but the origin it names is a declaration. The origin wins.
        klass = implied
        downgrades.append(
            f"the event claims {declared}, but its origin is {layer} ({implied}); an "
            "imported or vendor-declared source cannot observe, so the weaker class is "
            "kept")
    evidence_id = _evidence_id(event)
    if klass in OBSERVING_CLASSES and not evidence_id:
        raise EvidenceRefused(
            f"{klass} needs an evidence id; an observation nobody can point at is not evidence")
    observed = klass in OBSERVING_CLASSES
    return {
        "evidence_id": evidence_id or None,
        "class": klass,
        "layer": layer or None,
        "observed": observed,
        "algorithm": event.get("algorithm"),
        "parameters": event.get("parameters") or {},
        "purpose": event.get("purpose"),
        "location": event.get("location"),
        "observed_at": event.get("observed_at"),
        "downgrades": downgrades,
    }


def confidence(classes: Iterable[str]) -> dict[str, Any]:
    """Deterministic confidence from the evidence classes present.

    The ladder is the review's, stated as rules rather than as a number:

    ===================================  =============
    evidence                             confidence
    ===================================  =============
    nothing                              ``UNKNOWN``
    imported / vendor-declared / inferred ``LOW``  (capability only)
    static or configuration              ``MEDIUM``
    runtime or network                   ``HIGH``
    runtime *and* network                ``VERY_HIGH``
    ===================================  =============

    Runtime plus network is the top of the ladder because the two are collected by
    different mechanisms: a process tracing a crypto call and a sensor reading a
    TLS handshake cannot both be produced by one lying collector.
    """
    present = {str(value).strip().upper() for value in classes}
    observing = present & set(OBSERVING_CLASSES)
    if not present:
        return {"level": "UNKNOWN", "reason": "no evidence has been collected for this asset",
                "classes": []}
    if not observing:
        return {
            "level": "LOW",
            "reason": ("only declared evidence is present ("
                       + ", ".join(sorted(present)) + "), which supports a capability and "
                       "never proves usage"),
            "classes": sorted(present)}
    has_runtime = "RUNTIME_OBSERVED" in observing
    has_network = "NETWORK_OBSERVED" in observing
    static = sorted(observing & {"STATIC_OBSERVED", "CONFIGURED"})
    if has_runtime and has_network:
        return {"level": "VERY_HIGH",
                "reason": ("runtime and network both observed this asset, which are independent "
                           "collection mechanisms"),
                "classes": sorted(present)}
    if has_runtime or has_network:
        which = "runtime" if has_runtime else "network"
        return {"level": "HIGH",
                "reason": f"{which} observed the operation"
                          + (f"; static/configuration also agrees ({', '.join(static)})"
                             if static else ""),
                "classes": sorted(present)}
    return {"level": "MEDIUM",
            "reason": ("static or configuration evidence places the algorithm here, but nothing "
                       "watched it run"),
            "classes": sorted(present)}


def usage_profile(asset: Mapping[str, Any],
                  events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Capability, per-layer observation and confidence for one crypto asset.

    ``usage`` has three answers, and they are not interchangeable:

    ``OBSERVED`` — at least one observing layer saw the operation.
    ``CANDIDATE_ONLY`` — only declared/capability evidence exists. The asset is in
    the CBOM because something *could* use it, which is exactly the false
    attribution the review warns about; the statement says so.
    ``NOT_OBSERVED`` — evidence was collected and none of it concerns this asset.
    """
    if not isinstance(asset, Mapping):
        raise EvidenceRefused("an asset must be an object")
    if not str(asset.get("algorithm") or "").strip():
        raise EvidenceRefused(
            "an asset needs an algorithm: a profile of nothing is not a statement about crypto")
    normalized: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for event in events:
        try:
            normalized.append(normalize_event(event))
        except EvidenceRefused as exc:
            refused.append({"event": dict(event) if isinstance(event, Mapping) else event,
                            "reason": str(exc)})
    algorithm = str(asset.get("algorithm") or "").strip()
    parameters = asset.get("parameters") or {}
    purpose = asset.get("purpose")
    matching = [event for event in normalized
                if not algorithm or str(event.get("algorithm") or algorithm).lower()
                == algorithm.lower()]
    by_class: dict[str, dict[str, Any]] = {
        klass: {"observed": False, "count": 0, "evidence": []} for klass in EVIDENCE_CLASSES}
    for event in matching:
        row = by_class[event["class"]]
        row["observed"] = row["observed"] or event["observed"]
        row["count"] += 1
        if event["evidence_id"] and event["evidence_id"] not in row["evidence"]:
            row["evidence"].append(event["evidence_id"])
    observed_classes = [klass for klass in EVIDENCE_CLASSES
                        if by_class[klass]["observed"]]
    capability = any(by_class[klass]["count"] for klass in DECLARED_CLASSES) or bool(observed_classes)
    if observed_classes:
        state = "OBSERVED"
    elif capability:
        state = "CANDIDATE_ONLY"
    else:
        state = "NOT_OBSERVED"
    ladder = confidence(observed_classes) if observed_classes else confidence(
        [klass for klass in EVIDENCE_CLASSES if by_class[klass]["count"]])
    layers = {name: {"class": LAYER_CLASSES[name], "observed": by_class[LAYER_CLASSES[name]]["observed"],
                     "evidence": by_class[LAYER_CLASSES[name]]["evidence"]}
              for name in ("static", "config", "runtime", "network")}
    evidence_ids = sorted({ident for event in matching for ident in [event["evidence_id"]] if ident})
    statement_parts = [
        f"{algorithm or 'this asset'}"
        + (f" ({', '.join(f'{k}={v}' for k, v in parameters.items())})" if parameters else "")
        + f": {state.lower().replace('_', ' ')}"]
    if state == "CANDIDATE_ONLY":
        statement_parts.append(
            "the evidence says it could be used, which is a capability and not an invocation")
    if observed_classes:
        statement_parts.append("observed by " + ", ".join(
            by_class[klass]["evidence"][0] for klass in observed_classes)[:200])
    if purpose and str(purpose).upper() not in PURPOSES:
        statement_parts.append(f"{purpose!r} is not a known purpose")
    return {
        "schema": SCHEMA,
        "asset": {"algorithm": algorithm or None, "parameters": parameters,
                  "purpose": str(purpose).upper() if purpose else None},
        "capability": capability,
        "usage": state,
        "layers": layers,
        "classes": {klass: by_class[klass] for klass in EVIDENCE_CLASSES
                    if by_class[klass]["count"]},
        "observed_classes": observed_classes,
        "evidence_ids": evidence_ids,
        "confidence": ladder["level"],
        "confidence_reason": ladder["reason"],
        "refused": refused,
        "statement": "; ".join(statement_parts),
    }


def capability_candidates(component: str, algorithms: Sequence[str], *,
                          source: str = "sbom", evidence_id: str | None = None) -> dict[str, Any]:
    """Algorithms a crypto-capable library supports — as candidates only.

    This is the review's item 6 in code: OpenSSL supporting AES, RSA and ECDSA
    must not mint three ``USED`` assets. Each candidate is ``CANDIDATE_ONLY`` at
    ``LOW`` confidence, carrying the library it came from, and the statement says
    what would promote it.
    """
    rows = []
    for algorithm in algorithms:
        name = str(algorithm or "").strip()
        if not name:
            continue
        rows.append({
            "algorithm": name,
            "usage": "CANDIDATE_ONLY",
            "capability": True,
            "confidence": "LOW",
            "basis": "CAPABILITY_ONLY",
            "component": component,
            "evidence": [{"class": LAYER_CLASSES.get(source, "IMPORTED"),
                          "evidence_id": evidence_id or f"{source}:{component}"}],
        })
    return {
        "schema": SCHEMA,
        "component": component,
        "candidates": rows,
        "promotable_by": ["STATIC_OBSERVED", "RUNTIME_OBSERVED", "NETWORK_OBSERVED"],
        "statement": (
            f"{len(rows)} candidate algorithm(s) from {component}'s capability. A library that "
            "supports an algorithm is not an application that calls it, so none of these is a "
            "usage claim until an observing layer reports the operation"),
    }


def reconcile(claims: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Per-source facts for one field, with conflicts stated and nothing collapsed.

    Returns every claim (source, fact, class, evidence) and the conflicts between
    *observing* sources. ``resolved`` names the strongest claim and is explicit
    that it is a precedence rule, not proof: two observing sources that disagree
    mean the estate changed, the versions differ across artifacts, or one
    collector is wrong — a human decides which.
    """
    rows: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for claim in claims:
        try:
            event = normalize_event(claim)
        except EvidenceRefused as exc:
            refused.append({"claim": dict(claim) if isinstance(claim, Mapping) else claim,
                            "reason": str(exc)})
            continue
        rows.append({
            "field": claim.get("field"),
            "fact": claim.get("fact"),
            "source": event["layer"] or claim.get("source"),
            "class": event["class"],
            "observed": event["observed"],
            "evidence_id": event["evidence_id"],
            "observed_at": event["observed_at"],
        })
    fields = sorted({str(row["field"]) for row in rows})
    conflicts: list[dict[str, Any]] = []
    for field in fields:
        present = [row for row in rows if str(row["field"]) == field]
        observing = [row for row in present if row["observed"]]
        values = sorted({str(row["fact"]) for row in observing})
        if len(values) > 1:
            conflicts.append({
                "field": field,
                "kind": "VERSION_CONFLICT" if field in {"version", "library_version"}
                        else "FACT_CONFLICT",
                "values": {row["source"] or row["class"]: row["fact"] for row in observing},
                "evidence": {row["source"] or row["class"]: row["evidence_id"]
                             for row in observing},
                "statement": (
                    f"{field} has {len(values)} observed values across "
                    f"{len(observing)} source(s); the observation layers disagree and the "
                    "disagreement is the finding"),
            })
    resolved: list[dict[str, Any]] = []
    rank = {klass: index for index, klass in enumerate(
        ["RUNTIME_OBSERVED", "NETWORK_OBSERVED", "OBSERVED", "CONFIGURED",
         "STATIC_OBSERVED", "IMPORTED", "VENDOR_DECLARED", "INFERRED", "UNKNOWN"])}
    for field in fields:
        present = [row for row in rows if str(row["field"]) == field]
        best = sorted(present, key=lambda row: (rank.get(row["class"], 99),
                                                str(row["source"] or "")))[0]
        conflicted = any(conflict["field"] == field for conflict in conflicts)
        resolved.append({
            "field": field,
            "value": None if conflicted else best["fact"],
            "basis": best["class"],
            "source": best["source"],
            "evidence_id": best["evidence_id"],
            "statement": ("no single value is asserted: the sources conflict"
                          if conflicted else
                          f"{best['fact']} from {best['source'] or best['class']} "
                          f"({best['class']}), the strongest available claim"),
        })
    return {
        "schema": SCHEMA,
        "rows": rows,
        "conflicts": conflicts,
        "resolved": resolved,
        "refused": refused,
        "statement": (
            f"{len(rows)} claim(s) across {len({row['source'] for row in rows})} source(s), "
            f"{len(conflicts)} conflict(s)"
            + ("; nothing is collapsed into a single value where the sources disagree"
               if conflicts else "")),
    }


def tls_paths(hops: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """One cryptographic relationship per hop, never one attribute per application.

    A load balancer terminating TLS 1.3 in front of an application that speaks
    TLS 1.2 to a gateway is three relationships. Each hop is reported with the
    interface that observed it; ``attributed_to`` is the endpoint, and the
    statement refuses to promote a terminating hop to the application behind it.
    """
    rows: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for index, hop in enumerate(hops, start=1):
        try:
            event = normalize_event({**dict(hop), "layer": hop.get("layer") or "network"})
        except EvidenceRefused as exc:
            refused.append({"hop": dict(hop), "reason": str(exc)})
            continue
        if not hop.get("endpoint"):
            refused.append({"hop": dict(hop),
                            "reason": "a hop needs the endpoint where it was observed"})
            continue
        rows.append({
            "path": index,
            "from": hop.get("from"),
            "to": hop.get("to"),
            "endpoint": hop.get("endpoint"),
            "observed_on": hop.get("observed_on"),
            "tls_version": hop.get("tls_version"),
            "cipher_suite": hop.get("cipher_suite"),
            "key_exchange": hop.get("key_exchange"),
            "certificate_ref": hop.get("certificate_ref"),
            "evidence_id": event["evidence_id"],
            "class": event["class"],
            "attributed_to": hop.get("endpoint"),
            "terminates_here": bool(hop.get("terminates", True)),
        })
    attributed = {row["attributed_to"] for row in rows}
    return {
        "schema": SCHEMA,
        "paths": rows,
        "refused": refused,
        "terminations": [row["path"] for row in rows if row["terminates_here"]],
        "statement": (
            f"{len(rows)} TLS relationship(s) across {len(attributed)} endpoint(s)"
            + ("; each hop is attributed to the interface that terminated it, not to the "
               "application behind it" if rows else "")
            + (f"; {len(refused)} hop(s) refused for carrying no evidence" if refused else "")),
    }


def certificate_evidence(certificate: Mapping[str, Any]) -> dict[str, Any]:
    """A certificate as its own evidence category.

    The public key and signature algorithm of a certificate describe *the
    certificate*. They do not describe the application's cryptographic
    operations, and this record says so rather than letting ``ECDSA-P256`` leak
    into an application's algorithm inventory.
    """
    row = {
        "category": "CERTIFICATE",
        "certificate_ref": certificate.get("certificate_ref") or certificate.get("serial"),
        "public_key_algorithm": certificate.get("public_key_algorithm"),
        "key_size": certificate.get("key_size"),
        "curve": certificate.get("curve"),
        "signature_algorithm": certificate.get("signature_algorithm"),
        "issuer": certificate.get("issuer"),
        "subject": certificate.get("subject"),
        "san": list(certificate.get("san") or ()),
        "not_before": certificate.get("not_before"),
        "not_after": certificate.get("not_after"),
        "endpoint": certificate.get("endpoint"),
        "observed_on": certificate.get("observed_on"),
        "evidence_id": certificate.get("evidence_id"),
    }
    missing = [key for key in ("public_key_algorithm", "signature_algorithm", "evidence_id")
               if not row.get(key)]
    return {
        "schema": SCHEMA,
        "certificate": row,
        "usage": "CERTIFICATE_ONLY",
        "application_operation_proven": False,
        "incomplete": missing,
        "statement": (
            f"{row['public_key_algorithm'] or 'this certificate'} / "
            f"{row['signature_algorithm'] or 'unknown signature'} describes the certificate on "
            f"{row['endpoint'] or 'an endpoint'}. A certificate's public key does not prove the "
            "application behind it performs that algorithm")
        + (f"; missing {', '.join(missing)}" if missing else ""),
    }


def key_metadata(record: Mapping[str, Any]) -> dict[str, Any]:
    """Key metadata a bank may store: references and properties, never material.

    Any field that is not in :data:`KEY_METADATA_FIELDS` is refused, and any field
    whose *name* looks like key material is refused even when it would otherwise
    be allowed. A CBOM that quietly ingests a private key is a CBOM that has to be
    deleted, so the refusal is an error rather than a warning.
    """
    suspicious = [str(field) for field in record
                  if any(marker in str(field).lower() for marker in SECRET_MARKERS)]
    if suspicious:
        raise EvidenceRefused(
            "this record carries " + ", ".join(sorted(suspicious))
            + "; a CBOM stores key references and properties, never key material")
    unknown = [str(field) for field in record if str(field) not in KEY_METADATA_FIELDS]
    if unknown:
        raise EvidenceRefused(
            "unexpected key metadata field(s): " + ", ".join(sorted(unknown)))
    if not str(record.get("key_ref") or "").strip():
        raise EvidenceRefused("a key record needs a key_ref; the material itself is never stored")
    purpose = str(record.get("purpose") or "").upper() or None
    return {
        "schema": SCHEMA,
        "key_ref": record["key_ref"],
        "algorithm": record.get("algorithm"),
        "key_size": record.get("key_size"),
        "curve": record.get("curve"),
        "purpose": purpose,
        "purpose_known": purpose in PURPOSES if purpose else None,
        "usage": record.get("usage"),
        "key_type": record.get("key_type"),
        "provider": record.get("provider"),
        "location": record.get("location"),
        "hsm_id": record.get("hsm_id"),
        "kms_id": record.get("kms_id"),
        "created_at": record.get("created_at"),
        "rotated_at": record.get("rotated_at"),
        "rotated": bool(record.get("rotated_at")),
        "status": record.get("status"),
        "certificate_ref": record.get("certificate_ref"),
        "owner": record.get("owner"),
        "application": record.get("application"),
        "system": record.get("system"),
        "evidence_id": record.get("evidence_id"),
        "private_material": "NOT STORED",
    }


def hsm_evidence(kind: str, *, evidence_id: str | None = None,
                 operation: str | None = None) -> dict[str, Any]:
    """Capability, configured key and operation are three different answers."""
    key = str(kind or "").strip().upper()
    if key not in HSM_EVIDENCE:
        raise EvidenceRefused(
            f"{kind!r} is not an HSM evidence kind; expected one of {', '.join(HSM_EVIDENCE)}")
    klass = HSM_EVIDENCE[key]
    observed = klass in OBSERVING_CLASSES
    if observed and not str(evidence_id or "").strip():
        raise EvidenceRefused(f"{key} is an observation and needs an evidence id")
    return {
        "kind": key,
        "class": klass,
        "observed": observed,
        "operation": str(operation).upper() if operation else None,
        "evidence_id": evidence_id or None,
        "statement": {
            "CAPABILITY": "the module supports this algorithm; no key and no operation is implied",
            "CONFIGURED_KEY": "a key with these properties exists in the partition; nothing says "
                              "it was used",
            "OPERATION": "an operation was recorded; this is the only one of the three that is "
                         "usage",
        }[key],
    }


def coverage(total_systems: int, inspected_systems: int, assets: int,
             *, unit: str = "application") -> dict[str, Any]:
    """How much of the estate the CBOM speaks for, and what it may not claim.

    ``assets`` discovered over a partial estate is not "the bank has N"; it is "N
    discovered, with this coverage". Completeness is ``NONE``/``PARTIAL``/
    ``COMPLETE`` and only ``COMPLETE`` lets the count be quoted as a total.
    """
    total = max(int(total_systems or 0), 0)
    inspected = max(int(inspected_systems or 0), 0)
    assets = max(int(assets or 0), 0)
    if inspected > total:
        inspected = total
    pct = round(100.0 * inspected / total, 1) if total else 0.0
    if total == 0:
        completeness = "UNKNOWN"
    elif inspected == 0:
        completeness = "NONE"
    elif inspected < total:
        completeness = "PARTIAL"
    else:
        completeness = "COMPLETE"
    return {
        "schema": SCHEMA,
        "assets_discovered": assets,
        "systems_total": total,
        "systems_inspected": inspected,
        "coverage_pct": pct,
        "completeness": completeness,
        "quotable_as_total": completeness == "COMPLETE",
        "statement": (
            f"{assets} crypto asset(s) discovered; {inspected}/{total} {unit}(s) inspected"
            + (f" ({pct:g}%)" if total else "")
            + ("; this count is a total only because every system was inspected"
               if completeness == "COMPLETE" else
               "; the count is what was discovered, not what exists")),
    }
