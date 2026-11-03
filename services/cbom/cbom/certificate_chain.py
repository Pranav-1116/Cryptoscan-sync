"""Endpoint → certificate → key → signature → issuer → trust chain, one hop at a time.

Review item 9 asks for the correlation a PKI team actually needs:

    CERT-9281 · ECDSA P-256 · ECDSA-SHA256 · issuer BANK-ICA-01 · expiry · SAN

The NBOM already records a certificate per endpoint, and ``usage_evidence.
certificate_evidence`` already refuses to let a certificate's public key become an
application's algorithm. What was missing is the **chain**: which certificate signed
which, where the path stops, whether the stop is an anchor or a hole, and what each hop
means for expiry, key strength and quantum exposure.

Two distinctions decide the honesty of this module:

* **assembled is not validated.** The chain here is assembled from *names* and *key
  identifiers* — subject → issuer, ``authority_key_id`` → ``subject_key_id``. Nothing in
  this module verifies a signature, checks a revocation list or consults a policy. A path
  that reaches a self-signed root is reported ``ANCHORED``, never ``TRUSTED``.
* **an unknown issuer is a hole, not a root.** A leaf whose issuer is absent from the
  inventory stops at ``INCOMPLETE`` with the missing subject named, because a chain that
  ends where the collection ended is a collection gap.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.certificate-chain/1"

POSITIONS: tuple[str, ...] = ("LEAF", "INTERMEDIATE", "ROOT")

STATES: tuple[str, ...] = ("VALID", "EXPIRING", "EXPIRED", "NOT_YET_VALID", "UNKNOWN")

#: how a chain stops. `ANCHORED` is a shape, not a trust decision.
RESOLUTIONS: tuple[str, ...] = ("ANCHORED", "INCOMPLETE", "LOOP", "UNRESOLVED")

#: signature algorithms a bank should not accept on a public certificate
WEAK_SIGNATURES: tuple[str, ...] = ("MD5", "SHA1", "SHA-1", "MD2", "NONE")

#: issuers are matched by key id first, then by name; this is the order of preference
MATCHES: tuple[str, ...] = ("AUTHORITY_KEY_ID", "ISSUER_NAME", "DECLARED")

#: days within which expiry is called out before it happens
EXPIRY_WARNING_DAYS = 30

#: key sizes below these are called out, per algorithm family
MINIMUM_KEY_SIZE: dict[str, int] = {
    "RSA": 2048, "DSA": 2048, "DH": 2048, "ECDSA": 256, "ECDH": 256, "ED25519": 256,
}

NOT_PROVEN = [
    "that the chain is valid: this module assembles a path from names and key "
    "identifiers and verifies no signature, so a chain that reaches an anchor is a "
    "shape and not a trust decision",
    "that a certificate is trusted by any client: trust is a property of the relying "
    "party's store, which this inventory does not read",
    "that a certificate is revoked: no OCSP response and no CRL is consulted here, so "
    "revocation is unknown for every row",
    "that the key belongs to the subject it names: identity proofing happens at "
    "issuance, and a name is a claim the issuer made",
]


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _moment(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        return sorted({str(item).strip() for item in value if str(item).strip()})
    return []


def _normalise_name(name: Any) -> str:
    """A DN reduced to its comparable form: lower case, component order preserved."""
    text = _text(name)
    if not text:
        return ""
    parts = [part.strip() for part in text.replace(" / ", ",").split(",") if part.strip()]
    return ",".join(part.lower() for part in parts)


def reference(certificate: Mapping[str, Any]) -> str:
    """The one name a certificate is referred to by, or a refusal."""
    explicit = _text(certificate.get("certificate_ref"))
    if explicit:
        return explicit
    fingerprint = _text(certificate.get("fingerprint_sha256"))
    if fingerprint:
        return f"CERT-{fingerprint[:12].upper()}"
    serial = _text(certificate.get("serial"))
    if serial:
        digest = hashlib.sha256(
            f"{_normalise_name(certificate.get('subject'))}|{serial}".encode()
        ).hexdigest()[:12].upper()
        return f"CERT-{digest}"
    raise ValueError(
        "a certificate needs a reference, a SHA-256 fingerprint or a serial and a "
        "subject: without one the chain cannot say which certificate it is talking about")


def certificate(row: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """One certificate record → the normalised hop, with its state and its caveats."""
    if not isinstance(row, Mapping):
        raise ValueError("a certificate must be an object")
    ref = reference(row)
    evidence = [value for value in [_text(row.get("evidence_id"))] if value]
    if not evidence:
        raise ValueError(f"{ref} carries no evidence id, so it cannot be cited in a chain")
    algorithm = (_text(row.get("public_key_algorithm")) or "").upper() or None
    key_size = row.get("key_size")
    curve = _text(row.get("curve"))
    signature = (_text(row.get("signature_algorithm")) or "").upper() or None
    not_before = _moment(row.get("not_before"))
    not_after = _moment(row.get("not_after"))
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    if not_after is None:
        state, days = "UNKNOWN", None
        state_note = "no expiry was recorded, which is a collection gap and not a pass"
    else:
        days = int((not_after - moment).total_seconds() // 86400)
        if not_before and moment < not_before:
            state, state_note = "NOT_YET_VALID", "the certificate is not valid yet"
        elif days < 0:
            state, state_note = "EXPIRED", f"expired {abs(days)} day(s) ago"
        elif days <= EXPIRY_WARNING_DAYS:
            state, state_note = "EXPIRING", f"expires in {days} day(s)"
        else:
            state, state_note = "VALID", f"valid for {days} more day(s)"

    problems: list[dict[str, Any]] = []
    minimum = MINIMUM_KEY_SIZE.get(algorithm or "")
    if minimum and isinstance(key_size, int) and key_size < minimum:
        problems.append({"kind": "WEAK_KEY", "detail": (
            f"{algorithm}-{key_size} is below the {minimum}-bit floor this model uses")})
    if signature and any(token in signature.replace("-", "") for token in
                         (value.replace("-", "") for value in WEAK_SIGNATURES)):
        problems.append({"kind": "WEAK_SIGNATURE", "detail": (
            f"{signature} uses a hash that collision attacks have reached")})
    if state in {"EXPIRED", "NOT_YET_VALID"}:
        problems.append({"kind": f"CERTIFICATE_{state}", "detail": state_note})
    if algorithm in {"RSA", "ECDSA", "ECDH", "DH", "DSA"}:
        problems.append({"kind": "QUANTUM_VULNERABLE",
                         "detail": (f"{algorithm} is broken by Shor's algorithm; a "
                                    "migration replaces the key and its signature")})
    subject = _normalise_name(row.get("subject"))
    issuer = _normalise_name(row.get("issuer"))
    self_signed = bool(row.get("self_signed")) or (subject and subject == issuer)
    return {
        "certificate_ref": ref,
        "subject": _text(row.get("subject")),
        "issuer": _text(row.get("issuer")),
        "subject_normalised": subject,
        "issuer_normalised": issuer,
        "serial": _text(row.get("serial")),
        "fingerprint_sha256": _text(row.get("fingerprint_sha256")),
        "san": _values(row.get("san")),
        "not_before": _text(row.get("not_before")),
        "not_after": _text(row.get("not_after")),
        "state": state,
        "state_note": state_note,
        "days_to_expiry": days,
        "public_key": {"algorithm": algorithm, "key_size": key_size, "curve": curve,
                       "quantum_vulnerable": algorithm in {"RSA", "ECDSA", "ECDH", "DH",
                                                           "DSA"}},
        "signature_algorithm": signature,
        "self_signed": bool(self_signed),
        "is_ca": bool(row.get("is_ca")),
        "authority_key_id": _text(row.get("authority_key_id")
                                  or row.get("issuer_key_id")),
        "subject_key_id": _text(row.get("subject_key_id")),
        "key_usage": _values(row.get("key_usage")),
        "endpoints": _values(row.get("endpoint") or row.get("endpoints")),
        "source": _text(row.get("source")),
        "observed_at": _text(row.get("observed_at")),
        "evidence_ids": sorted(evidence),
        "problems": problems,
        "revocation": "UNKNOWN",
        "private_material": "NOT_STORED",
    }


def _index(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    by_subject: dict[str, list[dict[str, Any]]] = {}
    by_key_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if record["subject_normalised"]:
            by_subject.setdefault(record["subject_normalised"], []).append(record)
        for key in (record.get("subject_key_id"), record.get("fingerprint_sha256")):
            if key:
                by_key_id.setdefault(str(key), record)
    return {"subject": by_subject, "key_id": by_key_id}


def _issuer_for(record: Mapping[str, Any], index: Mapping[str, Any],
                declared: Mapping[str, str] | None) -> tuple[dict[str, Any] | None, str | None]:
    akid = record.get("authority_key_id")
    if akid and akid in index["key_id"]:
        candidate = index["key_id"][akid]
        if candidate["certificate_ref"] != record["certificate_ref"]:
            return candidate, "AUTHORITY_KEY_ID"
    issuer = record.get("issuer_normalised")
    if issuer and issuer in index["subject"]:
        candidates = [row for row in index["subject"][issuer]
                      if row["certificate_ref"] != record["certificate_ref"]]
        if len(candidates) == 1:
            return candidates[0], "ISSUER_NAME"
        if len(candidates) > 1:
            return None, "AMBIGUOUS_ISSUER"
    if declared:
        target = declared.get(record["certificate_ref"])
        if target and target in index["key_id"]:
            return index["key_id"][target], "DECLARED"
    return None, None


def chain(entries: Iterable[Mapping[str, Any]], *,
          anchors: Iterable[str] | None = None,
          declared: Mapping[str, str] | None = None,
          now: datetime | None = None) -> dict[str, Any]:
    """A pile of certificates → the chains they form, and every hole in them.

    ``anchors`` names certificate refs the caller treats as trust anchors — typically
    the roots of the bank's own PKI. A self-signed root that is *not* declared is still
    where a chain ends; it is reported as an anchor the caller has not confirmed.
    """
    records: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for row in entries or ():
        try:
            records.append(certificate(row, now=now))
        except ValueError as exc:
            refused.append({"certificate": row, "reason": str(exc)})
    anchor_refs = {str(value) for value in anchors or ()}
    index = _index(records)

    paths: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda row: row["certificate_ref"]):
        hops: list[dict[str, Any]] = [record]
        matches: list[str] = []
        resolution = "UNRESOLVED"
        seen = {record["certificate_ref"]}
        while True:
            current = hops[-1]
            if current["certificate_ref"] in anchor_refs:
                resolution = "ANCHORED"
                break
            if current["self_signed"]:
                resolution = "ANCHORED" if (current["certificate_ref"] in anchor_refs
                                            or current["is_ca"]) else "UNRESOLVED"
                break
            issuer, how = _issuer_for(current, index, declared)
            if issuer is None:
                resolution = "LOOP" if how == "AMBIGUOUS_ISSUER" else "INCOMPLETE"
                break
            if issuer["certificate_ref"] in seen:
                resolution = "LOOP"
                break
            seen.add(issuer["certificate_ref"])
            hops.append(issuer)
            matches.append(str(how))
        if len(hops) == 1 and record["self_signed"]:
            position = "ROOT"
        elif record["is_ca"] or record["self_signed"]:
            position = "INTERMEDIATE" if not record["self_signed"] else "ROOT"
        else:
            position = "LEAF"
        paths.append({
            "certificate_ref": record["certificate_ref"],
            "position": position,
            "resolution": resolution,
            "depth": len(hops),
            "path": [{"certificate_ref": hop["certificate_ref"],
                      "subject": hop["subject"], "state": hop["state"],
                      "public_key": hop["public_key"]["algorithm"],
                      "key_size": hop["public_key"]["key_size"]}
                     for hop in hops],
            "matched_by": matches,
            "anchor": hops[-1]["certificate_ref"] if resolution == "ANCHORED" else None,
            "missing_issuer": (record["issuer"] if resolution == "INCOMPLETE" else None),
            "evidence_ids": sorted({value for hop in hops
                                    for value in hop["evidence_ids"]}),
            "problems": [problem for hop in hops for problem in hop["problems"]],
            "statement": (
                f"{record['certificate_ref']} ({position.lower()}) → "
                + " → ".join(hop["certificate_ref"] for hop in hops[1:])
                if len(hops) > 1 else
                f"{record['certificate_ref']} ({position.lower()}) stands alone")
            + f": {resolution.lower()}"
            + (f", matched by {', '.join(matches)}" if matches else "")
            + (f"; issuer {record['issuer']} is not in the inventory"
               if resolution == "INCOMPLETE" else ""),
        })

    resolutions: dict[str, int] = {}
    for path in paths:
        resolutions[path["resolution"]] = resolutions.get(path["resolution"], 0) + 1
    key_reuse: dict[str, list[str]] = {}
    for record in records:
        fingerprint = record.get("fingerprint_sha256")
        if fingerprint:
            key_reuse.setdefault(str(fingerprint), []).append(record["certificate_ref"])
    shared_keys = {fingerprint: refs for fingerprint, refs in key_reuse.items()
                   if len(refs) > 1}
    return {
        "schema": SCHEMA,
        "certificates": {record["certificate_ref"]: record for record in records},
        "refused": refused,
        "paths": paths,
        "resolutions": dict(sorted(resolutions.items())),
        "anchors_declared": sorted(anchor_refs),
        "anchors_unconfirmed": sorted({path["anchor"] for path in paths
                                       if path["resolution"] == "ANCHORED"
                                       and path["anchor"] not in anchor_refs}),
        "shared_public_keys": shared_keys,
        "states": {state: sum(1 for record in records if record["state"] == state)
                   for state in STATES
                   if any(record["state"] == state for record in records)},
        "statement": (
            f"{len(records)} certificate(s) assembled into {len(paths)} path(s): "
            + (", ".join(f"{count} {name.lower()}" for name, count in
                         sorted(resolutions.items())) or "no path resolved")
            + (f"; {len([value for value in shared_keys.values()])} public key(s) shared "
               "between certificates" if shared_keys else "")
            + ". The paths are assembled from names and key identifiers; no signature "
              "was verified"),
        "not_proven": list(NOT_PROVEN),
    }


def edges(body: Mapping[str, Any]) -> dict[str, Any]:
    """The chain as evidence-backed relationships: `USES_CERTIFICATE`, `SIGNED_BY`."""
    if not isinstance(body, Mapping) or body.get("schema") != SCHEMA:
        raise ValueError(f"the chain is not a {SCHEMA} document")
    rows: list[dict[str, Any]] = []
    for path in body.get("paths") or []:
        record = (body.get("certificates") or {}).get(path["certificate_ref"]) or {}
        for endpoint in record.get("endpoints") or []:
            rows.append({
                "from": endpoint, "to": path["certificate_ref"],
                "kind": "USES_CERTIFICATE",
                "evidence_id": (record.get("evidence_ids") or [None])[0],
                "evidence_ids": list(record.get("evidence_ids") or []),
                "observed_at": record.get("observed_at"),
                "source": record.get("source"),
                "confidence": "OBSERVED",
                "detail": (f"{endpoint} presented {path['certificate_ref']} "
                           f"({record.get('state', 'unknown')})"),
            })
        for child, parent in zip(path["path"], path["path"][1:]):
            issuer = (body.get("certificates") or {}).get(parent["certificate_ref"]) or {}
            rows.append({
                "from": child["certificate_ref"], "to": parent["certificate_ref"],
                "kind": "SIGNED_BY",
                "evidence_id": next(iter(issuer.get("evidence_ids") or []), None),
                "evidence_ids": list(issuer.get("evidence_ids") or []),
                "observed_at": issuer.get("observed_at"),
                "source": issuer.get("source"),
                "confidence": "ASSEMBLED",
                "detail": (f"{child['certificate_ref']} names {parent['subject']} as its "
                           "issuer; the signature itself was not verified"),
            })
    # an edge that claims to be OBSERVED needs the moment it was observed; without a
    # timestamp it is a claim about a certificate somewhere, sometime
    untimed = [row for row in rows
               if row["kind"] == "USES_CERTIFICATE" and not row["observed_at"]]
    rows = [row for row in rows if row not in untimed]
    for row in untimed:
        row["confidence"] = "UNTIMED"
        row["detail"] = (f"{row['detail']}, but no observation time was recorded, so "
                         "the edge is not written")
    incomplete = [{"from": path["certificate_ref"], "to": path["missing_issuer"],
                   "kind": "SIGNED_BY", "evidence_id": None, "evidence_ids": [],
                   "observed_at": None, "source": None, "confidence": "ABSENT",
                   "detail": ("the issuer named in this certificate is not in the "
                              "inventory, so the edge is a hole and is not written")}
                  for path in body.get("paths") or []
                  if path["resolution"] == "INCOMPLETE"]
    # every certificate's path repeats the hops above it, so the same SIGNED_BY edge
    # is discovered once per descendant; the topology wants it once
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        unique.setdefault((row["from"], row["to"], row["kind"]), row)
    rows = list(unique.values())
    return {
        "schema": SCHEMA,
        "edges": [row for row in rows if row["evidence_id"]],
        "refused": ([row for row in rows if not row["evidence_id"]] + untimed
                    + incomplete),
        "counts": {kind: sum(1 for row in rows
                             if row["kind"] == kind and row["evidence_id"])
                   for kind in ("USES_CERTIFICATE", "SIGNED_BY")},
        "statement": (
            f"{len([row for row in rows if row['evidence_id']])} evidence-backed "
            f"relationship(s) from the chain; "
            f"{len(incomplete)} missing issuer(s) are reported as holes rather than "
            "drawn as edges"
            + (f"; {len(untimed)} presentation(s) had no observation time and were not "
               "written" if untimed else "")),
    }


def summary(body: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: what the PKI inventory can answer, and what it cannot."""
    paths = body.get("paths") or []
    certificates = body.get("certificates") or {}
    expiring = sorted(ref for ref, row in certificates.items()
                      if row["state"] in {"EXPIRING", "EXPIRED", "NOT_YET_VALID"})
    weak = sorted(ref for ref, row in certificates.items()
                  if any(problem["kind"] in {"WEAK_KEY", "WEAK_SIGNATURE"}
                         for problem in row["problems"]))
    quantum = sorted(ref for ref, row in certificates.items()
                     if row["public_key"]["quantum_vulnerable"])
    return {
        "schema": SCHEMA,
        "certificates": len(certificates),
        "paths": len(paths),
        "resolutions": body.get("resolutions"),
        "anchored": [path["certificate_ref"] for path in paths
                     if path["resolution"] == "ANCHORED"],
        "incomplete": [path["certificate_ref"] for path in paths
                       if path["resolution"] == "INCOMPLETE"],
        "expiring": expiring,
        "weak": weak,
        "quantum_vulnerable": quantum,
        "shared_public_keys": len(body.get("shared_public_keys") or {}),
        "statement": body.get("statement", ""),
        "not_proven": list(NOT_PROVEN),
    }
