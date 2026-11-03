"""Passive observation, and the privacy contract that has to come first.

Review item 15 asks for passive observation — cryptography recorded from traffic the
estate is already sending, instead of from authenticated API polls. The review gates it
on a privacy contract, and this module treats that gate as code rather than a paragraph:
**the contract is checked before a record is accepted**, and a record containing a field
the contract prohibits is refused rather than stripped.

Three design decisions are worth stating, because each one is a place where a passive
collector usually goes wrong.

**Refuse, do not redact silently.** If a collector hands over a payload, a password or a
session token, the right answer is a visible refusal with the field named — not a quiet
`sanitise()` that teaches the operator the schema tolerates it. Redaction is for the
fields the contract *classifies*, and it is deterministic and one-way.

**Pseudonyms need a per-deployment salt, and the salt is never stored.** An address
hashed with a fixed salt is a global identifier; hashed with a deployment salt it cannot
be joined against another deployment's records. The contract records a salt *id*, the
caller passes the salt, and this module keeps neither the salt nor the raw value.

**A passive observation is evidence of one exchange.** What was seen is `OBSERVED` and
stays `OBSERVED`: a passive collector cannot upgrade a fact to "configured" or
"declared", because it never asked the device anything. That keeps guide 154's
SUPPORTED/CONFIGURED/NEGOTIATED distinction intact, with a fourth source of the same
`NEGOTIATED` claim.

**An expired observation is not evidence.** Retention is part of the contract, and a
record past its class's retention is reported as expired instead of being quietly used —
an inventory that keeps citing a capture from two years ago is worse than one that says
it has nothing.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.cbom-passive/1"

#: how a field may be handled
METADATA = "METADATA"            # kept as observed: sizes, timings, versions, suites
PSEUDONYMOUS = "PSEUDONYMOUS"    # kept only as a keyed pseudonym
PROHIBITED = "PROHIBITED"        # refused: never accepted, not even to be dropped
CLASSES: tuple[str, ...] = (METADATA, PSEUDONYMOUS, PROHIBITED)

#: the field classification. Every ingestible field appears here; anything else is unknown
#: and unknown fields are refused as loudly as prohibited ones.
FIELDS: dict[str, str] = {
    # what the exchange looked like
    "src": METADATA,
    "dst": METADATA,
    "src_port": METADATA,
    "dst_port": METADATA,
    "protocol": METADATA,
    "first_seen": METADATA,
    "last_seen": METADATA,
    "bytes_client_to_server": METADATA,
    "bytes_server_to_client": METADATA,
    "packets": METADATA,
    "tls_version": METADATA,
    "cipher_suite": METADATA,
    "kex_group": METADATA,
    "signature_algorithm": METADATA,
    "ssh_kex": METADATA,
    "ssh_host_key": METADATA,
    "ssh_cipher": METADATA,
    "ssh_mac": METADATA,
    "certificate_sha256": METADATA,
    "certificate_key_bits": METADATA,
    "certificate_key_type": METADATA,
    "session_id_present": METADATA,
    "evidence_id": METADATA,
    "source": METADATA,
    # linkable to a client or a person, so only pseudonymous
    "client_address": PSEUDONYMOUS,
    "server_name": PSEUDONYMOUS,
    "ja3": PSEUDONYMOUS,
    "ja4": PSEUDONYMOUS,
    "session_id_hash": PSEUDONYMOUS,
    # never accepted
    "payload": PROHIBITED,
    "plaintext": PROHIBITED,
    "decrypted": PROHIBITED,
    "password": PROHIBITED,
    "cookie": PROHIBITED,
    "authorization": PROHIBITED,
    "token": PROHIBITED,
    "client_certificate_subject": PROHIBITED,
    "http_headers": PROHIBITED,
    "private_key": PROHIBITED,
}

#: default retention per class, in days. Pseudonymous fields expire sooner than metadata
DEFAULT_RETENTION: dict[str, int] = {METADATA: 90, PSEUDONYMOUS: 30}

#: the purposes a contract may claim. A collector that cannot name its purpose cannot run
PURPOSES: tuple[str, ...] = (
    "CRYPTO_INVENTORY",
    "MIGRATION_PLANNING",
    "WEAK_PROTOCOL_DETECTION",
    "INCIDENT_RESPONSE",
)

NOT_PROVEN = [
    "that the observed exchange is the estate's current configuration: a capture is one "
    "conversation, and a client can negotiate a weaker suite than the server's policy "
    "allows on the next one",
    "anything about exchanges the collector did not see: a passive tap at one point "
    "misses what is tunnelled, off-net or carried over a path it does not span",
    "that a pseudonym is unlinkable in practice: the salt keeps two deployments apart, "
    "and inside one deployment the same pseudonym across records is still a link",
    "the contents of the session: this model reads handshake metadata and refuses "
    "payload, so it cannot say what was sent or whether it was sensitive",
    "that a certificate seen on the wire was valid at the time: chain validation is "
    "guide 159's subject and is not re-derived from a fingerprint",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def contract(**overrides: Any) -> dict[str, Any]:
    """A privacy contract that can be checked, not a policy document that can be cited."""
    body = {
        "schema": SCHEMA,
        "contract_id": None,
        "owner": None,
        "purposes": [],
        "lawful_basis": None,
        "retention_days": dict(DEFAULT_RETENTION),
        "salt_id": None,
        "reviewed_at": None,
        "collects": [],
        "prohibits": sorted(name for name, cls in FIELDS.items() if cls == PROHIBITED),
    }
    body.update(overrides)
    problems: list[str] = []
    if not body["contract_id"]:
        problems.append("a contract needs an id, so an observation can cite it")
    if not body["owner"]:
        problems.append("a contract needs an owner who signed it")
    purposes = [str(value).strip().upper() for value in body["purposes"] or []]
    if not purposes:
        problems.append("a contract needs at least one purpose")
    unknown = [purpose for purpose in purposes if purpose not in PURPOSES]
    if unknown:
        problems.append(f"unsupported purpose(s): {', '.join(unknown)}")
    if not body["lawful_basis"]:
        problems.append("a contract needs a lawful basis; 'because it is on the wire' "
                        "is not one")
    retention = dict(body["retention_days"] or {})
    if set(retention) != {METADATA, PSEUDONYMOUS}:
        problems.append("retention must be set for both METADATA and PSEUDONYMOUS")
    for name, days in retention.items():
        if not isinstance(days, int) or days <= 0:
            problems.append(f"retention for {name} must be a positive number of days")
        elif name == PSEUDONYMOUS and days > retention.get(METADATA, days):
            problems.append("pseudonymous fields must not outlive metadata")
    collects = [str(name) for name in body["collects"] or []]
    for name in collects:
        if name not in FIELDS:
            problems.append(f"{name} is not a field this collector knows how to classify")
        elif FIELDS[name] == PROHIBITED:
            problems.append(f"{name} is prohibited and cannot be collected")
    needs_salt = any(FIELDS.get(name) == PSEUDONYMOUS for name in collects)
    if needs_salt and not body["salt_id"]:
        problems.append("collecting a pseudonymous field needs a salt id; a fixed salt "
                        "makes a pseudonym a global identifier")
    body.update({
        "purposes": purposes,
        "collects": collects,
        "enforceable": not problems,
        "problems": problems,
        "statement": (f"contract {body['contract_id']} by {body['owner']}: "
                      + ", ".join(purposes)
                      + f"; retention {retention.get(METADATA, 0)}d metadata / "
                      f"{retention.get(PSEUDONYMOUS, 0)}d pseudonymous"
                      + (f"; salt {body['salt_id']}" if body["salt_id"] else "")
                      if not problems else
                      f"contract rejected: {len(problems)} problem(s): {problems[0]}"),
    })
    return body


def pseudonym(value: Any, salt: str, *, length: int = 12) -> str:
    """A keyed, truncated pseudonym. One-way, and equal only within one deployment."""
    if not salt:
        raise ValueError("a pseudonym needs a deployment salt")
    text = "" if value is None else str(value).strip().lower()
    if not text:
        raise ValueError("a pseudonym needs a value")
    digest = hashlib.sha256(f"{salt}\x00{text}".encode("utf-8")).hexdigest()
    return f"p-{digest[:length]}"


def observe(record: Mapping[str, Any], *, privacy: Mapping[str, Any],
            salt: str | None = None, as_of: Any = None) -> dict[str, Any]:
    """One captured exchange → one observation that carries its contract and its expiry."""
    if not isinstance(record, Mapping):
        raise ValueError("an observation must be an object")
    if not isinstance(privacy, Mapping) or privacy.get("schema") != SCHEMA:
        raise ValueError(f"an observation needs a {SCHEMA} privacy contract")
    if not privacy.get("enforceable"):
        raise ValueError("the privacy contract is not enforceable; it cannot vouch for "
                         "a record")
    evidence = record.get("evidence_id")
    if not evidence:
        raise ValueError("an observation without an evidence id is a claim, not a capture")
    forbidden = sorted(name for name in record if name not in FIELDS)
    if forbidden:
        raise ValueError(
            f"{evidence}: field(s) this collector cannot classify: {', '.join(forbidden)} "
            "— refused rather than dropped, because dropping them would teach the "
            "collector the schema tolerates them")
    prohibited = sorted(name for name in record if FIELDS.get(name) == PROHIBITED)
    if prohibited:
        raise ValueError(
            f"{evidence}: prohibited field(s) offered: {', '.join(prohibited)} — the "
            "contract covers handshake metadata, not the traffic")
    allowed = [name for name in record if name in set(privacy.get("collects") or [])]
    not_contracted = sorted(name for name in record
                            if name != "evidence_id" and name not in allowed)
    if not_contracted:
        raise ValueError(
            f"{evidence}: field(s) outside the contract: {', '.join(not_contracted)} — "
            "the contract lists what may be collected, and a collector adds nothing to it")
    fields: dict[str, Any] = {}
    for name in allowed:
        value = record.get(name)
        if FIELDS[name] == PSEUDONYMOUS:
            if value in (None, ""):
                continue
            if not salt:
                raise ValueError(
                    f"{evidence}: {name} is pseudonymous and no salt was supplied; the "
                    "raw value is never stored")
            fields[name] = pseudonym(value, salt)
        else:
            fields[name] = value
    first = _parse_time(record.get("first_seen")) or _parse_time(as_of) or _now()
    last = _parse_time(record.get("last_seen")) or first
    retention = privacy.get("retention_days") or DEFAULT_RETENTION
    # an observation expires with its shortest-lived field: keeping the pseudonym past its
    # retention because a timestamp beside it is allowed to live longer would defeat the
    # retention entirely.
    classes = {FIELDS[name] for name in fields}
    horizon_class = min(classes, key=lambda cls: int(retention.get(cls, 0))) \
        if classes else METADATA
    horizon = int(retention.get(horizon_class, 0))
    expires = last + timedelta(days=horizon)
    moment = _parse_time(as_of) or _now()
    return {
        "schema": SCHEMA,
        "evidence_id": str(evidence),
        "contract_id": privacy.get("contract_id"),
        "pseudonym_salt": privacy.get("salt_id"),
        "fields": fields,
        "pseudonymous_fields": sorted(
            name for name, cls in FIELDS.items()
            if cls == PSEUDONYMOUS and name in fields),
        "first_seen": first.isoformat(),
        "last_seen": last.isoformat(),
        "retention_days": {"METADATA": retention.get(METADATA),
                           "PSEUDONYMOUS": retention.get(PSEUDONYMOUS)},
        "expires_with": horizon_class,
        "expires_at": expires.isoformat(),
        "expired": moment >= expires,
        "confidence": "OBSERVED",
        "statement": _statement(str(evidence), fields, first, last),
    }


def _statement(evidence: str, fields: Mapping[str, Any], first: datetime,
               last: datetime) -> str:
    what = fields.get("cipher_suite") or fields.get("ssh_cipher") or "unknown suite"
    version = fields.get("tls_version") or fields.get("protocol") or ""
    where = fields.get("dst") or "?"
    return (f"capture {evidence}: {where} {version + ' ' if version else ''}{what} "
            f"between {first.isoformat()} and {last.isoformat()} — one exchange, "
            "observed and nothing more")


def estate(records: Iterable[Mapping[str, Any]], *, privacy: Mapping[str, Any],
           salt: str | None = None, as_of: Any = None) -> dict[str, Any]:
    """Many captures → the passive view, with refusals and expiries kept visible."""
    observations: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for record in records or ():
        try:
            observations.append(observe(record, privacy=privacy, salt=salt, as_of=as_of))
        except ValueError as exc:
            refused.append({
                "capture": ({key: record.get(key) for key in ("evidence_id", "dst")}
                            if isinstance(record, Mapping) else record),
                "reason": str(exc)})
    live = [body for body in observations if not body["expired"]]
    expired = [body["evidence_id"] for body in observations if body["expired"]]
    suites = sorted({str(body["fields"].get("cipher_suite") or body["fields"].get(
        "ssh_cipher")) for body in live if body["fields"].get("cipher_suite")
        or body["fields"].get("ssh_cipher")})
    return {
        "schema": SCHEMA,
        "contract_id": privacy.get("contract_id"),
        "observations": observations,
        "refused": refused,
        "expired": expired,
        "live": len(live),
        "suites": suites,
        "statement": (
            f"{len(observations)} observation(s) under contract "
            f"{privacy.get('contract_id')}, {len(live)} live and {len(expired)} expired"
            + (f"; suites seen: {', '.join(suites)}" if suites else "")
            + (f"; {len(refused)} refused" if refused else "")),
        "not_proven": list(NOT_PROVEN),
    }


def to_algorithms(body: Mapping[str, Any]) -> dict[str, Any]:
    """Passive observations as CBOM facts — OBSERVED, never promoted to configured."""
    if not isinstance(body, Mapping) or body.get("schema") != SCHEMA:
        raise ValueError(f"not a {SCHEMA} document")
    facts: list[dict[str, Any]] = []
    for observation in body.get("observations") or []:
        if observation.get("expired"):
            continue
        fields = observation.get("fields") or {}
        pairs = [
            ("tls_version", "PROTOCOL"),
            ("cipher_suite", "BULK"),
            ("kex_group", "KEY_EXCHANGE"),
            ("signature_algorithm", "SIGNATURE"),
            ("ssh_kex", "KEY_EXCHANGE"),
            ("ssh_host_key", "SIGNATURE"),
            ("ssh_cipher", "BULK"),
            ("ssh_mac", "MAC"),
            ("certificate_key_type", "SIGNATURE"),
        ]
        for name, role in pairs:
            value = fields.get(name)
            if not value:
                continue
            facts.append({
                "algorithm": str(value),
                "role": role,
                "parameters": ({"key_bits": fields.get("certificate_key_bits")}
                               if name == "certificate_key_type"
                               and fields.get("certificate_key_bits") else {}),
                "class": "NETWORK_OBSERVED",
                "collection": "PASSIVE",
                "confidence": "OBSERVED",
                "evidence_ids": [observation["evidence_id"]],
                "contract_id": observation.get("contract_id"),
                "destination": fields.get("dst"),
                "protocol": str(fields.get("protocol") or "TLS").upper(),
            })
    seen: dict[tuple[Any, str, str], dict[str, Any]] = {}
    for fact in facts:
        seen.setdefault((fact["destination"], fact["role"], fact["algorithm"]), fact)
    return {
        "schema": SCHEMA,
        "facts": sorted(seen.values(), key=lambda fact: (str(fact["destination"]),
                                                         fact["role"],
                                                         fact["algorithm"])),
        "destinations": sorted({str(fact["destination"]) for fact in facts}),
        "statement": (f"{len(seen)} distinct observed fact(s) across "
                      f"{len({fact['destination'] for fact in facts})} destination(s), "
                      "each evidence-cited and none promoted beyond OBSERVED"),
    }


def summary(body: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: what was observed, under which contract, and what is no longer usable."""
    return {
        "schema": SCHEMA,
        "contract_id": body.get("contract_id"),
        "observations": len(body.get("observations") or []),
        "live": body.get("live", 0),
        "expired": body.get("expired") or [],
        "refused": len(body.get("refused") or []),
        "suites": body.get("suites") or [],
        "statement": body.get("statement", ""),
        "not_proven": list(NOT_PROVEN),
    }
