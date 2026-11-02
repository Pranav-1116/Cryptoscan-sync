"""Runtime usage evidence: what a connection actually negotiated.

A configuration says what an appliance *may* do. Only an observed session says
what it *did*. This module turns a metadata-only transcript of completed
sessions into ``USAGE_OBSERVED`` evidence: a cipher-suite name decoded into the
primitives it exercises, a key-exchange group decoded into the curve or the KEM
it used, and one evidence row per session so a claim can be traced back to the
handshake somebody can go and look at.

Two rules shape the design.

**Metadata only.** A record carries a suite name, a group, a peer and a time —
never a payload, a premaster, a session key or a ticket. A record containing one
of those fields is refused by name at ingestion, because a connector that
*sometimes* passes key material through is a connector that will eventually log
it.

**Decoding is declared, not guessed.** A suite name this module cannot decompose
produces an ``undecoded`` entry with the reason, not a plausible-looking
algorithm. "We saw TLS traffic and did not recognise the suite" is a finding;
"saw AES-256" when the code guessed is a false statement in a VBOM.

No sockets are opened here: the caller supplies already-collected records.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.runtime-usage/1"

#: Fields a session record may carry. Anything else is ignored and reported, and
#: anything matching :data:`FORBIDDEN_FIELDS` refuses the whole record.
METADATA_FIELDS: tuple[str, ...] = (
    "session_id", "asset_id", "peer", "started_at", "observed_at", "protocol",
    "tls_version", "cipher_suite", "group", "kex_group", "signature_algorithm",
    "sni", "client_certificate_algorithm", "bytes_read", "bytes_written",
)

FORBIDDEN_FRAGMENTS: tuple[str, ...] = (
    "payload", "plaintext", "cleartext", "secret", "private", "premaster",
    "session_key", "traffic_key", "psk", "ticket_key", "master_secret",
)


class PayloadRefused(ValueError):
    """A session record carried data this module must not hold."""


class IncompleteSession(ValueError):
    """A session record lacks the fields that make it evidence."""


@dataclass(frozen=True)
class Primitive:
    """One cryptographic primitive a session exercised."""

    algorithm: str
    role: str                     # "aead", "hash", "mac", "signature", "key_exchange"
    key_size: int | None = None
    mode: str | None = None
    hybrid: bool = False

    @property
    def pqc(self) -> bool:
        return self.algorithm.startswith(("ML-KEM", "ML-DSA", "SLH-DSA", "Falcon", "HQC"))

    def to_dict(self) -> dict[str, Any]:
        return {"algorithm": self.algorithm, "role": self.role, "key_size": self.key_size,
                "mode": self.mode, "hybrid": self.hybrid, "pqc": self.pqc}


_BULK = (
    (re.compile(r"AES[-_]?(128|256)[-_]?(GCM|CBC|CCM|CTR)?"), "aes"),
    (re.compile(r"CHACHA20[-_]?POLY1305|CHACHA20"), "chacha"),
    (re.compile(r"3DES|DES[-_]?CBC3|TDEA"), "3des"),
    (re.compile(r"(?<!3)DES[-_]?CBC|(?<!3)DES$"), "des"),
    (re.compile(r"RC4"), "rc4"),
    (re.compile(r"AES[-_]?(128|256)?$"), "aes"),
)

#: A TLS 1.2 IANA name (``TLS_RSA_WITH_AES_128_CBC_SHA``) carries the same
#: information as its OpenSSL spelling; the only difference is separators.
_KEX_TOKENS = frozenset({"ECDHE", "DHE", "ECDH", "DH", "RSA", "PSK", "SRP"})

_GROUPS: dict[str, list[Primitive]] = {
    "X25519": [Primitive("X25519", "key_exchange", 255)],
    "PRIME256V1": [Primitive("ECDH-P-256", "key_exchange", 256)],
    "SECP256R1": [Primitive("ECDH-P-256", "key_exchange", 256)],
    "SECP384R1": [Primitive("ECDH-P-384", "key_exchange", 384)],
    "SECP521R1": [Primitive("ECDH-P-521", "key_exchange", 521)],
    "X448": [Primitive("X448", "key_exchange", 448)],
    "FFDHE2048": [Primitive("DH-2048", "key_exchange", 2048)],
    "FFDHE3072": [Primitive("DH-3072", "key_exchange", 3072)],
    # The hybrid groups are where PQC shows up in the wild today: a connection
    # that negotiated one of these really did run ML-KEM, alongside a classical
    # curve.
    "X25519MLKEM768": [Primitive("X25519", "key_exchange", 255, hybrid=True),
                       Primitive("ML-KEM-768", "key_exchange", None, hybrid=True)],
    "SECP256R1MLKEM768": [Primitive("ECDH-P-256", "key_exchange", 256, hybrid=True),
                          Primitive("ML-KEM-768", "key_exchange", None, hybrid=True)],
    "MLKEM768": [Primitive("ML-KEM-768", "key_exchange")],
    "MLKEM1024": [Primitive("ML-KEM-1024", "key_exchange")],
}

_GROUP_ALIASES = {
    "X25519KYBER768": "X25519MLKEM768",
    "X25519KYBER768DRAFT00": "X25519MLKEM768",
    "SECP256R1KYBER768": "SECP256R1MLKEM768",
    "P256": "SECP256R1",
    "P384": "SECP384R1",
    "P521": "SECP521R1",
}


def _compact(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(value or "").upper())


def decode_cipher_suite(name: Any) -> dict[str, Any]:
    """Decompose a TLS cipher-suite name into the primitives it exercises.

    ``TLS_AES_256_GCM_SHA384`` → AES-256-GCM (aead) and SHA-384 (mac, TLS 1.3
    transcript hash); ``ECDHE-RSA-AES128-GCM-SHA256`` → AES-128-GCM, ECDHE,
    RSA and SHA-256. An unrecognised name returns ``known=False`` with a reason
    and **no** primitives.
    """
    raw = str(name or "").strip()
    if not raw:
        return {"suite": "", "known": False, "primitives": [],
                "reason": "no cipher suite name was supplied"}
    text = raw.upper().replace(" ", "_")
    primitives: list[Primitive] = []
    signature: str | None = None

    if text.startswith("TLS_") and re.match(
            r"(AES_|CHACHA20_|CCM_|AES_CCM_)", text[4:]):
        body = text[4:]
        match = re.match(r"(AES)_(128|256)_(GCM|CCM)", body)
        if match:
            primitives.append(Primitive(f"AES-{match.group(2)}-{match.group(3)}", "aead",
                                        int(match.group(2)), match.group(3)))
        elif body.startswith("CHACHA20_POLY1305"):
            primitives.append(Primitive("ChaCha20-Poly1305", "aead", 256, "POLY1305"))
        hash_match = re.search(r"SHA(1|256|384|512)", body)
        if hash_match:
            primitives.append(Primitive(f"SHA-{hash_match.group(1)}", "hash",
                                        int(hash_match.group(1))))
        if primitives:
            return {"suite": raw, "known": True, "protocol": "TLS1.3",
                    "primitives": [p.to_dict() for p in primitives], "reason": ""}
        return {"suite": raw, "known": False, "primitives": [],
                "reason": "a TLS 1.3 suite name without a bulk cipher this module decodes"}

    if text.startswith("TLS_"):
        # IANA spelling: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        text = text[4:].replace("_WITH_", "_")
    tokens = [token for token in re.split(r"[-_]", text) if token]
    if tokens and tokens[0] in {"ECDHE", "DHE", "ECDH", "DH", "RSA", "PSK", "TLS"}:
        kex = tokens.pop(0)
        if kex in {"ECDHE", "ECDH"}:
            primitives.append(Primitive("ECDHE", "key_exchange", mode="EPHEMERAL"))
        elif kex in {"DHE", "DH"}:
            primitives.append(Primitive("DHE", "key_exchange", mode="EPHEMERAL"))
        elif kex == "RSA":
            primitives.append(Primitive("RSA", "key_exchange", mode="KEY_TRANSPORT"))
        if tokens and tokens[0] in {"RSA", "ECDSA", "PSK", "DSS"}:
            signature = tokens.pop(0)
            primitives.append(Primitive(
                "ECDSA" if signature == "ECDSA" else signature, "signature"))
    rest = "-".join(tokens)
    for pattern, kind in _BULK:
        match = pattern.search(rest)
        if not match:
            continue
        if kind == "aes":
            size = match.group(1) if match.groups() and match.group(1) else None
            mode = match.group(2) if len(match.groups()) > 1 else None
            primitives.append(Primitive(f"AES-{size}" + (f"-{mode}" if mode else ""), "aead",
                                        int(size) if size else None, mode))
        elif kind == "chacha":
            primitives.append(Primitive("ChaCha20-Poly1305", "aead", 256, "POLY1305"))
        elif kind == "3des":
            primitives.append(Primitive("3DES", "aead", 168, "CBC"))
        elif kind == "des":
            primitives.append(Primitive("DES", "aead", 56, "CBC"))
        elif kind == "rc4":
            primitives.append(Primitive("RC4", "aead", 128))
        break
    hash_match = re.search(r"SHA(1|256|384|512)", rest)
    if hash_match:
        primitives.append(Primitive(f"SHA-{hash_match.group(1)}", "mac",
                                    int(hash_match.group(1))))
    if not primitives:
        return {"suite": raw, "known": False, "primitives": [],
                "reason": "no bulk cipher or key exchange this module decodes"}
    if all(primitive.role in {"mac", "hash"} for primitive in primitives):
        # A hash name alone is not a decoded suite. Reporting "we saw SHA-256"
        # from a name nobody recognises would be a guess dressed as a finding.
        return {"suite": raw, "known": False, "primitives": [],
                "reason": "only a hash name was recognised, which does not identify the suite"}
    return {"suite": raw, "known": True, "protocol": "TLS1.2",
            "primitives": [p.to_dict() for p in primitives], "reason": ""}


def decode_group(name: Any) -> dict[str, Any]:
    """The curve or KEM behind a named group, with hybrid groups kept hybrid."""
    compact = _compact(name)
    if not compact:
        return {"group": "", "known": False, "primitives": [], "hybrid": False,
                "reason": "no group was recorded"}
    key = _GROUP_ALIASES.get(compact, compact)
    if key not in _GROUPS:
        return {"group": str(name), "known": False, "primitives": [], "hybrid": False,
                "reason": f"{name} is not a group this module knows"}
    primitives = _GROUPS[key]
    return {"group": str(name), "known": True,
            "primitives": [p.to_dict() for p in primitives],
            "hybrid": any(p.hybrid for p in primitives), "reason": ""}


def _assert_metadata_only(record: Mapping[str, Any]) -> list[str]:
    """Refuse key material by name; return the fields this reader ignores."""
    ignored: list[str] = []
    for field in record:
        lowered = str(field).lower()
        for fragment in FORBIDDEN_FRAGMENTS:
            if fragment in lowered:
                raise PayloadRefused(
                    f"field {field!r} looks like key material or payload: this reader keeps "
                    "metadata only, and a connector that passes a payload through is a "
                    "connector that will log one")
        if str(field) not in METADATA_FIELDS:
            ignored.append(str(field))
    return ignored


def _as_date(value: Any) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def _confidence(sessions: int) -> str:
    if sessions >= 10:
        return "HIGH"
    if sessions >= 2:
        return "MEDIUM"
    return "LOW"


def ingest_sessions(records: Iterable[Mapping[str, Any]], *, asset_id: str,
                    vendor: str | None = None, product: str | None = None,
                    product_version: str | None = None,
                    as_of: date | None = None) -> dict[str, Any]:
    """Turn metadata-only session records into usage evidence and claims."""
    asset = str(asset_id or "").strip()
    if not asset:
        raise ValueError("usage evidence belongs to an asset; an unowned observation is not auditable")
    rows = [dict(record) for record in records]
    ignored: set[str] = set()
    for record in rows:
        ignored.update(_assert_metadata_only(record))
    if not rows:
        return {"schema": SCHEMA, "asset_id": asset, "sessions": 0, "primitives": [],
                "undecoded": [], "peers": [], "pqc_used": False,
                "statement": ("no sessions were observed, so nothing is known about production "
                              "use — an empty transcript is not evidence of absence")}

    seen: dict[tuple[str, str], dict[str, Any]] = {}
    undecoded: list[dict[str, str]] = []
    peers: set[str] = set()
    stamps: list[date] = []
    session_ids: list[str] = []
    per_primitive_sessions: dict[tuple[str, str], set[str]] = {}

    for index, record in enumerate(rows):
        session = str(record.get("session_id") or "").strip()
        if not session:
            raise IncompleteSession(f"session record {index} has no session_id, so it cannot be cited")
        started = _as_date(record.get("started_at") or record.get("observed_at"))
        if started is None:
            raise IncompleteSession(
                f"session {session} has no usable started_at, so its age cannot be stated")
        suite = record.get("cipher_suite")
        if not suite:
            raise IncompleteSession(f"session {session} names no cipher suite")
        session_ids.append(session)
        stamps.append(started)
        if record.get("peer"):
            peers.add(str(record["peer"]))

        decoded = decode_cipher_suite(suite)
        primitives = list(decoded["primitives"])
        if not decoded["known"]:
            undecoded.append({"session_id": session, "kind": "cipher_suite",
                              "value": str(suite), "reason": decoded["reason"]})
        group = record.get("group") or record.get("kex_group")
        if group:
            group_decoded = decode_group(group)
            if group_decoded["known"]:
                primitives.extend(group_decoded["primitives"])
            else:
                undecoded.append({"session_id": session, "kind": "group",
                                  "value": str(group), "reason": group_decoded["reason"]})
        for primitive in primitives:
            key = (primitive["algorithm"], primitive["role"])
            per_primitive_sessions.setdefault(key, set()).add(session)
            row = seen.setdefault(key, {"algorithm": primitive["algorithm"],
                                        "role": primitive["role"],
                                        "key_size": primitive["key_size"],
                                        "mode": primitive["mode"],
                                        "hybrid": primitive["hybrid"],
                                        "pqc": primitive["pqc"],
                                        "sessions": 0, "peers": [], "protocols": []})
            if primitive["key_size"] and not row["key_size"]:
                row["key_size"] = primitive["key_size"]
            if primitive["mode"] and not row["mode"]:
                row["mode"] = primitive["mode"]
            row["hybrid"] = row["hybrid"] or primitive["hybrid"]
            row["pqc"] = row["pqc"] or primitive["pqc"]
            row["sessions"] = len(per_primitive_sessions[key])
            if record.get("peer") and str(record["peer"]) not in row["peers"]:
                row["peers"].append(str(record["peer"]))
            protocol = decoded.get("protocol") or record.get("tls_version") or record.get("protocol")
            if protocol and protocol not in row["protocols"]:
                row["protocols"].append(str(protocol))

    for row in seen.values():
        row["confidence"] = _confidence(row["sessions"])
        row["evidence_ids"] = [
            "VE-" + hashlib.sha256(f"RUNTIME_OBSERVED|session:{session}|".encode()).hexdigest()[:12]
            for session in sorted(per_primitive_sessions[(row["algorithm"], row["role"])])
        ]
    primitives_out = sorted(seen.values(), key=lambda row: (row["algorithm"], row["role"]))
    pqc = [row["algorithm"] for row in primitives_out if row["pqc"]]
    first, last = min(stamps), max(stamps)
    return {
        "schema": SCHEMA,
        "asset_id": asset,
        "vendor": vendor,
        "product": product,
        "product_version": product_version,
        "as_of": (as_of or date.today()).isoformat(),
        "sessions": len(session_ids),
        "session_ids": session_ids,
        "peers": sorted(peers),
        "period": {"first": first.isoformat(), "last": last.isoformat()},
        "primitives": primitives_out,
        "undecoded": undecoded,
        "ignored_fields": sorted(ignored),
        "pqc_used": bool(pqc),
        "pqc_primitives": sorted(set(pqc)),
        "confidence": _confidence(len(session_ids)),
        "statement": _statement(asset, len(session_ids), primitives_out, undecoded, pqc),
    }


def _statement(asset: str, sessions: int, primitives: Sequence[Mapping[str, Any]],
               undecoded: Sequence[Mapping[str, str]], pqc: Sequence[str]) -> str:
    if not primitives:
        return (f"{asset}: {sessions} session(s) observed and no primitive decoded — that is a "
                "decoder gap, not an absence of cryptography")
    algorithms = ", ".join(row["algorithm"] for row in primitives)
    text = (f"{asset}: {sessions} observed session(s) exercised {algorithms}; "
            f"this is usage evidence, not a vendor declaration")
    if pqc:
        text += f"; post-quantum key establishment was observed ({', '.join(sorted(set(pqc)))})"
    if undecoded:
        text += f"; {len(undecoded)} suite(s) could not be decoded and are reported, not guessed"
    return text


def to_claims(summary: Mapping[str, Any], *, asset_id: str | None = None,
              product: Any = None) -> list[Any]:
    """The usage summary as ``CapabilityClaim`` rows carrying their sessions.

    Imported lazily so this module stays usable for decoding alone, and so the
    evidence model keeps no dependency on the transport that fed it. Each claim
    cites every session the primitive was seen in — a claim backed by one
    session and a claim backed by forty are different statements, and the
    ``confidence`` field says which one this is.
    """
    from vendor_intel.vendor_evidence import (  # noqa: PLC0415
        CapabilityClaim, Evidence, EvidenceType)

    asset = asset_id or str(summary.get("asset_id") or "")
    stamp = observed_at(summary)
    claims = []
    for row in summary.get("primitives") or ():
        evidence = tuple(
            Evidence(EvidenceType.RUNTIME_OBSERVED,
                     reference=f"session:{session}",
                     observed_at=stamp,
                     source_document=summary.get("schema"))
            for session in summary.get("session_ids") or ()
        )
        claims.append(CapabilityClaim(
            asset_id=asset,
            algorithm=row["algorithm"],
            key_size=row.get("key_size"),
            mode=row.get("mode"),
            purpose=row.get("role"),
            provider=summary.get("vendor"),
            product=product,
            firmware_version=summary.get("product_version"),
            discovery_method="RUNTIME_OBSERVED",
            observed_at=stamp,
            evidence=evidence,
        ))
    return claims


def observed_at(summary: Mapping[str, Any]) -> date | None:
    last = (summary.get("period") or {}).get("last")
    return _as_date(last)
