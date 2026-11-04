"""The common collector contract: six verbs, read-only, evidence-carrying.

Every control type and every vendor reduces to this module. A vendor does not get its own
architecture; it gets an :class:`AdapterSpec` that says which dialect (section names, field
aliases, event kinds, read-only endpoints) its config export or API speaks, and the same
:class:`DeviceCollector` answers the same six questions.

Why a *feed* and not a socket
-----------------------------

A collector is constructed with a **feed** — the normalized rows a device's read-only API or
config export produced — rather than performing I/O inside the contract. Three reasons, all
of them the reason this guide can prove anything:

* the privacy rule is provable offline. A fake device that returns a private key must not
  produce an artifact containing it, and that is a hermetic test rather than a review;
* the evidence rule is provable offline. The feed is where a vendor string would smuggle a
  claim in without an id, and :class:`DeviceCollector` refuses it there;
* the live read-only clients (one per dialect, described in each ``vendors.py``) can land
  later without the contract, the normal form or the tests changing shape.

Feed shape::

    {
      "assets":  [{"kind": "FIREWALL", "name": "FW-EDGE-01", "version": "7.4.3", ...}],
      "sections": {"rules": [...], "zones": [...], ...},      # vendor section names
      "crypto":  [{"asset": "FW-EDGE-01", "tls_version": "TLSv1.2", ...}],
      "relationships": [{"from": "FW-EDGE-01", "relation": "PROTECTS",
                         "to": "PAYMENTS-SEG", "basis": "config-parse",
                         "evidence": "fw-rule-1"}],
      "events":  [{"kind": "ALERT", "signature": "1:2001219", "src": "10.20.3.4", ...}],
      "health":  {"reachable": True, "api_version": "v2", "read_only": True}
    }

Absent sections are empty, never invented.
"""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from cbom import techbom

# --------------------------------------------------------------------------- #
# Control types and the read-only capability model
# --------------------------------------------------------------------------- #

#: one entry per package under this namespace; a control type that is not here has no
#: collector, and :func:`control_spec` refuses it rather than guessing a shape.
CONTROL_TYPES: tuple[str, ...] = (
    "FIREWALL",
    "IDS",
    "IPS",
    "WAF",
    "LOAD_BALANCER",
    "API_GATEWAY",
    "RATE_LIMIT",
    "VPN",
    "SIEM",
    "HSM",
    "KMS",
    "PKI",
    "NETWORK",
)

#: every operation a collector may declare. This is the whole allow-list: it is deliberately
#: short and boring, because a longer one would eventually contain "set".
READ_OPERATIONS: frozenset[str] = frozenset({
    "GET", "API_GET", "SHOW", "SHOW_RUNNING", "CLI_SHOW", "LIST", "EXPORT_CONFIG",
    "READ_CONFIG_FILE", "QUERY", "TAIL_EVENTS", "SYSLOG_READ", "PROBE_TLS", "PCAP_READ",
    "KMIP_QUERY", "PKCS11_QUERY", "SIEM_QUERY", "SNMP_GET",
})

#: operations that change a device. Naming one is not a warning, it is a refusal: a read-only
#: integration that *can* push a policy will eventually push one.
MUTATING_OPERATIONS: frozenset[str] = frozenset({
    "POST", "PUT", "PATCH", "DELETE", "SET", "CONFIG", "CONFIGURE", "RELOAD", "RESTART",
    "PUSH_POLICY", "PUSH", "APPLY", "COMMIT", "BLOCK", "DENY", "ALLOW", "CREATE", "UPDATE",
    "WRITE", "DELETE_RULE", "GENERATE_KEY", "SIGN", "DECRYPT", "ENCRYPT", "ISSUE",
    "REVOKE", "ROTATE", "THROTTLE", "EXPORT_KEY", "DISABLE", "ENABLE", "TUNE",
})

# --------------------------------------------------------------------------- #
# Facts: three, and they never merge
# --------------------------------------------------------------------------- #

CONFIGURED = techbom.CONFIGURED
OBSERVED = techbom.OBSERVED
RUNTIME_OBSERVED = techbom.RUNTIME_OBSERVED

#: the three the specification names. ``STATIC_OBSERVED``, ``IMPORTED``, ``VENDOR_DECLARED``,
#: ``INFERRED`` and ``UNKNOWN`` remain available from :mod:`cbom.techbom`; they are already part
#: of the platform vocabulary and this layer does not extend it.
FACT_CLASSES: tuple[str, ...] = (CONFIGURED, OBSERVED, RUNTIME_OBSERVED)

# --------------------------------------------------------------------------- #
# The prohibition list, as code
# --------------------------------------------------------------------------- #

REDACTED = "[REDACTED]"

#: field names (normalized: lowercase, alphanumerics only) that are never read. Exact match.
PROHIBITED_FIELDS: frozenset[str] = frozenset({
    "privatekey", "privatekeypem", "hsmkeymaterial", "keymaterial", "plaintextkey",
    "password", "passwd", "passphrase", "apisecret", "apikey", "clientsecret",
    "sessiontoken", "accesstoken", "refreshtoken", "authtoken", "bearertoken",
    "customerpayload", "requestbody", "responsebody", "httpbody", "body",
    "decryptedtraffic", "decryptedpayload", "plaintexttraffic",
    "pan", "cvv", "cvv2", "cardnumber", "paymentcard", "trackdata", "pinblock",
    "credential", "credentials", "username", "userpassword",
    "cookie", "setcookie", "authorization", "authorizationheader", "proxyauthorization",
    "presharedkey", "psk", "snmpcommunity", "community",
})

#: suffix rules, so ``db_password`` and ``x_api_secret`` are caught without listing every
#: compound a vendor's schema might invent.
PROHIBITED_SUFFIXES: tuple[str, ...] = (
    "privatekey", "secretkey", "keymaterial", "secret", "password", "passwd", "passphrase",
    "token", "cookie", "credential", "credentials", "cardnumber", "cvv", "psk",
    "community",
)

#: Fields whose value is a *structured number*, not a secret. A guard that redacts every digit
#: run is as useless as one that redacts none: it fills the snapshot with redactions, hides the
#: evidence a reviewer needs, and trains everyone to ignore the redaction list. These names are
#: where a 13-19 digit value is ordinary — an epoch in milliseconds, a 64-bit object id, an
#: inode, a serial, a byte count.
#:
#: The allowlist only exempts the *shape* check for that field. A prohibited field name
#: (``pan``, ``cvv``) is still refused under any spelling, and a PEM key in a field called
#: ``timestamp`` is still a PEM key.
NUMERIC_ALLOWANCES: frozenset[str] = frozenset({
    # time
    "timestamp", "timestamps", "time", "ts", "epoch", "epochms", "epochmicros", "epochnanos",
    "starttime", "endtime", "firstseen", "lastseen", "createdat", "updatedat", "modifiedat",
    "expiresat", "expiry", "notbefore", "notafter", "uptime", "uptimems", "durationms",
    "latencyus", "generatedat", "collectedat", "observedat", "detectedat",
    # identity and counter
    "id", "ids", "objectid", "objectidentifier", "serial", "serialnumber", "serialreference",
    "policyid", "ruleid", "ruleindex", "sensorid", "sensoridint", "deviceid", "tenantid",
    "correlationid", "eventid", "windowseventid", "inode", "fileid", "sequence", "seq",
    "index", "count", "counter", "requests", "packets", "bytes", "octets", "hits", "sessions",
    # network structure
    "port", "ports", "srcport", "dstport", "localport", "remoteport", "vlan", "vlanid", "mtu",
    "asn", "ouiprefix", "bssid", "ssid", "netmask", "ipv4int", "ipv4", "ipv6",
    # size and version
    "size", "keysize", "bits", "keybits", "version", "revision", "rulerevision",
    "configversion", "firmwareid", "buildnumber", "major", "minor", "patch",
})

#: the shapes the allowlist can excuse. A PEM key, a bearer token or an AWS key is never
#: structural, in any field.
ALLOWABLE_SHAPES: frozenset[str] = frozenset({"CARD_NUMBER"})

#: content shapes. A field can be innocently named and still carry a secret; the value is
#: inspected as well, because renaming a field is not a privacy control.
PROHIBITED_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PEM_PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("AUTHORIZATION_HEADER", re.compile(r"(?i)\bauthorization\s*:\s*\S+")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("CARD_NUMBER", re.compile(r"(?<![\d.])(?:\d[ -]?){13,19}(?![\d.])")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
)

#: what a redaction leaves behind: the fact that something was refused, never the value.
REDACTION_MARKER = "redaction"


class ControlRefused(Exception):
    """A collector would have broken the contract. Refusal, with a code and a reason."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "reason": self.reason}


#: fields the estate builder owns. Anything else a feed says about an asset is an attribute.
#: the keys of a driver's read record that ``health()`` passes through unchanged
_READ_KEYS: tuple[str, ...] = ("sections", "failed_sections", "coverage", "section_digests",
                               "unchanged_sections", "truncated", "limits", "partial", "detail",
                               "reachable")

_RESERVED_ASSET_FIELDS: frozenset[str] = frozenset({
    "kind", "name", "version", "environment", "location", "owner", "status",
    "source", "evidence_ids", "attributes", "id", "key", "digest",
})


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", _norm(value).lower())


def digest(payload: Any, size: int = 12) -> str:
    """Stable digest over a JSON-able payload — the same fact, the same id, tomorrow too."""
    try:
        text = json.dumps(payload, sort_keys=True, default=str)
    except (TypeError, ValueError):  # pragma: no cover — defensive
        text = repr(payload)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:size]


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

#: card issuer ranges (IIN). A 13-19 digit run that starts with none of these is not a PAN,
#: whatever else it looks like — this is the check that keeps epoch milliseconds out.
_CARD_IIN_PREFIXES: tuple[str, ...] = (
    "4", "51", "52", "53", "54", "55", "22", "23", "24", "25", "26", "27",
    "34", "37", "30", "36", "38", "39", "60", "65", "62", "35", "31", "33",
)


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _card_like(value: str) -> bool:
    """Whether a digit run is a payment card number, by the two checks that matter.

    A shape regex over ``13-19`` digits matches epoch milliseconds (13 digits), a microsecond
    timestamp (16), a 64-bit object id (up to 20), a hex-free serial, a byte total. Redacting
    all of those is not a privacy control, it is an outage of the evidence. So a candidate must
    be **Luhn-valid** *and* start with an issuer range before it is treated as a card.
    """
    digits = re.sub(r"[ -]", "", value)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    if not any(digits.startswith(prefix) for prefix in _CARD_IIN_PREFIXES):
        return False
    return _luhn(digits)


def _shape_of(value: Any, *, field: str = "") -> str | None:
    if not isinstance(value, str) or len(value) < 8:
        return None
    allowed = _slug(field) in NUMERIC_ALLOWANCES
    for name, pattern in PROHIBITED_SHAPES:
        if allowed and name in ALLOWABLE_SHAPES:
            continue
        if name == "CARD_NUMBER":
            if _card_like(value):
                return name
            continue
        if pattern.search(value):
            return name
    return None


def redaction_allowlist() -> dict[str, Any]:
    """What the guard deliberately does *not* redact, and why — printed with every audit.

    A redaction guard is a trade. Saying out loud which numeric fields are structural is what
    makes the trade reviewable; the alternative is a rule nobody can argue with because nobody
    knows what it covers.
    """
    return {
        "schema": "cryptoscan.redaction-allowlist/1",
        "numeric_fields": sorted(NUMERIC_ALLOWANCES),
        "allowed_shapes": sorted(ALLOWABLE_SHAPES),
        "card_rule": ("a 13-19 digit run is a PAN only when it is Luhn-valid *and* starts with "
                      "an issuer range; epoch milliseconds, object ids and byte counts fail "
                      "one of those two"),
        "never_allowed": sorted({name for name, _ in PROHIBITED_SHAPES} - ALLOWABLE_SHAPES),
        "note": ("the allowlist relaxes the *shape* check for a named field; a prohibited "
                 "field name is still refused under every spelling"),
    }


def scrub(payload: Any, *, path: str = "") -> tuple[Any, list[dict[str, Any]]]:
    """Return ``(clean_copy, redactions)`` with every prohibited field and shape removed.

    The redaction list is evidence, not log noise: it says *which* field was refused, on
    which path, and why. The value is never in it, not even truncated — a redaction record
    that quotes the secret is the leak it was meant to prevent.
    """
    redactions: list[dict[str, Any]] = []
    clean = _scrub(payload, path, redactions)
    return clean, redactions


def _scrub(payload: Any, path: str, redactions: list[dict[str, Any]]) -> Any:
    if isinstance(payload, Mapping):
        out: dict[str, Any] = {}
        for key, value in payload.items():
            key_text = _norm(key)
            where = f"{path}.{key_text}" if path else key_text
            reason = _prohibited_reason(key_text)
            if reason:
                redactions.append({"path": where, "reason": reason, "field": key_text})
                out[key_text] = REDACTED
                continue
            out[key_text] = _scrub(value, where, redactions)
        return out
    if isinstance(payload, (list, tuple, set)):
        return [_scrub(item, f"{path}[{index}]", redactions)
                for index, item in enumerate(payload)]
    shape = _shape_of(payload, field=path)
    if shape:
        redactions.append({"path": path or "(value)", "reason": shape, "field": path})
        return REDACTED
    return payload


def _prohibited_reason(field_name: str) -> str | None:
    key = _slug(field_name)
    if not key:
        return None
    if key in PROHIBITED_FIELDS:
        return "PROHIBITED_FIELD"
    if key.endswith(PROHIBITED_SUFFIXES):
        return "PROHIBITED_FIELD"
    return None


def read_only_violations(operations: Iterable[Any]) -> list[str]:
    """The operations a spec names that a read-only integration may not perform."""
    found: list[str] = []
    for raw in operations or ():
        operation = _norm(raw).upper()
        if not operation:
            continue
        if operation in MUTATING_OPERATIONS:
            found.append(operation)
        elif operation not in READ_OPERATIONS:
            # an operation nobody can classify is refused, not assumed harmless
            found.append(operation)
    return sorted(set(found))


# --------------------------------------------------------------------------- #
# Evidence and the adapter spec
# --------------------------------------------------------------------------- #

#: The digest scheme, as a prefix on every id.
#:
#: Why a prefix and not a bare hash: an evidence id is a citation, and a citation that silently
#: changes meaning when the hashing rule changes invalidates every report that quoted it. With
#: ``EVID-v1-FIREWALL-<hash>`` in place, ``v2`` can add a field to the digest — a device config
#: version, a schema revision — and a reader can tell which ids were minted under which rule.
#: Ids minted before this guide (``EVID-FIREWALL-<hash>``, no scheme token) are *legacy v0*:
#: they still resolve, and :func:`evidence_scheme` reports them as such rather than pretending
#: they were computed the same way.
EVIDENCE_SCHEME = "v1"
LEGACY_SCHEME = "v0"

#: fields that carry a device's own view of *which revision* of a rule this is. When a row has
#: one, it enters the digest: a rule can keep its identity (``allow-payments``) and change its
#: text, and the id has to move when the text moves. A re-read of the unchanged rule keeps the
#: same version, so the id stays stable — which is the property that makes a diff possible.
CONFIG_VERSION_FIELDS: tuple[str, ...] = (
    "version", "revision", "rule_revision", "rule_version", "config_version", "config_rev",
    "generation", "etag", "last_modified", "modified_at", "updated_at", "last_changed",
    "commit", "checksum", "text_digest",
)


def evidence_scheme(evidence_id: Any) -> str:
    """Which digest rule minted this id. Never raises: an unknown shape is reported as such."""
    parts = _norm(evidence_id).split("-")
    if len(parts) >= 4 and parts[0] == "EVID" and parts[1] in {"v0", "v1", "v2", "v3"}:
        return parts[1]
    if len(parts) >= 3 and parts[0] == "EVID":
        return LEGACY_SCHEME
    return "UNKNOWN"


def config_version(facts: Any) -> dict[str, Any]:
    """The row's own configuration revision, under whatever the vendor calls it."""
    if not isinstance(facts, Mapping):
        return {}
    found: dict[str, Any] = {}
    for key, value in facts.items():
        slug = _slug(key)
        if slug in {_slug(name) for name in CONFIG_VERSION_FIELDS} and value not in (None, ""):
            found[slug] = value
    return dict(sorted(found.items()))


class EvidenceBook:
    """Deterministic evidence ids for one collector.

    ``EVID-v1-<CONTROL>-<digest12>`` over (scheme, control, vendor, system, kind, identity,
    config version, facts).

    Three properties, each one deliberate:

    * **stable** — the same fact read twice is the same id, so a snapshot can be diffed and a
      retried collection does not manufacture a change;
    * **versioned** — a rule whose *text* changed while its identity did not moves its id,
      because the device's own revision (``version``, ``revision``, ``etag``, ``last_modified``
      …) is part of the digest. Without it, "policy 12 changed" is invisible in a diff of ids;
    * **scheme-tagged** — the rule above can be replaced without invalidating history.
    """

    def __init__(self, control: str, vendor: str, system: str,
                 scheme: str = EVIDENCE_SCHEME) -> None:
        self.control = _norm(control).upper()
        self.vendor = _norm(vendor)
        self.system = _norm(system)
        self.scheme = scheme
        self.records: dict[str, dict[str, Any]] = {}

    def id_for(self, kind: str, identity: Any, facts: Any = None,
               *, version: Any = None) -> str:
        """Mint (or re-mint) the id for one fact.

        ``version`` overrides the version discovered in ``facts``; a caller that knows the
        device's configuration revision passes it explicitly rather than hoping the row was
        shaped the way :func:`config_version` expects.
        """
        evidence_id = self._mint(kind, identity, facts, version)
        config = config_version(facts)
        if version not in (None, ""):
            config = {**config, "declared": version}
        self.records.setdefault(evidence_id, {
            "evidence_id": evidence_id,
            "scheme": self.scheme,
            "control": self.control,
            "vendor": self.vendor,
            "system": self.system,
            "kind": _norm(kind).upper(),
            "identity": _norm(identity),
            "config_version": config,
        })
        return evidence_id

    def _mint(self, kind: str, identity: Any, facts: Any = None,
              version: Any = None) -> str:
        """The digest, with no bookkeeping — so ``verify`` can recompute without writing."""
        config = config_version(facts)
        if version not in (None, ""):
            config = {**config, "declared": version}
        body = {
            "scheme": self.scheme,
            "control": self.control,
            "vendor": self.vendor,
            "system": self.system,
            "kind": _norm(kind).upper(),
            "identity": _norm(identity),
            "config_version": config,
            "facts": facts if facts in (None, "", [], {}) else facts,
        }
        return f"EVID-{self.scheme}-{self.control}-{digest(body, 12)}"

    def verify(self, evidence_id: Any, kind: str, identity: Any, facts: Any = None) -> dict[str, Any]:
        """Recompute an id and say whether the citation still holds.

        This is what a report needs when it is re-read six months later: *does the fact I cited
        still hash to the id I printed?* A mismatch is not an error in the report — it is a
        changed fact (or an edited citation), and the answer distinguishes them.
        """
        expected = self._mint(kind, identity, facts)
        scheme = evidence_scheme(evidence_id)
        return {
            "evidence_id": _norm(evidence_id),
            "recomputed": expected,
            "matches": _norm(evidence_id) == expected,
            "scheme": scheme,
            "current_scheme": self.scheme,
            "legacy": scheme == LEGACY_SCHEME,
            "reason": ("the citation resolves under the current digest rule"
                       if _norm(evidence_id) == expected else
                       "the fact hashes differently now: either the fact changed or the "
                       "citation was never this fact's id"),
        }

    def as_list(self) -> list[dict[str, Any]]:
        return [self.records[key] for key in sorted(self.records)]


@dataclass(frozen=True)
class AdapterSpec:
    """One vendor's dialect, as data.

    ``sections`` maps the vendor's own section name to the canonical one, ``aliases`` maps a
    canonical field to the vendor spellings to try, and ``endpoints`` records the read-only
    calls a live driver would make — as documentation and as an auditable allow-list, since
    :meth:`__post_init__` refuses a mutating one.
    """

    key: str
    control: str
    vendor: str
    product: str
    operations: tuple[str, ...] = ("API_GET",)
    sections: Mapping[str, str] = field(default_factory=dict)
    aliases: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    event_kinds: tuple[str, ...] = ("ALERT",)
    endpoints: tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        control = _norm(self.control).upper()
        if control not in CONTROL_TYPES:
            raise ControlRefused(
                "UNKNOWN_CONTROL",
                f"{control or '(none)'} is not a security control type; the contract has "
                f"{len(CONTROL_TYPES)} and a new one needs a package, not a string")
        violations = read_only_violations(self.operations)
        if violations:
            raise ControlRefused(
                "NOT_READ_ONLY",
                f"{self.key} declares {', '.join(violations)}; this integration reads "
                "controls and never changes them, so the adapter is refused at registration")
        for endpoint in self.endpoints:
            upper = _norm(endpoint).upper()
            if any(f" {verb} " in f" {upper} " for verb in MUTATING_OPERATIONS):
                raise ControlRefused(
                    "NOT_READ_ONLY",
                    f"{self.key} documents a mutating endpoint {endpoint!r}; endpoints are "
                    "declared so they can be audited, and a write cannot be declared")

    def capabilities(self) -> dict[str, Any]:
        """The declared surface, for a reviewer and for the harness."""
        return {
            "key": self.key,
            "control": _norm(self.control).upper(),
            "vendor": self.vendor,
            "product": self.product,
            "read_only": True,
            "read_operations": sorted({_norm(op).upper() for op in self.operations}),
            "write_operations": [],
            "sections": sorted(self.sections.values()),
            "event_kinds": list(self.event_kinds),
            "endpoints": list(self.endpoints),
            "never_collects": sorted({
                "private_keys", "hsm_key_material", "passwords", "api_secrets",
                "session_tokens", "customer_payloads", "http_bodies", "decrypted_traffic",
                "payment_card_data", "credentials", "cookies", "authorization_headers",
            }),
        }


# --------------------------------------------------------------------------- #
# The contract
# --------------------------------------------------------------------------- #

class SecurityControlCollector(ABC):
    """Six verbs. None of them writes, and a subclass may not add a seventh that does."""

    spec: AdapterSpec

    # -- capabilities ------------------------------------------------------- #
    @property
    def control(self) -> str:
        return _norm(self.spec.control).upper()

    @property
    def vendor(self) -> str:
        return self.spec.vendor

    @property
    def read_only(self) -> bool:
        return True

    def capabilities(self) -> dict[str, Any]:
        return self.spec.capabilities()

    # -- the six ------------------------------------------------------------ #
    @abstractmethod
    def discover_assets(self) -> list[dict[str, Any]]:
        """Inventory rows this control owns, each with an evidence id."""

    @abstractmethod
    def collect_configuration(self) -> dict[str, Any]:
        """Sections, scrubbed, each row carrying its evidence id."""

    @abstractmethod
    def collect_crypto_metadata(self) -> list[dict[str, Any]]:
        """TLS versions, cipher suites, certificates — metadata, never key material."""

    @abstractmethod
    def collect_relationships(self) -> list[dict[str, Any]]:
        """Claims ready for :func:`cbom.techbom.build`, one evidence id each."""

    @abstractmethod
    def collect_security_events(self) -> list[dict[str, Any]]:
        """Security events, as metadata; no payload, no body, no decrypted bytes."""

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Whether the device was readable at all, and from where."""


class DeviceCollector(SecurityControlCollector):
    """The one implementation. A vendor supplies a spec and a feed; nothing else.

    Every refusal here is named and kept: an asset whose kind the model does not have, a
    relationship with no legal relation or no evidence, an event of a kind the adapter did
    not declare. A refused row is a finding about the integration, so it is returned in
    ``refusals`` rather than dropped.
    """

    def __init__(self, spec: AdapterSpec, feed: Mapping[str, Any] | None = None) -> None:
        self.spec = spec
        self.feed: Mapping[str, Any] = feed or {}
        self.evidence = EvidenceBook(self.control, spec.vendor,
                                     _norm(self.feed.get("system")) or _norm(self.feed.get("host"))
                                     or spec.key)
        self.refusals: list[dict[str, Any]] = []
        self.redactions: list[dict[str, Any]] = []

    # -- helpers ------------------------------------------------------------ #
    def _refuse(self, code: str, subject: Any, reason: str) -> None:
        self.refusals.append({
            "code": code,
            "subject": subject if isinstance(subject, str) else _norm(subject),
            "control": self.control,
            "vendor": self.spec.vendor,
            "reason": reason,
        })

    def _section_rows(self, canonical: str) -> list[dict[str, Any]]:
        """Rows of a canonical section, under whatever the vendor calls it."""
        sections = self.feed.get("sections") or {}
        if not isinstance(sections, Mapping):
            return []
        wanted = {canonical}
        wanted |= {vendor for vendor, name in self.spec.sections.items() if name == canonical}
        rows: list[dict[str, Any]] = []
        for name in wanted:
            found = sections.get(name)
            if isinstance(found, Mapping):
                found = [found]
            for row in found or []:
                if isinstance(row, Mapping):
                    rows.append({_norm(key): value for key, value in row.items()})
        return rows

    def _field(self, row: Mapping[str, Any], canonical: str, default: Any = None) -> Any:
        """Read a canonical field under the vendor's spelling, in declared order."""
        for alias in self.spec.aliases.get(canonical, ()):  # vendor spellings first
            if alias in row and row[alias] not in (None, ""):
                return row[alias]
        if canonical in row and row[canonical] not in (None, ""):
            return row[canonical]
        return default

    # -- the six ------------------------------------------------------------ #
    def discover_assets(self) -> list[dict[str, Any]]:
        rows = self.feed.get("assets") or []
        assets: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, Mapping):
                self._refuse("MALFORMED_ASSET", "(row)", "an asset row must be a mapping")
                continue
            kind = _norm(raw.get("kind") or self.control).upper()
            name = _norm(raw.get("name"))
            if not name:
                self._refuse("MISSING_NAME", kind, "an asset row with no name is not an asset")
                continue
            if kind not in techbom.ASSET_TYPES:
                self._refuse(
                    "UNKNOWN_KIND", name,
                    f"{kind} is not a technology asset type; the collector declares an "
                    f"{self.control} and the model has no {kind}")
                continue
            clean, redactions = scrub({key: value for key, value in raw.items()
                                       if key not in {"kind", "name"}})
            self.redactions.extend({**item, "asset": name} for item in redactions)
            evidence_id = self.evidence.id_for("ASSET", f"{kind}:{name}", clean)
            assets.append({
                "kind": kind,
                "name": name,
                "vendor": _norm(raw.get("vendor")) or self.spec.vendor,
                "product": _norm(raw.get("product")) or self.spec.product,
                "environment": _norm(raw.get("environment")).upper() or "PRODUCTION",
                "version": _norm(raw.get("version")) or None,
                "location": _norm(raw.get("location")) or None,
                "attributes": {
                    "control_type": self.control,
                    "adapter": self.spec.key,
                    # a canonical field is mapped onto the asset, not repeated inside it:
                    # the estate builder owns kind/name/version/environment and would
                    # otherwise receive two answers to one question
                    **{str(key): value for key, value in clean.items()
                       if key not in _RESERVED_ASSET_FIELDS
                       and value not in (None, "", [], {})},
                },
                "fact": CONFIGURED,
                "evidence_id": evidence_id,
            })
        return assets

    def collect_configuration(self) -> dict[str, Any]:
        sections: dict[str, list[dict[str, Any]]] = {}
        for canonical in sorted(set(self.spec.sections.values()) or {"configuration"}):
            rows = self._section_rows(canonical)
            normalized: list[dict[str, Any]] = []
            for raw in rows:
                clean, redactions = scrub(raw)
                self.redactions.extend({**item, "section": canonical} for item in redactions)
                identity = json.dumps(clean, sort_keys=True, default=str)
                normalized.append({
                    "section": canonical,
                    "control": self.control,
                    "vendor": self.spec.vendor,
                    "fields": clean,
                    "fact": CONFIGURED,
                    "evidence_id": self.evidence.id_for(f"CONFIG:{canonical.upper()}",
                                                        identity, clean),
                })
            if normalized:
                sections[canonical] = normalized
        return {
            "control": self.control,
            "vendor": self.spec.vendor,
            "adapter": self.spec.key,
            "sections": sections,
            "redactions": [item for item in self.redactions
                           if "section" in item or "asset" in item],
            "fact": CONFIGURED,
        }

    def collect_crypto_metadata(self) -> list[dict[str, Any]]:
        rows = self.feed.get("crypto") or []
        crypto: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, Mapping):
                self._refuse("MALFORMED_CRYPTO", "(row)", "a crypto row must be a mapping")
                continue
            asset = _norm(raw.get("asset"))
            if not asset:
                self._refuse("MALFORMED_CRYPTO", "(row)",
                             "crypto metadata without the asset it describes is unattached")
                continue
            clean, redactions = scrub({key: value for key, value in raw.items()
                                       if key != "asset"})
            self.redactions.extend({**item, "asset": asset} for item in redactions)
            certificate = clean.get("certificate") or {}
            if isinstance(certificate, Mapping) and certificate.get("private_key"):
                self._refuse("KEY_MATERIAL_REFUSED", asset,
                             "a certificate record arrived carrying key material; the field is "
                             "redacted and the row is refused rather than trusted")
            facts = {key: value for key, value in clean.items() if value not in (None, "", [], {})}
            crypto.append({
                "asset": asset,
                "control": self.control,
                "vendor": self.spec.vendor,
                "tls_version": clean.get("tls_version"),
                "cipher_suites": list(clean.get("cipher_suites") or []),
                "key_exchange": clean.get("key_exchange"),
                "certificate": clean.get("certificate") or None,
                "sni": clean.get("sni"),
                "alpn": clean.get("alpn"),
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("CRYPTO", asset, facts),
            })
        return crypto

    def collect_relationships(self) -> list[dict[str, Any]]:
        rows = self.feed.get("relationships") or []
        claims: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, Mapping):
                self._refuse("MALFORMED_RELATIONSHIP", "(row)",
                             "a relationship row must be a mapping")
                continue
            source = _norm(raw.get("from"))
            relation = _norm(raw.get("relation")).upper()
            target = _norm(raw.get("to"))
            basis = _norm(raw.get("basis"))
            evidence = [_norm(value) for value in
                        (raw.get("evidence_ids") or raw.get("evidence") or [])
                        if _norm(value)]
            if raw.get("evidence") and not raw.get("evidence_ids"):
                evidence = [_norm(raw.get("evidence"))]
            subject = f"{source} {relation or '(none)'} {target}".strip()
            if not source or not target:
                self._refuse("INCOMPLETE_RELATIONSHIP", subject,
                             "a relationship needs both ends; half an edge is not a fact")
                continue
            if relation not in techbom.RELATIONS:
                self._refuse("UNKNOWN_RELATION", subject,
                             f"{relation or '(none)'} is not a technology relation; a vendor "
                             "does not get to name one")
                continue
            if basis not in techbom.BASES:
                self._refuse("UNKNOWN_BASIS", subject,
                             f"{basis or '(none)'} is not a basis this model classifies")
                continue
            if not evidence:
                self._refuse("RELATIONSHIP_WITHOUT_EVIDENCE", subject,
                             "every relationship carries the evidence id that states it; "
                             "this one would be a drawing")
                continue
            # a feed may nest its facts (``{"port": 443, "rule": "FW-001"}``) or inline
            # them; the edge carries one flat record either way
            nested = raw.get("facts") if isinstance(raw.get("facts"), Mapping) else {}
            facts = {**{str(key): value for key, value in nested.items()
                        if value not in (None, "", [], {})},
                     **{str(key): value for key, value in raw.items()
                        if key not in {"from", "relation", "to", "basis", "evidence",
                                       "evidence_ids", "confidence", "note",
                                       "observed_at", "facts"}
                        and value not in (None, "", [], {})}}
            clean_facts, redactions = scrub(facts)
            self.redactions.extend({**item, "relationship": subject} for item in redactions)
            claims.append({
                "from": source,
                "relation": relation,
                "to": target,
                "basis": basis,
                "confidence": _norm(raw.get("confidence")).upper()
                or techbom.BASES[basis],
                "fact": fact_class(basis),
                "evidence_ids": evidence,
                "control": self.control,
                "vendor": self.spec.vendor,
                "observed_at": _norm(raw.get("observed_at")) or None,
                "note": _norm(raw.get("note")) or None,
                "facts": clean_facts,
            })
        return claims

    def collect_security_events(self) -> list[dict[str, Any]]:
        rows = self.feed.get("events") or []
        declared = {_norm(kind).upper() for kind in self.spec.event_kinds}
        events: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, Mapping):
                self._refuse("MALFORMED_EVENT", "(row)", "an event row must be a mapping")
                continue
            kind = _norm(raw.get("kind") or "ALERT").upper()
            if kind not in declared:
                self._refuse(
                    "UNDECLARED_EVENT_KIND", kind,
                    f"{self.spec.key} declares {', '.join(sorted(declared))}; an event kind "
                    "appearing at runtime is a finding, not a row to normalize")
                continue
            # metadata only: every payload-shaped field is dropped before it is looked at
            metadata = {key: value for key, value in raw.items()
                        if key not in {"payload", "body", "request_body", "response_body",
                                       "raw", "packet", "bytes"}}
            clean, redactions = scrub(metadata)
            self.redactions.extend({**item, "event": kind} for item in redactions)
            identity = json.dumps({key: clean.get(key) for key in
                                   ("signature", "src", "dst", "timestamp", "action")},
                                  sort_keys=True, default=str)
            events.append({
                "kind": kind,
                "control": self.control,
                "vendor": self.spec.vendor,
                "signature": _norm(clean.get("signature")) or None,
                "signature_revision": _norm(clean.get("signature_revision")) or None,
                "action": _norm(clean.get("action")).upper() or None,
                "src": _norm(clean.get("src")) or None,
                "dst": _norm(clean.get("dst")) or None,
                "protocol": _norm(clean.get("protocol")) or None,
                "port": clean.get("port"),
                "tls_version": clean.get("tls_version"),
                "cipher_suite": clean.get("cipher_suite"),
                "sni": clean.get("sni"),
                "timestamp": _norm(clean.get("timestamp")) or None,
                "fact": OBSERVED,
                "evidence_id": self.evidence.id_for(f"EVENT:{kind}", identity, clean),
                "metadata": clean,
            })
        return events

    def health(self) -> dict[str, Any]:
        raw = dict(self.feed.get("health") or {})
        reachable = bool(raw.get("reachable", True))
        reported_read_only = raw.get("read_only", True)
        if not reported_read_only:
            self._refuse("DEVICE_OFFERS_WRITES", self.spec.key,
                         "the endpoint exposes write operations; the adapter stays on the "
                         "read-only subset and says so rather than trusting the session")
        state = "OK" if reachable else "UNREACHABLE"
        # a feed can state a stronger failure than "unreachable": a partial read, a refused
        # credential, a rate limit. It is carried through rather than flattened.
        declared = _norm(raw.get("state") or raw.get("read_state")).upper()
        from .taxonomy import STATES as _STATES, describe as _describe

        if declared in _STATES:
            state = declared
        return {
            "control": self.control,
            "vendor": self.spec.vendor,
            "adapter": self.spec.key,
            "system": self.evidence.system,
            "reachable": reachable,
            "status": "REACHABLE" if reachable else "UNREACHABLE",
            "state": state,
            "taxonomy": _describe(state),
            # the read block a live driver produced: which sections answered, how much of the
            # device was covered, what was skipped as unchanged and what was truncated. Carried
            # through ``health()`` so every surface reports the same coverage — a projection
            # summary and a console must not disagree about how much of a device was read.
            "read": {key: raw[key] for key in _READ_KEYS if key in raw},
            "read_only": True,
            "device_offers_writes": not bool(reported_read_only),
            "operations": sorted({_norm(op).upper() for op in self.spec.operations}),
            "collected_at": _norm(raw.get("collected_at")) or None,
            "detail": _norm(raw.get("detail")) or None,
        }

    # -- one snapshot, with the cross-cutting checks ------------------------- #
    def snapshot(self) -> dict[str, Any]:
        """Everything the collector saw, plus the refusals and the redaction record."""
        assets = self.discover_assets()
        configuration = self.collect_configuration()
        crypto = self.collect_crypto_metadata()
        relationships = self.collect_relationships()
        events = self.collect_security_events()
        health = self.health()
        fact_counts: dict[str, int] = {}
        for row in (*assets, *crypto, *relationships, *events):
            fact_counts[row["fact"]] = fact_counts.get(row["fact"], 0) + 1
        declared = {row["name"] for row in assets}
        for claim in relationships:
            for end in (claim["from"], claim["to"]):
                if end not in declared:
                    self._refuse(
                        "EDGE_TO_UNDECLARED_ASSET", claim["from"] + " " + claim["relation"]
                        + " " + claim["to"],
                        f"{end} is named by a relationship and is not an asset this feed "
                        "declares; the projection resolves it or refuses it, and this "
                        "collector does not invent it")
        return {
            "adapter": self.spec.key,
            "capabilities": self.capabilities(),
            "assets": assets,
            "configuration": configuration,
            "crypto": crypto,
            "relationships": relationships,
            "events": events,
            "health": health,
            "evidence": self.evidence.as_list(),
            "refusals": list(self.refusals),
            "redactions": list(self.redactions),
            "fact_counts": fact_counts,
        }


def fact_class(basis: Any) -> str:
    """The evidence class a basis supports — the strongest one, as the model defines it."""
    basis_text = _norm(basis).lower()
    if basis_text not in techbom.BASES:
        raise ControlRefused("UNKNOWN_BASIS",
                             f"{basis_text or '(none)'} is not a basis this model classifies")
    return techbom.BASES[basis_text]


def separate_facts(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Group records by fact class without ever merging two classes into one verdict.

    Returns ``{"CONFIGURED": [...], "OBSERVED": [...], "RUNTIME_OBSERVED": [...],
    "separated": bool, "conflict": {...} | None}``. ``separated`` is False when a record
    claims more than one class for a single value, which is the failure the model forbids.
    """
    buckets: dict[str, list[dict[str, Any]]] = {name: [] for name in FACT_CLASSES}
    conflict: dict[str, Any] | None = None
    for record in records or ():
        fact = _norm(record.get("fact")).upper()
        if fact in FACT_CLASSES:
            buckets[fact].append(dict(record))
            continue
        if fact in techbom.CONFIDENCE:  # a fourth class is legal elsewhere, not here
            buckets.setdefault(fact, []).append(dict(record))
            continue
        conflict = {"record": dict(record)}
    return {**buckets, "separated": conflict is None, "conflict": conflict}
