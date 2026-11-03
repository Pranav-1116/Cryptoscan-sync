"""The VBOM dependency graph: vendor → product → release → firmware/SDK → asset → chain.

A vendor inventory says *who supplies what*. A vendor **dependency** says which of the bank's
own assets, applications, crypto operations and business systems stop working when one
vendor's product, release or firmware changes — and it says how strongly each of those links
is believed.

Ten levels, kept apart because they have separate lifecycles and separate evidence:

    VENDOR → PRODUCT → RELEASE → FIRMWARE / PACKAGE → ASSET
           → APPLICATION → CRYPTO → RUNTIME → BUSINESS SYSTEM

Three rules run through the whole module.

**A claim is about a release, not a company.** ``RSA supported`` printed in a datasheet for
payShield 8.4 is a statement about 8.4. It does not transfer to 9.2, and the model refuses to
let it: every declaration is attached to a ``PRODUCT_VERSION``, and
:func:`applicability` compares that release with the release the asset actually runs.

**Vendor-declared is not used.** A vendor saying an HSM supports ML-KEM is a
``VENDOR_DECLARED`` capability. That is never promoted into ``USED``; :func:`declared_vs_observed`
prints the declaration, the observation and the gap between them, and
:func:`pqc_posture` answers ``DECLARED`` / ``UNKNOWN`` / ``NOT_OBSERVED`` rather than
``PQC READY = TRUE``.

**Applicability is decided, not assumed.** :func:`applicability` asks its questions in a
fixed order — product, version, supersession, expiry, deployment verification, prefix — and
the *first question that fails* decides the state. ``MATCHED`` is the last state reached and
the hardest to reach: it needs the product, the release and the firmware to line up **and** a
deployment somebody actually verified.

The document is a projection of the shared estate graph, like the other BOMs: :func:`build`
takes a vendor payload, :func:`from_documents` produces a canonical estate and
:func:`techbom.build` assigns the ids, so a VBOM here and an HBOM/NBOM/SBOM over the same
estate name the same nodes.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime, timezone
from typing import Any

from . import nbom_graph as n
from . import techbom as tb

SCHEMA = "cryptoscan.vbom-dependency/1"
INPUT_SCHEMA = "cryptoscan.vbom-input/1"

# --------------------------------------------------------------------------- #
# The ten levels
# --------------------------------------------------------------------------- #

#: the kinds that count as a *deployed thing* a vendor supplied. Kept broad on purpose: the
#: same vendor sells an HSM, a load balancer and a PKI appliance, and the applicability
#: question is identical for all three.
ASSET_KINDS: tuple[str, ...] = (
    "HSM", "KMS", "TPM", "HOST", "VM", "PHYSICAL_SERVER", "SECURITY_APPLIANCE",
    "CRYPTO_ACCELERATOR", "LOAD_BALANCER", "WAF", "API_GATEWAY", "SERVICE_MESH",
    "VPN_GATEWAY", "FIREWALL", "IDS", "IPS", "DATABASE", "CERTIFICATE_AUTHORITY",
    "CERTIFICATE", "SMART_CARD", "KUBERNETES_NODE", "CLOUD_INSTANCE",
)

#: ordered low → high. A row that skips a level is reported as a gap rather than quietly
#: joined to the next level up.
LEVELS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("vendor", ("VENDOR",), "who supplies"),
    ("product", ("VENDOR_PRODUCT",), "what they sell"),
    ("release", ("PRODUCT_VERSION",), "the version a claim applies to"),
    ("firmware", ("FIRMWARE",), "what the device actually runs"),
    ("package", ("PACKAGE", "CRYPTO_LIBRARY"), "what the SDK ships"),
    ("asset", ASSET_KINDS, "the thing in the estate"),
    ("application", ("APPLICATION", "SERVICE"), "what depends on it"),
    ("crypto", ("CRYPTO_CAPABILITY", "CRYPTO_ASSET"), "what it can or does do"),
    ("runtime", ("PROCESS", "CRYPTO_OPERATION"), "what was watched happening"),
    ("system", ("BUSINESS_SYSTEM",), "what the bank loses"),
)

LEVEL_KINDS: dict[str, tuple[str, ...]] = {name: kinds for name, kinds, _ in LEVELS}
LEVEL_ORDER: tuple[str, ...] = tuple(name for name, _, _ in LEVELS)
KIND_LEVEL: dict[str, str] = {kind: name for name, kinds, _ in LEVELS for kind in kinds}

# --------------------------------------------------------------------------- #
# Applicability — eight states, one precedence
# --------------------------------------------------------------------------- #

MATCHED = "MATCHED"
PARTIAL_MATCH = "PARTIAL_MATCH"
VERSION_MISMATCH = "VERSION_MISMATCH"
PRODUCT_MISMATCH = "PRODUCT_MISMATCH"
DEPLOYMENT_UNVERIFIED = "DEPLOYMENT_UNVERIFIED"
EXPIRED = "EXPIRED"
SUPERSEDED = "SUPERSEDED"
UNKNOWN_APPLICABILITY = "UNKNOWN"

APPLICABILITY: tuple[str, ...] = (MATCHED, PARTIAL_MATCH, VERSION_MISMATCH, PRODUCT_MISMATCH,
                                  DEPLOYMENT_UNVERIFIED, EXPIRED, SUPERSEDED,
                                  UNKNOWN_APPLICABILITY)

APPLICABILITY_MEANS: dict[str, str] = {
    MATCHED: "the claim's product, release and firmware are the ones deployed, and somebody "
             "verified the deployment",
    PARTIAL_MATCH: "the claim's release is a prefix of what is deployed (8.4 covers 8.4.2): "
                   "plausible, and not the same statement",
    VERSION_MISMATCH: "the claim is about a different release from the one deployed",
    PRODUCT_MISMATCH: "the claim is about a different product from the one deployed",
    DEPLOYMENT_UNVERIFIED: "the versions line up and nobody has verified that this asset is "
                           "what the estate says it is",
    EXPIRED: "the evidence the claim rests on is past its validity date",
    SUPERSEDED: "a later revision of the same document replaced this claim",
    UNKNOWN_APPLICABILITY: "there is nothing to compare: the claim or the deployment names "
                           "no version",
}

#: the order the questions are asked. The first one that fails decides the state; ``MATCHED``
#: is reached only by failing none of them.
PRECEDENCE: tuple[str, ...] = (PRODUCT_MISMATCH, VERSION_MISMATCH, SUPERSEDED, EXPIRED,
                               DEPLOYMENT_UNVERIFIED, PARTIAL_MATCH, MATCHED)

SAME = "SAME"
PREFIX = "PREFIX"
DIFFERENT = "DIFFERENT"
NOT_COMPARABLE = "NOT_COMPARABLE"

# --------------------------------------------------------------------------- #
# Lifecycle and evidence freshness
# --------------------------------------------------------------------------- #

ACTIVE = "ACTIVE"
SUPPORTED = "SUPPORTED"
MAINTENANCE = "MAINTENANCE"
EOL = "EOL"
EOS = "EOS"
RETIRED = "RETIRED"
UNKNOWN_LIFECYCLE = "UNKNOWN"

LIFECYCLE_STATES: tuple[str, ...] = (ACTIVE, SUPPORTED, MAINTENANCE, EOL, EOS, RETIRED,
                                     UNKNOWN_LIFECYCLE)
LIFECYCLE_RANK: dict[str, int] = {state: rank for rank, state in enumerate(LIFECYCLE_STATES)}
#: from here down, a product is a supply-chain risk rather than a support question
LIFECYCLE_TERMINAL: frozenset[str] = frozenset({EOL, EOS, RETIRED})

FRESH = "FRESH"
VENDOR_EVIDENCE_STALE = "VENDOR_EVIDENCE_STALE"
EVIDENCE_EXPIRED = "EXPIRED"
EVIDENCE_UNKNOWN = "UNKNOWN"

EVIDENCE_STATES: tuple[str, ...] = (FRESH, VENDOR_EVIDENCE_STALE, EVIDENCE_EXPIRED,
                                    EVIDENCE_UNKNOWN)

#: a questionnaire older than this is stale even when nobody set a validity date: the
#: vendor's answer is about a product that has had a year of releases since.
STALE_AFTER_DAYS = 365

#: the layers a version can be read from. A conflict between two of them is a finding, not a
#: tie to break (guide 178, point 24).
VERSION_SOURCES: tuple[str, ...] = ("VENDOR_DECLARED", "SBOM_OBSERVED", "CONTAINER_OBSERVED",
                                    "RUNTIME_OBSERVED", "FIRMWARE_OBSERVED")

#: what a vendor relationship change can be about (guide 178, point 25)
HISTORY_FIELDS: tuple[str, ...] = ("vendor", "product", "version", "firmware", "sdk",
                                   "support_status", "relationship")

INTERNAL_VENDOR = "INTERNAL"
UNKNOWN_VENDOR = "UNKNOWN"

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

_VERSION_SPLIT = re.compile(r"[.\-_+]")


def _norm(value: Any) -> str:
    return tb._norm(value)


def _key(kind: str, name: Any, environment: str = "PRODUCTION") -> str:
    return tb._key(kind, _norm(name), environment)


def _parse(value: Any) -> date | None:
    text = _norm(value)
    if not text:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None


def _today(as_of: Any = None) -> date:
    parsed = _parse(as_of)
    return parsed or datetime.now(timezone.utc).date()


def compare_versions(declared: Any, actual: Any) -> dict[str, Any]:
    """Two version strings, one comparison, and no cleverness about ordering.

    The only relation that is safe without a version algebra is *prefix*: ``8.4`` covers
    ``8.4.2`` and ``8.4.2`` is an instance of ``8.4``. Everything else is ``DIFFERENT`` —
    including ``8.4`` against ``8.40``, because a string comparison that pretends to know
    the vendor's numbering scheme is how a mismatch gets reported as a match.
    """
    left = _norm(declared).lower()
    right = _norm(actual).lower()
    if not left or not right:
        return {"result": NOT_COMPARABLE, "declared": left or None, "actual": right or None,
                "statement": "nothing to compare: "
                             + ("the claim names no version" if not left
                                else "the deployment names no version")}
    if left == right:
        return {"result": SAME, "declared": left, "actual": right,
                "statement": f"{left} is {right}"}
    left_tokens = [token for token in _VERSION_SPLIT.split(left) if token]
    right_tokens = [token for token in _VERSION_SPLIT.split(right) if token]
    shorter, longer = sorted((left_tokens, right_tokens), key=len)
    if shorter and longer[:len(shorter)] == shorter and len(longer) > len(shorter):
        return {"result": PREFIX, "declared": left, "actual": right,
                "statement": f"{left} and {right} agree on {'.'.join(shorter)}, and "
                             f"{'.'.join(longer)} says more"}
    return {"result": DIFFERENT, "declared": left, "actual": right,
            "statement": f"{left} is not {right}"}


def applicability(declaration: Mapping[str, Any], deployment: Mapping[str, Any], *,
                  as_of: Any = None) -> dict[str, Any]:
    """One vendor claim, one deployed thing, one answer.

    ``declaration`` names a product, a release, optionally a firmware and the document's
    validity; ``deployment`` names the same three as they were read from the estate plus
    whether anything verified the asset. The questions are asked in :data:`PRECEDENCE`
    order and the first failure decides — so an expired document about the wrong release is
    reported as ``VERSION_MISMATCH``, because that is the more useful sentence.
    """
    today = _today(as_of)
    declared_product = _norm(declaration.get("product"))
    actual_product = _norm(deployment.get("product"))
    version = compare_versions(declaration.get("version"), deployment.get("version"))
    firmware = compare_versions(declaration.get("firmware"), deployment.get("firmware"))
    checks: dict[str, str] = {}

    if declared_product and actual_product:
        if declared_product.lower() == actual_product.lower():
            checks["product"] = "PASS"
        else:
            checks["product"] = (f"the claim is about {declared_product}, the deployment is "
                                 f"{actual_product}")
    else:
        checks["product"] = "NOT_COMPARABLE"

    if version["result"] == SAME:
        checks["version"] = "PASS"
    elif version["result"] == NOT_COMPARABLE:
        checks["version"] = "NOT_COMPARABLE"
    else:
        checks["version"] = version["statement"]

    checks["firmware"] = ("PASS" if firmware["result"] == SAME
                          else firmware["statement"] if firmware["result"] != NOT_COMPARABLE
                          else "NOT_APPLICABLE")

    valid_until = _parse(declaration.get("valid_until"))
    if valid_until is None:
        checks["evidence"] = "NO_VALIDITY_DATE"
    elif today > valid_until:
        checks["evidence"] = (f"the document expired on {valid_until.isoformat()}; today is "
                              f"{today.isoformat()}")
    else:
        checks["evidence"] = "PASS"

    if declaration.get("superseded_by"):
        checks["supersession"] = (f"revision {declaration.get('superseded_by')} replaced "
                                  "this claim")
    else:
        checks["supersession"] = "PASS"

    if deployment.get("verified"):
        checks["deployment"] = "PASS"
    else:
        checks["deployment"] = ("nobody verified this asset: the claim lines up with a name "
                                "in the estate, not with a serial somebody read")

    observed = {str(item).lower() for item in deployment.get("observed_capabilities") or []}
    capability = _norm(declaration.get("capability"))
    if not capability:
        checks["capability"] = "NOT_CLAIMED"
    elif observed and capability.lower() in observed:
        checks["capability"] = "OBSERVED"
    else:
        checks["capability"] = "DECLARED_ONLY"

    if checks["product"] not in ("PASS", "NOT_COMPARABLE"):
        state, reason = PRODUCT_MISMATCH, checks["product"]
    elif version["result"] == DIFFERENT or (
            firmware["result"] == DIFFERENT and declaration.get("firmware")):
        state = VERSION_MISMATCH
        reason = (checks["version"] if version["result"] == DIFFERENT
                  else checks["firmware"])
    elif checks["supersession"] != "PASS":
        state, reason = SUPERSEDED, checks["supersession"]
    elif checks["evidence"].startswith("the document expired"):
        state, reason = EXPIRED, checks["evidence"]
    elif checks["deployment"] != "PASS":
        state, reason = DEPLOYMENT_UNVERIFIED, checks["deployment"]
    elif version["result"] == PREFIX or firmware["result"] == PREFIX:
        state = PARTIAL_MATCH
        reason = (version["statement"] if version["result"] == PREFIX
                  else firmware["statement"])
    elif version["result"] == NOT_COMPARABLE:
        state, reason = UNKNOWN_APPLICABILITY, version["statement"]
    else:
        state, reason = MATCHED, (f"{declared_product} {version['actual']} is what this "
                                  "deployment runs, and the deployment was verified")

    return {
        "state": state, "means": APPLICABILITY_MEANS[state], "reason": reason,
        "checks": checks,
        "declaration": {"product": declared_product or None,
                        "version": _norm(declaration.get("version")) or None,
                        "firmware": _norm(declaration.get("firmware")) or None,
                        "document": _norm(declaration.get("document")) or None,
                        "capability": capability or None},
        "deployment": {"asset": _norm(deployment.get("asset")) or None,
                       "product": actual_product or None,
                       "version": _norm(deployment.get("version")) or None,
                       "firmware": _norm(deployment.get("firmware")) or None,
                       "verified": bool(deployment.get("verified"))},
        "statement": f"{_norm(deployment.get('asset')) or 'deployment'}: {state} — {reason}",
        "rule": ("a vendor's claim applies to a release, and it applies to a deployment only "
                 "when somebody verified the deployment: the first failing question decides"),
        "not_proven": ["that the asset is running the release its record says: that is what "
                       "the deployment check is for, and it is not a version string"],
    }


def lifecycle_of(row: Mapping[str, Any], *, as_of: Any = None) -> dict[str, Any]:
    """The support state of a product, release or firmware, derived and dated.

    An explicit ``lifecycle`` wins, because the vendor's own bulletin is better evidence
    than a date arithmetic. Without one the dates decide: past ``eol_date`` the row is
    ``EOL``, past ``eos_date`` it is ``EOS``, and with neither it is ``UNKNOWN`` — not
    ``SUPPORTED``, because nobody said so.
    """
    today = _today(as_of)
    explicit = _norm(row.get("lifecycle") or row.get("support_status")).upper()
    if explicit in LIFECYCLE_STATES and explicit != UNKNOWN_LIFECYCLE:
        state, reason = explicit, f"the vendor states {explicit}"
    else:
        eol = _parse(row.get("eol_date"))
        eos = _parse(row.get("eos_date"))
        if eos and today > eos:
            state, reason = EOS, f"end of service {eos.isoformat()} has passed"
        elif eol and today > eol:
            state, reason = EOL, f"end of life {eol.isoformat()} has passed"
        elif eol or eos:
            state = SUPPORTED
            reason = (f"supported until {eol.isoformat()}" if eol
                      else f"supported until {eos.isoformat()}")
        else:
            state, reason = UNKNOWN_LIFECYCLE, "no support state and no dates to derive one"
    return {"state": state, "rank": LIFECYCLE_RANK[state], "reason": reason,
            "terminal": state in LIFECYCLE_TERMINAL,
            "eol_date": _norm(row.get("eol_date")) or None,
            "eos_date": _norm(row.get("eos_date")) or None,
            "statement": f"{_norm(row.get('name')) or 'row'}: {state} — {reason}"}


def evidence_freshness(document: Mapping[str, Any], *, as_of: Any = None,
                       stale_after_days: int = STALE_AFTER_DAYS) -> dict[str, Any]:
    """How old a vendor's answer is, and whether it may still be quoted.

    Three ways to be untrustworthy: past an explicit ``valid_until`` (``EXPIRED``), older
    than the review cadence (``VENDOR_EVIDENCE_STALE``), or undated (``UNKNOWN``). None of
    them deletes the claim — they are printed beside it.
    """
    today = _today(as_of)
    received = _parse(document.get("received_at") or document.get("collected_at"))
    valid_until = _parse(document.get("valid_until"))
    age_days = (today - received).days if received else None
    states: list[dict[str, Any]] = []
    if valid_until is not None and today > valid_until:
        states.append({"state": EVIDENCE_EXPIRED,
                       "reason": f"the document expired on {valid_until.isoformat()}"})
    if age_days is None:
        states.append({"state": EVIDENCE_UNKNOWN,
                       "reason": "the document carries no received_at, so its age is unknown"})
    elif age_days > stale_after_days:
        states.append({"state": VENDOR_EVIDENCE_STALE,
                       "reason": f"received {age_days} days ago, past the {stale_after_days}"
                                 "-day review cadence"})
    state = states[0]["state"] if states else FRESH
    return {
        "document": _norm(document.get("id")) or _norm(document.get("title")) or None,
        "state": state,
        "reasons": states,
        "age_days": age_days,
        "published_at": _norm(document.get("published_at")) or None,
        "received_at": _norm(document.get("received_at")) or None,
        "valid_from": _norm(document.get("valid_from")) or None,
        "valid_until": _norm(document.get("valid_until")) or None,
        "last_reviewed": _norm(document.get("last_reviewed")) or None,
        "reviewer": _norm(document.get("reviewer")) or None,
        "revision": document.get("revision"),
        "source_hash": _norm(document.get("source_hash")) or None,
        "statement": (f"{_norm(document.get('id')) or 'document'}: {state} — "
                      + (states[0]["reason"] if states else
                         f"reviewed {age_days} day(s) ago with a valid date"
                         if age_days is not None else "no age recorded")),
        "rule": ("vendor evidence ages: an expired questionnaire is a claim about a product "
                 "the vendor has released past, and it is labelled rather than trusted"),
    }


# --------------------------------------------------------------------------- #
# The builder — payload → canonical estate
# --------------------------------------------------------------------------- #

#: what a declared asset type maps to. A vendor payload says "HSM"; the estate says which
#: kind of node that is.
ASSET_TYPE_KINDS: dict[str, str] = {
    "HSM": "HSM", "KMS": "KMS", "TPM": "TPM", "HOST": "HOST", "VM": "VM",
    "PHYSICAL_SERVER": "PHYSICAL_SERVER", "SERVER": "PHYSICAL_SERVER",
    "SECURITY_APPLIANCE": "SECURITY_APPLIANCE", "APPLIANCE": "SECURITY_APPLIANCE",
    "CRYPTO_ACCELERATOR": "CRYPTO_ACCELERATOR", "LOAD_BALANCER": "LOAD_BALANCER",
    "LOADBALANCER": "LOAD_BALANCER", "WAF": "WAF", "API_GATEWAY": "API_GATEWAY",
    "SERVICE_MESH": "SERVICE_MESH", "VPN_GATEWAY": "VPN_GATEWAY", "VPN": "VPN_GATEWAY",
    "FIREWALL": "FIREWALL", "IDS": "IDS", "IPS": "IPS", "DATABASE": "DATABASE",
    "CA": "CERTIFICATE_AUTHORITY", "CERTIFICATE_AUTHORITY": "CERTIFICATE_AUTHORITY",
    "PKI": "CERTIFICATE_AUTHORITY", "CERTIFICATE": "CERTIFICATE",
    "SMART_CARD": "SMART_CARD", "KUBERNETES_NODE": "KUBERNETES_NODE",
    "CLOUD_INSTANCE": "CLOUD_INSTANCE",
}


def _capability_label(algorithm: Any, key_size: Any = None, mode: Any = None,
                      curve: Any = None) -> str:
    """``RSA-2048``, ``AES-256-GCM``, ``ECDSA-P256``: one capability, one readable name."""
    name = _norm(algorithm)
    if not name:
        return ""
    size = _norm(key_size)
    curve_text = _norm(curve)
    mode_text = _norm(mode).upper()
    if curve_text:
        return f"{name.upper()}-{curve_text.upper()}"
    if size:
        return f"{name.upper()}-{size}" + (f"-{mode_text}" if mode_text else "")
    return name.upper() + (f"-{mode_text}" if mode_text else "")


def _version_label(product: Any, version: Any) -> str:
    return f"{_norm(product)}@{_norm(version)}"


def _firmware_label(product: Any, version: Any) -> str:
    return f"{_norm(product)} firmware {_norm(version)}"


#: the fields :func:`techbom.asset` owns. An attribute may not shadow one of these.
_ASSET_FIELDS: frozenset[str] = frozenset({
    "kind", "name", "key", "environment", "version", "owner", "location", "status",
    "first_seen", "last_seen", "source", "evidence_ids", "attributes", "id", "digest",
})


class _Builder:
    """Payload → assets, claims and refusals. Nothing here knows how to draw a graph."""

    def __init__(self, environment: str = "PRODUCTION") -> None:
        self.environment = environment
        self.assets: list[dict[str, Any]] = []
        self.claims: list[dict[str, Any]] = []
        self.refused: list[dict[str, Any]] = []
        self.seen: set[str] = set()
        self.index: dict[str, dict[str, Any]] = {}
        self.documents: dict[str, dict[str, Any]] = {}
        self.declared: list[dict[str, Any]] = []

    # -- recording --------------------------------------------------------- #

    def add(self, kind: str, name: Any, *, evidence: Iterable[Any] = (),
            **attributes: Any) -> dict[str, Any] | None:
        label = _norm(name)
        if not label:
            self.refuse("NO_NAME", kind, "a row with no name cannot be a node")
            return None
        key = _key(kind, label, self.environment)
        if key in self.index:
            # the same node described twice — a release ships a package and an SBOM lists
            # it. The second description enriches the first; both facts are kept.
            row = self.index[key]
            for name, value in attributes.items():
                if value in (None, "", [], {}):
                    continue
                if name in _ASSET_FIELDS:
                    # a first-class field stays first-class: an attribute called ``version``
                    # would be a second version on the same node
                    row[name] = row.get(name) or value
                    continue
                row["attributes"].setdefault(name, value)
            for value in evidence:
                if _norm(value) and _norm(value) not in row["evidence_ids"]:
                    row["evidence_ids"].append(_norm(value))
            return row
        self.seen.add(key)
        try:
            row = tb.asset(kind, label, environment=self.environment,
                           evidence_ids=[value for value in evidence if _norm(value)],
                           **attributes)
        except tb.ClaimRefused as exc:
            self.refuse(exc.code, label, exc.reason)
            return None
        self.assets.append(row)
        self.index[key] = row
        return row

    def link(self, source: Any, relation: str, target: Any, *, basis: Any,
             evidence: Iterable[Any] = (), confidence: Any = None,
             **facts: Any) -> dict[str, Any] | None:
        if source is None or target is None:
            return None
        cited = [value for value in evidence if _norm(value)]
        if not cited:
            # an edge is evidenced by what its ends are evidenced by. A product with no
            # datasheet is still a product somebody registered, and the edge says so.
            for end in (source, target):
                if isinstance(end, Mapping):
                    cited.extend(end.get("evidence_ids") or [])
        try:
            row = tb.claim(_norm(source.get("name") if isinstance(source, Mapping) else source),
                           relation,
                           _norm(target.get("name") if isinstance(target, Mapping) else target),
                           basis=basis, confidence=confidence,
                           evidence_ids=cited,
                           **facts)
        except tb.ClaimRefused as exc:
            self.refuse(exc.code, f"{source} {relation} {target}", exc.reason)
            return None
        self.claims.append(row)
        return row

    def refuse(self, code: str, subject: Any, reason: str) -> None:
        self.refused.append({"code": code, "subject": _norm(subject) or None,
                             "reason": reason})

    # -- sections ---------------------------------------------------------- #

    def documents_section(self, rows: Sequence[Mapping[str, Any]]) -> None:
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            identifier = _norm(row.get("id"))
            if not identifier:
                self.refuse("DOCUMENT_WITHOUT_ID", row.get("title"),
                            "a vendor document with no id cannot be cited by the claims it "
                            "supports")
                continue
            self.documents[identifier] = dict(row)
            # a document is its own evidence: the citation is the thing you can go and read
            self.add("EVIDENCE", identifier, evidence=[identifier],
                     title=row.get("title"), vendor=row.get("vendor"),
                     product=row.get("product"), version=row.get("version"),
                     firmware=row.get("firmware"),
                     published_at=row.get("published_at"),
                     received_at=row.get("received_at"),
                     valid_from=row.get("valid_from"),
                     valid_until=row.get("valid_until"),
                     last_reviewed=row.get("last_reviewed"),
                     reviewer=row.get("reviewer"), revision=row.get("revision"),
                     source_hash=row.get("source_hash"),
                     evidence_type=tb.VENDOR_DECLARED)

    def vendor_key(self, name: Any) -> str | None:
        text = _norm(name)
        return _key("VENDOR", text, self.environment) if text else None

    def product_key(self, name: Any) -> str | None:
        text = _norm(name)
        return _key("VENDOR_PRODUCT", text, self.environment) if text else None

    def release_key(self, product: Any, version: Any) -> str | None:
        if not _norm(product) or not _norm(version):
            return None
        return _key("PRODUCT_VERSION", _version_label(product, version), self.environment)

    def firmware_key(self, product: Any, version: Any) -> str | None:
        if not _norm(product) or not _norm(version):
            return None
        return _key("FIRMWARE", _firmware_label(product, version), self.environment)

    def asset_key(self, kind: str, name: Any) -> str | None:
        text = _norm(name)
        return _key(kind, text, self.environment) if text else None


def _ensure_endpoint(build: "_Builder", name: str, evidence: Iterable[Any]) -> None:
    """A listener named by a device is a node: an endpoint nothing declares cannot be
    routed to, and a route to an undeclared node is refused by the estate."""
    host, _, port = name.rpartition(":")
    if not host or not port.isdigit():
        build.refuse("ENDPOINT_WITHOUT_PORT", name,
                     "an endpoint is host:port; a name with no port is a hostname, and a "
                     "hostname can be many services")
        return
    build.add("NETWORK_ENDPOINT", name, evidence=list(evidence) or [f"endpoint:{name}"],
              host=host, port=int(port), transport="TLS")


def _evidence_id(row: Mapping[str, Any]) -> list[str]:
    """The documents a row cites, in either of the three shapes a payload may use."""
    values: list[Any] = [row.get("document"), row.get("evidence_id"),
                         row.get("source_document")]
    documents = row.get("documents")
    if isinstance(documents, str):
        values.append(documents)
    elif isinstance(documents, (list, tuple)):
        values.extend(documents)
    return [_norm(value) for value in values if _norm(value)]


def from_documents(payload: Mapping[str, Any], *, environment: str = "PRODUCTION",
                   estate_id: str = "vbom") -> dict[str, Any]:
    """A vendor payload → one canonical estate document.

    Every declaration must cite a document. That is the whole point of the exercise: a
    capability with no page behind it is a rumour, and it is refused by name
    (``VENDOR_CLAIM_WITHOUT_DOCUMENT``) rather than imported.
    """
    body = payload if isinstance(payload, Mapping) else {}
    build = _Builder(environment)
    build.documents_section(body.get("documents") or [])

    # ---- vendors --------------------------------------------------------- #
    for row in body.get("vendors") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        evidence = _evidence_id(row)
        vendor = build.add("VENDOR", name, evidence=evidence or [f"vendor:{name}"],
                           lifecycle=_norm(row.get("lifecycle")).upper() or None,
                           risk_level=_norm(row.get("risk_level")).upper() or None,
                           vendor_type=row.get("vendor_type"),
                           contract_end_date=row.get("contract_end_date"))
        for document in evidence:
            if document in build.documents:
                build.link(vendor, "DOCUMENTED_BY", document, basis="vendor-datasheet",
                           evidence=[document])

    # ---- products -------------------------------------------------------- #
    for row in body.get("products") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        vendor_name = _norm(row.get("vendor"))
        evidence = _evidence_id(row)
        if not vendor_name:
            build.refuse("PRODUCT_WITHOUT_VENDOR", name,
                         "a product with no vendor cannot be attributed, and an unattributed "
                         "product is a supply-chain blind spot wearing a product name")
            continue
        product = build.add("VENDOR_PRODUCT", name,
                            evidence=evidence or [f"product:{name}"],
                            product_family=row.get("family"), product_type=row.get("type"),
                            lifecycle=_norm(row.get("lifecycle")).upper() or None,
                            eol_date=row.get("eol_date"), eos_date=row.get("eos_date"),
                            criticality=row.get("criticality"))
        build.link(product, "SUPPLIED_BY", vendor_name, basis="vendor-datasheet",
                   evidence=evidence, first_seen=row.get("first_seen"))
        for document in evidence:
            if document in build.documents:
                build.link(product, "DOCUMENTED_BY", document, basis="vendor-datasheet",
                           evidence=[document])

    # ---- releases, their capabilities and their packages ------------------ #
    for row in body.get("releases") or []:
        if not isinstance(row, Mapping):
            continue
        product_name = _norm(row.get("product"))
        version = _norm(row.get("version"))
        evidence = _evidence_id(row)
        if not product_name or not version:
            build.refuse("RELEASE_WITHOUT_VERSION", f"{product_name or '(none)'}",
                         "a release with no version is not a release: applicability is a "
                         "version comparison, and this row has nothing to compare")
            continue
        release = build.add("PRODUCT_VERSION", _version_label(product_name, version),
                            evidence=evidence or [f"release:{_version_label(product_name, version)}"],
                            version=version,
                            release_date=row.get("release_date"),
                            support_status=_norm(row.get("support_status")).upper() or None,
                            eol_date=row.get("eol_date"), eos_date=row.get("eos_date"),
                            pqc_capability=row.get("pqc_capability"),
                            security_status=row.get("security_status"))
        build.link(product_name, "RELEASES", release, basis="vendor-datasheet",
                   evidence=evidence, announced_at=row.get("release_date"))
        for document in evidence:
            if document in build.documents:
                build.link(release, "DOCUMENTED_BY", document, basis="vendor-datasheet",
                           evidence=[document])

        for capability in row.get("capabilities") or []:
            if not isinstance(capability, Mapping):
                continue
            algorithm = _norm(capability.get("algorithm"))
            label = _capability_label(algorithm, capability.get("key_size"),
                                      capability.get("mode"), capability.get("curve"))
            declared_in = _evidence_id(capability) or evidence
            if not algorithm:
                build.refuse("CAPABILITY_WITHOUT_ALGORITHM", product_name,
                             "a capability with no algorithm is not a capability")
                continue
            if not declared_in:
                build.refuse(
                    "VENDOR_CLAIM_WITHOUT_DOCUMENT", f"{product_name} {version} {label}",
                    "the vendor claims this on a page nobody filed: a capability with no "
                    "document cannot be cited, aged, or argued with")
                continue
            capability_row = build.add(
                "CRYPTO_CAPABILITY", f"{label} capability", evidence=declared_in,
                algorithm=algorithm, key_size=capability.get("key_size"),
                mode=capability.get("mode"), curve=capability.get("curve"),
                purpose=capability.get("purpose"), provider=capability.get("provider"),
                evidence_type=tb.VENDOR_DECLARED,
                vendor=product_name, quantum_sensitive=tb._quantum_sensitive(algorithm))
            algorithm_row = build.add("ALGORITHM", algorithm, evidence=declared_in,
                                      quantum_sensitive=tb._quantum_sensitive(algorithm))
            build.link(release, "SUPPORTS", capability_row, basis="vendor-datasheet",
                       evidence=declared_in, confidence=tb.VENDOR_DECLARED,
                       purpose=capability.get("purpose"))
            build.link(capability_row, "IMPLEMENTS", algorithm_row, basis="vendor-datasheet",
                       evidence=declared_in)
            build.declared.append({
                "document": declared_in[0], "vendor": _norm(row.get("vendor")) or None,
                "product": product_name, "version": version, "capability": label,
                "algorithm": algorithm, "key_size": capability.get("key_size"),
                "mode": capability.get("mode"), "curve": capability.get("curve"),
                "purpose": capability.get("purpose"),
                "valid_until": (build.documents.get(declared_in[0]) or {}).get("valid_until"),
            })

        for package in row.get("packages") or []:
            if not isinstance(package, Mapping):
                continue
            coordinate = _norm(package.get("coordinate"))
            if not coordinate:
                build.refuse("PACKAGE_WITHOUT_COORDINATE", product_name,
                             "a shipped package with no coordinate cannot be joined to an "
                             "SBOM, which is the only reason to record it here")
                continue
            package_row = build.add("PACKAGE", coordinate,
                                    evidence=evidence or [f"vendor:{coordinate}"],
                                    version=package.get("version"),
                                    origin="VENDOR", declared_version=package.get("version"))
            build.link(release, "SHIPS_PACKAGE", package_row, basis="vendor-datasheet",
                       evidence=evidence, version=package.get("version"))
            build.link(package_row, "PRODUCT_OF", product_name, basis="vendor-datasheet",
                       evidence=evidence)

    # ---- firmware -------------------------------------------------------- #
    for row in body.get("firmware") or []:
        if not isinstance(row, Mapping):
            continue
        product_name = _norm(row.get("product"))
        version = _norm(row.get("version"))
        evidence = _evidence_id(row)
        release_version = _norm(row.get("release")) or version
        if not product_name or not version:
            build.refuse("FIRMWARE_WITHOUT_VERSION", product_name,
                         "a firmware row with no version cannot be compared with what a "
                         "device reports it runs")
            continue
        firmware = build.add("FIRMWARE", _firmware_label(product_name, version),
                             evidence=evidence or
                             [f"firmware:{_firmware_label(product_name, version)}"],
                             version=version, product=product_name,
                             release_date=row.get("release_date"),
                             support_status=_norm(row.get("support_status")).upper() or None,
                             eol_date=row.get("eol_date"), eos_date=row.get("eos_date"),
                             security_status=row.get("security_status"),
                             pqc_capability=row.get("pqc_capability"),
                             signed=row.get("signed"))
        release = _version_label(product_name, release_version)
        if build.release_key(product_name, release_version):
            build.link(firmware, "FIRMWARE_OF", release, basis="vendor-datasheet",
                       evidence=evidence, release=release_version)
        for document in evidence:
            if document in build.documents:
                build.link(firmware, "DOCUMENTED_BY", document, basis="vendor-datasheet",
                           evidence=[document])

    # ---- the assets the bank actually runs -------------------------------- #
    for row in body.get("assets") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        declared_type = _norm(row.get("type")).upper()
        kind = ASSET_TYPE_KINDS.get(declared_type, "HOST")
        product_name = _norm(row.get("product"))
        evidence = _evidence_id(row) or [f"asset:{name}"]
        if not product_name:
            build.refuse("ASSET_WITHOUT_PRODUCT", name,
                         "an asset that names no product cannot be attributed to a vendor, "
                         "and an unattributed asset is a vendor dependency nobody owns")
            continue
        device = build.add(kind, name, evidence=evidence,
                           product=product_name, version=row.get("version"),
                           firmware=row.get("firmware"), model=row.get("model"),
                           serial=row.get("serial"), location=row.get("location"),
                           owner=row.get("owner"), datacenter=row.get("datacenter"),
                           verified=bool(row.get("verified") or row.get("serial")),
                           support_status=_norm(row.get("support_status")).upper() or None)
        build.link(device, "HAS_MODEL", product_name, basis="vendor-datasheet",
                   evidence=evidence, serial=row.get("serial"))
        firmware_version = _norm(row.get("firmware"))
        if firmware_version:
            firmware_label = _firmware_label(product_name, firmware_version)
            build.link(device, "RUNS_FIRMWARE", firmware_label, basis="api-poll",
                       evidence=evidence, version=firmware_version)

    # ---- packages already known from an SBOM ------------------------------ #
    for row in body.get("packages") or []:
        if not isinstance(row, Mapping):
            continue
        coordinate = _norm(row.get("coordinate"))
        if not coordinate:
            continue
        evidence = _evidence_id(row) or [f"sbom:{coordinate}"]
        package = build.add("PACKAGE", coordinate, evidence=evidence,
                            version=row.get("version"), origin="SBOM",
                            observed_version=row.get("version"))
        product_name = _norm(row.get("product"))
        if product_name:
            build.link(package, "PRODUCT_OF", product_name, basis="sbom-import",
                       evidence=evidence)

    # ---- applications, systems ------------------------------------------- #
    for row in body.get("applications") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        evidence = _evidence_id(row) or [f"cmdb:{name}"]
        application = build.add("APPLICATION", name, evidence=evidence,
                                owner=row.get("owner"), version=row.get("version"),
                                criticality=row.get("criticality"))
        system_name = _norm(row.get("system"))
        if system_name:
            system = build.add("BUSINESS_SYSTEM", system_name, evidence=evidence,
                               criticality=row.get("system_criticality"))
            build.link(system, "CONTAINS", application, basis="cmdb-import",
                       evidence=evidence)
        for product_name in row.get("products") or []:
            build.link(application, "EMBEDS", _norm(product_name), basis="cmdb-import",
                       evidence=evidence)
        for coordinate in row.get("packages") or []:
            build.link(application, "DEPENDS_ON", _norm(coordinate), basis="sbom-import",
                       evidence=evidence)
        for asset_name in row.get("assets") or []:
            build.link(_norm(asset_name), "SERVES", application, basis="cmdb-import",
                       evidence=evidence)
        for endpoint in row.get("endpoints") or []:
            build.link(application, "EXPOSES", _norm(endpoint), basis="config-parse",
                       evidence=evidence)

    for row in body.get("systems") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        build.add("BUSINESS_SYSTEM", name, evidence=_evidence_id(row) or [f"cmdb:{name}"],
                  criticality=row.get("criticality"), owner=row.get("owner"))

    # ---- runtime usage: the only section that may say OBSERVED ------------ #
    for row in body.get("usage") or []:
        if not isinstance(row, Mapping):
            continue
        process_name = _norm(row.get("process")) or _norm(row.get("application"))
        evidence = _evidence_id(row) or [f"probe:{_norm(row.get('host'))}:{row.get('pid')}"]
        if not process_name:
            build.refuse("USAGE_WITHOUT_PROCESS", row.get("application"),
                         "a usage row with no process is an opinion about crypto")
            continue
        process = build.add("PROCESS", process_name, evidence=evidence,
                            pid=row.get("pid"), host=row.get("host"),
                            application=_norm(row.get("application")),
                            started_at=row.get("started_at"),
                            verified=True)
        application_name = _norm(row.get("application"))
        if application_name:
            build.link(process, "RUNS_APPLICATION", application_name,
                       basis="process-trace", evidence=evidence,
                       observed_at=row.get("observed_at"))
        coordinate = _norm(row.get("package"))
        if coordinate:
            build.link(process, "LOADS", coordinate, basis="process-trace",
                       evidence=evidence, observed_at=row.get("observed_at"),
                       version=row.get("package_version"))
        algorithm = _norm(row.get("algorithm"))
        if algorithm:
            label = _capability_label(algorithm, row.get("key_size"), row.get("mode"),
                                      row.get("curve"))
            crypto = build.add("CRYPTO_ASSET", f"{label} use", evidence=evidence,
                               algorithm=algorithm, key_size=row.get("key_size"),
                               mode=row.get("mode"), curve=row.get("curve"),
                               purpose=row.get("purpose"), provider=row.get("provider"),
                               evidence_type=tb.RUNTIME_OBSERVED)
            algorithm_row = build.add("ALGORITHM", algorithm, evidence=evidence,
                                      quantum_sensitive=tb._quantum_sensitive(algorithm))
            build.link(process, "USES_CRYPTO", crypto, basis="process-trace",
                       evidence=evidence, observed_at=row.get("observed_at"),
                       operation=_norm(row.get("operation")) or None)
            build.link(crypto, "USES_ALGORITHM", algorithm_row, basis="process-trace",
                       evidence=evidence)

    # ---- network and PKI, the two vendor products that live in the path --- #
    for row in body.get("network") or []:
        if not isinstance(row, Mapping):
            continue
        name = _norm(row.get("name"))
        declared_type = _norm(row.get("type")).upper() or "LOAD_BALANCER"
        kind = ASSET_TYPE_KINDS.get(declared_type, "LOAD_BALANCER")
        evidence = _evidence_id(row) or [f"config:{name}"]
        device = build.add(kind, name, evidence=evidence, product=row.get("product"),
                           version=row.get("version"), firmware=row.get("firmware"),
                           serial=row.get("serial"), location=row.get("location"),
                           verified=bool(row.get("verified") or row.get("serial")),
                           tls_mode=_norm(row.get("tls_mode")).upper() or None)
        product_name = _norm(row.get("product"))
        if product_name:
            build.link(device, "HAS_MODEL", product_name, basis="config-parse",
                       evidence=evidence)
        firmware_version = _norm(row.get("firmware"))
        if firmware_version and product_name:
            build.link(device, "RUNS_FIRMWARE", _firmware_label(product_name,
                                                                firmware_version),
                       basis="api-poll", evidence=evidence)
        endpoint_name = _norm(row.get("endpoint"))
        if endpoint_name:
            _ensure_endpoint(build, endpoint_name, evidence)
            build.link(device, "LISTENS_ON", endpoint_name, basis="config-parse",
                       evidence=evidence, tls_mode=_norm(row.get("tls_mode")).upper() or None)
            application_name = _norm(row.get("application"))
            if application_name:
                build.link(endpoint_name, "ROUTES_TO", application_name,
                           basis="load-balancer-config", evidence=evidence)
        certificate = _norm(row.get("certificate"))
        if certificate and endpoint_name:
            build.link(endpoint_name, "PRESENTS", certificate, basis="config-parse",
                       evidence=evidence)

    for row in body.get("pki") or []:
        if not isinstance(row, Mapping):
            continue
        ca_name = _norm(row.get("ca"))
        certificate = _norm(row.get("certificate"))
        evidence = _evidence_id(row) or [f"pki:{ca_name}"]
        ca = build.add("CERTIFICATE_AUTHORITY", ca_name, evidence=evidence,
                       product=row.get("product"), version=row.get("version"),
                       serial=row.get("serial"), location=row.get("location"),
                       verified=bool(row.get("serial")))
        product_name = _norm(row.get("product"))
        if product_name:
            build.link(ca, "HAS_MODEL", product_name, basis="vendor-datasheet",
                       evidence=evidence)
        if certificate:
            build.add("CERTIFICATE", certificate, evidence=evidence,
                      not_after=row.get("not_after"), issuer=ca_name,
                      subject=row.get("subject"))
            build.link(certificate, "ISSUED_BY", ca_name, basis="config-parse",
                       evidence=evidence, not_after=row.get("not_after"))
            endpoint_name = _norm(row.get("endpoint"))
            if endpoint_name:
                _ensure_endpoint(build, endpoint_name, evidence)
                build.link(endpoint_name, "PRESENTS", certificate, basis="config-parse",
                           evidence=evidence)

    return n.estate(n.part(*build.assets, claims=build.claims), estate_id=estate_id,
                    environment=environment), build


def build(payload: Mapping[str, Any], *, environment: str = "PRODUCTION",
          estate_id: str = "vbom", as_of: Any = None) -> dict[str, Any]:
    """A vendor payload → an estate → a VBOM projection, with every report attached."""
    estate_doc, builder = from_documents(payload, environment=environment,
                                         estate_id=estate_id)
    bom = tb.build(estate_doc)
    as_of_text = _norm((payload or {}).get("as_of")) or _norm(as_of) or None
    return {
        "schema": SCHEMA,
        "as_of": as_of_text,
        "estate": estate_doc,
        "bom": bom,
        "levels": levels(bom),
        "declarations": builder.declared,
        "documents": list(builder.documents.values()),
        "refusals": builder.refused,
        "statement": (f"{len(builder.assets)} asset(s), {len(bom['assets'])} placed, "
                      f"{len(bom['claims'])} claim(s), {len(builder.refused)} refusal(s); "
                      + ", ".join(f"{name} {count}" for name, count in levels(bom).items()
                                  if count)),
        "rule": ("a vendor claim without a document is refused, and a claim is attached to "
                 "a release rather than to a company"),
    }


def levels(bom: Mapping[str, Any]) -> dict[str, int]:
    """How many nodes sit at each level of the vendor chain."""
    return {name: sum(1 for row in bom["assets"] if row["kind"] in kinds)
            for name, kinds, _ in LEVELS}


# --------------------------------------------------------------------------- #
# Reading the projection
# --------------------------------------------------------------------------- #

def _by_key(bom: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return bom["by_key"]


def _one(bom: Mapping[str, Any], query: Any) -> str:
    return n._resolve_one(bom, query)


def _rows(bom: Mapping[str, Any], *kinds: str) -> list[dict[str, Any]]:
    wanted = set(kinds)
    return [row for row in bom["assets"] if row["kind"] in wanted]


def _brief(row: Mapping[str, Any]) -> dict[str, Any]:
    attributes = row.get("attributes") or {}
    return {
        "name": row["name"], "kind": row["kind"], "id": row.get("id"),
        "version": row.get("version") or attributes.get("version"),
        "lifecycle": attributes.get("lifecycle") or attributes.get("support_status"),
    }


def _neighbours(bom: Mapping[str, Any], key: str, relations: Iterable[str], *,
                direction: str = "out") -> list[tuple[str, dict[str, Any]]]:
    """Every neighbour reachable in one hop, with the claim that reached it."""
    wanted = {str(relation).upper() for relation in relations}
    found: list[tuple[str, dict[str, Any]]] = []
    for claim in bom["claims"]:
        if claim["relation"] not in wanted:
            continue
        if direction in ("out", "both") and claim["from_key"] == key:
            found.append((claim["to_key"], claim))
        if direction in ("in", "both") and claim["to_key"] == key:
            found.append((claim["from_key"], claim))
    return found


def _reach(bom: Mapping[str, Any], key: str, relations: Iterable[str], *,
           direction: str = "out", max_depth: int = 8) -> dict[str, dict[str, Any]]:
    """Everything reachable through the given relations, with the path that got there."""
    found: dict[str, dict[str, Any]] = {}
    seen = {key}
    frontier: deque[tuple[str, list[str], int]] = deque([(key, [], 0)])
    while frontier:
        current, path, depth = frontier.popleft()
        if depth >= max_depth:
            continue
        for neighbour, claim in _neighbours(bom, current, relations, direction=direction):
            if neighbour in seen or neighbour not in bom["by_key"]:
                continue
            seen.add(neighbour)
            row = bom["by_key"][neighbour]
            link = [*path, claim["relation"]]
            found[neighbour] = {**_brief(row), "path": link,
                                "confidence": claim["confidence"],
                                "basis": claim["basis"],
                                "evidence_id": (claim.get("evidence_ids") or [None])[0]}
            frontier.append((neighbour, link, depth + 1))
    return found


def _by_level(rows: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {name: [] for name in LEVEL_ORDER}
    for row in rows:
        level = KIND_LEVEL.get(str(row.get("kind")), "")
        if level:
            buckets[level].append(dict(row))
    return {name: rows for name, rows in buckets.items() if rows}


def _attribute(row: Mapping[str, Any], name: str) -> Any:
    return (row.get("attributes") or {}).get(name)


# ---- 1. vendor → product -------------------------------------------------- #

def vendor_products(bom: Mapping[str, Any], *, vendor: Any) -> dict[str, Any]:
    """``vendor → product → release``, with the releases the vendor actually ships.

    The product is a node because ``Vendor X → RSA`` is not a dependency: an HSM and an SDK
    from the same vendor have different release cadences, different EOL dates and different
    owners, and a graph that collapses them can answer no question about either.
    """
    key = _one(bom, vendor)
    vendor_row = _by_key(bom)[key]
    products: list[dict[str, Any]] = []
    for product_key, claim in _neighbours(bom, key, ["SUPPLIED_BY"], direction="in"):
        product = _by_key(bom)[product_key]
        releases = []
        for release_key, release_claim in _neighbours(bom, product_key, ["RELEASES"]):
            release = _by_key(bom)[release_key]
            capabilities = [_by_key(bom)[target]["name"]
                            for target, _ in _neighbours(bom, release_key, ["SUPPORTS"])]
            releases.append({**_brief(release), "capabilities": sorted(capabilities),
                             "announced": (release_claim.get("facts") or {}).get(
                                 "announced_at")})
        products.append({**_brief(product), "basis": claim["basis"],
                         "evidence_id": (claim.get("evidence_ids") or [None])[0],
                         "family": _attribute(product, "product_family"),
                         "type": _attribute(product, "product_type"),
                         "releases": sorted(releases, key=lambda row: row["version"] or "")})
    products.sort(key=lambda row: row["name"])
    return {
        "query": str(vendor), "vendor": vendor_row["name"], "products": products,
        "releases": sum(len(row["releases"]) for row in products),
        "statement": (f"{vendor_row['name']}: {len(products)} product(s) — "
                      + ", ".join(f"{row['name']} ({len(row['releases'])} release(s))"
                                  for row in products) if products
                      else f"{vendor_row['name']}: no product is recorded against it"),
        "rule": ("a vendor supplies products, and a product has releases: a capability "
                 "recorded against the vendor rather than the release cannot be aged"),
        "not_proven": ["that the product list is complete: a vendor with no product rows is "
                       "a vendor nobody has mapped, not a vendor with nothing to sell"],
    }


def product_releases(bom: Mapping[str, Any], *, product: Any) -> dict[str, Any]:
    """The releases of one product, each with its lifecycle and what it supports."""
    key = _one(bom, product)
    row = _by_key(bom)[key]
    releases = []
    for release_key, _ in _neighbours(bom, key, ["RELEASES"]):
        release = _by_key(bom)[release_key]
        capabilities = [{"capability": _by_key(bom)[target]["name"],
                         "algorithm": _attribute(_by_key(bom)[target], "algorithm"),
                         "key_size": _attribute(_by_key(bom)[target], "key_size"),
                         "mode": _attribute(_by_key(bom)[target], "mode"),
                         "curve": _attribute(_by_key(bom)[target], "curve"),
                         "purpose": _attribute(_by_key(bom)[target], "purpose")}
                        for target, _ in _neighbours(bom, release_key, ["SUPPORTS"])]
        packages = [_by_key(bom)[target]["name"]
                    for target, _ in _neighbours(bom, release_key, ["SHIPS_PACKAGE"])]
        releases.append({**_brief(release),
                         "lifecycle_state": lifecycle_of({**_attribute_row(release),
                                                          "name": release["name"]}),
                         "capabilities": capabilities, "packages": sorted(packages)})
    releases.sort(key=lambda entry: entry["version"] or "")
    return {
        "query": str(product), "product": row["name"], "releases": releases,
        "statement": (f"{row['name']}: {len(releases)} release(s) — "
                      + ", ".join(f"{entry['version']} [{entry['lifecycle_state']['state']}]"
                                  for entry in releases) if releases
                      else f"{row['name']}: no release is recorded"),
        "rule": ("a release is the level vendor evidence applies to, and the level a "
                 "device's firmware is compared with"),
    }


# ---- 3. applicability ----------------------------------------------------- #

def _deployment_of(bom: Mapping[str, Any], asset_key: str) -> dict[str, Any]:
    row = bom["by_key"][asset_key]
    firmware = None
    for target, _ in _neighbours(bom, asset_key, ["RUNS_FIRMWARE"]):
        firmware = bom["by_key"][target]
        break
    return {
        "asset": row["name"], "kind": row["kind"], "key": asset_key,
        "product": _attribute(row, "product"),
        "version": _attribute(row, "version") or row.get("version"),
        "firmware": (firmware or {}).get("version") or _attribute(row, "firmware"),
        "verified": bool(_attribute(row, "verified")),
        "observed_capabilities": [_by_key(bom)[target]["name"]
                                  for target, _ in _neighbours(
                                      bom, asset_key, ["PERFORMS", "SUPPORTS"])],
    }


def deploy_is_read(bom: Mapping[str, Any], *, asset: Any) -> dict[str, Any]:
    """What the estate says a deployed asset runs, in the shape :func:`applicability` takes."""
    return _deployment_of(bom, _one(bom, asset))


def declaration_applicability(bom: Mapping[str, Any], *, document: Any = None,
                              product: Any = None, as_of: Any = None) -> dict[str, Any]:
    """Every declaration in the estate, answered against every deployment of its product.

    This is point 18 of the guide: the product matches, the release does not, the firmware
    is a prefix, the deployment was never verified — each of those is a different sentence
    and therefore a different state.
    """
    declarations = []
    for claim in bom["claims"]:
        if claim["relation"] != "SUPPORTS":
            continue
        release = bom["by_key"].get(claim["from_key"])
        if not release or release["kind"] != "PRODUCT_VERSION":
            continue
        document_id = (claim.get("evidence_ids") or [None])[0]
        if document and _norm(document).lower() not in (
                _norm(document_id).lower(), release["name"].lower()):
            continue
        product_name = release["name"].split("@")[0]
        if product and _norm(product).lower() != product_name.lower():
            continue
        capability = bom["by_key"][claim["to_key"]]
        document_row = next((row for row in _rows(bom, "EVIDENCE")
                             if row["name"] == document_id), {})
        declaration = {
            "product": product_name, "version": release.get("version"),
            "firmware": _attribute(document_row, "firmware"),
            "capability": capability["name"], "document": document_id,
            "valid_until": _attribute(document_row, "valid_until"),
            "verified": claim["confidence"] in tb.PROVEN,
        }
        for asset_key, _ in _neighbours(bom, claim["from_key"], ["FIRMWARE_OF"],
                                        direction="in"):
            firmware = bom["by_key"][asset_key]
            for device_key, _ in _neighbours(bom, asset_key, ["RUNS_FIRMWARE"],
                                             direction="in"):
                deployment = _deployment_of(bom, device_key)
                deployment["firmware"] = firmware.get("version")
                result = applicability(declaration, deployment, as_of=as_of)
                declarations.append({**result, "document": document_id,
                                     "capability": capability["name"]})
        for product_key, _ in _neighbours(bom, claim["from_key"], ["RELEASES"],
                                          direction="in"):
            for device_key, _ in _neighbours(bom, product_key, ["HAS_MODEL"],
                                             direction="in"):
                deployment = _deployment_of(bom, device_key)
                result = applicability(declaration, deployment, as_of=as_of)
                declarations.append({**result, "document": document_id,
                                     "capability": capability["name"]})
    states: dict[str, int] = {}
    for row in declarations:
        states[row["state"]] = states.get(row["state"], 0) + 1
    return {
        "query": _norm(document) or _norm(product) or "every declaration",
        "declarations": declarations, "states": states,
        "statement": (f"{len(declarations)} declaration/deployment pair(s): "
                      + ", ".join(f"{state} {count}" for state, count in sorted(states.items()))
                      if declarations else "no declaration reaches a deployment in this "
                                            "projection"),
        "rule": ("a vendor's claim is applied to a deployment only through a comparison of "
                 "product, release and firmware, and the answer names the question that "
                 "failed"),
        "not_proven": ["that a MATCHED claim was exercised: matching says the capability "
                       "exists on the release that is deployed, not that anything used it"],
    }


# ---- 4./5./6. the asset, hardware and software walks ----------------------- #

def vendor_assets(bom: Mapping[str, Any], *, vendor: Any, as_of: Any = None
                  ) -> dict[str, Any]:
    """``vendor → product → release → asset``: the things the bank actually runs."""
    key = _one(bom, vendor)
    rows: list[dict[str, Any]] = []
    for product_key, claim in _neighbours(bom, key, ["SUPPLIED_BY"], direction="in"):
        product = _by_key(bom)[product_key]
        for device_key, model_claim in _neighbours(bom, product_key, ["HAS_MODEL"],
                                                   direction="in"):
            device = _by_key(bom)[device_key]
            deployment = _deployment_of(bom, device_key)
            release_version = deployment["version"]
            release_key = _key("PRODUCT_VERSION",
                               _version_label(product["name"], release_version),
                               device.get("environment") or bom.get("environment")
                               or "PRODUCTION") if release_version else None
            release_row = bom["by_key"].get(release_key or "", {})
            documents = (release_row.get("evidence_ids")
                         or claim.get("evidence_ids") or [None])
            declaration = {"product": product["name"], "version": release_version,
                           "document": documents[0]}
            result = applicability(declaration, deployment, as_of=as_of)
            rows.append({
                **_brief(device),
                "product": product["name"], "model": _attribute(device, "model"),
                "serial": _attribute(device, "serial"),
                "location": device.get("location") or _attribute(device, "location"),
                "environment": device.get("environment"),
                "owner": device.get("owner"),
                "firmware": deployment["firmware"],
                "applicability": result["state"],
                "applicability_reason": result["reason"],
                "lifecycle": _product_lifecycle(bom, product_key, device),
                "reached_by": model_claim["relation"],
                "release": release_row.get("name") if release_version else None,
                "applicability_document": documents[0],
            })
    rows.sort(key=lambda row: row["name"])
    return {
        "query": str(vendor), "vendor": _by_key(bom)[key]["name"], "assets": rows,
        "statement": (f"{_by_key(bom)[key]['name']}: {len(rows)} asset(s) — "
                      + ", ".join(f"{row['name']} ({row['applicability']})" for row in rows)
                      if rows else
                      f"{_by_key(bom)[key]['name']}: no asset is attributable to a product "
                      "it supplies"),
        "rule": ("a vendor dependency reaches an asset through a product and a release, "
                 "never through a name match"),
    }


def _product_lifecycle(bom: Mapping[str, Any], product_key: str,
                       device: Mapping[str, Any]) -> str:
    """The device's support state, read from the product it models.

    A device has a *firmware* lifecycle and a *product* lifecycle, and the product's is the
    one that says whether the vendor still supports the thing at all.
    """
    product = bom["by_key"].get(product_key)
    if product is not None:
        state = lifecycle_of({**_attribute_row(product), "name": product["name"]})
        if state["state"] != UNKNOWN_LIFECYCLE:
            return state["state"]
    return lifecycle_of({**_attribute_row(device), "name": device["name"]})["state"]


def hardware_chain(bom: Mapping[str, Any], *, asset: Any, as_of: Any = None
                   ) -> dict[str, Any]:
    """``vendor → product → model → firmware → asset``, with the HBOM identity it shares.

    The identity is the one the HBOM uses — the same kind, the same model, the same
    firmware node — so a hardware finding and a vendor finding are about one device.
    """
    key = _one(bom, asset)
    row = _by_key(bom)[key]
    models = [(_by_key(bom)[target], claim)
              for target, claim in _neighbours(bom, key, ["HAS_MODEL"])]
    product = models[0][0] if models else None
    vendor_names = [(_by_key(bom)[target]["name"]) for target, _ in
                    _neighbours(bom, product["key"], ["SUPPLIED_BY"])] if product else []
    firmwares = []
    for target, claim in _neighbours(bom, key, ["RUNS_FIRMWARE"]):
        firmware = _by_key(bom)[target]
        firmwares.append({**_brief(firmware),
                          "lifecycle": lifecycle_of({**_attribute_row(firmware),
                                                     "name": firmware["name"]},
                                                    as_of=as_of)["state"],
                          "support_status": _attribute(firmware, "support_status"),
                          "release_date": _attribute(firmware, "release_date"),
                          "eol_date": _attribute(firmware, "eol_date"),
                          "eos_date": _attribute(firmware, "eos_date"),
                          "security_status": _attribute(firmware, "security_status"),
                          "pqc_capability": _attribute(firmware, "pqc_capability"),
                          "reached_by": claim["relation"]})
    return {
        "query": str(asset), "asset": row["name"], "kind": row["kind"],
        "model": product["name"] if product else None,
        "vendor": vendor_names[0] if vendor_names else None,
        "serial": _attribute(row, "serial"),
        "firmware": firmwares,
        "identity": {"kind": row["kind"], "name": row["name"],
                     "model": product["name"] if product else None,
                     "firmware": [entry["name"] for entry in firmwares],
                     "digest": row.get("digest"), "id": row.get("id")},
        "statement": (f"{row['name']}: {vendor_names[0] if vendor_names else '(no vendor)'} → "
                      f"{product['name'] if product else '(no model)'} → "
                      + (", ".join(entry["name"] for entry in firmwares) or "(no firmware)")
                      + f" → {row['name']}"),
        "rule": ("the hardware identity is the HBOM's: one device, one kind, one firmware "
                 "node, whichever BOM is looking at it"),
    }


def software_chain(bom: Mapping[str, Any], *, vendor: Any = None, product: Any = None
                   ) -> dict[str, Any]:
    """``vendor → product → release → package → application``, joined to the SBOM."""
    if vendor is not None:
        start = _one(bom, vendor)
        query = str(vendor)
    elif product is not None:
        start = _one(bom, product)
        query = str(product)
    else:
        raise tb.ClaimRefused("NO_QUERY", "a software chain starts at a vendor or a product")
    reached = _reach(bom, start, ["SUPPLIED_BY", "RELEASES", "SHIPS_PACKAGE", "PRODUCT_OF",
                                  "DEPENDS_ON", "EMBEDS"], direction="both")
    packages = [row for row in reached.values() if row["kind"] in ("PACKAGE",
                                                                  "CRYPTO_LIBRARY")]
    applications = [row for row in reached.values() if row["kind"] in ("APPLICATION",
                                                                      "SERVICE")]
    return {
        "query": query,
        "vendor": _by_key(bom)[start]["name"] if vendor is not None else None,
        "packages": sorted(packages, key=lambda row: row["name"]),
        "applications": sorted(applications, key=lambda row: row["name"]),
        "statement": (f"{query}: {len(packages)} package(s), {len(applications)} "
                      "application(s) — "
                      + ", ".join(row["name"] for row in sorted(packages,
                                                                key=lambda item: item["name"]))
                      + (" → " + ", ".join(row["name"] for row in applications)
                         if applications else "")),
        "rule": ("a vendor's software reaches an application through a package, because a "
                 "package is what an SBOM can name and an application is what an owner does"),
    }


# ---- 7./8. crypto: declared vs observed ----------------------------------- #

def crypto_chain(bom: Mapping[str, Any], *, vendor: Any = None, product: Any = None
                 ) -> dict[str, Any]:
    """``vendor → product → release → capability → algorithm → key size / mode / purpose``."""
    start = _one(bom, vendor if vendor is not None else product)
    query = str(vendor if vendor is not None else product)
    reached = _reach(bom, start, ["SUPPLIED_BY", "RELEASES", "SUPPORTS", "IMPLEMENTS",
                                  "SHIPS_PACKAGE", "PRODUCT_OF", "USES_CRYPTO",
                                  "USES_ALGORITHM"], direction="both")
    rows: list[dict[str, Any]] = []
    for key, row in reached.items():
        if row["kind"] != "CRYPTO_CAPABILITY":
            continue
        asset_row = _by_key(bom)[key]
        algorithms = [_by_key(bom)[target]["name"]
                      for target, _ in _neighbours(bom, key, ["IMPLEMENTS"])]
        rows.append({**row, "capability": row["name"],
                     "algorithm": _attribute(asset_row, "algorithm"),
                     "key_size": _attribute(asset_row, "key_size"),
                     "mode": _attribute(asset_row, "mode"),
                     "curve": _attribute(asset_row, "curve"),
                     "purpose": _attribute(asset_row, "purpose"),
                     "implemented_as": algorithms,
                     "class": tb.VENDOR_DECLARED,
                     "quantum_sensitive": _attribute(asset_row, "quantum_sensitive")})
    rows.sort(key=lambda row: row["name"])
    return {
        "query": query, "capabilities": rows,
        "algorithm_count": len({row["algorithm"] for row in rows if row["algorithm"]}),
        "statement": (f"{query}: {len(rows)} declared capability(ies) across "
                      f"{len({row['algorithm'] for row in rows if row['algorithm']})} "
                      "algorithm(s) — "
                      + ", ".join(f"{row['name']} ({row['algorithm']}"
                                  + (f"-{row['key_size']}" if row["key_size"] else "")
                                  + (f"-{row['mode']}" if row["mode"] else "") + ")"
                                  for row in rows)),
        "rule": ("what a vendor declares is a capability at VENDOR_DECLARED: it says what "
                 "the release can do, and nothing about what the bank does with it"),
    }


def declared_vs_observed(bom: Mapping[str, Any], *, product: Any = None,
                         vendor: Any = None) -> dict[str, Any]:
    """The declaration, the observation, and the gap — kept as three columns.

    A vendor that supports ML-KEM and a bank that never negotiated it is the normal case,
    and the answer is ``VENDOR_DECLARED`` + ``NOT_OBSERVED``. Nothing here promotes a
    declared capability into usage.
    """
    start = _one(bom, vendor if vendor is not None else product)
    query = str(vendor if vendor is not None else product)
    declared = _reach(bom, start, ["SUPPLIED_BY", "RELEASES", "SUPPORTS"], direction="both")
    observed_crypto = _rows(bom, "CRYPTO_ASSET")
    observed = {_norm(_attribute(row, "algorithm")).upper()
                for row in observed_crypto if _attribute(row, "algorithm")}
    rows: list[dict[str, Any]] = []
    for key, row in declared.items():
        if row["kind"] != "CRYPTO_CAPABILITY":
            continue
        capability = _by_key(bom)[key]
        algorithm = _norm(_attribute(capability, "algorithm")).upper()
        if algorithm in observed:
            state = tb.RUNTIME_OBSERVED
            note = "an observation of this algorithm exists in the estate"
        else:
            state = tb.VENDOR_DECLARED
            note = "declared by the vendor and never observed here"
        rows.append({"capability": capability["name"], "algorithm": algorithm,
                     "declared": tb.VENDOR_DECLARED, "observed": state,
                     "observed_usage": sum(1 for row in observed_crypto
                                           if _norm(_attribute(row, "algorithm")).upper()
                                           == algorithm),
                     "state": state, "note": note})
    rows.sort(key=lambda row: row["capability"])
    not_observed = [row["capability"] for row in rows if row["state"] == tb.VENDOR_DECLARED]
    return {
        "query": query, "rows": rows,
        "declared_count": len(rows),
        "observed_count": sum(1 for row in rows if row["state"] != tb.VENDOR_DECLARED),
        "not_observed": not_observed,
        "statement": (f"{query}: {len(rows)} declared, "
                      f"{len(rows) - len(not_observed)} observed somewhere in the estate, "
                      f"{len(not_observed)} declared and never observed"
                      + (f" ({', '.join(not_observed)})" if not_observed else "")),
        "rule": ("declared ≠ used: a capability the vendor lists is a capability, and only "
                 "an observation makes it a usage"),
        "not_proven": ["that an algorithm observed somewhere is observed *here*: usage is "
                       "counted across the estate, and the row says how many observations"],
    }


# ---- 9./10./11. applications, systems, and the question that matters ------ #

def vendor_applications(bom: Mapping[str, Any], *, vendor: Any) -> dict[str, Any]:
    """Which applications depend on this vendor — through hardware, packages or an SDK."""
    key = _one(bom, vendor)
    paths = _reach(bom, key, ["SUPPLIED_BY", "RELEASES", "HAS_MODEL", "SERVES", "SHIPS_PACKAGE",
                             "PRODUCT_OF", "DEPENDS_ON", "EMBEDS", "RUNS_APPLICATION",
                             "LOADED_BY"], direction="both")
    applications = [row for row in paths.values() if row["kind"] in ("APPLICATION",
                                                                   "SERVICE")]
    return {
        "query": str(vendor), "vendor": _by_key(bom)[key]["name"],
        "applications": sorted(applications, key=lambda row: row["name"]),
        "statement": (f"{_by_key(bom)[key]['name']}: {len(applications)} application(s) — "
                      + ", ".join(row["name"] for row in
                                  sorted(applications, key=lambda item: item["name"]))
                      if applications else
                      f"{_by_key(bom)[key]['name']}: no application is reachable from it"),
        "rule": ("an application depends on a vendor when a path of recorded relations says "
                 "so: the path is returned, because 'depends' without a path is a guess"),
    }


def vendor_systems(bom: Mapping[str, Any], *, vendor: Any) -> dict[str, Any]:
    """``vendor → product → application → business system``, and the impact when it breaks."""
    key = _one(bom, vendor)
    paths = _reach(bom, key, ["SUPPLIED_BY", "RELEASES", "HAS_MODEL", "SERVES", "SHIPS_PACKAGE",
                             "PRODUCT_OF", "DEPENDS_ON", "EMBEDS", "CONTAINS",
                             "RUNS_APPLICATION", "LOADED_BY"], direction="both")
    systems = [row for row in paths.values() if row["kind"] == "BUSINESS_SYSTEM"]
    return {
        "query": str(vendor), "vendor": _by_key(bom)[key]["name"],
        "systems": sorted(systems, key=lambda row: row["name"]),
        "statement": (f"{_by_key(bom)[key]['name']}: {len(systems)} business system(s) — "
                      + ", ".join(row["name"] for row in systems) if systems
                      else f"{_by_key(bom)[key]['name']}: reaches no business system"),
        "rule": ("business impact is a property of the graph, not of the vendor's criticality "
                 "field: a tier-1 vendor with no path to a system has no business impact"),
    }


def crypto_business(bom: Mapping[str, Any], *, vendor: Any, algorithm: Any = None
                    ) -> dict[str, Any]:
    """Which business systems depend on this vendor **for this algorithm**.

    This is the question the whole graph exists to answer: ``vendor → product → asset →
    crypto → application → system``, printed as a path rather than as a count.
    """
    key = _one(bom, vendor)
    paths = _reach(bom, key, ["SUPPLIED_BY", "RELEASES", "SUPPORTS", "HAS_MODEL", "SERVES",
                              "USES_CRYPTO", "USES_ALGORITHM", "IMPLEMENTS", "DEPENDS_ON",
                              "EMBEDS", "CONTAINS", "SHIPS_PACKAGE", "PRODUCT_OF",
                              "RUNS_APPLICATION", "LOADED_BY"], direction="both")
    wanted = _norm(algorithm).upper()
    crypto_rows = []
    for row_key, row in paths.items():
        if row["kind"] not in ("CRYPTO_CAPABILITY", "CRYPTO_ASSET"):
            continue
        asset_row = _by_key(bom)[row_key]
        name = _norm(_attribute(asset_row, "algorithm")).upper()
        if wanted and name != wanted:
            continue
        crypto_rows.append({**row, "algorithm": name,
                            "key_size": _attribute(asset_row, "key_size"),
                            "mode": _attribute(asset_row, "mode")})
    # the systems have to be reachable *through* one of the matching crypto assets: a
    # vendor that offers no 3DES reaches no system "for 3DES", however many systems it
    # reaches for AES
    reachable: set[str] = set()
    for row in crypto_rows:
        crypto_key = next((key for key, entry in paths.items()
                           if entry["name"] == row["name"] and entry["kind"] == entry["kind"]),
                          None)
        if crypto_key is None:
            continue
        reachable.add(crypto_key)
        for target, _ in _reach(bom, crypto_key,
                                ["IMPLEMENTS", "SUPPORTS", "USES_ALGORITHM",
                                 "USES_CRYPTO", "SERVES", "RUNS_APPLICATION", "CONTAINS",
                                 "EMBEDS", "DEPENDS_ON", "LOADS", "SHIPS_PACKAGE",
                                 "PRODUCT_OF", "HAS_MODEL", "RELEASES", "SUPPLIED_BY"],
                                direction="both").items():
            reachable.add(target)
    systems = sorted({bom["by_key"][key]["name"] for key in reachable
                      if key in bom["by_key"]
                      and bom["by_key"][key]["kind"] == "BUSINESS_SYSTEM"})
    applications = sorted({bom["by_key"][key]["name"] for key in reachable
                           if key in bom["by_key"]
                           and bom["by_key"][key]["kind"] in ("APPLICATION", "SERVICE")})
    return {
        "query": f"{_by_key(bom)[key]['name']} / {algorithm or 'any algorithm'}",
        "vendor": _by_key(bom)[key]["name"], "algorithm": wanted or None,
        "crypto": sorted(crypto_rows, key=lambda row: row["name"]),
        "applications": applications, "systems": systems,
        "statement": (f"{_by_key(bom)[key]['name']} → {algorithm or 'crypto'} → "
                      f"{len(applications)} application(s) → {len(systems)} business "
                      f"system(s): {', '.join(systems) or 'none'}"),
        "rule": ("the answer names the crypto asset and the path that reaches the system, so "
                 "a migration can be scoped by algorithm rather than by vendor"),
    }


# ---- 12./13./14. runtime, network, PKI ------------------------------------ #

def runtime_dependency(bom: Mapping[str, Any], *, vendor: Any) -> dict[str, Any]:
    """``vendor → product → component → process → runtime observation``.

    The last hop is the one that turns a declaration into a fact: a process that loaded the
    vendor's package and an operation that was watched. Nothing above this line is
    ``OBSERVED``.
    """
    key = _one(bom, vendor)
    paths = _reach(bom, key, ["SUPPLIED_BY", "RELEASES", "SHIPS_PACKAGE", "PRODUCT_OF",
                              "LOADS", "RUNS_APPLICATION", "HAS_MODEL", "SERVES"],
                   direction="both")
    processes = [row for row in paths.values() if row["kind"] == "PROCESS"]
    observed = []
    for process in processes:
        process_key = next(key_ for key_, row in paths.items()
                           if row["name"] == process["name"] and row["kind"] == "PROCESS")
        for target, claim in _neighbours(bom, process_key, ["USES_CRYPTO"]):
            crypto = _by_key(bom)[target]
            observed.append({"process": process["name"],
                             "algorithm": _attribute(crypto, "algorithm"),
                             "key_size": _attribute(crypto, "key_size"),
                             "mode": _attribute(crypto, "mode"),
                             "operation": (claim.get("facts") or {}).get("operation"),
                             "class": claim["confidence"], "basis": claim["basis"],
                             "evidence_id": (claim.get("evidence_ids") or [None])[0],
                             "observed_at": claim.get("observed_at")})
    return {
        "query": str(vendor), "vendor": _by_key(bom)[key]["name"],
        "processes": sorted(processes, key=lambda row: row["name"]),
        "observations": observed,
        "statement": (f"{_by_key(bom)[key]['name']}: {len(processes)} process(es) load its "
                      f"software, {len(observed)} operation(s) were watched — "
                      + ", ".join(f"{row['algorithm']} {row['operation'] or ''}".strip()
                                  for row in observed) if observed
                      else f"{_by_key(bom)[key]['name']}: no process was watched using it"),
        "rule": ("only a trace reaches OBSERVED; a loaded package is a dependency and an "
                 "operation is a usage, and the two are different rows"),
    }


def network_dependency(bom: Mapping[str, Any], *, vendor: Any) -> dict[str, Any]:
    """``vendor → network product → device → endpoint → application`` (the NBOM join)."""
    key = _one(bom, vendor)
    paths = _reach(bom, key, ["SUPPLIED_BY", "HAS_MODEL", "LISTENS_ON", "ROUTES_TO",
                              "FRONTED_BY", "PROTECTS", "PRESENTS", "RUNS_FIRMWARE"],
                   direction="both")
    devices = [row for row in paths.values()
               if row["kind"] in ("LOAD_BALANCER", "WAF", "API_GATEWAY", "SERVICE_MESH",
                                  "FIREWALL", "VPN_GATEWAY", "IDS", "IPS")]
    endpoints = [row for row in paths.values() if row["kind"] == "NETWORK_ENDPOINT"]
    applications = [row for row in paths.values() if row["kind"] in ("APPLICATION",
                                                                    "SERVICE")]
    return {
        "query": str(vendor), "vendor": _by_key(bom)[key]["name"],
        "devices": sorted(devices, key=lambda row: row["name"]),
        "endpoints": sorted(endpoints, key=lambda row: row["name"]),
        "applications": sorted(applications, key=lambda row: row["name"]),
        "statement": (f"{_by_key(bom)[key]['name']}: {len(devices)} network device(s), "
                      f"{len(endpoints)} endpoint(s), {len(applications)} application(s) "
                      "behind them"),
        "rule": ("a network vendor's product reaches an application through an endpoint, and "
                 "the endpoint is the node the NBOM records"),
    }


def pki_dependency(bom: Mapping[str, Any], *, vendor: Any) -> dict[str, Any]:
    """``vendor → CA product → CA instance → certificate → endpoint → application``."""
    key = _one(bom, vendor)
    paths = _reach(bom, key, ["SUPPLIED_BY", "HAS_MODEL", "ISSUED_BY", "PRESENTS",
                              "ROUTES_TO", "CONTAINS_KEY"], direction="both")
    authorities = [row for row in paths.values() if row["kind"] == "CERTIFICATE_AUTHORITY"]
    certificates = [row for row in paths.values() if row["kind"] == "CERTIFICATE"]
    endpoints = [row for row in paths.values() if row["kind"] == "NETWORK_ENDPOINT"]
    applications = [row for row in paths.values() if row["kind"] in ("APPLICATION",
                                                                    "SERVICE")]
    return {
        "query": str(vendor), "vendor": _by_key(bom)[key]["name"],
        "authorities": sorted(authorities, key=lambda row: row["name"]),
        "certificates": sorted(certificates, key=lambda row: row["name"]),
        "endpoints": sorted(endpoints, key=lambda row: row["name"]),
        "applications": sorted(applications, key=lambda row: row["name"]),
        "statement": (f"{_by_key(bom)[key]['name']}: {len(authorities)} CA instance(s), "
                      f"{len(certificates)} certificate(s), {len(endpoints)} endpoint(s) — "
                      + ", ".join(row["name"] for row in
                                  sorted(certificates, key=lambda item: item["name"]))),
        "rule": ("a certificate is issued by an instance of a product from a vendor: the "
                 "migration unit is the CA, and the affected unit is the endpoint"),
    }


# ---- 15./16. firmware and lifecycle -------------------------------------- #

def firmware_posture(bom: Mapping[str, Any], *, firmware: Any = None,
                     as_of: Any = None) -> dict[str, Any]:
    """Firmware as a dependency: dates, support, security status, PQC claim, and its assets."""
    if firmware is not None:
        key = _one(bom, firmware)
        keys = [key]
    else:
        keys = [row["key"] for row in _rows(bom, "FIRMWARE")]
    rows = []
    for fw_key in keys:
        row = _by_key(bom)[fw_key]
        devices = [_by_key(bom)[target]["name"]
                   for target, _ in _neighbours(bom, fw_key, ["RUNS_FIRMWARE"],
                                                direction="in")]
        rows.append({
            **_brief(row), "product": _attribute(row, "product"),
            "release_date": _attribute(row, "release_date"),
            "support_status": _attribute(row, "support_status"),
            "eol_date": _attribute(row, "eol_date"),
            "eos_date": _attribute(row, "eos_date"),
            "security_status": _attribute(row, "security_status"),
            "pqc_capability": _attribute(row, "pqc_capability"),
            "lifecycle": lifecycle_of({**_attribute_row(row), "name": row["name"]},
                                      as_of=as_of)["state"],
            "devices": sorted(devices),
        })
    rows.sort(key=lambda entry: (entry["product"] or "", entry["version"] or ""))
    return {
        "query": _norm(firmware) or "every firmware",
        "firmware": rows,
        "statement": (f"{len(rows)} firmware row(s): "
                      + ", ".join(f"{row['name']} [{row['lifecycle']}] on "
                                  f"{len(row['devices'])} device(s)" for row in rows)),
        "rule": ("firmware is versioned, dated and supportable on its own: a product's "
                 "support statement is not a firmware's"),
    }


def lifecycle_impact(bom: Mapping[str, Any], *, product: Any = None,
                     as_of: Any = None) -> dict[str, Any]:
    """``EOL → assets → applications → crypto → business systems``, as a fan-out.

    The impact is computed from the graph. A product with an EOL date and no path to a
    system has no business impact, and the report says so instead of guessing from the
    product's criticality field.
    """
    if product is not None:
        start = _one(bom, product)
    else:
        candidates = [row for row in _rows(bom, "VENDOR_PRODUCT")
                      if lifecycle_of({**_attribute_row(row), "name": row["name"]},
                                      as_of=as_of)["terminal"]]
        if not candidates:
            return {"query": "every product", "product": None, "affected": {},
                    "statement": "no product is past end of life in this projection",
                    "rule": "lifecycle impact is computed from what is reachable, not assumed"}
        start = candidates[0]["key"]
    row = _by_key(bom)[start]
    products = [start]
    if row["kind"] != "VENDOR_PRODUCT":
        products = [target for target, _ in _neighbours(bom, start, ["HAS_MODEL"])]
    affected: dict[str, list[dict[str, Any]]] = {name: [] for name in LEVEL_ORDER}
    for product_key in products:
        reached = _reach(bom, product_key, ["HAS_MODEL", "RELEASES", "RUNS_FIRMWARE",
                                           "SHIPS_PACKAGE", "PRODUCT_OF", "SERVES",
                                           "DEPENDS_ON", "EMBEDS", "CONTAINS",
                                           "RUNS_APPLICATION", "USES_CRYPTO",
                                           "USES_ALGORITHM", "LOADS"],
                         direction="both")
        for entry in reached.values():
            level = KIND_LEVEL.get(entry["kind"])
            if level:
                affected.setdefault(level, []).append(entry)
    buckets = {name: sorted({(row["name"], row["kind"]) for row in rows})
               for name, rows in affected.items() if rows}
    lifecycle = lifecycle_of({**_attribute_row(row), "name": row["name"]}, as_of=as_of)
    return {
        "query": str(product) if product is not None else row["name"],
        "product": row["name"], "lifecycle": lifecycle,
        "affected": {name: [{"name": name_, "kind": kind} for name_, kind in
                            sorted(values)] for name, values in buckets.items()},
        "statement": (f"{row['name']} [{lifecycle['state']}] → "
                      + ", ".join(f"{len(values)} {name}" for name, values in
                                  sorted(buckets.items()))
                      + ("" if buckets else "nothing reachable from it")),
        "rule": ("a product lifecycle is a supply-chain risk only where the graph reaches a "
                 "business system; the fan-out is returned so the claim can be checked"),
        "not_proven": ["that every affected asset was inventoried: the impact is as complete "
                       "as the asset rows, and a device nobody recorded is not in it"],
    }


def _attribute_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """The attributes of a node, in the shape :func:`lifecycle_of` reads."""
    attributes = dict(row.get("attributes") or {})
    attributes.setdefault("name", row.get("name"))
    if row.get("version"):
        attributes.setdefault("version", row["version"])
    return attributes


# ---- 17./18. evidence freshness and verification -------------------------- #

def evidence_report(bom: Mapping[str, Any], *, as_of: Any = None) -> dict[str, Any]:
    """Every vendor document, aged: how old, reviewed by whom, and whether it still holds."""
    rows = []
    for row in _rows(bom, "EVIDENCE"):
        document = {"id": row["name"], **_attribute_row(row)}
        report = evidence_freshness(document, as_of=as_of)
        rows.append(report)
    complaints = [row for row in rows if row["state"] != FRESH]
    return {
        "documents": sorted(rows, key=lambda row: row["document"] or ""),
        "states": {state: sum(1 for row in rows if row["state"] == state)
                   for state in EVIDENCE_STATES},
        "statement": (f"{len(rows)} document(s): "
                      + ", ".join(f"{state} {sum(1 for row in rows if row['state'] == state)}"
                                  for state in EVIDENCE_STATES)
                      + (f"; {len(complaints)} cannot be quoted as current"
                         if complaints else "")),
        "rule": ("a vendor's answer ages like any other evidence, and it is labelled rather "
                 "than deleted: the claim is still the claim it was"),
    }


def verification(bom: Mapping[str, Any], *, document: Any = None, product: Any = None,
                 as_of: Any = None) -> dict[str, Any]:
    """The five questions of point 18, answered one at a time for each declaration."""
    report = declaration_applicability(bom, document=document, product=product, as_of=as_of)
    rows = []
    for entry in report["declarations"]:
        checks = entry["checks"]
        rows.append({
            "document": entry["document"], "capability": entry["capability"],
            "asset": entry["deployment"]["asset"],
            "product_match": checks["product"] == "PASS",
            "version_match": checks["version"] == "PASS",
            "firmware_match": checks["firmware"] == "PASS",
            "deployment_verified": checks["deployment"] == "PASS",
            "capability_observed": checks["capability"] == "OBSERVED",
            "state": entry["state"],
        })
    return {
        "query": _norm(document) or _norm(product) or "every declaration",
        "rows": rows,
        "verified": sum(1 for row in rows if row["state"] == MATCHED),
        "statement": (f"{len(rows)} declaration(s): {sum(1 for r in rows if r['state'] == MATCHED)}"
                      f" MATCHED, {len(rows) - sum(1 for r in rows if r['state'] == MATCHED)}"
                      " otherwise — "
                      + ", ".join(sorted({row["state"] for row in rows}))),
        "rule": ("five checks, and a claim is MATCHED only when all five pass: the check "
                 "list is the evidence, the state is only the summary"),
    }


# ---- 19./20. SBOM and CBOM agreement ------------------------------------- #

def sbom_agreement(bom: Mapping[str, Any], *, product: Any = None, vendor: Any = None
                   ) -> dict[str, Any]:
    """Vendor-declared package version against the SBOM's.

    ``Vendor says SDK 5.7, the sbom contains 5.4`` is the finding this exists for. Both
    versions are printed; neither becomes *the* version.
    """
    start = _one(bom, vendor if vendor is not None else product)
    query = str(vendor if vendor is not None else product)
    reached = _reach(bom, start, ["SUPPLIED_BY", "RELEASES", "SHIPS_PACKAGE", "PRODUCT_OF"],
                     direction="both")
    rows = []
    for key, entry in reached.items():
        if entry["kind"] not in ("PACKAGE", "CRYPTO_LIBRARY"):
            continue
        row = _by_key(bom)[key]
        declared = _attribute(row, "declared_version")
        observed = _attribute(row, "observed_version") or row.get("version")
        comparison = compare_versions(declared, observed)
        rows.append({
            "package": row["name"], "declared": declared, "observed": observed,
            "result": comparison["result"],
            "state": (tb.IMPORTED if comparison["result"] == SAME
                      else "VENDOR_DEPLOYMENT_VERSION_CONFLICT"),
            "statement": comparison["statement"],
        })
    rows.sort(key=lambda row: row["package"])
    conflicts = [row for row in rows if row["state"] == "VENDOR_DEPLOYMENT_VERSION_CONFLICT"]
    return {
        "query": query, "packages": rows, "conflicts": conflicts,
        "statement": (f"{query}: {len(rows)} package(s), {len(conflicts)} declared/observed "
                      "conflict(s) — "
                      + ", ".join(f"{row['package']} declared {row['declared']}, saw "
                                  f"{row['observed']}" for row in conflicts)
                      if conflicts else f"{query}: declared and observed versions agree"),
        "rule": ("a declared version and an observed version are two rows: choosing one as "
                 "the truth is how a bank ships a version it thinks it patched"),
        "not_proven": ["that the SBOM row is complete: a package the SBOM does not list is "
                       "absent from the comparison, not proven absent"],
    }


def cbom_agreement(bom: Mapping[str, Any], *, vendor: Any = None, product: Any = None
                   ) -> dict[str, Any]:
    """Vendor capability against CBOM observation, with the declaration left where it is."""
    declared = declared_vs_observed(bom, vendor=vendor, product=product)
    observed_rows = []
    for row in _rows(bom, "CRYPTO_ASSET"):
        observed_rows.append({
            "asset": row["name"], "algorithm": _attribute(row, "algorithm"),
            "key_size": _attribute(row, "key_size"), "mode": _attribute(row, "mode"),
            "class": _attribute(row, "evidence_type") or tb.OBSERVED,
        })
    observed_algorithms = {_norm(row["algorithm"]).upper() for row in observed_rows}
    declared_algorithms = {row["algorithm"] for row in declared["rows"]}
    declared_only = ", ".join(sorted(declared_algorithms - observed_algorithms)) or "none"
    observed_only = ", ".join(sorted(observed_algorithms - declared_algorithms)) or "none"
    return {
        "query": declared["query"], "declared": declared["rows"],
        "observed": sorted(observed_rows, key=lambda row: row["asset"]),
        "declared_only": sorted(declared_algorithms - observed_algorithms),
        "observed_only": sorted(observed_algorithms - declared_algorithms),
        "both": sorted(declared_algorithms & observed_algorithms),
        "statement": (f"{declared['query']}: {len(declared_algorithms)} declared, "
                      f"{len(observed_algorithms)} observed, "
                      f"{len(declared_algorithms & observed_algorithms)} in both — declared "
                      f"only: {declared_only}; observed only: {observed_only}"),
        "rule": ("the CBOM and the VBOM answer different questions about the same algorithm, "
                 "and the projection keeps both answers"),
    }


# ---- 21./22. identity shared with the other BOMs -------------------------- #

def hardware_identity(bom: Mapping[str, Any], *, asset: Any) -> dict[str, Any]:
    """The canonical hardware identity: kind, model, serial, firmware — and its digest."""
    chain = hardware_chain(bom, asset=asset)
    row = _by_key(bom)[_one(bom, asset)]
    return {
        "query": str(asset), "identity": chain["identity"],
        "serial": chain["serial"], "model": chain["model"], "vendor": chain["vendor"],
        "statement": (f"{row['name']}: {row['kind']} {chain['model'] or '(no model)'} "
                      f"serial {chain['serial'] or '(none)'} — shared with HBOM as "
                      f"{row.get('id')}"),
        "rule": ("one device has one identity across the BOMs: the hardware reviewer and the "
                 "vendor reviewer must be looking at the same node"),
    }


def network_identity(bom: Mapping[str, Any], *, asset: Any) -> dict[str, Any]:
    """The network identity of a vendor device: what it listens on and how TLS crosses it."""
    key = _one(bom, asset)
    row = _by_key(bom)[key]
    endpoints = [(_by_key(bom)[target], claim)
                 for target, claim in _neighbours(bom, key, ["LISTENS_ON"])]
    return {
        "query": str(asset), "device": row["name"], "kind": row["kind"],
        "endpoints": [{"endpoint": endpoint["name"],
                       "tls_mode": (claim.get("facts") or {}).get("tls_mode"),
                       "routes_to": [_by_key(bom)[target]["name"] for target, _ in
                                     _neighbours(bom, endpoint["key"], ["ROUTES_TO"])]}
                      for endpoint, claim in endpoints],
        "statement": (f"{row['name']}: "
                      + (", ".join(endpoint["name"] for endpoint, _ in endpoints)
                         or "no endpoint is recorded")
                      + " — the NBOM records the same nodes"),
        "rule": ("a network vendor's device is a node in the NBOM and a product in the VBOM, "
                 "and the two are joined by the endpoint rather than by the device's name"),
    }


# ---- 23. the twin -------------------------------------------------------- #

def twin(bom: Mapping[str, Any]) -> dict[str, Any]:
    """The whole vendor graph, as the digital twin holds it: levels, edges, and the gaps.

    The point of the twin is that the VBOM is a *projection* of it: nothing in this report is
    computed from vendor records alone, and a node the twin does not hold cannot appear here.
    """
    counts = levels(bom)
    edges: dict[str, int] = {}
    for claim in bom["claims"]:
        edges[claim["relation"]] = edges.get(claim["relation"], 0) + 1
    vendor_edges = {relation: count for relation, count in edges.items()
                    if relation in ("SUPPLIED_BY", "RELEASES", "FIRMWARE_OF",
                                    "SHIPS_PACKAGE", "HAS_MODEL", "RUNS_FIRMWARE",
                                    "SUPPORTS", "DOCUMENTED_BY", "PRODUCT_OF")}
    populated = [name for name, count in counts.items() if count]
    gaps = [name for name, count in counts.items() if not count]
    return {
        "levels": counts, "edges": dict(sorted(edges.items())),
        "vendor_edges": dict(sorted(vendor_edges.items())),
        "populated": populated, "gaps": gaps,
        "nodes": len(bom["assets"]), "claims": len(bom["claims"]),
        "statement": (f"the twin holds {len(bom['assets'])} node(s) and {len(bom['claims'])} "
                      f"claim(s); {len(populated)}/{len(counts)} vendor level(s) are "
                      f"populated"
                      + (f"; gaps: {', '.join(gaps)}" if gaps else "")),
        "rule": ("the VBOM is a projection of the twin: a vendor fact that is not in the "
                 "graph is not in the BOM, and a level with no rows is printed as a gap"),
    }


# ---- 24./25. conflicts and history --------------------------------------- #

def version_conflicts(bom: Mapping[str, Any]) -> dict[str, Any]:
    """Every subject with more than one version claim, with each layer named.

    ``VENDOR_DECLARED 3.0.13 / SBOM_OBSERVED 3.0.11 / RUNTIME_OBSERVED 3.0.11`` is not a
    vote. The four layers are printed and the subject is flagged.
    """
    rows: list[dict[str, Any]] = []
    for row in _rows(bom, "PACKAGE", "CRYPTO_LIBRARY", "VENDOR_PRODUCT", "FIRMWARE"):
        layers: dict[str, str] = {}
        declared = _attribute(row, "declared_version")
        observed = _attribute(row, "observed_version")
        if declared:
            layers["VENDOR_DECLARED"] = _norm(declared)
        if observed:
            layers["SBOM_OBSERVED"] = _norm(observed)
        if row["kind"] == "FIRMWARE" and row.get("version"):
            layers.setdefault("FIRMWARE_OBSERVED", _norm(row["version"]))
        for claim in bom["claims"]:
            if claim["to_key"] != row["key"] or claim["relation"] not in ("LOADS",
                                                                         "INSTALLED_IN"):
                continue
            version = (claim.get("facts") or {}).get("version")
            if version:
                layers["RUNTIME_OBSERVED"] = _norm(version)
        distinct = {value for value in layers.values() if value}
        if len(distinct) > 1:
            rows.append({"subject": row["name"], "kind": row["kind"], "layers": layers,
                         "distinct": sorted(distinct), "code":
                             "VENDOR_DEPLOYMENT_VERSION_CONFLICT"})
    rows.sort(key=lambda row: row["subject"])
    return {
        "conflicts": rows,
        "statement": (f"{len(rows)} subject(s) carry more than one version claim"
                      + (": " + ", ".join(f"{row['subject']} "
                                          f"({', '.join(f'{k}={v}' for k, v in row['layers'].items())})"
                                          for row in rows) if rows else "")),
        "rule": ("a version conflict is a finding with four layers named: the model does not "
                 "vote, because the bank may be running neither"),
    }


def history(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Vendor relationship changes over time: ``VENDOR_CHANGED`` with both sides cited.

    A dependency that changed vendor, product, release or firmware is a different dependency
    from last quarter, and the row that says so carries the evidence before and after.
    """
    body = payload if isinstance(payload, Mapping) else {}
    rows = []
    for row in body.get("history") or []:
        if not isinstance(row, Mapping):
            continue
        field = _norm(row.get("field")).lower()
        subject = _norm(row.get("subject"))
        previous = _norm(row.get("previous"))
        current = _norm(row.get("current"))
        if not subject or field not in HISTORY_FIELDS:
            continue
        if previous == current:
            continue
        code = ("VENDOR_CHANGED" if field == "vendor"
                else f"VENDOR_{field.upper()}_CHANGED")
        rows.append({"subject": subject, "field": field, "previous": previous or None,
                     "current": current or None, "code": code,
                     "changed_at": _norm(row.get("changed_at")) or None,
                     "evidence_before": _norm(row.get("evidence_before")) or None,
                     "evidence_after": _norm(row.get("evidence_after")) or None,
                     "statement": (f"{subject}: {field} {previous or '(none)'} → "
                                   f"{current or '(none)'} at "
                                   f"{_norm(row.get('changed_at')) or '(undated)'}")})
    rows.sort(key=lambda row: (row["subject"], row["field"]))
    return {
        "changes": rows,
        "statement": (f"{len(rows)} relationship change(s): "
                      + ", ".join(f"{row['subject']} {row['field']}" for row in rows)
                      if rows else "no vendor relationship changed in the window"),
        "rule": ("a vendor dependency has a history: the change is recorded with the evidence "
                 "on both sides, because 'who supplied this last quarter' is an audit "
                 "question"),
    }


def coverage(payload: Mapping[str, Any]) -> dict[str, Any]:
    """How much of the software estate has a vendor, and the three answers that are not one.

    ``UNKNOWN`` is not ``INTERNAL`` and neither is ``no vendor``: 82% mapped with 13% nobody
    has identified is a different sentence from 82% mapped with 13% in-house.
    """
    body = payload if isinstance(payload, Mapping) else {}
    rows = [row for row in body.get("components") or [] if isinstance(row, Mapping)]
    identified = unknown = internal = 0
    for row in rows:
        vendor = _norm(row.get("vendor")).upper()
        if not vendor or vendor == UNKNOWN_VENDOR:
            unknown += 1
        elif vendor == INTERNAL_VENDOR:
            internal += 1
        else:
            identified += 1
    total = len(rows)
    percent = round(100.0 * identified / total, 1) if total else 0.0
    mapped = round(100.0 * (identified + internal) / total, 1) if total else 0.0
    return {
        "total": total, "identified": identified, "unknown": unknown, "internal": internal,
        "coverage_percent": percent, "accounted_percent": mapped,
        "unidentified": [row.get("coordinate") for row in rows
                         if _norm(row.get("vendor")).upper() in ("", UNKNOWN_VENDOR)],
        "statement": (f"{identified} of {total} component(s) have a vendor "
                      f"({percent}%); {unknown} unknown, {internal} internal — "
                      f"{mapped}% of the estate is accounted for"),
        "rule": ("an unknown vendor is a mapping gap and an internal component is not a gap: "
                 "adding them together is how a coverage figure becomes a comfort"),
        "not_proven": ["that the vendor fields are right: coverage counts answers, not "
                       "correct answers"],
    }


# ---- 26. risk propagation ------------------------------------------------- #

#: how much each level contributes to a propagated score. A vendor's product reaching an
#: application that a tier-1 system contains is worth more than the same product sitting on
#: an unowned host.
LEVEL_WEIGHT: dict[str, int] = {
    "vendor": 0, "product": 1, "release": 1, "firmware": 2, "package": 2, "asset": 3,
    "application": 3, "crypto": 2, "runtime": 2, "system": 5,
}


def risk_propagation(bom: Mapping[str, Any], *, vendor: Any, as_of: Any = None
                     ) -> dict[str, Any]:
    """``vendor → product → asset → crypto → application → system``, scored as it travels.

    The score is deliberately simple and printed: it is the sum of the level weights of the
    nodes the vendor reaches, plus a multiplier for a terminal lifecycle. What matters is
    that it travels **through the graph** — a vendor risk that reaches nothing scores zero,
    and says so.
    """
    key = _one(bom, vendor)
    vendor_row = _by_key(bom)[key]
    reached = _reach(bom, key, ["SUPPLIED_BY", "RELEASES", "HAS_MODEL", "RUNS_FIRMWARE",
                              "SHIPS_PACKAGE", "PRODUCT_OF", "SERVES", "DEPENDS_ON",
                              "EMBEDS", "CONTAINS", "RUNS_APPLICATION", "USES_CRYPTO",
                              "USES_ALGORITHM", "LOADS"], direction="both")
    weights: dict[str, int] = {}
    for entry in reached.values():
        level = KIND_LEVEL.get(entry["kind"])
        if level:
            weights[level] = weights.get(level, 0) + 1
    base = sum(LEVEL_WEIGHT.get(level, 0) * count for level, count in weights.items())
    terminal = []
    for product_key, _ in _neighbours(bom, key, ["SUPPLIED_BY"], direction="in"):
        product = _by_key(bom)[product_key]
        state = lifecycle_of({**_attribute_row(product), "name": product["name"]},
                             as_of=as_of)
        if state["terminal"]:
            terminal.append({"product": product["name"], "state": state["state"]})
    systems = [entry for entry in reached.values() if entry["kind"] == "BUSINESS_SYSTEM"]
    critical = 3 if systems else 1
    score = base * critical * (2 if terminal else 1)
    return {
        "query": str(vendor), "vendor": vendor_row["name"],
        "weights": weights, "base": base, "terminal": terminal,
        "systems": sorted({entry["name"] for entry in systems}),
        "score": score,
        "statement": (f"{vendor_row['name']}: score {score} = base {base} × {critical} "
                      f"({len(systems)} business system(s))"
                      + (f" × 2 ({len(terminal)} product(s) end of life)" if terminal else "")
                      + "; levels reached: "
                      + ", ".join(f"{level} {count}" for level, count in
                                  sorted(weights.items()))),
        "rule": ("risk travels through dependencies: a vendor pointing at nothing carries no "
                 "propagated risk, whatever its criticality field says"),
        "not_proven": ["that the weights are calibrated: they are stated so they can be "
                       "argued with, and a bank should replace them with its own"],
    }


# ---- 27. PQC ------------------------------------------------------------- #

PQC_DECLARED = "DECLARED"
PQC_UNKNOWN = "UNKNOWN"
PQC_NOT_OBSERVED = "NOT_OBSERVED"


def pqc_posture(bom: Mapping[str, Any], *, vendor: Any = None, product: Any = None
                ) -> dict[str, Any]:
    """Three separate answers: what the vendor declares, what the deployment is, what ran.

    The one answer this deliberately does not give is ``PQC READY``.
    """
    start = _one(bom, vendor if vendor is not None else product)
    query = str(vendor if vendor is not None else product)
    reached = _reach(bom, start, ["SUPPLIED_BY", "RELEASES", "RUNS_FIRMWARE", "HAS_MODEL",
                                  "SHIPS_PACKAGE", "PRODUCT_OF", "LOADS", "USES_CRYPTO"],
                     direction="both")
    declared = PQC_UNKNOWN
    declared_by = None
    for product_key, entry in reached.items():
        if entry["kind"] not in ("PRODUCT_VERSION", "FIRMWARE"):
            continue
        row = _by_key(bom)[product_key]
        claim = _norm(_attribute(row, "pqc_capability")).upper()
        if claim in ("DECLARED", "YES", "SUPPORTED"):
            declared, declared_by = PQC_DECLARED, row["name"]
            break
    # what the *deployment* is, which is a different question: a firmware row that claims
    # PQC and a device nobody verified is UNKNOWN, not declared
    deployment = PQC_UNKNOWN
    for device_key, entry in reached.items():
        if entry["kind"] not in ASSET_KINDS:
            continue
        row = _by_key(bom)[device_key]
        claim = _norm(_attribute(row, "pqc_capability")).upper()
        if claim in ("DECLARED", "YES", "SUPPORTED") and _attribute(row, "verified"):
            deployment = PQC_DECLARED
            break
    observed = [row["name"] for row in _rows(bom, "CRYPTO_ASSET")
                if any(token in _norm(_attribute(row, "algorithm")).upper()
                       for token in ("ML-KEM", "MLKEM", "KYBER", "ML-DSA", "DILITHIUM",
                                     "SLH-DSA", "SPHINCS"))]
    runtime = tb.OBSERVED if observed else PQC_NOT_OBSERVED
    return {
        "query": query, "declared": declared, "declared_by": declared_by,
        "deployment": deployment, "runtime": runtime, "observed": observed,
        "statement": (f"{query}: vendor PQC capability {declared}"
                      + (f" ({declared_by})" if declared_by else "")
                      + f"; deployment PQC capability {deployment}; PQC usage {runtime}"),
        "rule": ("a vendor's PQC claim is a declaration, a deployment's is a capability and "
                 "a runtime's is an observation: 'PQC READY' would be none of the three"),
        "not_proven": ["that the estate can use PQC if the vendor supports it: a capability "
                       "in the product is not a configuration in the bank"],
    }
