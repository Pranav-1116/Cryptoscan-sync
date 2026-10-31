"""Joining the planes on a *subject* — which first has to mean one asset.

Correlation across planes is only as good as the name the planes agree on. The
static collector names a host ``alb-payments-01``, the certificate probe names it
``payments.bank.example:443``, the runtime observer names the process that runs on
it ``payments-api`` and the identity resolver names the workload
``spiffe://bank.example/ns/payments/sa/api``. Those are four names for one asset,
and a correlator that groups by the string it was handed will report four separate
subjects and no agreement at all.

The rule here is deliberately narrow, because the alternative manufactures
corroboration:

* **keys are declared, not derived.** An asset states the names it is known by —
  its id, its name and the identity fields the graph recorded (hostname, address,
  DNS name, SPIFFE id, certificate serial). Nothing is invented by trimming a
  domain, taking the first label, or matching a prefix;
* **equality only.** A subject resolves when a key matches exactly after
  normalisation (case, whitespace, a port suffix, a trailing dot). There is no
  fuzzy score, because a 0.8 similarity between two hosts is a merged pair of
  hosts;
* **ambiguity refuses.** If two assets declare the same key, the subject is
  ``AMBIGUOUS`` and is *not* merged into either — a coin flip between two assets
  is worse than an unresolved name, which at worst leaves one subject alone;
* **the scheme is reported.** A pattern joining two subjects says whether it joined
  them on a SPIFFE id, an address or a bare name, and those are not equally strong.

Nothing here decides that two *different* keys mean the same machine. That would
be identity resolution against the estate, and a resolver that guessed it would put
two banks' hosts in one pattern.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.subject-resolution/1"

#: key schemes, strongest first. The order decides which key wins when a subject
#: matches more than one — a SPIFFE id outranks a bare name, always.
SCHEMES: tuple[str, ...] = ("SPIFFE", "CERT", "DNS", "IP", "HOST", "NAME")

#: which asset identity fields declare which scheme. The graph's own vocabulary:
#: ``{"spiffe_id": ..., "hostname": ..., "ip": ...}``.
IDENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "SPIFFE": ("spiffe_id", "spiffe", "spiffe_uri", "uri"),
    "CERT": ("serial", "serial_number", "thumbprint", "fingerprint", "sha256"),
    "DNS": ("dns", "dns_name", "fqdn", "common_name", "cn", "subject"),
    "IP": ("ip", "ip_address", "address", "addr"),
    "HOST": ("hostname", "host", "node", "machine"),
    "NAME": ("name", "workload", "service", "asset"),
}

RESOLVED = "RESOLVED"
AMBIGUOUS = "AMBIGUOUS"
UNRESOLVED = "UNRESOLVED"

_PORT = re.compile(r":\d{1,5}$")
_SPIFFE = re.compile(r"^spiffe://", re.IGNORECASE)


def _text(value: Any) -> str:
    return str(value or "").strip()


def normalise(value: Any, scheme: str) -> str:
    """One key value, in the form two planes can be compared on.

    Normalisation is limited to spelling: case, surrounding space, a port suffix and
    a trailing DNS dot. Nothing here changes *which* asset a name refers to.
    """
    text = _text(value)
    if not text:
        return ""
    if scheme == "SPIFFE":
        return text.rstrip("/").lower()
    if scheme in ("DNS", "HOST", "IP"):
        text = _PORT.sub("", text)
        if scheme == "IP" and text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        text = text.rstrip(".").lower()
        return text
    if scheme == "CERT":
        return re.sub(r"[^0-9a-f]", "", text.lower())
    return text.lower()


def classify(subject: Any) -> tuple[str, str]:
    """Guess the scheme of a bare subject string, and normalise it.

    A guess, and only about *spelling*: a string that starts with ``spiffe://`` is a
    SPIFFE id, one that parses as an address is an address, one containing a dot is a
    DNS name, anything else is a bare name. A wrong guess can only fail to resolve —
    it can never merge two subjects, because merging needs a key an asset declared.
    """
    text = _text(subject)
    if not text:
        return "", ""
    if _SPIFFE.match(text):
        return "SPIFFE", normalise(text, "SPIFFE")
    bare = _PORT.sub("", text)
    try:
        ipaddress.ip_address(bare.strip("[]"))
        return "IP", normalise(text, "IP")
    except ValueError:
        pass
    if "." in bare:
        return "DNS", normalise(text, "DNS")
    return "NAME", normalise(text, "NAME")


@dataclass(frozen=True)
class Resolution:
    """What one subject turned out to be, with the reason when it is not one asset."""

    subject: str
    status: str
    asset_id: str | None
    scheme: str | None
    candidates: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def key(self) -> str:
        """The grouping key: the asset when resolved, the raw subject otherwise."""
        return f"asset:{self.asset_id}" if self.asset_id else f"raw:{self.subject.lower()}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "status": self.status,
            "asset_id": self.asset_id,
            "scheme": self.scheme,
            "candidates": list(self.candidates),
            "reason": self.reason,
        }


class SubjectIndex:
    """Every name the estate's assets declare, and the asset that declared it.

    Built once per correlation and never mutated: the same stored estate must always
    group the same way.
    """

    def __init__(self, identities: Iterable[Mapping[str, Any]] = ()) -> None:
        #: scheme → normalised key → asset ids that declared it
        self._keys: dict[str, dict[str, set[str]]] = {scheme: {} for scheme in SCHEMES}
        self._declared: dict[str, set[str]] = {}
        for identity in identities:
            self._add(identity)

    # -- construction ------------------------------------------------------ #

    def _add(self, identity: Mapping[str, Any]) -> None:
        asset_id = _text(identity.get("asset_id") or identity.get("id"))
        if not asset_id:
            return
        self._declared.setdefault(asset_id, set())
        for scheme, value in _declared_keys(identity):
            normalised = normalise(value, scheme)
            if not normalised:
                continue
            self._keys[scheme].setdefault(normalised, set()).add(asset_id)
            self._declared[asset_id].add(f"{scheme}:{normalised}")

    @classmethod
    def from_assets(cls, assets: Iterable[Mapping[str, Any]]) -> "SubjectIndex":
        """Build from estate-graph assets, using the identity fields they declare."""
        return cls(_identity_of(asset) for asset in assets)

    # -- reads ------------------------------------------------------------- #

    def resolve(self, subject: Any) -> Resolution:
        text = _text(subject)
        if not text:
            return Resolution(text, UNRESOLVED, None, None, reason="empty subject")
        declared = self._declared.get(text)
        if declared is not None:
            # the subject *is* an asset id: the strongest key there is
            return Resolution(text, RESOLVED, text, "ASSET_ID")
        scheme, key = classify(text)
        if not scheme or not key:
            return Resolution(text, UNRESOLVED, None, None, reason="nothing to match on")
        # The scheme guessed from the string is tried first, then the others: a bare
        # token can legitimately be a hostname, and a name is what most collectors use.
        # Every attempt is an exact key comparison, so a wrong guess can only fail to
        # resolve — it can never join two assets.
        for candidate_scheme in (scheme, *(item for item in SCHEMES if item != scheme)):
            owners = self._keys.get(candidate_scheme, {}).get(key)
            if not owners:
                continue
            if len(owners) == 1:
                return Resolution(text, RESOLVED, next(iter(owners)), candidate_scheme)
            return Resolution(
                text,
                AMBIGUOUS,
                None,
                candidate_scheme,
                candidates=tuple(sorted(owners)),
                reason=(
                    f"{len(owners)} assets declare the {candidate_scheme} key {key!r}; "
                    "merging would join unrelated assets, so this subject stays ungrouped"
                ),
            )
        return Resolution(
            text,
            UNRESOLVED,
            None,
            scheme,
            reason=f"no asset in this estate declares the {scheme} key {key!r}",
        )

    def keys_for(self, asset_id: str) -> list[str]:
        return sorted(self._declared.get(asset_id) or [])

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "assets": len(self._declared),
            "keys": {scheme: len(values) for scheme, values in self._keys.items()},
            "ambiguous_keys": {
                scheme: {
                    key: sorted(owners)
                    for key, owners in values.items()
                    if len(owners) > 1
                }
                for scheme, values in self._keys.items()
                if any(len(owners) > 1 for owners in values.values())
            },
            "note": (
                "keys are declared by assets and matched exactly. Ambiguous keys are reported "
                "here and refused at resolution time rather than resolved by preference"
            ),
        }


def _identity_of(asset: Mapping[str, Any]) -> dict[str, Any]:
    """An asset's declared names, in the graph's shape, plus its id and name."""
    identity: dict[str, Any] = {"asset_id": _text(asset.get("asset_id") or asset.get("id"))}
    declared = asset.get("identity") if isinstance(asset.get("identity"), Mapping) else {}
    for key, value in declared.items():
        identity.setdefault(str(key), value)
    if asset.get("name"):
        identity.setdefault("name", asset.get("name"))
    for key in ("hostname", "ip", "ip_address", "fqdn", "dns", "spiffe_id", "serial"):
        if asset.get(key):
            identity.setdefault(key, asset[key])
    attributes = asset.get("attributes") if isinstance(asset.get("attributes"), Mapping) else {}
    for key in ("hostname", "ip", "ip_address", "fqdn", "dns", "spiffe_id", "serial"):
        if attributes.get(key):
            identity.setdefault(key, attributes[key])
    return identity


def _declared_keys(identity: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """(scheme, value) for every key an asset declares, in a stable order."""
    out: list[tuple[str, Any]] = []
    for scheme in SCHEMES:
        for field in IDENTITY_FIELDS[scheme]:
            value = identity.get(field)
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    out.append((scheme, item))
                continue
            if value not in (None, ""):
                out.append((scheme, value))
    return out


def summarise(resolutions: Iterable[Resolution]) -> dict[str, Any]:
    """Counts over the subjects a correlation actually saw."""
    items = list(resolutions)
    by_status: dict[str, int] = {}
    by_scheme: dict[str, int] = {}
    groups: dict[str, set[str]] = {}
    for item in items:
        by_status[item.status] = by_status.get(item.status, 0) + 1
        if item.status == RESOLVED and item.asset_id:
            by_scheme[item.scheme or "UNKNOWN"] = by_scheme.get(item.scheme or "UNKNOWN", 0) + 1
            groups.setdefault(item.asset_id, set()).add(item.subject)
    merged = [
        {"asset_id": asset_id, "subjects": sorted(subjects)}
        for asset_id, subjects in sorted(groups.items())
        if len(subjects) > 1
    ]
    return {
        "subjects": len(items),
        "by_status": {status: by_status.get(status, 0) for status in (RESOLVED, UNRESOLVED, AMBIGUOUS)},
        "by_scheme": by_scheme,
        "merged_subjects": merged,
        "ambiguous": [
            item.as_dict() for item in items if item.status == AMBIGUOUS
        ],
        "unresolved": [item.as_dict() for item in items if item.status == UNRESOLVED][:50],
        "note": (
            "a subject is joined to an asset by exact key equality, on a key that asset declares. "
            "AMBIGUOUS subjects are left ungrouped on purpose: picking one of two owners is how a "
            "correlator invents agreement between two hosts"
        ),
    }


__all__ = [
    "AMBIGUOUS",
    "IDENTITY_FIELDS",
    "RESOLVED",
    "SCHEMES",
    "SCHEMA",
    "SubjectIndex",
    "UNRESOLVED",
    "Resolution",
    "classify",
    "normalise",
    "summarise",
]
