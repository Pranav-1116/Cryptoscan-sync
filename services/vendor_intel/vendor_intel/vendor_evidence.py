"""Vendor evidence: a declaration is not a deployment.

The VBOM's weakest assumption is the one every vendor BOM starts with: *the
vendor says product X supports AES-256 and ML-DSA, therefore the bank's payment
system uses them*. That inference is wrong in three separate ways, and this
module refuses all three:

1. **A capability is not a usage.** A vendor document proves what the product
   *can* do. It proves nothing about what the bank configured, deployed or
   exercises at runtime. Those are different evidence types and they stay
   different rows (:class:`EvidenceType`).
2. **A declaration has a version, and the bank has another.** A declaration for
   firmware 8.2 does not describe firmware 8.4. :func:`assess_applicability`
   compares the two and returns `VERSION_MISMATCH` rather than attaching the
   8.2 crypto inventory to an 8.4 appliance.
3. **Sources disagree, and disagreement is the finding.** When the vendor says
   OpenSSL 3.0.13 and the SBOM and the runtime say 3.0.11, reconciling them into
   one "latest" value destroys the only interesting fact on the page.
   :func:`reconcile` keeps every observation and reports `CONFLICT`.

Everything here is pure: plain dataclasses in, plain dicts out. Nothing in this
module touches a database, a network or a vendor API, and nothing it returns is
a secret — the fields it projects are names, versions, dates and evidence
references.

The vocabulary is deliberately narrow. :data:`EVIDENCE_TYPES` is the closed set
from the review; a caller that cannot say which one it holds passes `UNKNOWN`
rather than the strongest one it hopes for.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.vendor-evidence/1"

# --------------------------------------------------------------------------- #
# 6. the evidence vocabulary
# --------------------------------------------------------------------------- #


class EvidenceType(str, Enum):
    """Where a fact came from. Every row in a VBOM carries exactly one.

    The order in :data:`EVIDENCE_RANK` is not a hierarchy of truth — a
    `CONFIGURED` usage is not "less true" than an `OBSERVED` capability. It is a
    hierarchy of *distance from the machine*, used only to say which evidence
    wins when two sources describe the same attribute.
    """

    DECLARED = "DECLARED"                    # a vendor document or questionnaire
    IMPORTED = "IMPORTED"                    # a vendor CBOM/SBOM or registry import
    CONFIGURED = "CONFIGURED"                # a bank configuration names it
    OBSERVED = "OBSERVED"                    # the bank's collector read it on the asset
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"    # a running process or session showed it
    NETWORK_OBSERVED = "NETWORK_OBSERVED"    # a handshake, probe or capture showed it
    INFERRED = "INFERRED"                    # derived from other facts, and labelled so
    UNKNOWN = "UNKNOWN"                      # nobody looked, or the source is gone


EVIDENCE_TYPES: tuple[str, ...] = tuple(kind.value for kind in EvidenceType)

#: Strongest evidence wins a disagreement; equal ranks conflict rather than
#: silently overwrite.
EVIDENCE_RANK: dict[str, int] = {
    EvidenceType.UNKNOWN.value: 0,
    EvidenceType.INFERRED.value: 1,
    EvidenceType.DECLARED.value: 2,
    EvidenceType.IMPORTED.value: 3,
    EvidenceType.CONFIGURED.value: 3,
    EvidenceType.OBSERVED.value: 4,
    EvidenceType.NETWORK_OBSERVED.value: 4,
    EvidenceType.RUNTIME_OBSERVED.value: 5,
}

#: Evidence types that describe the *bank's* estate rather than the vendor's
#: claims. A capability claim is only "verified" once one of these is attached.
BANK_OBSERVED_TYPES = frozenset({
    EvidenceType.OBSERVED.value,
    EvidenceType.RUNTIME_OBSERVED.value,
    EvidenceType.NETWORK_OBSERVED.value,
    EvidenceType.CONFIGURED.value,
})


@dataclass(frozen=True)
class Evidence:
    """One citation: what kind of evidence, which record, and when.

    ``reference`` is an identifier the estate can resolve — a document id, a
    configuration path, an observation id. It is never the evidence itself, and
    it is never a credential.
    """

    kind: EvidenceType
    reference: str
    observed_at: date | None = None
    source_document: str | None = None
    source_hash: str | None = None

    def __post_init__(self) -> None:
        if not str(self.reference or "").strip():
            raise ValueError("evidence needs a reference; a claim with no citation is an opinion")
        object.__setattr__(self, "kind", EvidenceType(self.kind))

    @property
    def evidence_id(self) -> str:
        digest = hashlib.sha256(
            f"{self.kind.value}|{self.reference}|{self.source_hash or ''}".encode()
        ).hexdigest()
        return f"VE-{digest[:12]}"

    @property
    def is_bank_observation(self) -> bool:
        return self.kind.value in BANK_OBSERVED_TYPES and self.kind != EvidenceType.CONFIGURED

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_type": self.kind.value,
            "evidence_id": self.evidence_id,
            "reference": self.reference,
            "observed_at": _iso_date(self.observed_at),
            "source_document": self.source_document,
            "source_hash": self.source_hash,
        }


def _iso_date(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _as_date(value: Any) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None


def strongest(evidence: Iterable[Evidence]) -> Evidence | None:
    """The evidence that speaks loudest — ties resolved by first sighted."""
    best: Evidence | None = None
    for item in evidence:
        if best is None or EVIDENCE_RANK[item.kind.value] > EVIDENCE_RANK[best.kind.value]:
            best = item
    return best


# --------------------------------------------------------------------------- #
# 7. vendor product / version identity
# --------------------------------------------------------------------------- #


class ProductMismatch(ValueError):
    """A declaration and a deployment are not about the same thing."""


@dataclass(frozen=True)
class ProductIdentity:
    """The triple every vendor document and every bank asset must agree on."""

    vendor: str
    product: str
    version: str | None = None
    revision: str | None = None

    def __post_init__(self) -> None:
        if not _norm(self.vendor):
            raise ValueError("vendor is required; an anonymous declaration is not evidence")
        if not _norm(self.product):
            raise ValueError("product is required; a vendor-wide claim is not a product claim")
        object.__setattr__(self, "vendor", self.vendor.strip())
        object.__setattr__(self, "product", self.product.strip())

    def key(self) -> tuple[str, str]:
        return _norm(self.vendor), _norm(self.product)

    def to_dict(self) -> dict[str, Any]:
        return {"vendor": self.vendor, "product": self.product,
                "version": self.version, "revision": self.revision}


def _norm(value: Any) -> str:
    return "".join(str(value or "").split()).upper()


def version_tokens(version: str | None) -> tuple[int | str, ...]:
    """``"8.2.1"`` -> ``(8, 2, 1)``; ``"1.2.3-rc1"`` -> ``(1, 2, 3, "RC1")``.

    Numeric parts compare as numbers and textual parts as text, so ``8.10`` is
    greater than ``8.9`` — the bug a string comparison would ship. An empty
    version is an empty tuple, which compares as "not stated" rather than as 0.
    """
    if not version:
        return ()
    parts: list[int | str] = []
    for chunk in str(version).replace("_", ".").replace("-", ".").split("."):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            parts.append(chunk.upper())
    return tuple(parts)


class VersionRelation(str, Enum):
    EXACT = "EXACT"
    REVISION_DIFF = "REVISION_DIFF"
    PATCH_DIFF = "PATCH_DIFF"
    MINOR_DIFF = "MINOR_DIFF"
    MAJOR_DIFF = "MAJOR_DIFF"
    INCOMPARABLE = "INCOMPARABLE"


def compare_versions(declared: str | None, observed: str | None) -> VersionRelation:
    """How far apart two product versions are.

    Only ``EXACT`` means "this document describes this deployment". A patch
    difference is a `PARTIAL_MATCH` — the bank still has to read the advisory,
    but the crypto inventory is usually the same. A minor or major difference is
    a different product generation and the declaration does not travel with it.
    """
    left, right = version_tokens(declared), version_tokens(observed)
    if not left or not right:
        return VersionRelation.INCOMPARABLE
    if left == right:
        return VersionRelation.EXACT
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    if padded_left == padded_right:
        return VersionRelation.REVISION_DIFF
    for index in range(width):
        if padded_left[index] == padded_right[index]:
            continue
        # A textual suffix ("RC1") is a revision-level difference, not a major one.
        if isinstance(padded_left[index], str) or isinstance(padded_right[index], str):
            return VersionRelation.REVISION_DIFF
        if index == 0:
            return VersionRelation.MAJOR_DIFF
        if index == 1:
            return VersionRelation.MINOR_DIFF
        if index == 2:
            return VersionRelation.PATCH_DIFF
        return VersionRelation.REVISION_DIFF
    return VersionRelation.EXACT


# --------------------------------------------------------------------------- #
# 8. vendor evidence applicability
# --------------------------------------------------------------------------- #


class Applicability(str, Enum):
    """Whether a vendor document applies to what the bank actually runs."""

    MATCHED = "MATCHED"
    PARTIAL_MATCH = "PARTIAL_MATCH"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    PRODUCT_MISMATCH = "PRODUCT_MISMATCH"
    DEPLOYMENT_UNVERIFIED = "DEPLOYMENT_UNVERIFIED"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"
    UNKNOWN = "UNKNOWN"


APPLICABILITY_STATES: tuple[str, ...] = tuple(state.value for state in Applicability)

#: States in which a declaration may inform a capability claim at all.
APPLICABLE_STATES = frozenset({Applicability.MATCHED.value, Applicability.PARTIAL_MATCH.value})


@dataclass(frozen=True)
class VendorDeclaration:
    """One versioned statement from a vendor, with the document behind it."""

    identity: ProductIdentity
    document: str
    issued_at: date | None = None
    valid_until: date | None = None
    max_age_days: int = 365
    superseded_by: str | None = None
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.document:
            raise ValueError("a declaration without a document cannot be audited")

    @property
    def declaration_id(self) -> str:
        payload = json.dumps({"identity": self.identity.to_dict(), "document": self.document,
                              "issued_at": _iso_date(self.issued_at),
                              "capabilities": list(self.capabilities)}, sort_keys=True)
        return f"VD-{hashlib.sha256(payload.encode()).hexdigest()[:12]}"


@dataclass(frozen=True)
class ApplicabilityResult:
    state: Applicability
    version_relation: VersionRelation
    reasons: tuple[str, ...]
    declaration_id: str | None = None

    @property
    def applicable(self) -> bool:
        return self.state.value in APPLICABLE_STATES

    @property
    def vendor_capabilities_usable(self) -> bool:
        """The narrow question every VBOM row asks before it cites a vendor claim."""
        return self.applicable

    def to_dict(self) -> dict[str, Any]:
        return {"applicability": self.state.value,
                "version_relation": self.version_relation.value,
                "vendor_capabilities_usable": self.vendor_capabilities_usable,
                "reasons": list(self.reasons),
                "declaration_id": self.declaration_id}


def _expiry(declaration: VendorDeclaration, as_of: date) -> tuple[str, str] | None:
    """``("EXPIRED", reason)`` when the document is out of date, else ``None``."""
    if declaration.valid_until is not None:
        end = _as_date(declaration.valid_until)
        if end is not None and as_of > end:
            return "EXPIRED", f"the document expired on {end.isoformat()}"
    issued = _as_date(declaration.issued_at)
    if issued is not None and declaration.max_age_days:
        limit = issued + timedelta(days=int(declaration.max_age_days))
        if as_of > limit:
            age = (as_of - issued).days
            return "EXPIRED", (f"the document was issued {age} days ago, past its "
                               f"{declaration.max_age_days}-day validity")
    return None


def assess_applicability(declaration: VendorDeclaration, deployment: ProductIdentity, *,
                         as_of: date | None = None) -> ApplicabilityResult:
    """Does this vendor document describe this deployment?

    The order of checks is the order a reviewer would ask them: is it the same
    vendor and product, is the bank's version even known, is the document
    superseded or stale, and only then — do the versions line up?
    """
    as_of = as_of or date.today()
    reasons: list[str] = []
    relation = compare_versions(declaration.identity.version, deployment.version)

    if declaration.superseded_by:
        reasons.append(f"superseded by {declaration.superseded_by}")
        return ApplicabilityResult(Applicability.SUPERSEDED, relation, tuple(reasons),
                                   declaration.declaration_id)
    if declaration.identity.key() != deployment.key():
        reasons.append(
            f"declared {declaration.identity.vendor} {declaration.identity.product}, "
            f"deployed {deployment.vendor} {deployment.product}")
        return ApplicabilityResult(Applicability.PRODUCT_MISMATCH, relation, tuple(reasons),
                                   declaration.declaration_id)

    expired = _expiry(declaration, as_of)
    if expired:
        reasons.append(expired[1])
        return ApplicabilityResult(Applicability.EXPIRED, relation, tuple(reasons),
                                   declaration.declaration_id)

    if not deployment.version:
        reasons.append("the deployment has no observed version, so no document can be said "
                       "to describe it")
        return ApplicabilityResult(Applicability.DEPLOYMENT_UNVERIFIED, relation,
                                   tuple(reasons), declaration.declaration_id)
    if not declaration.identity.version:
        reasons.append("the declaration states no version, so it cannot be matched")
        return ApplicabilityResult(Applicability.UNKNOWN, relation, tuple(reasons),
                                   declaration.declaration_id)

    if relation is VersionRelation.EXACT:
        reasons.append(f"declared and deployed version are both "
                       f"{declaration.identity.version}")
        return ApplicabilityResult(Applicability.MATCHED, relation, tuple(reasons),
                                   declaration.declaration_id)
    if relation in {VersionRelation.PATCH_DIFF, VersionRelation.REVISION_DIFF}:
        reasons.append(
            f"declared {declaration.identity.version}, deployed {deployment.version}: "
            "same generation, different build — the vendor's own advisory decides whether "
            "the difference matters")
        return ApplicabilityResult(Applicability.PARTIAL_MATCH, relation, tuple(reasons),
                                   declaration.declaration_id)
    reasons.append(
        f"declared {declaration.identity.version}, deployed {deployment.version}: a "
        "different generation, so the declared crypto inventory does not travel")
    return ApplicabilityResult(Applicability.VERSION_MISMATCH, relation, tuple(reasons),
                               declaration.declaration_id)


# --------------------------------------------------------------------------- #
# 14. freshness
# --------------------------------------------------------------------------- #


class Freshness(str, Enum):
    FRESH = "FRESH"
    STALE = "STALE"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


def freshness(observed_at: Any, *, as_of: date | None = None,
              max_age_days: int = 365) -> dict[str, Any]:
    """How old one piece of evidence is, in the terms a reviewer reads.

    ``STALE`` is not a failure and not a pass: it is a statement that the estate
    is showing a 2024 questionnaire in 2026 and must say so. At twice the
    validity window the row is `EXPIRED` and cannot support a "PQC ready" claim.
    """
    as_of = as_of or date.today()
    stamp = _as_date(observed_at)
    if stamp is None:
        return {"state": Freshness.UNKNOWN.value, "age_days": None,
                "last_verified": None, "stale_after_days": max_age_days,
                "statement": "no verification date, so the age of this evidence is unknown"}
    age = (as_of - stamp).days
    if age < 0:
        return {"state": Freshness.UNKNOWN.value, "age_days": age,
                "last_verified": stamp.isoformat(), "stale_after_days": max_age_days,
                "statement": "the verification date is in the future, which is not evidence"}
    if age <= max_age_days:
        state = Freshness.FRESH.value
        statement = f"verified {age} days ago"
    elif age <= max_age_days * 2:
        state = Freshness.STALE.value
        statement = (f"last verified {stamp.isoformat()}, {age} days ago — past the "
                     f"{max_age_days}-day review window")
    else:
        state = Freshness.EXPIRED.value
        statement = (f"last verified {stamp.isoformat()}, {age} days ago — more than twice "
                     "the review window, so it cannot support a current claim")
    return {"state": state, "age_days": age, "last_verified": stamp.isoformat(),
            "stale_after_days": max_age_days, "statement": statement}


# --------------------------------------------------------------------------- #
# 13. the capability claim
# --------------------------------------------------------------------------- #


class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"                    # declared and observed on the bank's asset
    CORROBORATED = "CORROBORATED"              # declared and observed at runtime or network
    DECLARED_ONLY = "DECLARED_ONLY"            # the vendor says so and nothing else does
    BANK_OBSERVED_ONLY = "BANK_OBSERVED_ONLY"  # the bank sees it; the vendor never said so
    CONFIGURED_ONLY = "CONFIGURED_ONLY"        # a bank config names it, nothing exercises it
    CONFLICTED = "CONFLICTED"
    STALE = "STALE"
    INAPPLICABLE = "INAPPLICABLE"              # the declaration does not describe this asset
    UNKNOWN = "UNKNOWN"


@dataclass
class CapabilityClaim:
    """One crypto capability of one asset, with every piece of evidence for it.

    This is the record the review asked for in item 13: it keeps algorithm,
    size, curve, mode, purpose, provider and product identity *and* the evidence
    trail — because "RSA-2048" alone cannot be audited, and a single
    ``pqc_ready`` boolean cannot be defended.
    """

    asset_id: str
    algorithm: str
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    purpose: str | None = None
    provider: str | None = None
    product: ProductIdentity | None = None
    firmware_version: str | None = None
    discovery_method: str | None = None
    source_document: str | None = None
    source_hash: str | None = None
    observed_at: date | None = None
    valid_from: date | None = None
    valid_until: date | None = None
    applicability: ApplicabilityResult | None = None
    evidence: tuple[Evidence, ...] = ()
    conflict: bool = False

    def __post_init__(self) -> None:
        if not str(self.asset_id or "").strip():
            raise ValueError("a capability belongs to an asset; an unowned claim is not auditable")
        if not str(self.algorithm or "").strip():
            raise ValueError("algorithm is required")
        self.evidence = tuple(self.evidence)

    # -- the six flags a reviewer reads ---------------------------------- #

    @property
    def vendor_declared(self) -> bool:
        """A vendor claim that applies to *this* asset, or nothing.

        This is the gate the whole module exists for: a declaration attached to
        firmware 8.2 does not light this flag on an 8.4 appliance.
        """
        if self.applicability is not None and not self.applicability.applicable:
            return False
        return any(item.kind in {EvidenceType.DECLARED, EvidenceType.IMPORTED}
                   for item in self.evidence)

    @property
    def bank_observed(self) -> bool:
        return any(item.kind == EvidenceType.OBSERVED for item in self.evidence)

    @property
    def runtime_observed(self) -> bool:
        return any(item.kind in {EvidenceType.RUNTIME_OBSERVED, EvidenceType.NETWORK_OBSERVED}
                   for item in self.evidence)

    @property
    def production_usage(self) -> bool:
        return any(item.kind == EvidenceType.CONFIGURED for item in self.evidence)

    @property
    def version_matched(self) -> bool:
        return self.applicability is not None and self.applicability.applicable

    @property
    def evidence_fresh(self, *, as_of: date | None = None) -> bool:
        state = freshness(self.observed_at, as_of=as_of)["state"]
        return state in {Freshness.FRESH.value, Freshness.STALE.value}

    @property
    def freshness(self) -> dict[str, Any]:
        return freshness(self.observed_at)

    @property
    def verification_status(self) -> VerificationStatus:
        if self.conflict:
            return VerificationStatus.CONFLICTED
        if self.applicability is not None and not self.applicability.applicable:
            return VerificationStatus.INAPPLICABLE
        if not self.evidence:
            return VerificationStatus.UNKNOWN
        if not self.evidence_fresh:
            return VerificationStatus.STALE
        if self.vendor_declared and self.runtime_observed:
            return VerificationStatus.CORROBORATED
        if self.vendor_declared and self.bank_observed:
            return VerificationStatus.CONFIRMED
        if self.runtime_observed or self.bank_observed:
            return VerificationStatus.BANK_OBSERVED_ONLY
        if self.production_usage:
            return VerificationStatus.CONFIGURED_ONLY
        if self.vendor_declared:
            return VerificationStatus.DECLARED_ONLY
        return VerificationStatus.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "asset_id": self.asset_id,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "curve": self.curve,
            "mode": self.mode,
            "purpose": self.purpose,
            "provider": self.provider,
            "product": self.product.to_dict() if self.product else None,
            "firmware_version": self.firmware_version,
            "discovery_method": self.discovery_method,
            "source_document": self.source_document,
            "source_hash": self.source_hash,
            "observed_at": _iso_date(self.observed_at),
            "valid_from": _iso_date(self.valid_from),
            "valid_until": _iso_date(self.valid_until),
            "applicability": self.applicability.to_dict() if self.applicability else {
                "applicability": Applicability.UNKNOWN.value,
                "vendor_capabilities_usable": False,
                "reasons": ["no vendor declaration was checked against this asset"]},
            "confidence": self.confidence,
            "verification_status": self.verification_status.value,
            "verification": {
                "vendor_declared": self.vendor_declared,
                "bank_observed": self.bank_observed,
                "runtime_observed": self.runtime_observed,
                "production_usage": self.production_usage,
                "version_matched": self.version_matched,
                "evidence_fresh": self.evidence_fresh,
            },
            "freshness": self.freshness,
            "evidence": [item.to_dict() for item in self.evidence],
        }

    @property
    def confidence(self) -> str:
        """Confidence is the weakest link, not the loudest source."""
        if self.conflict or (self.applicability is not None
                             and not self.applicability.applicable):
            return "LOW"
        if not self.evidence:
            return "UNKNOWN"
        if self.runtime_observed and self.bank_observed:
            return "HIGH"
        if self.bank_observed or self.production_usage:
            return "MEDIUM"
        return "LOW"


def claims_from_declaration(declaration: VendorDeclaration, deployment: ProductIdentity, *,
                            asset_id: str, as_of: date | None = None,
                            extra_evidence: Iterable[Evidence] = ()) -> list[CapabilityClaim]:
    """Turn a vendor document into claims — *only* if it applies to the asset.

    When it does not apply, the claims are still returned, carrying the
    applicability result and no capability. Dropping them silently would hide a
    mismatch the reviewer needs to see; promoting them would be the exact defect
    the review named.
    """
    result = assess_applicability(declaration, deployment, as_of=as_of)
    declared = [Evidence(EvidenceType.DECLARED, f"{declaration.document}#{capability}",
                         observed_at=declaration.issued_at,
                         source_document=declaration.document)
                for capability in declaration.capabilities] if result.applicable else []
    claims: list[CapabilityClaim] = []
    for index, capability in enumerate(declaration.capabilities or ("UNSPECIFIED",)):
        evidence = tuple(declared[index:index + 1]) + tuple(extra_evidence)
        claims.append(CapabilityClaim(
            asset_id=asset_id, algorithm=capability, product=deployment,
            provider=deployment.vendor, discovery_method="vendor-declaration",
            source_document=declaration.document, observed_at=declaration.issued_at,
            valid_until=declaration.valid_until, applicability=result, evidence=evidence))
    return claims


# --------------------------------------------------------------------------- #
# 15. reconciliation across sources
# --------------------------------------------------------------------------- #


class ReconciliationState(str, Enum):
    AGREE = "AGREE"
    CONFLICT = "CONFLICT"
    PARTIAL = "PARTIAL"
    SINGLE_SOURCE = "SINGLE_SOURCE"
    UNKNOWN = "UNKNOWN"


def _less_specific(shorter: str, longer: str) -> bool:
    """``"3.0"`` is a less specific form of ``"3.0.11"``; ``"3.0.13"`` is not."""
    if not shorter or not longer or shorter == longer:
        return False
    if not longer.startswith(shorter):
        return False
    return longer[len(shorter)] in ".-_ ,"


def reconcile(attribute: str, observations: Mapping[Any, Any], *,
              sources: Mapping[Any, EvidenceType] | None = None) -> dict[str, Any]:
    """Compare one attribute as several sources see it — and never average them.

    ``observations`` maps a source label (``"vendor"``, ``"sbom"``, ``"runtime"``)
    to the value that source reports. The result keeps every row: a VBOM that
    prints OpenSSL 3.0.13 because the vendor said so, while the SBOM and the
    runtime both say 3.0.11, is not a summary — it is a false statement.
    """
    sources = dict(sources or {})
    rows = []
    for label, value in observations.items():
        kind = sources.get(label, EvidenceType.UNKNOWN)
        if not isinstance(kind, EvidenceType):
            kind = EvidenceType(kind)
        rows.append({"source": str(label), "value": value, "evidence_type": kind.value,
                     "evidence_rank": EVIDENCE_RANK[kind.value]})
    stated = [row for row in rows if row["value"] not in (None, "")]
    if not stated:
        state = ReconciliationState.UNKNOWN
    else:
        distinct = {_norm(row["value"]) for row in stated}
        if len(stated) == 1:
            state = ReconciliationState.SINGLE_SOURCE
        elif len(distinct) == 1:
            state = ReconciliationState.AGREE
        elif all(_less_specific(a, b) or _less_specific(b, a)
                 for index, a in enumerate(distinct) for b in list(distinct)[index + 1:]):
            # Every pair differs only by precision ("3.0" against "3.0.11"), so no
            # two sources contradict each other — one simply says less.
            state = ReconciliationState.PARTIAL
        else:
            state = ReconciliationState.CONFLICT
    strongest_row = max(stated, key=lambda row: row["evidence_rank"]) if stated else None
    return {
        "attribute": attribute,
        "state": state.value,
        "row_count": len(stated),
        "distinct_values": sorted({str(row["value"]) for row in stated}),
        # The strongest evidence is offered as a reading, and never as a correction
        # of the others: the conflict is the finding.
        "strongest_evidence_type": strongest_row["evidence_type"] if strongest_row else None,
        "rows": rows,
        "statement": _reconcile_statement(attribute, state, stated),
    }


def _reconcile_statement(attribute: str, state: ReconciliationState,
                         stated: Sequence[Mapping[str, Any]]) -> str:
    if state is ReconciliationState.UNKNOWN:
        return f"no source states {attribute}, so its value is unknown rather than defaulted"
    if state is ReconciliationState.SINGLE_SOURCE:
        return (f"only {stated[0]['source']} states {attribute} "
                f"({stated[0]['value']}); that is a fact about one source, not corroboration")
    if state is ReconciliationState.AGREE:
        return (f"{len(stated)} source(s) agree on {attribute} = {stated[0]['value']}")
    if state is ReconciliationState.CONFLICT:
        values = ", ".join(f"{row['source']}={row['value']}" for row in stated)
        return (f"CONFLICT on {attribute}: {values} — the disagreement is the finding and "
                "is reported with every row attached")
    return (f"sources differ on {attribute} and the strongest evidence outranks the rest: "
            + ", ".join(f"{row['source']}={row['value']}" for row in stated))


def reconcile_capabilities(claims: Iterable[CapabilityClaim], *,
                           as_of: date | None = None) -> list[dict[str, Any]]:
    """Group claims by asset+algorithm and reconcile their algorithm identity."""
    grouped: dict[tuple[str, str], list[CapabilityClaim]] = {}
    for claim in claims:
        grouped.setdefault((claim.asset_id, claim.algorithm.upper()), []).append(claim)
    reports = []
    for (asset_id, algorithm), group in sorted(grouped.items()):
        observations = {}
        sources = {}
        for claim in group:
            label = claim.discovery_method or "unknown"
            for item in claim.evidence:
                observations[f"{label}:{item.kind.value}"] = (
                    claim.key_size or claim.curve or claim.mode or algorithm)
                sources[f"{label}:{item.kind.value}"] = item.kind
        report = reconcile(f"{asset_id}/{algorithm}", observations, sources=sources)
        report["asset_id"] = asset_id
        report["algorithm"] = algorithm
        report["verification_status"] = _group_status(group, as_of=as_of)
        report["evidence"] = sorted({item.evidence_id for claim in group
                                    for item in claim.evidence})
        reports.append(report)
    return reports


def _group_status(group: Sequence[CapabilityClaim], *, as_of: date | None) -> str:
    """One status for every claim about the same asset and algorithm.

    Computed from the *union* of the claims' evidence, because that is the whole
    point of grouping them: a vendor row and an observation row are two halves of
    one answer, and neither half alone may be reported as the answer.
    """
    fresh = [claim for claim in group
             if freshness(claim.observed_at, as_of=as_of)["state"]
             in {Freshness.FRESH.value, Freshness.STALE.value}]
    pool = fresh or list(group)
    if any(claim.conflict for claim in group):
        return VerificationStatus.CONFLICTED.value
    if not any(claim.verification_status is not VerificationStatus.INAPPLICABLE
               for claim in group):
        return VerificationStatus.INAPPLICABLE.value
    declared = any(claim.vendor_declared for claim in pool)
    observed = any(claim.bank_observed for claim in pool)
    runtime = any(claim.runtime_observed for claim in pool)
    configured = any(claim.production_usage for claim in pool)
    if declared and runtime:
        return VerificationStatus.CORROBORATED.value
    if declared and observed:
        return VerificationStatus.CONFIRMED.value
    if observed or runtime:
        return VerificationStatus.BANK_OBSERVED_ONLY.value
    if configured:
        return VerificationStatus.CONFIGURED_ONLY.value
    if declared:
        return (VerificationStatus.DECLARED_ONLY.value if fresh
                else VerificationStatus.STALE.value)
    return VerificationStatus.UNKNOWN.value


# --------------------------------------------------------------------------- #
# 9. structured due diligence
# --------------------------------------------------------------------------- #

#: The twenty-two sections the review asked a bank procurement record to hold.
#: A section that is missing is named; it is never silently worth zero points.
DUE_DILIGENCE_SECTIONS: tuple[str, ...] = (
    "vendor_identity", "product", "product_version", "contract", "support_lifecycle",
    "end_of_life", "security_advisories", "crypto_capabilities", "pqc_roadmap",
    "certifications", "fips_claims", "common_criteria_claims", "secure_development",
    "sbom_availability", "cbom_availability", "vulnerability_disclosure",
    "incident_history", "supply_chain_evidence", "last_review", "reviewer",
    "review_status", "evidence",
)

REVIEW_STATUSES = ("APPROVED", "CONDITIONAL", "PENDING", "REJECTED", "NOT_REVIEWED")


def evaluate_due_diligence(sections: Mapping[str, Any], *, as_of: date | None = None,
                           max_age_days: int = 365) -> dict[str, Any]:
    """Which due-diligence sections are present, which are empty, and how old.

    An empty string and a missing key are different answers — "the vendor says
    nothing about SBOM" is a finding, while "nobody asked" is a process gap — so
    both are named separately.
    """
    as_of = as_of or date.today()
    missing = [name for name in DUE_DILIGENCE_SECTIONS if sections.get(name) in (None, "", [], {})]
    present = [name for name in DUE_DILIGENCE_SECTIONS if name not in missing]
    review_state = str(sections.get("review_status") or "NOT_REVIEWED").upper()
    if review_state not in REVIEW_STATUSES:
        raise ValueError(f"unknown review status {review_state!r}; "
                         f"expected one of {REVIEW_STATUSES}")
    age = freshness(sections.get("last_review"), as_of=as_of, max_age_days=max_age_days)
    completeness = round(100 * len(present) / len(DUE_DILIGENCE_SECTIONS), 1)
    blockers: list[str] = []
    if review_state not in {"APPROVED", "CONDITIONAL"}:
        blockers.append(f"review status is {review_state}")
    if age["state"] in {Freshness.STALE.value, Freshness.EXPIRED.value,
                        Freshness.UNKNOWN.value}:
        blockers.append(f"the last review is {age['state'].lower()}: {age['statement']}")
    for section in ("sbom_availability", "cbom_availability", "end_of_life",
                    "vulnerability_disclosure"):
        if section in missing:
            blockers.append(f"no {section} on record")
    return {
        "sections_expected": len(DUE_DILIGENCE_SECTIONS),
        "sections_present": len(present),
        "complete": not missing,
        "completeness": completeness,
        "missing": missing,
        "present": present,
        "review_status": review_state,
        "review_age": age,
        "blockers": blockers,
        "status": "COMPLETE" if not missing and not blockers else "INCOMPLETE",
    }


# --------------------------------------------------------------------------- #
# 10. product lifecycle
# --------------------------------------------------------------------------- #


class LifecycleState(str, Enum):
    CURRENT = "CURRENT"
    SUPPORTED = "SUPPORTED"
    MAINTENANCE = "MAINTENANCE"
    END_OF_SUPPORT = "END_OF_SUPPORT"
    END_OF_LIFE = "END_OF_LIFE"
    RETIRED = "RETIRED"


LIFECYCLE_ORDER: tuple[str, ...] = tuple(state.value for state in LifecycleState)

#: Past these, a product cannot be part of a crypto migration plan that assumes
#: vendor fixes exist.
UNSUPPORTED_STATES = frozenset({LifecycleState.END_OF_SUPPORT.value,
                                LifecycleState.END_OF_LIFE.value,
                                LifecycleState.RETIRED.value})


@dataclass(frozen=True)
class Lifecycle:
    product: ProductIdentity
    state: LifecycleState
    support_ends_on: date | None = None
    end_of_life_on: date | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", LifecycleState(self.state))

    def effective_state(self, *, as_of: date | None = None) -> LifecycleState:
        """The state the dates imply, when a declared state has fallen behind.

        A product recorded as `SUPPORTED` whose support ended last month is not
        supported; the record is stale and the dates win.
        """
        as_of = as_of or date.today()
        if self.end_of_life_on and as_of >= self.end_of_life_on:
            return LifecycleState.END_OF_LIFE
        if self.support_ends_on and as_of >= self.support_ends_on:
            return LifecycleState.END_OF_SUPPORT
        return self.state

    def to_dict(self, *, as_of: date | None = None) -> dict[str, Any]:
        effective = self.effective_state(as_of=as_of)
        return {"product": self.product.to_dict(), "declared_state": self.state.value,
                "effective_state": effective.value,
                "unsupported": effective.value in UNSUPPORTED_STATES,
                "support_ends_on": _iso_date(self.support_ends_on),
                "end_of_life_on": _iso_date(self.end_of_life_on),
                "source": self.source,
                "drifted": effective is not self.state}


# --------------------------------------------------------------------------- #
# 11 / 12. dependency chains
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HardwareDependency:
    """One deployed appliance, and the estate that sits on top of it."""

    asset_id: str
    product: ProductIdentity
    applications: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    business_systems: tuple[str, ...] = ()
    critical_systems: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class SoftwareDependency:
    """One vendor software component, and what ships it."""

    vendor: str
    product: str
    component: str
    version: str | None
    applications: tuple[str, ...] = ()
    containers: tuple[str, ...] = ()
    systems: tuple[str, ...] = ()
    critical_services: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()


def vendor_exposure(assets: Iterable[HardwareDependency], *, vendor: str | None = None,
                    product: str | None = None) -> dict[str, Any]:
    """Which bank systems depend on this vendor's product?

    Counts are per-set, never summed across levels: three appliances running two
    applications is not five of anything, and a reader that adds the levels
    together produces the number a risk committee will later have to un-learn.
    """
    selected = [asset for asset in assets
                if (vendor is None or _norm(asset.product.vendor) == _norm(vendor))
                and (product is None or _norm(asset.product.product) == _norm(product))]
    applications = sorted({name for asset in selected for name in asset.applications})
    services = sorted({name for asset in selected for name in asset.services})
    systems = sorted({name for asset in selected for name in asset.business_systems})
    critical = sorted({name for asset in selected for name in asset.critical_systems})
    return {
        "vendor": vendor, "product": product,
        "assets": sorted({asset.asset_id for asset in selected}),
        "asset_count": len({asset.asset_id for asset in selected}),
        "applications": applications,
        "services": services,
        "business_systems": systems,
        "critical_systems": critical,
        "statement": _exposure_statement(selected, applications, services, critical),
        "evidence": sorted({item.evidence_id for asset in selected for item in asset.evidence}),
    }


def _exposure_statement(assets: Sequence[HardwareDependency], applications: Sequence[str],
                        services: Sequence[str], critical: Sequence[str]) -> str:
    if not assets:
        return "no deployment of this vendor product is recorded — which is not the same as none"
    return (f"{len({asset.asset_id for asset in assets})} asset(s) carry this product, "
            f"reaching {len(applications)} application(s), {len(services)} service(s) and "
            f"{len(critical)} critical system(s)")


def software_impact(component: str, dependencies: Iterable[SoftwareDependency], *,
                    version: str | None = None) -> dict[str, Any]:
    """If this vendor component is end-of-life, what breaks?

    ``version`` narrows the question to the versions that are actually
    installed; without it the answer covers every version the estate runs, which
    is the honest answer to "what uses this component at all".
    """
    selected = [row for row in dependencies
                if _norm(row.component) == _norm(component)
                and (version is None or str(row.version or "") == version)]
    return {
        "component": component, "version": version,
        "installed_versions": sorted({str(row.version) for row in selected if row.version}),
        "applications": sorted({name for row in selected for name in row.applications}),
        "containers": sorted({name for row in selected for name in row.containers}),
        "systems": sorted({name for row in selected for name in row.systems}),
        "critical_services": sorted({name for row in selected
                                     for name in row.critical_services}),
        "statement": (f"{len(selected)} deployment(s) of {component}"
                      + (f" {version}" if version else "")
                      + f" reach {len({name for row in selected for name in row.applications})} "
                        "application(s)"),
    }


# --------------------------------------------------------------------------- #
# 16. evidence-based risk
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RiskFactor:
    name: str
    points: int
    state: str
    reason: str
    evidence: tuple[str, ...] = ()


RISK_SEVERITIES = ((70, "CRITICAL"), (45, "HIGH"), (20, "MEDIUM"), (0, "LOW"))


def vendor_risk(*, critical_systems: int = 0, weak_algorithms: Sequence[str] = (),
                lifecycle: Lifecycle | None = None, pqc_available: bool | None = None,
                stale_evidence: bool = False, deployment_verified: bool | None = None,
                sbom_available: bool | None = None, open_advisories: int = 0,
                supply_chain_evidence: bool = False, business_criticality: str | None = None,
                crypto_dependency: bool | None = None,
                as_of: date | None = None) -> dict[str, Any]:
    """A vendor rating that can be explained, factor by factor.

    Every point is attached to a named factor with the evidence behind it, so
    "CRITICAL" is a sentence a risk committee can argue with — not a colour
    somebody typed into a field.
    """
    as_of = as_of or date.today()
    factors: list[RiskFactor] = []

    def add(name: str, points: int, state: str, reason: str, evidence: Iterable[str] = ()) -> None:
        if points:
            factors.append(RiskFactor(name, points, state, reason, tuple(evidence)))

    if critical_systems:
        add("critical_systems_affected", min(30, 10 + 5 * critical_systems), "CRITICAL",
            f"{critical_systems} critical system(s) depend on this vendor")
    if crypto_dependency:
        add("crypto_dependency", 15, "WARNING",
            "the estate's crypto path runs through this vendor's product")
    if weak_algorithms:
        add("weak_algorithms", min(25, 5 * len(weak_algorithms)), "WARNING",
            f"{len(weak_algorithms)} weak or deprecated algorithm(s) declared: "
            + ", ".join(sorted(weak_algorithms)[:5]))
    if lifecycle is not None:
        effective = lifecycle.effective_state(as_of=as_of)
        if effective.value in UNSUPPORTED_STATES:
            add("product_lifecycle", 25, "CRITICAL",
                f"the product is {effective.value}; the vendor will not ship a fix",
                [lifecycle.source] if lifecycle.source else [])
        elif effective.value == LifecycleState.MAINTENANCE.value:
            add("product_lifecycle", 10, "WARNING",
                "the product is in maintenance: fixes only, no new capability",
                [lifecycle.source] if lifecycle.source else [])
    if pqc_available is False:
        add("pqc_capability", 20, "WARNING",
            "the vendor declares no post-quantum capability for this product")
    elif pqc_available is None:
        add("pqc_capability", 10, "UNKNOWN",
            "the vendor has not stated a post-quantum position")
    if stale_evidence:
        add("evidence_freshness", 15, "WARNING",
            "the vendor's questionnaire or document is past its review window")
    if deployment_verified is False:
        add("deployment_verification", 15, "WARNING",
            "no bank observation confirms the declared capability is deployed")
    if sbom_available is False:
        add("sbom_availability", 10, "WARNING",
            "the vendor publishes no SBOM for this product")
    if open_advisories:
        add("vulnerability_history", min(15, 5 * open_advisories), "WARNING",
            f"{open_advisories} open advisory/advisories affect this product")
    if not supply_chain_evidence:
        add("supply_chain_evidence", 10, "UNKNOWN",
            "no supply-chain attestation is on record")
    if str(business_criticality or "").upper() in {"CRITICAL", "HIGH"}:
        add("business_criticality", 10 if str(business_criticality).upper() == "CRITICAL" else 5,
            "WARNING", f"the business system is rated {str(business_criticality).upper()}")

    score = min(100, sum(factor.points for factor in factors))
    severity = next(label for threshold, label in RISK_SEVERITIES if score >= threshold)
    return {
        "score": score,
        "severity": severity,
        "factors": [{"factor": factor.name, "points": factor.points, "state": factor.state,
                     "reason": factor.reason, "evidence": list(factor.evidence)}
                    for factor in sorted(factors, key=lambda item: -item.points)],
        "explainable": all(factor.reason for factor in factors),
        "statement": (f"{severity} ({score}/100) from {len(factors)} factor(s): "
                      + "; ".join(f"{factor.name} +{factor.points}"
                                  for factor in sorted(factors, key=lambda i: -i.points))),
    }


# --------------------------------------------------------------------------- #
# drift vocabulary
# --------------------------------------------------------------------------- #

#: One event name per applicability state, so an expired document is not filed as
#: a version mismatch simply because the claim was refused.
_STATE_EVENTS: dict[Applicability, str] = {
    Applicability.PRODUCT_MISMATCH: "VENDOR_PRODUCT_MISMATCH",
    Applicability.VERSION_MISMATCH: "VENDOR_VERSION_MISMATCH",
    Applicability.DEPLOYMENT_UNVERIFIED: "VENDOR_DEPLOYMENT_UNVERIFIED",
    Applicability.EXPIRED: "VENDOR_DOCUMENT_EXPIRED",
    Applicability.SUPERSEDED: "VENDOR_DOCUMENT_SUPERSEDED",
    Applicability.UNKNOWN: "VENDOR_EVIDENCE_UNKNOWN",
}


#: The event names this module can emit, and the condition each one records.
VENDOR_EVENTS: dict[str, str] = {
    "CAPABILITY_DECLARED": "a vendor document states a capability for a product version",
    "CAPABILITY_OBSERVED": "a bank collector read that capability on the asset",
    "USAGE_OBSERVED": "a configuration or a runtime observation proves the capability is used",
    "VENDOR_EVIDENCE_STALE": "the vendor evidence behind a claim is past its review window",
    "VENDOR_DOCUMENT_SUPERSEDED": "a newer vendor document replaces the cited one",
    "VENDOR_DEPLOYMENT_UNVERIFIED": "a declaration exists and no deployment version does",
    "VENDOR_VERSION_MISMATCH": "the declaration and the deployment are different generations",
    "VENDOR_PRODUCT_MISMATCH": "the declaration is about a different vendor or product",
    "VENDOR_DOCUMENT_EXPIRED": "the cited vendor document is past its validity window",
    "VENDOR_EVIDENCE_UNKNOWN": "the declaration carries no version, so it cannot be matched",
    "EVIDENCE_CONFLICT": "two sources disagree about the same attribute",
}


def events_for(claims: Iterable[CapabilityClaim], *, as_of: date | None = None,
               reconciliations: Iterable[Mapping[str, Any]] = ()) -> list[dict[str, Any]]:
    """Translate claim state into the shared drift vocabulary.

    A vendor document does not emit `CAPABILITY_OBSERVED`, and a bank observation
    does not emit `CAPABILITY_DECLARED` — which is the distinction the review
    asked for, expressed as event names rather than as prose.
    """
    as_of = as_of or date.today()
    events: list[dict[str, Any]] = []

    def emit(name: str, asset: str, detail: str, evidence: Iterable[str] = ()) -> None:
        events.append({"event_type": name, "asset_id": asset, "detail": detail,
                       "at": as_of.isoformat(), "evidence": sorted(set(evidence))})

    for claim in claims:
        applied = claim.applicability.applicable if claim.applicability else False
        if claim.vendor_declared:
            emit("CAPABILITY_DECLARED", claim.asset_id,
                 f"{claim.algorithm} declared for {claim.product.version if claim.product else '?'}",
                 (item.evidence_id for item in claim.evidence
                  if item.kind in {EvidenceType.DECLARED, EvidenceType.IMPORTED}))
        elif claim.applicability is not None and not applied:
            name = _STATE_EVENTS.get(claim.applicability.state, "VENDOR_VERSION_MISMATCH")
            emit(name, claim.asset_id,
                 f"{claim.algorithm}: {claim.applicability.state.value} — "
                 + "; ".join(claim.applicability.reasons),
                 (item.evidence_id for item in claim.evidence))
        if claim.bank_observed:
            emit("CAPABILITY_OBSERVED", claim.asset_id,
                 f"{claim.algorithm} read on the asset",
                 (item.evidence_id for item in claim.evidence
                  if item.kind is EvidenceType.OBSERVED))
        if claim.runtime_observed or claim.production_usage:
            emit("USAGE_OBSERVED", claim.asset_id,
                 f"{claim.algorithm} is used, not merely supported",
                 (item.evidence_id for item in claim.evidence
                  if item.kind in {EvidenceType.RUNTIME_OBSERVED,
                                   EvidenceType.NETWORK_OBSERVED,
                                   EvidenceType.CONFIGURED}))
        if claim.freshness["state"] in {Freshness.STALE.value, Freshness.EXPIRED.value}:
            emit("VENDOR_EVIDENCE_STALE", claim.asset_id, claim.freshness["statement"],
                 (item.evidence_id for item in claim.evidence))
    for report in reconciliations:
        if report.get("state") == ReconciliationState.CONFLICT.value:
            emit("EVIDENCE_CONFLICT", str(report.get("asset_id") or ""),
                 report.get("statement", ""), report.get("evidence") or ())
    return events


#: Families that are post-quantum by construction. Everything else is either a
#: classical asymmetric algorithm (broken by Shor) or a symmetric primitive,
#: which is why the VBOM row carries a basis string beside the boolean.
PQC_FAMILIES = ("ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "SPHINCS", "KYBER", "DILITHIUM",
                "BIKE", "HQC", "NTRU")
CLASSICAL_ASYMMETRIC = ("RSA", "ECDSA", "ECDH", "EDDSA", "DH", "DSA", "X25519", "ELGAMAL")


def pqc_basis(algorithm: str) -> tuple[bool, str]:
    """Whether a named algorithm is post-quantum, and on what basis.

    A boolean alone is not auditable: "AES-256 is PQC ready" and "ML-DSA-65 is PQC
    ready" are different claims, and a VBOM that prints the same tick for both is
    the reason a migration plan drifts.
    """
    name = _norm(algorithm)
    for family in PQC_FAMILIES:
        if name.startswith(family.replace("-", "")) or name.startswith(family):
            return True, f"{family} is a post-quantum construction"
    for family in CLASSICAL_ASYMMETRIC:
        if name.startswith(family.replace("-", "")) or name.startswith(family):
            return False, f"{family} is broken by Shor's algorithm"
    if name.startswith(("AES", "SHA", "HMAC", "CHACHA", "CAMELLIA")):
        return False, "symmetric primitive: Grover halves the margin, Shor does not apply"
    return False, "the algorithm is not in this module's classification table"


def to_vbom_row(claim: CapabilityClaim) -> dict[str, Any]:
    """A ``vendor_crypto_inventory`` row carrying the evidence, for ``VbomGenerator``.

    The existing VBOM accepts rows with ``algorithm``, ``key_size``, ``mode``,
    ``pqc_ready``, ``discovery_method``, ``confidence`` and ``source_document``;
    this adds the evidence type, the applicability verdict, the verification
    status and the evidence ids, so the same generator can print a VBOM whose
    rows can be defended one at a time.
    """
    pqc, basis = pqc_basis(claim.algorithm)
    return {
        "algorithm": claim.algorithm,
        "key_size": claim.key_size,
        "mode": claim.mode,
        "curve": claim.curve,
        "pqc_ready": pqc,
        "pqc_basis": basis,
        "discovery_method": claim.discovery_method,
        "confidence": claim.confidence,
        "verified_at": _iso_date(claim.observed_at),
        "source_document": claim.source_document,
        "source_hash": claim.source_hash,
        "evidence_type": (claim.evidence[-1].kind.value if claim.evidence else "UNKNOWN"),
        "evidence_ids": [item.evidence_id for item in claim.evidence],
        "applicability": (claim.applicability.state.value if claim.applicability
                          else Applicability.UNKNOWN.value),
        "verification_status": claim.verification_status.value,
    }


# --------------------------------------------------------------------------- #
# the VBOM slice
# --------------------------------------------------------------------------- #


def build_vbom_slice(*, vendor: str, declarations: Sequence[VendorDeclaration],
                     deployments: Sequence[ProductIdentity], assets: Sequence[HardwareDependency],
                     claims: Sequence[CapabilityClaim], due_diligence: Mapping[str, Any],
                     lifecycle: Lifecycle | None = None, as_of: date | None = None) -> dict[str, Any]:
    """One vendor's VBOM entry: every claim with its evidence and its applicability."""
    as_of = as_of or date.today()
    applicability = []
    for declaration in declarations:
        for deployment in deployments:
            applicability.append(assess_applicability(declaration, deployment, as_of=as_of)
                                 .to_dict() | {"deployment": deployment.to_dict()})
    status_counts: dict[str, int] = {}
    for claim in claims:
        key = claim.verification_status.value
        status_counts[key] = status_counts.get(key, 0) + 1
    return {
        "schema": SCHEMA,
        "vendor": vendor,
        "as_of": as_of.isoformat(),
        "declarations": [declaration.declaration_id for declaration in declarations],
        "applicability": applicability,
        "capabilities": [claim.to_dict() for claim in claims],
        "verification_counts": dict(sorted(status_counts.items())),
        "exposure": vendor_exposure(assets, vendor=vendor),
        "due_diligence": dict(due_diligence),
        "lifecycle": lifecycle.to_dict(as_of=as_of) if lifecycle else None,
        "reconciliation": reconcile_capabilities(claims, as_of=as_of),
        "events": events_for(claims, as_of=as_of),
        # The sentence a reader should take away, and the one a dashboard should
        # not be allowed to replace with "PQC READY ✓".
        "statement": _vbom_statement(vendor, status_counts, due_diligence),
    }


def _vbom_statement(vendor: str, status_counts: Mapping[str, int],
                    due_diligence: Mapping[str, Any]) -> str:
    declared = status_counts.get(VerificationStatus.DECLARED_ONLY.value, 0)
    confirmed = status_counts.get(VerificationStatus.CONFIRMED.value, 0)
    corroborated = status_counts.get(VerificationStatus.CORROBORATED.value, 0)
    inapplicable = status_counts.get(VerificationStatus.INAPPLICABLE.value, 0)
    review = due_diligence.get("review_status", "NOT_REVIEWED")
    return (f"{vendor}: {declared} capability claim(s) rest on the vendor's word alone, "
            f"{confirmed} are confirmed by a bank observation and {corroborated} corroborated "
            f"at runtime; {inapplicable} declaration(s) do not apply to what is deployed. "
            f"Due diligence is {review}.")


def _utcnow() -> datetime:  # pragma: no cover - convenience for callers
    return datetime.now(timezone.utc)


__all__ = [
    "APPLICABILITY_STATES",
    "Applicability",
    "ApplicabilityResult",
    "BANK_OBSERVED_TYPES",
    "CapabilityClaim",
    "DUE_DILIGENCE_SECTIONS",
    "EVIDENCE_RANK",
    "EVIDENCE_TYPES",
    "Evidence",
    "EvidenceType",
    "Freshness",
    "HardwareDependency",
    "LIFECYCLE_ORDER",
    "Lifecycle",
    "LifecycleState",
    "ProductIdentity",
    "ProductMismatch",
    "ReconciliationState",
    "RiskFactor",
    "SCHEMA",
    "SoftwareDependency",
    "UNSUPPORTED_STATES",
    "VENDOR_EVENTS",
    "VendorDeclaration",
    "VerificationStatus",
    "VersionRelation",
    "assess_applicability",
    "build_vbom_slice",
    "claims_from_declaration",
    "compare_versions",
    "evaluate_due_diligence",
    "events_for",
    "freshness",
    "pqc_basis",
    "to_vbom_row",
    "reconcile",
    "reconcile_capabilities",
    "software_impact",
    "strongest",
    "vendor_exposure",
    "vendor_risk",
    "version_tokens",
]
