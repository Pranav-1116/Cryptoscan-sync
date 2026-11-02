"""SBOM evidence: identity, provenance, signing, vulnerability, VEX, promotion.

An SBOM is a statement about a build, not about a running system. Every
function here exists to keep the difference: a component can be *in the
artifact* and still not be *in production*, a scanner can report *no matches*
and still not have *assessed* anything, and a library that *can* do AES is not
an application that *did*.

The pieces, in the order the review listed them:

* **artifact and deployment identity** (items 5/6) — a registry reference must
  be digest-pinned (`:latest` is refused, not flagged), and a deployment
  observation is what turns "this component exists in an SBOM" into "this
  component is running here, and somebody saw it".
* **build provenance** (7) — commit → build → digest → SBOM → deployment, with
  the gaps named.
* **storage durability** (8) — a production evidence store may not fall back to
  temporary storage; that is a refusal, not a warning.
* **the signing ladder** (9) — integrity, authenticity and non-repudiation are
  three different claims and each signature kind earns a specific one.
* **vulnerability status** (10) — six states, so "0 vulnerabilities" is never
  the same answer as "nobody looked".
* **VEX governance** (11) — a statement that expires, names a reviewer and
  cites evidence, or it is not a statement.
* **licence states** (12) — detected is not approved.
* **the promotion ladder** (13) — capability, static, runtime and network are
  four rungs; evidence moves a candidate up and nothing moves it down by
  assumption.
* **history and diff** (15/16) — changes over time, and a diff that reports
  crypto impact as unknown until somebody observed it.
* **untrusted import** (17.1) and **parser budgets** (17.5) — an imported
  document may add rows and may not overwrite a fact, and a hostile lockfile
  hits a limit before it hits the CPU.

Everything is a pure function of the records handed to it; the service layer
supplies the records.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.sbom-evidence/1"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
_FLOATING_TAGS = frozenset({"latest", "main", "master", "stable", "edge", "nightly", "dev",
                            "prod", "production", "head"})


class IdentityError(ValueError):
    """The record does not identify anything closely enough to be evidence."""


# --------------------------------------------------------------------------- #
# items 5/6: artifact and deployment identity
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ArtifactIdentity:
    """One artifact, pinned by digest.

    ``reference`` is the registry path (``ghcr.io/bank/payments-api``);
    ``digest`` is the content address. ``tag`` is recorded and never trusted: it
    is the mutable half of a reference, and a bank deployment pinned to a tag is
    a deployment whose evidence can change under it.
    """

    reference: str
    digest: str
    tag: str | None = None

    def __post_init__(self) -> None:
        if not str(self.reference or "").strip():
            raise IdentityError("an artifact needs a reference")
        if not _DIGEST.match(str(self.digest or "")):
            raise IdentityError(
                f"{self.digest!r} is not a sha256 digest; an artifact identified by a tag "
                "cannot be evidence of what is deployed")
        reference = str(self.reference).strip()
        if "@" in reference:
            reference, _, pinned = reference.partition("@")
            if pinned != self.digest:
                raise IdentityError(
                    f"the reference pins {pinned} and the record says {self.digest}")
        object.__setattr__(self, "reference", reference)

    @property
    def mutable(self) -> bool:
        """True when the only thing naming this artifact could move."""
        return bool(self.tag) and str(self.tag).lower() in _FLOATING_TAGS

    def to_dict(self) -> dict[str, Any]:
        return {"reference": self.reference, "digest": self.digest, "tag": self.tag,
                "pinned": True, "mutable_tag": self.mutable}


def parse_image_reference(text: str) -> ArtifactIdentity:
    """``repo/app@sha256:…`` -> identity; ``repo/app:latest`` -> refused.

    A digest-qualified reference is the only form accepted as identity. A tag,
    even a specific one, is recorded as a tag and rejected as an identity: the
    review's point is that a tag is mutable, and "v1.4.2" is a tag.
    """
    raw = str(text or "").strip()
    if not raw:
        raise IdentityError("an empty reference identifies nothing")
    if "@" in raw:
        reference, _, digest = raw.partition("@")
        tag = None
        if ":" in reference.rsplit("/", 1)[-1]:
            reference, _, tag = reference.rpartition(":")
        return ArtifactIdentity(reference=reference, digest=digest, tag=tag)
    raise IdentityError(
        f"{raw!r} names no digest. A tag — including a version tag — can be repointed, so it "
        "cannot identify an artifact in evidence. Pin the digest from the registry.")


@dataclass(frozen=True)
class DeploymentObservation:
    """Somebody saw this artifact running, here, at this time."""

    deployment: str
    environment: str
    artifact: ArtifactIdentity
    workload: str | None = None
    observed_at: date | None = None
    evidence_id: str | None = None
    source: str = "k8s"

    def __post_init__(self) -> None:
        if not str(self.deployment or "").strip():
            raise IdentityError("a deployment observation needs a deployment name")
        if self.observed_at is None:
            raise IdentityError(
                "a deployment observation needs an observed_at: without it, 'is deployed' has "
                "no tense and cannot be audited")

    def to_dict(self) -> dict[str, Any]:
        return {"deployment": self.deployment, "environment": self.environment,
                "workload": self.workload, "artifact": self.artifact.to_dict(),
                "observed_at": _iso(self.observed_at), "evidence_id": self.evidence_id,
                "source": self.source}


@dataclass(frozen=True)
class SbomRecord:
    """One SBOM, tied to the artifact it describes."""

    sbom_id: str
    artifact: ArtifactIdentity | None
    components: tuple[Mapping[str, Any], ...] = ()
    created_at: date | None = None
    build_id: str | None = None

    def names(self) -> set[str]:
        return {_norm(component.get("name")) for component in self.components
                if component.get("name")}

    def component(self, name: str) -> Mapping[str, Any] | None:
        target = _norm(name)
        return next((row for row in self.components if _norm(row.get("name")) == target), None)


def presence_in_deployment(sbom: SbomRecord, component: str,
                           observations: Iterable[DeploymentObservation]) -> dict[str, Any]:
    """The review's #1 question: deployed, or merely described?

    Four answers, and only the first lets a report say *present in production*:

    ``PRESENT_IN_DEPLOYMENT`` — in the SBOM, and an observation of that
    artifact's digest in an environment.
    ``PRESENT_IN_ARTIFACT`` — in the SBOM, and the SBOM is bound to a digest, but
    nothing observed that digest running.
    ``PRESENT_IN_SBOM_ONLY`` — in the SBOM and the SBOM is bound to nothing.
    ``NOT_IN_SBOM`` — the component is not there at all, which is a different
    finding from any of the above.
    """
    row = sbom.component(component)
    if row is None:
        return {"component": component, "state": "NOT_IN_SBOM", "deployments": [],
                "statement": (f"{component} does not appear in {sbom.sbom_id}; that is a "
                              "statement about the inventory, not about production")}
    if sbom.artifact is None:
        return {"component": component, "state": "PRESENT_IN_SBOM_ONLY", "deployments": [],
                "version": row.get("version"),
                "statement": (f"{component} {row.get('version')} is in {sbom.sbom_id}, which is "
                              "bound to no artifact digest — an uploaded document, not a "
                              "deployment")}
    matching = [obs for obs in observations
                if obs.artifact.digest == sbom.artifact.digest]
    if not matching:
        return {"component": component, "state": "PRESENT_IN_ARTIFACT",
                "artifact": sbom.artifact.to_dict(), "deployments": [],
                "version": row.get("version"),
                "statement": (f"{component} {row.get('version')} is in the SBOM for "
                              f"{sbom.artifact.digest[:19]}…, and no observation has seen that "
                              "digest running")}
    environments = sorted({obs.environment for obs in matching})
    return {"component": component, "state": "PRESENT_IN_DEPLOYMENT",
            "artifact": sbom.artifact.to_dict(), "version": row.get("version"),
            "environments": environments,
            "deployments": [obs.to_dict() for obs in matching],
            "statement": (f"{component} {row.get('version')} is present in "
                          f"{', '.join(sorted({obs.deployment for obs in matching}))} "
                          f"({', '.join(environments)})")}


# --------------------------------------------------------------------------- #
# item 7: build provenance
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BuildIdentity:
    """commit → build → digest → SBOM, as one auditable record."""

    source_commit: str
    build_id: str
    builder: str
    pipeline: str
    artifact: ArtifactIdentity | None = None
    sbom_id: str | None = None
    started_at: date | None = None
    finished_at: date | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"source_commit": self.source_commit, "build_id": self.build_id,
                "builder": self.builder, "pipeline": self.pipeline,
                "artifact": self.artifact.to_dict() if self.artifact else None,
                "sbom_id": self.sbom_id,
                "started_at": _iso(self.started_at), "finished_at": _iso(self.finished_at)}


def build_provenance(build: BuildIdentity, sbom: SbomRecord | None,
                     deployments: Iterable[DeploymentObservation]) -> dict[str, Any]:
    """The provenance chain, and every link that is missing from it."""
    gaps: list[str] = []
    if not _COMMIT.match(str(build.source_commit or "")):
        gaps.append("source_commit is not a commit hash, so the build cannot be traced to a tree")
    if not build.build_id or not build.build_id.strip():
        gaps.append("build_id is empty")
    if not build.builder or not build.builder.strip():
        gaps.append("builder is not recorded, so nobody can say what produced the artifact")
    if build.artifact is None:
        gaps.append("the build names no artifact digest")
    else:
        if build.artifact.mutable:
            gaps.append(f"the artifact carries the mutable tag {build.artifact.tag!r}")
    if sbom is None or sbom.sbom_id != build.sbom_id:
        gaps.append("no SBOM is bound to this build, or the bound SBOM is a different one")
    elif sbom.artifact is None or (build.artifact and sbom.artifact.digest != build.artifact.digest):
        gaps.append("the SBOM describes a different artifact than the build produced")
    elif build.finished_at and sbom.created_at and sbom.created_at < build.finished_at:
        gaps.append("the SBOM predates the build it is attached to")
    if build.started_at and build.finished_at and build.finished_at < build.started_at:
        gaps.append("the build finished before it started")
    observed = [obs for obs in deployments
                if build.artifact and obs.artifact.digest == build.artifact.digest]
    states = sorted({obs.environment for obs in observed})
    complete = not gaps
    return {
        "schema": SCHEMA,
        "build": build.to_dict(),
        "gaps": gaps,
        "complete": complete and bool(observed),
        "deployed_environments": states,
        "deployments": [obs.to_dict() for obs in observed],
        "statement": (
            f"build {build.build_id} from {build.source_commit[:12]} produced "
            f"{build.artifact.digest[:19] + '…' if build.artifact else 'no digest'}; "
            + (f"observed running in {', '.join(states)}" if states else
               "never observed running, so provenance stops at the artifact")
            + (f"; {len(gaps)} gap(s): {gaps[0]}" if gaps else "")),
    }


# --------------------------------------------------------------------------- #
# item 8: storage durability
# --------------------------------------------------------------------------- #

#: Environments where temporary storage is allowed. Nowhere else.
EPHEMERAL_ENVIRONMENTS = frozenset({"test", "dev", "development", "local", "ci"})


def storage_policy(*, environment: str, configured_store: str | None, writable: bool,
                   durable: bool, backup: str | None = None, retention_days: int | None = None,
                   integrity_verified: bool = False) -> dict[str, Any]:
    """May this store hold production evidence?

    The review's requirement is blunt: *temporary fallback must not be allowed
    for production evidence*. So a production run with no configured store is
    refused — not warned, not degraded to a temp directory and not silently
    successful — and a store without backup, retention or integrity is refused
    as well.
    """
    env = str(environment or "").strip().lower()
    reasons: list[str] = []
    if env in EPHEMERAL_ENVIRONMENTS:
        if configured_store:
            return {"environment": env, "verdict": "ALLOW",
                    "mode": "CONFIGURED" if durable else "EPHEMERAL_OK",
                    "reasons": [f"{env} may use ephemeral storage by policy"], "fallback": False}
        return {"environment": env, "verdict": "ALLOW", "mode": "EPHEMERAL_OK",
                "reasons": [f"{env} stores nothing for the record"], "fallback": True}
    if not configured_store:
        reasons.append(
            "no artifact store is configured, and falling back to temporary storage would "
            f"leave evidence for a {env or 'production'} run with no durable home")
    if not writable:
        reasons.append("the configured store is not writable")
    if not durable:
        reasons.append("the configured store is not durable (it is node-local or ephemeral)")
    if not backup:
        reasons.append("no backup target is configured, so a restore cannot be demonstrated")
    if not retention_days:
        reasons.append("no retention period is set, so evidence may be deleted early or kept "
                       "past policy")
    if not integrity_verified:
        reasons.append("artifact integrity is not verified on write")
    return {
        "environment": env,
        "verdict": "REFUSE" if reasons else "ALLOW",
        "mode": "CONFIGURED" if configured_store else "NO_STORE",
        "reasons": reasons or ["durable store, backup, retention and integrity verification are "
                               "all configured"],
        "fallback": False,
        "statement": (
            "production evidence storage is configured and durable" if not reasons else
            "REFUSED: " + "; ".join(reasons)),
    }


# --------------------------------------------------------------------------- #
# item 9: the signing ladder
# --------------------------------------------------------------------------- #

#: What each algorithm can claim, independent of key state.
SIGNATURE_CLAIMS: dict[str, dict[str, bool]] = {
    "SHA-256": {"integrity": True, "authenticity": False, "non_repudiation": False},
    "HMAC-SHA256": {"integrity": True, "authenticity": True, "non_repudiation": False},
    "Ed25519": {"integrity": True, "authenticity": True, "non_repudiation": True},
    "ECDSA-P-256": {"integrity": True, "authenticity": True, "non_repudiation": True},
    "RSA-PSS-3072": {"integrity": True, "authenticity": True, "non_repudiation": True},
    "ML-DSA-65": {"integrity": True, "authenticity": True, "non_repudiation": True},
}

KEY_STATUSES = ("ACTIVE", "ROTATED", "REVOKED", "EXPIRED")


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    algorithm: str
    status: str = "ACTIVE"
    trust_anchor: str | None = None
    valid_from: date | None = None
    valid_until: date | None = None
    rotated_to: str | None = None

    def __post_init__(self) -> None:
        status = str(self.status or "").upper()
        if status not in KEY_STATUSES:
            raise IdentityError(f"unknown key status {self.status!r}; expected {KEY_STATUSES}")
        if self.algorithm not in SIGNATURE_CLAIMS:
            raise IdentityError(
                f"{self.algorithm!r} is not an algorithm this verifier knows; an unknown "
                "algorithm cannot be treated as a signature")
        object.__setattr__(self, "status", status)

    def to_dict(self) -> dict[str, Any]:
        return {"key_id": self.key_id, "algorithm": self.algorithm, "status": self.status,
                "trust_anchor": self.trust_anchor,
                "valid_from": _iso(self.valid_from), "valid_until": _iso(self.valid_until),
                "rotated_to": self.rotated_to}


@dataclass(frozen=True)
class Signature:
    key_id: str
    signed_at: date
    value: str
    subject: str

    def __post_init__(self) -> None:
        if not str(self.value or "").strip():
            raise IdentityError("a signature with no value is not a signature")
        if not str(self.subject or "").strip():
            raise IdentityError("a signature must name what it signs")


def verify_signature(subject: str, digest: str, signature: Signature | None,
                     key: SigningKey | None, *, known_anchors: Iterable[str] = (),
                     as_of: date | None = None) -> dict[str, Any]:
    """Which of the three claims does this actually support?

    ``integrity`` — the digest matches the subject and a signature exists.
    ``authenticity`` — the signature was made by the holder of *some* key.
    ``non_repudiation`` — that key is asymmetric and anchored to a trust anchor
    the verifier was given, and was valid when it signed.

    Revocation and rotation are decided from the key's own record, not from a
    timestamp guess: a signature made while a key was ACTIVE survives its
    rotation (marked as such), and a revoked key fails everything.
    """
    as_of = as_of or date.today()
    claims = {"integrity": False, "authenticity": False, "non_repudiation": False}
    reasons: list[str] = []
    if not _DIGEST.match(str(digest or "")):
        reasons.append("the digest is not a sha256 content address, so nothing can be bound "
                       "to it")
    if signature is None or key is None:
        return {"subject": subject, "verdict": "UNSIGNED", "claims": claims,
                "key": key.to_dict() if key else None, "reasons": reasons or [
                    "no signature and no key: the artifact has not been authenticated"],
                "statement": "UNSIGNED: the digest may be intact and nothing vouches for it"}
    capability = SIGNATURE_CLAIMS[key.algorithm]
    claims["integrity"] = True
    if key.status == "REVOKED":
        reasons.append(f"key {key.key_id} is revoked; the signature is invalid regardless of "
                       "when it was made")
        return {"subject": subject, "verdict": "REVOKED_KEY", "claims": claims,
                "key": key.to_dict(), "reasons": reasons,
                "statement": f"REVOKED_KEY: {subject} is signed by a revoked key"}
    if key.valid_until and as_of > key.valid_until:
        reasons.append(f"key {key.key_id} expired on {key.valid_until.isoformat()}")
        return {"subject": subject, "verdict": "EXPIRED_KEY", "claims": claims,
                "key": key.to_dict(), "reasons": reasons,
                "statement": f"EXPIRED_KEY: {subject} is signed by an expired key"}
    if key.valid_from and signature.signed_at < key.valid_from:
        reasons.append(f"the signature predates the key ({key.valid_from.isoformat()})")
        return {"subject": subject, "verdict": "NOT_YET_VALID", "claims": claims,
                "key": key.to_dict(), "reasons": reasons,
                "statement": "NOT_YET_VALID: the signature was made before the key existed"}

    claims["authenticity"] = capability["authenticity"]
    rotation_note = ""
    if key.status == "ROTATED" and key.rotated_to:
        rotation_note = (f"; the key was rotated to {key.rotated_to} after signing, and the "
                         "signature remains valid for its signing date")
    anchored = bool(key.trust_anchor) and (not known_anchors
                                           or key.trust_anchor in set(known_anchors))
    if capability["non_repudiation"]:
        claims["non_repudiation"] = anchored
        if not anchored:
            reasons.append(
                f"key {key.key_id} is not anchored to a trust anchor this verifier knows "
                f"({sorted(set(known_anchors)) or 'none supplied'}), so the signature proves "
                "possession rather than identity")
    else:
        reasons.append(
            f"{key.algorithm} is a shared-secret construction: it authenticates to anyone who "
            "holds the key, so it cannot support non-repudiation")
    verdict = ("NON_REPUDIABLE" if claims["non_repudiation"] else
               "AUTHENTIC" if claims["authenticity"] else "INTEGRITY_ONLY")
    return {"subject": subject, "verdict": verdict, "claims": claims, "key": key.to_dict(),
            "digest": digest, "signed_at": _iso(signature.signed_at),
            "verified_at": as_of.isoformat(), "reasons": reasons,
            "statement": (f"{verdict}: {subject} — integrity {_yes(claims['integrity'])}, "
                          f"authenticity {_yes(claims['authenticity'])}, non-repudiation "
                          f"{_yes(claims['non_repudiation'])}{rotation_note}")}


# --------------------------------------------------------------------------- #
# item 10: vulnerability status
# --------------------------------------------------------------------------- #

VULN_STATES = ("NOT_ASSESSED", "ASSESSED_NO_MATCH", "MATCHED", "UNKNOWN", "STALE_FEED",
               "INSUFFICIENT_IDENTIFIER")


def assess_vulnerabilities(component: Mapping[str, Any], *, feed: Mapping[str, Any] | None,
                           advisories: Sequence[Mapping[str, Any]] = (),
                           as_of: date | None = None,
                           max_feed_age_days: int = 7) -> dict[str, Any]:
    """One component's vulnerability posture, with the reason for the answer.

    The distinctions that matter are between *not looked at* and *looked at*,
    and between *looked at with a current feed* and *looked at with a stale one*.
    ``0 matches`` from a feed nobody has updated in a month is ``STALE_FEED``.
    """
    as_of = as_of or date.today()
    purl = str(component.get("purl") or "").strip()
    version = component.get("version")
    row = {
        "component": component.get("name"),
        "version": version,
        "purl": purl or None,
        "feed": None, "feed_version": None, "feed_timestamp": None,
        "match_method": None, "confidence": "UNKNOWN", "advisories": [],
    }
    if not feed:
        return row | {"status": "NOT_ASSESSED", "reason":
                      "no vulnerability feed was consulted, so this component has no "
                      "vulnerability posture — which is not the same as having none"}
    updated = _as_date(feed.get("updated_at"))
    row.update({"feed": feed.get("name") or "unnamed-feed",
                "feed_version": feed.get("version"),
                "feed_timestamp": _iso(updated)})
    if updated is None:
        return row | {"status": "UNKNOWN", "reason":
                      "the feed states no update time, so its currency cannot be established"}
    age = (as_of - updated).days
    if age > max_feed_age_days:
        return row | {"status": "STALE_FEED", "feed_age_days": age, "reason":
                      f"the feed is {age} days old (limit {max_feed_age_days}); a zero-match "
                      "result from a stale feed is not an all-clear"}
    if not purl:
        return row | {"status": "INSUFFICIENT_IDENTIFIER", "reason":
                      "the component has no purl, so a version-range match would be a guess "
                      "against a name"}
    if not version:
        return row | {"status": "INSUFFICIENT_IDENTIFIER", "reason":
                      "the component has no version, and an advisory range cannot be applied "
                      "to it"}
    matches = [advisory for advisory in advisories
               if _advisory_matches(advisory, purl, str(version))]
    row["advisories"] = [dict(advisory) for advisory in matches]
    row["match_method"] = "purl+version"
    if not matches:
        return row | {"status": "ASSESSED_NO_MATCH", "confidence": "MEDIUM", "reason":
                      f"assessed against {row['feed']} {row['feed_timestamp']} with "
                      "purl+version matching and nothing matched"}
    row["confidence"] = "HIGH"
    identifiers = ", ".join(str(advisory.get("id")) for advisory in matches)
    return row | {"status": "MATCHED", "reason": f"{len(matches)} advisory match(es): "
                                                 f"{identifiers}"}


def _advisory_matches(advisory: Mapping[str, Any], purl: str, version: str) -> bool:
    target = str(advisory.get("package") or advisory.get("purl") or "")
    if target and target.split("@")[0] != purl.split("@")[0]:
        return False
    affected = advisory.get("affected_versions") or advisory.get("versions") or ()
    if not affected:
        return True
    return str(version) in {str(item) for item in affected}


# --------------------------------------------------------------------------- #
# item 11: VEX governance
# --------------------------------------------------------------------------- #

VEX_STATUSES = ("NOT_AFFECTED", "AFFECTED", "FIXED", "UNDER_INVESTIGATION")
VEX_JUSTIFICATIONS = ("VULNERABLE_CODE_NOT_PRESENT", "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH",
                      "VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY",
                      "INLINE_MITIGATIONS_ALREADY_EXIST", "COMPONENT_NOT_IN_ARTIFACT",
                      "NOT_AFFECTED_BY_CONFIGURATION")


def vex_statement(*, cve: str, component: str, affected_versions: Sequence[str],
                  application: str, deployment: str, status: str, justification: str | None,
                  reviewer: str | None, evidence_id: str | None, assessed_at: date,
                  expires_at: date, as_of: date | None = None) -> dict[str, Any]:
    """A VEX statement for bank governance: it expires, or it is not one.

    A statement that never expires is a permanent excuse, so ``expires_at`` is
    required. ``NOT_AFFECTED`` requires a justification from the closed list and
    a named reviewer, because "we decided it does not affect us" with no reason
    and no owner is the failure mode VEX exists to prevent.
    """
    as_of = as_of or date.today()
    problems: list[str] = []
    status = str(status or "").upper()
    if status not in VEX_STATUSES:
        problems.append(f"unknown VEX status {status!r}; expected {VEX_STATUSES}")
    if status == "NOT_AFFECTED":
        if justification not in VEX_JUSTIFICATIONS:
            problems.append(
                "NOT_AFFECTED needs a justification from the closed list "
                f"({', '.join(VEX_JUSTIFICATIONS[:2])}, …); free text is not a justification")
        if not (reviewer or "").strip():
            problems.append("NOT_AFFECTED needs a named reviewer")
        if not (evidence_id or "").strip():
            problems.append("NOT_AFFECTED needs an evidence id a reader can open")
    if expires_at < assessed_at:
        problems.append("the statement expires before it was assessed")
    if not _cve_ok(cve):
        problems.append(f"{cve!r} is not a CVE or advisory identifier")
    expired = as_of > expires_at
    return {
        "cve": cve, "component": component, "affected_versions": list(affected_versions),
        "application": application, "deployment": deployment, "status": status,
        "justification": justification, "reviewer": reviewer, "evidence_id": evidence_id,
        "assessed_at": _iso(assessed_at), "expires_at": _iso(expires_at),
        "expired": expired,
        "verdict": ("INVALID" if problems else "EXPIRED" if expired else "CURRENT"),
        "problems": problems,
        "statement": _vex_statement(status, component, cve, expired, problems, expires_at),
    }


def _vex_statement(status: str, component: str, cve: str, expired: bool,
                   problems: Sequence[str], expires_at: date) -> str:
    if problems:
        return f"INVALID: {cve} on {component} — {problems[0]}"
    if expired:
        return (f"EXPIRED: the {status} assessment for {cve} on {component} lapsed on "
                f"{expires_at.isoformat()} and no longer suppresses the finding")
    return f"CURRENT: {cve} on {component} is {status} until {expires_at.isoformat()}"


def _cve_ok(value: Any) -> bool:
    return bool(re.match(r"^(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z-]{8,}|BANK-\d{4}-\d+)$",
                         str(value or "").strip()))


# --------------------------------------------------------------------------- #
# item 12: licences
# --------------------------------------------------------------------------- #

LICENSE_STATES = ("DECLARED", "DETECTED", "UNKNOWN", "CONFLICT", "POLICY_ACCEPTED",
                  "POLICY_REJECTED", "REQUIRES_REVIEW")


def license_assessment(*, declared: str | None, detected: str | None,
                       policy: Mapping[str, str] | None = None) -> dict[str, Any]:
    """What is known about a component's licence — and what is not decided.

    ``DETECTED`` is a scanner's reading, ``DECLARED`` is the package's metadata
    and ``POLICY_ACCEPTED`` is a decision somebody made. The three are kept
    apart because a detected licence is not a legal approval, and this function
    will not produce the word ACCEPTED from a detection alone.
    """
    policy = {str(key).upper(): str(value).upper() for key, value in (policy or {}).items()}
    if declared and detected and declared.upper() != detected.upper():
        return {"state": "CONFLICT", "declared": declared, "detected": detected,
                "statement": (f"the package declares {declared} and the scanner detected "
                              f"{detected}; neither is a decision, and the difference is a "
                              "question for legal")}
    value = detected or declared
    if not value:
        return {"state": "UNKNOWN", "declared": declared, "detected": detected,
                "statement": "no licence was declared or detected, so nothing can be accepted"}
    licence = value.upper()
    decision = policy.get(licence)
    if decision == "DENY":
        return {"state": "POLICY_REJECTED", "declared": declared, "detected": detected,
                "licence": value, "statement": f"{value} is denied by policy"}
    if decision == "ALLOW":
        return {"state": "POLICY_ACCEPTED", "declared": declared, "detected": detected,
                "licence": value,
                "statement": f"{value} is accepted by policy (a decision, not a detection)"}
    return {"state": "REQUIRES_REVIEW", "declared": declared, "detected": detected,
            "licence": value,
            "statement": (f"{value} is known and no policy decision exists for it; the scanner "
                          "reports, it does not approve")}


# --------------------------------------------------------------------------- #
# item 13: the crypto promotion ladder
# --------------------------------------------------------------------------- #

#: The four rungs, in order. Each one is a different kind of claim.
PROMOTION_LADDER: tuple[str, ...] = ("CAPABILITY", "STATIC_OBSERVED", "RUNTIME_OBSERVED",
                                     "NETWORK_OBSERVED")
_PROMOTION_RANK = {name: index for index, name in enumerate(PROMOTION_LADDER)}


@dataclass(frozen=True)
class CryptoEvidence:
    """One observation, at one rung, with a citation."""

    kind: str
    reference: str
    observed_at: date | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        kind = str(self.kind or "").upper()
        if kind not in _PROMOTION_RANK:
            raise IdentityError(f"{self.kind!r} is not a rung on the promotion ladder; "
                                f"expected one of {PROMOTION_LADDER}")
        if not str(self.reference or "").strip():
            raise IdentityError("crypto evidence needs a reference")
        object.__setattr__(self, "kind", kind)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "reference": self.reference,
                "observed_at": _iso(self.observed_at), "detail": self.detail}


def crypto_candidate(component: str, version: str | None, *,
                     algorithms: Sequence[str], source: str = "SBOM") -> dict[str, Any]:
    """An SBOM says a library *can* do AES. That is where the ladder starts."""
    return {
        "component": component,
        "version": version,
        "algorithms": list(dict.fromkeys(algorithms)),
        "rung": "CAPABILITY",
        "confidence": "LOW",
        "evidence": [{"kind": "CAPABILITY", "reference": source}],
        "statement": (f"{component} {version or ''} is inventoried as crypto-capable. That is a "
                      "capability claim about a package, not a statement that any application "
                      "uses it").replace("  ", " ").strip(),
    }


def promote(candidate: Mapping[str, Any], evidence: Iterable[CryptoEvidence]) -> dict[str, Any]:
    """Move a candidate up the ladder, only as far as the evidence reaches.

    A rung is added only when evidence of that kind exists *and* every lower
    rung is already present: runtime evidence without static evidence is a
    gap in the record rather than a shortcut, and is reported as such.
    """
    rows = list(evidence)
    # The candidate itself is the CAPABILITY rung, and any rung it already carries
    # stays carried: promotion is cumulative, so re-promoting a promoted candidate
    # may not lose the evidence that got it there.
    carried = {str(row.get("kind")) for row in candidate.get("evidence") or ()
               if isinstance(row, Mapping) and row.get("kind")}
    present = {"CAPABILITY"} | carried | {row.kind for row in rows}
    rung = "CAPABILITY"
    gaps: list[str] = []
    for step, kind in enumerate(PROMOTION_LADDER):
        if kind in present:
            rung = kind
            continue
        higher = sorted((other for other in present if _PROMOTION_RANK[other] > step),
                        key=_PROMOTION_RANK.get)
        if higher:
            gaps.append(
                f"{kind} has no evidence while {', '.join(higher)} does: the ladder cannot skip "
                f"a rung, so the candidate stops at {rung} until {kind} is evidenced")
        break
    confidence = {"CAPABILITY": "LOW", "STATIC_OBSERVED": "MEDIUM",
                  "RUNTIME_OBSERVED": "HIGH", "NETWORK_OBSERVED": "HIGH"}[rung]
    declared = list(candidate.get("algorithms") or ())
    verified = sorted({row.detail for row in rows if row.detail}) or []
    return dict(candidate) | {
        "rung": rung,
        "confidence": confidence,
        "evidence": list(candidate.get("evidence") or ()) + [row.to_dict() for row in rows],
        "gaps": gaps,
        "statement": _promotion_statement(candidate.get("component"), rung, declared, verified),
    }


def _promotion_statement(component: Any, rung: str, declared: Sequence[str],
                         verified: Sequence[str]) -> str:
    if rung == "CAPABILITY":
        return (f"{component}: capability only — the SBOM says the library supports "
                f"{', '.join(declared) or 'cryptography'}, and nothing observed it being used")
    if rung == "STATIC_OBSERVED":
        return (f"{component}: static evidence shows the code path calls "
                f"{', '.join(verified) or 'a crypto API'}; still not a statement about traffic")
    if rung == "RUNTIME_OBSERVED":
        return (f"{component}: runtime evidence shows {', '.join(verified) or 'primitives'} "
                "executed; that is use, not yet negotiated network crypto")
    return (f"{component}: network evidence shows {', '.join(verified) or 'a negotiated suite'} "
            "on the wire")


# --------------------------------------------------------------------------- #
# items 15/16: history and evidence-aware diff
# --------------------------------------------------------------------------- #

CHANGE_KINDS = ("PACKAGE_ADDED", "PACKAGE_REMOVED", "VERSION_CHANGED", "DEPENDENCY_CHANGED",
                "LICENSE_CHANGED", "CRYPTO_CAPABILITY_CHANGED", "ARTIFACT_CHANGED",
                "DEPLOYMENT_CHANGED")


def snapshot_changes(previous: SbomRecord, current: SbomRecord) -> list[dict[str, Any]]:
    """What moved between two SBOM snapshots, in the review's vocabulary."""
    changes: list[dict[str, Any]] = []
    before = {_norm(row.get("name")): row for row in previous.components if row.get("name")}
    after = {_norm(row.get("name")): row for row in current.components if row.get("name")}
    for name in sorted(set(after) - set(before)):
        changes.append({"kind": "PACKAGE_ADDED", "component": after[name].get("name"),
                        "from": None, "to": after[name].get("version")})
    for name in sorted(set(before) - set(after)):
        changes.append({"kind": "PACKAGE_REMOVED", "component": before[name].get("name"),
                        "from": before[name].get("version"), "to": None})
    for name in sorted(set(before) & set(after)):
        old, new = before[name], after[name]
        if str(old.get("version")) != str(new.get("version")):
            changes.append({"kind": "VERSION_CHANGED", "component": new.get("name"),
                            "from": old.get("version"), "to": new.get("version")})
        if str(old.get("license") or "") != str(new.get("license") or ""):
            changes.append({"kind": "LICENSE_CHANGED", "component": new.get("name"),
                            "from": old.get("license"), "to": new.get("license")})
        if bool(old.get("crypto_relevant")) != bool(new.get("crypto_relevant")):
            changes.append({"kind": "CRYPTO_CAPABILITY_CHANGED", "component": new.get("name"),
                            "from": bool(old.get("crypto_relevant")),
                            "to": bool(new.get("crypto_relevant"))})
        if sorted(map(str, old.get("depends_on") or ())) != sorted(
                map(str, new.get("depends_on") or ())):
            changes.append({"kind": "DEPENDENCY_CHANGED", "component": new.get("name"),
                            "from": sorted(map(str, old.get("depends_on") or ())),
                            "to": sorted(map(str, new.get("depends_on") or ()))})
    if (previous.artifact and current.artifact
            and previous.artifact.digest != current.artifact.digest):
        changes.append({"kind": "ARTIFACT_CHANGED", "component": None,
                        "from": previous.artifact.digest, "to": current.artifact.digest})
    return changes


def evidence_aware_diff(previous: SbomRecord, current: SbomRecord, *,
                        deployments: Iterable[DeploymentObservation] = (),
                        runtime_verified: Iterable[str] = (),
                        network_verified: Iterable[str] = ()) -> dict[str, Any]:
    """A diff that says what changed *and* what that means cryptographically.

    The rule the review asks for: a version bump does not tell you the crypto
    impact. ``crypto_impact`` is ``UNKNOWN`` unless a runtime or network
    observation covers the component, and ``runtime_verification`` is
    ``NOT_OBSERVED`` unless a session was seen — because the alternative is a
    diff that reads like a conclusion.
    """
    changes = snapshot_changes(previous, current)
    runtime = {_norm(item) for item in runtime_verified}
    network = {_norm(item) for item in network_verified}
    observed = list(deployments)
    rows = []
    for change in changes:
        name = _norm(change.get("component"))
        crypto = change["kind"] in {"CRYPTO_CAPABILITY_CHANGED", "VERSION_CHANGED"}
        if not crypto and change["kind"] not in {"PACKAGE_ADDED", "PACKAGE_REMOVED"}:
            impact = "NO_CRYPTO_CHANGE_DETECTED"
        elif name and name in runtime:
            impact = "RUNTIME_EVIDENCE_PRESENT"
        else:
            impact = "UNKNOWN"
        rows.append(change | {
            "artifact": (current.artifact.reference if current.artifact else None),
            "release": current.build_id,
            "deployment": sorted({obs.environment for obs in observed}) or None,
            "crypto_impact": impact,
            "runtime_verification": ("OBSERVED" if name in runtime else "NOT_OBSERVED"),
            "network_impact": ("OBSERVED" if name in network else "NO_CHANGE_OBSERVED"),
        })
    evidence_id = "DIF-" + hashlib.sha256(
        "|".join(f"{row['kind']}:{row['component']}:{row['from']}:{row['to']}"
                 for row in changes).encode()).hexdigest()[:12]
    return {
        "schema": SCHEMA,
        "previous": previous.sbom_id,
        "current": current.sbom_id,
        "changes": rows,
        "evidence_id": evidence_id,
        "counts": {kind: sum(1 for row in rows if row["kind"] == kind)
                   for kind in CHANGE_KINDS},
        "statement": (
            f"{len(rows)} change(s) between {previous.sbom_id} and {current.sbom_id}; "
            f"{sum(1 for row in rows if row['crypto_impact'] == 'UNKNOWN')} have an unknown "
            "crypto impact because nothing observed the new version running"),
    }


# --------------------------------------------------------------------------- #
# item 17.1: untrusted import
# --------------------------------------------------------------------------- #

#: Facts an imported document may never overwrite, whatever it says.
PROTECTED_FACTS: tuple[str, ...] = ("deployment_identity", "runtime_evidence",
                                    "authorization", "observed_fact")


def import_sbom(document: Mapping[str, Any], *, source: str,
                existing: Mapping[str, Any] | None = None,
                refuse_protected_claims: bool = False) -> dict[str, Any]:
    """An imported SBOM adds rows and changes no facts.

    The review's first security blocker, mechanised: an import is ``UNTRUSTED``,
    every row it contributes is marked as imported with a content hash, and any
    field that would overwrite a protected fact is refused and recorded — not
    merged, not trusted because it looks authoritative.
    """
    if not isinstance(document, Mapping):
        raise IdentityError("an imported SBOM is a JSON object")
    existing = dict(existing or {})
    payload = str(sorted(document.items(), key=lambda item: str(item[0])))
    content_hash = hashlib.sha256(payload.encode()).hexdigest()
    refused: list[dict[str, str]] = []
    accepted: list[str] = []
    for key, value in document.items():
        if str(key) in PROTECTED_FACTS:
            if existing.get(key) not in (None, value):
                refused.append({
                    "field": str(key),
                    "reason": (f"the imported document would replace {key}={existing.get(key)!r} "
                               f"with {value!r}; an imported SBOM is untrusted input and may not "
                               "overwrite an observed fact")})
                continue
            if refuse_protected_claims:
                # Nothing to overwrite, and still refused: a fact the platform
                # observes is not something an upload may assert at all.
                refused.append({
                    "field": str(key),
                    "reason": (f"the imported document asserts {key}={value!r}; an imported "
                               "SBOM may add rows and may not state an observed fact")})
                continue
        accepted.append(str(key))
    components = document.get("components") or []
    rows = []
    if isinstance(components, Sequence):
        for component in components:
            if not isinstance(component, Mapping):
                continue
            rows.append({
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl"),
                "evidence_type": "IMPORTED",
                "may_override": False,
                "source": source,
                "content_hash": content_hash[:16],
            })
    return {
        "schema": SCHEMA,
        "source": source,
        "trust": "UNTRUSTED",
        "content_hash": content_hash,
        "components": rows,
        "accepted_fields": accepted,
        "refused": refused,
        "verdict": "REJECTED" if refused else "ACCEPTED_AS_EVIDENCE",
        "statement": (
            "REFUSED: " + refused[0]["reason"] if refused else
            f"{len(rows)} component row(s) imported from {source} as untrusted evidence; "
            "nothing observed was replaced"),
    }


# --------------------------------------------------------------------------- #
# item 17.5: parser budgets
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ParserBudget:
    """Limits a hostile document has to fit inside before it is parsed."""

    max_bytes: int = 8_000_000
    max_components: int = 50_000
    max_depth: int = 64
    max_cycles: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"max_bytes": self.max_bytes, "max_components": self.max_components,
                "max_depth": self.max_depth, "max_cycles": self.max_cycles}


DEFAULT_BUDGET = ParserBudget()


def check_budget(document: Mapping[str, Any] | None, *, size_bytes: int | None = None,
                 budget: ParserBudget | None = None) -> dict[str, Any]:
    """Refuse a document that is too big, too deep, or cyclic.

    A bank can submit a 100 MB lockfile by accident and an attacker can submit
    one on purpose; either way the answer is a stated limit rather than a
    process that stops responding.
    """
    budget = budget or DEFAULT_BUDGET
    problems: list[str] = []
    if size_bytes is not None and size_bytes > budget.max_bytes:
        problems.append(f"{size_bytes} bytes exceeds the {budget.max_bytes}-byte limit")
    if not isinstance(document, Mapping):
        return {"verdict": "REFUSED", "problems": ["the document is not a JSON object"],
                "budget": budget.to_dict(), "components": 0, "depth": 0, "cycles": 0}
    components = document.get("components") or []
    count = len(components) if isinstance(components, Sequence) else 0
    if count > budget.max_components:
        problems.append(f"{count} components exceeds the {budget.max_components} limit")
    depends = {}
    for component in components if isinstance(components, Sequence) else ():
        if not isinstance(component, Mapping):
            continue
        ref = str(component.get("bom-ref") or component.get("name") or "")
        targets = []
        for dependency in component.get("dependsOn") or ():
            targets.append(str(dependency))
        depends[ref] = targets
    depth, cycles = _depth_and_cycles(depends)
    if depth > budget.max_depth:
        problems.append(f"dependency depth {depth} exceeds the {budget.max_depth} limit")
    if cycles > budget.max_cycles:
        problems.append(f"{cycles} dependency cycle(s) found; this parser does not resolve "
                        "cycles and would recurse")
    return {
        "verdict": "REFUSED" if problems else "WITHIN_BUDGET",
        "problems": problems,
        "budget": budget.to_dict(),
        "components": count,
        "depth": depth,
        "cycles": cycles,
        "statement": ("; ".join(problems) if problems else
                      f"{count} component(s), depth {depth}, no cycles — inside the budget"),
    }


def _depth_and_cycles(graph: Mapping[str, Sequence[str]]) -> tuple[int, int]:
    """Longest path and cycle count, iteratively — a hostile graph must not blow
    the Python stack before it hits the depth limit."""
    state: dict[str, int] = {}
    depth: dict[str, int] = {}
    cycles = 0
    for start in list(graph):
        if state.get(start) == 2:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        order: list[str] = []
        while stack:
            node, index = stack.pop()
            if index == 0:
                state[node] = 1
                order.append(node)
            targets = [target for target in graph.get(node, ()) if target in graph]
            if index < len(targets):
                stack.append((node, index + 1))
                child = targets[index]
                mark = state.get(child, 0)
                if mark == 1:
                    cycles += 1
                elif mark == 0:
                    stack.append((child, 0))
                continue
            state[node] = 2
            depth[node] = 1 + max((depth.get(child, 0) for child in targets), default=0)
        for node in order:
            state[node] = 2
    return (max(depth.values()) if depth else 0), cycles


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# item 10, at document scale: every component, with its posture and its reason
# --------------------------------------------------------------------------- #

#: The fields a vulnerability row must carry for a reviewer to defend it.
VULN_ROW_FIELDS: tuple[str, ...] = ("component", "version", "purl", "feed", "feed_version",
                                    "feed_timestamp", "match_method", "confidence",
                                    "advisories", "status", "reason")


def assess_document(sbom: SbomRecord, *, feed: Mapping[str, Any] | None,
                    advisories: Sequence[Mapping[str, Any]] = (),
                    as_of: date | None = None,
                    max_feed_age_days: int = 7) -> dict[str, Any]:
    """Vulnerability posture for a whole SBOM, not one lucky component.

    A per-component answer is easy; the hard part is the rollup. The counts keep
    ``MATCHED`` and ``NOT_ASSESSED`` apart, so a document whose components were
    never looked at cannot be summarised as "clean" — the summary says how many
    were assessed, and the statement names the states that are *not* a pass.
    """
    as_of = as_of or date.today()
    rows = [assess_vulnerabilities(component, feed=feed, advisories=advisories,
                                   as_of=as_of, max_feed_age_days=max_feed_age_days)
            for component in sbom.components]
    counts = {state: sum(1 for row in rows if row["status"] == state) for state in VULN_STATES}
    assessed = counts["MATCHED"] + counts["ASSESSED_NO_MATCH"]
    unassessed = len(rows) - assessed
    return {
        "schema": SCHEMA,
        "sbom": sbom.sbom_id,
        "as_of": as_of.isoformat(),
        "feed": (dict(feed) if feed else None),
        "components": rows,
        "counts": counts,
        "assessed": assessed,
        "unassessed": unassessed,
        "statement": (
            f"{len(rows)} component(s): {counts['MATCHED']} matched, "
            f"{counts['ASSESSED_NO_MATCH']} assessed with no match, {unassessed} not "
            "assessed against a current feed"
            + ("" if not unassessed else
               f" — {unassessed} of {len(rows)} have no posture and may not be reported as "
               "clean")),
    }


# --------------------------------------------------------------------------- #
# item 14: SBOM edges for the digital twin, each carrying its evidence
# --------------------------------------------------------------------------- #

#: Edge kinds the twin consumes. Every one of them is a claim with a source.
TWIN_EDGE_KINDS: tuple[str, ...] = ("CONTAINS", "DESCRIBED_BY", "PRODUCED", "DEPLOYED_AS",
                                    "RUNS_AS", "SERVES", "HAS_CAPABILITY")


def twin_edges(sbom: SbomRecord, *, build: BuildIdentity | None = None,
               deployments: Iterable[DeploymentObservation] = (),
               application: str | None = None,
               business_system: str | None = None,
               algorithms: Mapping[str, Sequence[str]] | None = None) -> dict[str, Any]:
    """Software → application → release → artifact → deployment → workload edges.

    The review's distinction matters here: the twin must be able to answer *where
    is this package deployed*, not *which document contains it*. So ``CONTAINS``
    comes from an SBOM and stops at the artifact, and only an observation —
    carrying its own id and timestamp — produces ``DEPLOYED_AS``/``RUNS_AS``.
    A component with no observation therefore has no path to production, in the
    graph as well as in the report.
    """
    observed = list(deployments)
    edges: list[dict[str, Any]] = []
    artifact = sbom.artifact

    def edge(source: str, kind: str, target: str, *, evidence_id: str, evidence_type: str,
             origin: str, observed_at: Any = None, confidence: str = "HIGH") -> None:
        edges.append({"from": source, "kind": kind, "to": target,
                      "evidence_id": evidence_id, "evidence_type": evidence_type,
                      "source": origin, "observed_at": _iso(observed_at),
                      "confidence": confidence})

    artifact_ref = artifact.reference if artifact else "artifact:unknown"
    edge(f"sbom:{sbom.sbom_id}", "DESCRIBED_BY", artifact_ref, evidence_id=sbom.sbom_id,
         evidence_type="SBOM", origin="scan", observed_at=sbom.created_at,
         confidence="HIGH" if artifact else "MEDIUM")

    if application:
        edge(application, "SERVES", business_system or "business-system:unstated",
             evidence_id=f"APP-{_norm(application)}", evidence_type="REGISTER",
             origin="cmdb", confidence="MEDIUM")

    for component in sbom.components:
        name = _norm(component.get("name"))
        if not name:
            continue
        edge(f"sbom:{sbom.sbom_id}", "CONTAINS", f"component:{name}",
             evidence_id=sbom.sbom_id, evidence_type="SBOM", origin="scan",
             observed_at=sbom.created_at,
             confidence="HIGH" if component.get("version") else "MEDIUM")
        if component.get("crypto_relevant"):
            for algorithm in (algorithms or {}).get(name, ()) or ():
                edge(f"component:{name}", "HAS_CAPABILITY", f"algorithm:{_norm(algorithm)}",
                     evidence_id=f"CAP-{name}", evidence_type="CAPABILITY", origin="sbom",
                     observed_at=sbom.created_at,
                     confidence="LOW")  # capability, never usage

    if build is not None and build.artifact is not None:
        edge(f"release:{build.build_id}", "PRODUCED", artifact_ref,
             evidence_id=build.build_id, evidence_type="BUILD", origin=build.builder or "builder",
             observed_at=build.finished_at)

    matched = [obs for obs in observed
               if artifact and obs.artifact.digest == artifact.digest]
    for observation in matched:
        edge(f"deployment:{observation.deployment}", "DEPLOYED_AS", artifact_ref,
             evidence_id=observation.evidence_id, evidence_type="OBSERVATION",
             origin=observation.source, observed_at=observation.observed_at)
        edge(f"workload:{observation.workload}", "RUNS_AS",
             f"deployment:{observation.deployment}",
             evidence_id=observation.evidence_id, evidence_type="OBSERVATION",
             origin=observation.source, observed_at=observation.observed_at)

    unresolved = [component.get("name") for component in sbom.components
                  if component.get("name")
                  and not any(obs.artifact.digest == (artifact.digest if artifact else None)
                              for obs in observed)]
    return {
        "schema": SCHEMA,
        "nodes": sorted({node for e in edges for node in (e["from"], e["to"])}),
        "edges": edges,
        "unobserved_components": unresolved,
        "statement": (
            f"{len(edges)} edge(s) from {sbom.sbom_id}"
            + (f", {len(matched)} deployment observation(s) reaching "
               f"{', '.join(sorted({obs.environment for obs in matched}))}" if matched else
               "; no observation reaches this artifact, so no component resolves to a running "
               "system")),
    }


# --------------------------------------------------------------------------- #
# item 15: snapshots are a series, not a file
# --------------------------------------------------------------------------- #


def history(snapshots: Sequence[SbomRecord]) -> dict[str, Any]:
    """A timeline of snapshots and what moved at each step.

    ``snapshot_changes`` answers one pair; a bank asks a series. Ordering is by
    ``created_at`` and ties are broken by id, so the same set of snapshots always
    produces the same timeline — a drift engine that reorders itself is not
    evidence.
    """
    ordered = sorted(snapshots, key=lambda record: (record.created_at or date.min,
                                                    str(record.sbom_id)))
    transitions: list[dict[str, Any]] = []
    for previous, current in zip(ordered, ordered[1:]):
        changes = snapshot_changes(previous, current)
        transitions.append({
            "from": previous.sbom_id, "to": current.sbom_id,
            "at": _iso(current.created_at),
            "changes": changes,
            "counts": {kind: sum(1 for row in changes if row["kind"] == kind)
                       for kind in CHANGE_KINDS},
        })
    timeline: dict[str, list[dict[str, Any]]] = {}
    for record in ordered:
        for component in record.components:
            name = _norm(component.get("name"))
            if not name:
                continue
            timeline.setdefault(str(component.get("name")), []).append({
                "sbom": record.sbom_id, "at": _iso(record.created_at),
                "version": component.get("version"),
            })
    durations = [(later.created_at - earlier.created_at).days
                 for earlier, later in zip(ordered, ordered[1:])
                 if earlier.created_at and later.created_at]
    return {
        "schema": SCHEMA,
        "snapshots": [record.sbom_id for record in ordered],
        "transitions": transitions,
        "components": timeline,
        "changed_transitions": sum(1 for row in transitions if row["changes"]),
        "gap_days": max(durations) if durations else None,
        "statement": (
            f"{len(ordered)} snapshot(s), {len(transitions)} transition(s), "
            f"{sum(1 for row in transitions if not row['changes'])} with no change"
            + (f"; the longest gap between snapshots is {max(durations)} day(s)"
               if durations else "")),
    }


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def _iso(value: Any) -> str | None:
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
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None
