"""Deterministic Threat Intelligence Engine (roadmap item 4).

Nine threat classes, each detector deterministic: the same evidence in, the same
findings out. A finding is not a verdict — it is a structured question that must
answer all six of the roadmap's mandatory questions:

* **what changed** — the observed delta or standing exposure;
* **which asset** — the subject of the finding;
* **why it matters** — the consequence, stated without invention;
* **evidence** — the records the finding rests on (a finding with no evidence is
  refused, not filed with a blank column);
* **what is NOT proven** — the boundary of the claim: a detection never declares
  a compromise, and this field exists so an analyst cannot read one into it;
* **what to investigate** — the next concrete step.

"AI can explain and summarize the finding, but must not invent evidence or
independently declare a compromise" — so the engine carries no summariser and no
verdict field, and ``not_proven`` is mandatory at construction.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

THREAT_SCHEMA = "cryptoscan.threat-intelligence/1"

#: the nine classes the roadmap names
CRYPTO_REGRESSION = "CRYPTO_REGRESSION"
WEAK_ALGORITHM_EXPOSURE = "WEAK_ALGORITHM_EXPOSURE"
CERTIFICATE_RISK = "CERTIFICATE_RISK"
TRUST_PATH_MUTATION = "TRUST_PATH_MUTATION"
HSM_DEPENDENCY = "HSM_DEPENDENCY"
LIBRARY_RISK = "LIBRARY_RISK"
VENDOR_RISK = "VENDOR_RISK"
COLLECTION_BLIND_SPOT = "COLLECTION_BLIND_SPOT"
PQC_REGRESSION = "PQC_REGRESSION"
THREAT_CLASSES: tuple[str, ...] = (
    CRYPTO_REGRESSION, WEAK_ALGORITHM_EXPOSURE, CERTIFICATE_RISK,
    TRUST_PATH_MUTATION, HSM_DEPENDENCY, LIBRARY_RISK, VENDOR_RISK,
    COLLECTION_BLIND_SPOT, PQC_REGRESSION,
)

ALGORITHM_RANK: dict[str, int] = {
    "ML-DSA-87": 90, "ML-DSA-65": 88, "ML-DSA-44": 86,
    "ML-KEM-1024": 84, "ML-KEM-768": 82, "ML-KEM-512": 80,
    "SLH-DSA-SHA2-128S": 70,
    "RSA-4096": 60, "RSA-3072": 58, "RSA-2048": 50,
    "ECDSA-P256": 45, "ECDSA-P384": 47,
    "AES-256": 40, "AES-128": 30,
    "RSA-1024": 10, "SHA-1": 5, "MD5": 1,
}


def finding(*, class_: str, asset: str, what_changed: str, why_it_matters: str,
            evidence_ids: Sequence[str], not_proven: str,
            investigate: str) -> dict[str, Any]:
    """Construct one finding. All six answers are mandatory; evidence cannot be empty.

    There is no verdict field and no severity-by-feeling: the class is the
    detector's, the evidence is the estate's, and the boundary of the claim is
    always spelled out in ``not_proven``.
    """
    threat_class = str(class_ or "").upper()
    if threat_class not in THREAT_CLASSES:
        raise ValueError(f"unknown threat class {class_!r}; expected one of "
                         f"{', '.join(THREAT_CLASSES)}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "a finding without evidence is an assertion: this engine refuses to "
            "file findings with no evidence behind them")
    for field_name, value in (("what_changed", what_changed),
                              ("why_it_matters", why_it_matters),
                              ("not_proven", not_proven),
                              ("investigate", investigate)):
        if not str(value or "").strip():
            raise ValueError(f"finding field {field_name!r} is mandatory: every "
                             f"finding answers all six questions")
    return {
        "schema": THREAT_SCHEMA,
        "class": threat_class,
        "asset": str(asset or "(unnamed)"),
        "what_changed": str(what_changed),
        "why_it_matters": str(why_it_matters),
        "evidence_ids": ids,
        "not_proven": str(not_proven),
        "investigate": str(investigate),
        "compromise_declared": False,
    }


def detect_crypto_regression(*, asset: str, observations: Sequence[Mapping[str, Any]],
                             evidence_ids: Sequence[str]) -> list[dict[str, Any]]:
    """A weaker algorithm observed after a stronger one, per asset.

    ``observations`` are ordered sightings ``{algorithm, observed_at}``. A drop in
    registry rank between consecutive sightings is a regression — what it means
    (an attack, a misconfiguration, a rollback) is exactly what the finding says
    is NOT proven.
    """
    rows = sorted(observations, key=lambda r: str(r.get("observed_at") or ""))
    out: list[dict[str, Any]] = []
    for before, after in zip(rows, rows[1:]):
        rank_a = ALGORITHM_RANK.get(str(before.get("algorithm") or ""), None)
        rank_b = ALGORITHM_RANK.get(str(after.get("algorithm") or ""), None)
        if rank_a is None or rank_b is None or rank_b >= rank_a:
            continue
        out.append(finding(
            class_=CRYPTO_REGRESSION, asset=asset,
            what_changed=(f"the observed algorithm dropped from "
                          f"{before.get('algorithm')} (rank {rank_a}) to "
                          f"{after.get('algorithm')} (rank {rank_b})"),
            why_it_matters=("the asset now protects traffic or data with a weaker "
                            "algorithm than the estate previously recorded"),
            evidence_ids=evidence_ids,
            not_proven=("this does not prove an attack, a downgrade attack, or who "
                        "changed it — only that the recorded algorithm weakened"),
            investigate=("who changed the configuration between the two "
                         "observations, and was the change authorised and logged")))
    return out


def detect_weak_algorithm_exposure(*, asset: str, algorithm: str,
                                   algorithm_info: Mapping[str, Any] | None,
                                   usage_state: str,
                                   evidence_ids: Sequence[str]) -> list[dict[str, Any]]:
    """Live or configured use of a DISALLOWED or DEPRECATED algorithm.

    Capability-only sightings are out of scope: a library that *can* do MD5 is not
    exposure; a negotiated MD5 is.
    """
    if str(usage_state).upper() not in {"CONFIGURED", "OBSERVED", "NEGOTIATED"}:
        return []
    if algorithm_info is None:
        info: Mapping[str, Any] = {}
    elif isinstance(algorithm_info, Mapping):
        info = algorithm_info
    elif hasattr(algorithm_info, "to_dict"):
        info = algorithm_info.to_dict()
    else:
        info = {k: v for k, v in vars(algorithm_info).items()}
    status = str(info.get("status") or "").upper()
    if status not in {"DISALLOWED", "DEPRECATED"}:
        return []
    return [finding(
        class_=WEAK_ALGORITHM_EXPOSURE, asset=asset,
        what_changed=(f"{algorithm} is in {str(usage_state).upper()} use and the "
                      f"registry lists it as {status}"),
        why_it_matters=("an algorithm on the disallowed or deprecated list is "
                        "protecting live traffic or data on this asset"),
        evidence_ids=evidence_ids,
        not_proven=("this does not prove the algorithm was broken here, or that "
                    "data was recovered — only that weak crypto is in use"),
        investigate=("where this algorithm is pinned, and what the migration "
                     "target and wave for this asset are"))]


def detect_certificate_risk(*, asset: str, certificate: Mapping[str, Any],
                            evidence_ids: Sequence[str],
                            expiry_warning_days: int = 30) -> list[dict[str, Any]]:
    """Certificate near expiry, per the supplied certificate facts.

    ``days_until_expiry`` comes from the evidence — the engine never computes
    expiry from the wall clock, so the finding is reproducible against the record
    it cites.
    """
    days = certificate.get("days_until_expiry")
    if days is None:
        return [finding(
            class_=CERTIFICATE_RISK, asset=asset,
            what_changed=("the certificate's expiry could not be determined from "
                          "its evidence"),
            why_it_matters=("an undated certificate is not a safe certificate: its "
                            "expiry risk is unknown"),
            evidence_ids=evidence_ids,
            not_proven="this does not prove the certificate is expiring or expired",
            investigate=("re-collect the certificate's not-after field so the "
                         "expiry window can be measured"))]
    if int(days) >= int(expiry_warning_days):
        return []
    return [finding(
        class_=CERTIFICATE_RISK, asset=asset,
        what_changed=(f"the certificate expires in {days} day(s), inside the "
                      f"{expiry_warning_days}-day warning window"),
        why_it_matters=("an expired certificate breaks the trust path for every "
                        "service that presents it"),
        evidence_ids=evidence_ids,
        not_proven=("this does not prove an outage will happen, or that renewal "
                    "has not begun elsewhere"),
        investigate=("who owns renewal for this certificate and whether a "
                     "replacement is already issued"))]


def detect_trust_path_mutation(*, asset: str, before: Mapping[str, Any],
                               after: Mapping[str, Any],
                               evidence_ids: Sequence[str]) -> list[dict[str, Any]]:
    """The trust path changed between two observations (issuer, root or chain)."""
    changed = [key for key in ("issuer", "root", "chain")
               if before.get(key) != after.get(key)]
    if not changed:
        return []
    return [finding(
        class_=TRUST_PATH_MUTATION, asset=asset,
        what_changed=("the trust path changed in "
                      + ", ".join(sorted(changed))
                      + f": { {k: before.get(k) for k in sorted(changed)} } → "
                      + f"{ {k: after.get(k) for k in sorted(changed)} }"),
        why_it_matters=("a mutated trust path determines what this asset will "
                        "trust; an unnoticed mutation is how trust gets stolen"),
        evidence_ids=evidence_ids,
        not_proven=("this does not prove compromise or a rogue CA — trust paths "
                    "also change under ordinary certificate lifecycle events"),
        investigate=("whether the new path is the approved one, and who approved "
                     "the change"))]


def detect_hsm_dependency(*, asset: str, dependency: Mapping[str, Any],
                          target_algorithm: str,
                          evidence_ids: Sequence[str]) -> list[dict[str, Any]]:
    """The migration target depends on an HSM/KMS whose capability is missing or
    unknown — an operational dependency with quantum consequences."""
    state = str(dependency.get("capability_state") or "NOT_ASSESSED").upper()
    if state == "SUPPORTS" and dependency.get("evidence_ids"):
        return []
    certainty = ("proven missing" if state == "LACKS" and dependency.get("evidence_ids")
                 else "missing or unassessed")
    return [finding(
        class_=HSM_DEPENDENCY, asset=asset,
        what_changed=(f"the dependency {dependency.get('name')} on the migration "
                      f"path to {target_algorithm} has {certainty} capability"),
        why_it_matters=("a migration cannot move past the capability of the HSM "
                        "or KMS that must hold the new keys"),
        evidence_ids=evidence_ids,
        not_proven=("this does not prove the migration will fail, only that the "
                    "dependency does not currently carry evidenced support"),
        investigate=("the vendor roadmap and firmware plan for this HSM/KMS, and "
                     "whether the target algorithm is on its qualified list"))]


def detect_library_risk(*, asset: str, library: Mapping[str, Any],
                        advisory: Mapping[str, Any],
                        evidence_ids: Sequence[str]) -> list[dict[str, Any]]:
    """A library version matched against a *supplied* advisory.

    The advisory is an input, cited by id — this engine never invents
    vulnerabilities and never matches against anything it was not handed.
    """
    if not str(advisory.get("advisory_id") or "").strip():
        raise ValueError("an advisory without an id cannot be cited: the engine "
                         "will not match libraries against anonymous claims")
    if str(advisory.get("affected_versions") or "") != str(library.get("version") or ""):
        return []
    return [finding(
        class_=LIBRARY_RISK, asset=asset,
        what_changed=(f"library {library.get('name')} {library.get('version')} "
                      f"matches advisory {advisory.get('advisory_id')}"),
        why_it_matters=("the named vulnerability applies to the exact version in "
                        "use on this asset"),
        evidence_ids=evidence_ids + [str(advisory["advisory_id"])],
        not_proven=("this does not prove the vulnerability is exploitable here, "
                    "or that it was exploited"),
        investigate=("whether the vulnerable code path is reachable on this asset "
                     "and what the fixed version is"))]


def detect_vendor_risk(*, asset: str, vendor_facts: Mapping[str, Any],
                       evidence_ids: Sequence[str]) -> list[dict[str, Any]]:
    """Vendor standing that threatens continuity or the PQC roadmap."""
    problems = []
    if str(vendor_facts.get("support_state") or "").upper() == "EOL":
        problems.append("vendor support is at end of life")
    if vendor_facts.get("eol_announced"):
        problems.append("an end-of-life date has been announced")
    if vendor_facts.get("pqc_roadmap_gap"):
        problems.append("the vendor has no PQC roadmap")
    if not problems:
        return []
    return [finding(
        class_=VENDOR_RISK, asset=asset,
        what_changed="; ".join(problems) + f" (vendor {vendor_facts.get('vendor')})",
        why_it_matters=("vendor standing governs whether fixes and PQC firmware "
                        "will exist when this asset needs them"),
        evidence_ids=evidence_ids,
        not_proven=("this does not prove the vendor will fail to deliver, only "
                    "that the risk is on the record"),
        investigate=("the contractual support horizon and any exit or replacement "
                     "options for this dependency"))]


def detect_collection_blind_spot(*, coverage: Mapping[str, Any],
                                 evidence_ids: Sequence[str]) -> list[dict[str, Any]]:
    """Coverage gaps become findings: a blind spot is a threat, not a footnote."""
    out: list[dict[str, Any]] = []
    for gap in coverage.get("gaps") or []:
        out.append(finding(
            class_=COLLECTION_BLIND_SPOT, asset=str(gap.get("kind")),
            what_changed=(f"coverage gap: {gap.get('detail')} "
                          f"(count {gap.get('count')})"),
            why_it_matters=("what cannot be seen cannot be defended or cleared: "
                            "a missing asset is never a clean security result"),
            evidence_ids=evidence_ids,
            not_proven=("this does not prove anything is wrong in the gap — only "
                        "that nothing is known there"),
            investigate=("re-run or repair the collectors behind this gap, and "
                         "record access or support fixes as coverage work")))
    return out


def detect_pqc_regression(*, asset: str, contradictions: Sequence[Mapping[str, Any]],
                          evidence_ids: Sequence[str]) -> list[dict[str, Any]]:
    """PQC validated-then-regressed, from preserved claim contradictions."""
    out: list[dict[str, Any]] = []
    for row in contradictions:
        validated = row.get("validated_claim") or {}
        conflicting = row.get("conflicting_claim") or {}
        out.append(finding(
            class_=PQC_REGRESSION, asset=asset,
            what_changed=("a validated post-quantum claim is contradicted by a "
                          "later classical observation "
                          f"({validated.get('algorithm')} → "
                          f"{conflicting.get('algorithm')})"),
            why_it_matters=("the subject may have regressed out of its validated "
                            "post-quantum state after the migration was signed off"),
            evidence_ids=evidence_ids,
            not_proven=("this does not prove when or how the regression happened, "
                        "nor that validation itself was wrong"),
            investigate=("the change log between the two observations and whether "
                         "the validation scope covered this code path")))
    return out


def threat_report(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Assemble detections into a report. Detection is a question, not a verdict."""
    rows = [dict(item) for item in findings]
    return {
        "schema": THREAT_SCHEMA,
        "findings": rows,
        "counts": {name: sum(1 for r in rows if r.get("class") == name)
                   for name in THREAT_CLASSES},
        "compromise_declared": False,
        "note": ("every finding answers what changed, which asset, why it "
                 "matters, the evidence, what is NOT proven and what to "
                 "investigate; a detection is a question — the engine never "
                 "declares a compromise and never invents evidence"),
    }
