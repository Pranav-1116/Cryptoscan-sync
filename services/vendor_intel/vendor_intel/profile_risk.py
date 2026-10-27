"""Conservative due-diligence risk evaluation.

This is not a certification or an assertion about a vendor. It turns known
profile data and missing required data into an explainable screening signal.
Unknown controls add uncertainty; they never score as a passing control.
"""
from __future__ import annotations

from typing import Any

from vendor_intel.profile import VendorProfile, profile_completeness


def assess_profile_risk(
    profile: VendorProfile,
    crypto_risk: dict[str, Any] | None = None,
    profile_status: str = "DRAFT",
) -> dict[str, Any]:
    completeness = profile_completeness(profile)
    score = max(0.0, 100.0 - completeness["score"])
    factors: list[dict[str, Any]] = []

    def add(name: str, points: float, reason: str, state: str = "warning") -> None:
        nonlocal score
        score += points
        factors.append({"factor": name, "points": points, "state": state, "reason": reason})

    if profile.security_compliance.assessments:
        ratings = [item.risk_rating for item in profile.security_compliance.assessments]
        if "critical" in ratings:
            add("security_assessment", 20, "A security assessment is rated critical")
        elif "high" in ratings:
            add("security_assessment", 12, "A security assessment is rated high")
        elif "unknown" in ratings:
            add("security_assessment", 8, "An assessment exists without a known risk rating")
    else:
        add("security_assessment", 15, "No security assessment has been supplied")

    if profile.security_compliance.certifications and all(
        certification.status in {"CURRENT", "UNVERIFIED"}
        for certification in profile.security_compliance.certifications
    ):
        if any(certification.status == "UNVERIFIED" for certification in profile.security_compliance.certifications):
            add("certification_verification", 5, "Certification metadata is present but evidence is unverified")
    else:
        add("certification", 8, "No current certification evidence is recorded")

    if not profile.contracts:
        add("contract", 8, "Contract, renewal, and termination terms are not recorded")
    if profile.data_privacy.data_classification is None or not profile.data_privacy.data_residency:
        add("data_governance", 10, "Data classification or residency is unknown")
    if profile.security_compliance.compliance.dpa_signed is False:
        add("data_processing_agreement", 10, "The profile records that no DPA is signed")
    if profile.data_privacy.data_types_processed and not profile.data_privacy.privacy_mechanisms:
        add("privacy_mechanisms", 5, "Data is processed but privacy mechanisms are not recorded")
    if profile.financial_stability.financial_risk == "critical":
        add("financial_stability", 15, "Financial stability is rated critical")
    elif profile.financial_stability.financial_risk == "high":
        add("financial_stability", 10, "Financial stability is rated high")
    elif profile.financial_stability.financial_risk == "unknown":
        add("financial_stability", 6, "Financial stability has not been established")

    severe_incidents = [incident for incident in profile.incident_history.incidents if incident.severity in {"critical", "high"}]
    if severe_incidents:
        add("incident_history", 12, "High or critical incidents are recorded")
    elif not profile.incident_history.incidents and not profile.incident_history.incident_response_plan:
        add("incident_history", 8, "Incident history and response plan are both unknown")

    deps = profile.dependencies
    if deps.single_point_of_failure is True:
        add("single_point_of_failure", 12, "Vendor is recorded as a single point of failure")
    if deps.irreplaceability == "high":
        add("irreplaceability", 8, "Vendor has high irreplaceability")
    if deps.concentration_risk == "high":
        add("concentration", 8, "Concentration risk is rated high")
    if deps.supply_chain_visibility_depth is None and deps.sub_vendors:
        add("fourth_party_visibility", 6, "Sub-vendors exist but visibility depth is not recorded")
    if deps.sub_vendors and not deps.nth_party_visibility:
        add("nth_party_visibility", 5, "Nth-party visibility is not recorded")

    if profile.access_permissions.privileged_access is True and not profile.access_permissions.access_controls:
        add("privileged_access", 10, "Privileged access is recorded without access controls")
    elif not profile.access_permissions.access_types:
        add("access_governance", 6, "Vendor access type and scope are unknown")
    if profile.access_permissions.access_types and profile.access_permissions.mfa_required is None:
        add("mfa_control", 5, "Access exists but MFA requirement is unknown")

    if not profile.exit_strategy.data_retrieval_process or not profile.exit_strategy.transition_period:
        add("exit_strategy", 10, "Data retrieval or transition planning is incomplete")
    if not profile.exit_strategy.data_deletion_confirmation:
        add("exit_deletion", 5, "Exit data-deletion confirmation is not recorded")
    if profile_status == "EXPIRED":
        add("profile_status", 15, "The current due-diligence revision is expired")

    score = round(min(100.0, score), 2)
    if completeness["status"] != "COMPLETE" or profile_status == "EXPIRED":
        rating = "UNKNOWN"
    elif score >= 70:
        rating = "HIGH"
    elif score >= 40:
        rating = "MEDIUM"
    else:
        rating = "LOW"
    return {
        "risk_score": score,
        "risk_rating": rating,
        "status": (
            "EXPIRED" if profile_status == "EXPIRED"
            else "INCOMPLETE" if completeness["status"] != "COMPLETE" else "EVALUATED"
        ),
        "profile_status": profile_status,
        "completeness": completeness,
        "factors": factors,
        "crypto_risk": crypto_risk,
        "disclaimer": "Screening signal only; unknown values are not evidence of vendor safety or compliance.",
    }
