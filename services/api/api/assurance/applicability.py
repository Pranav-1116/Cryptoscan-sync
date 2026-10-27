"""Versioned contextual assessments; the original observation is never mutated."""
from fastapi import HTTPException
from db.models.evidence_record import EvidenceRecord
from db.models.software_supply_chain import ReleaseSbomBinding
from . import store


def assess(db, owner, evidence_id, body, actor):
    finding = store.exact(db, EvidenceRecord, owner, evidence_id)
    if finding.deleted_at:
        raise HTTPException(409, "Retracted observations cannot receive a current assessment")
    context = body.model_dump(mode="json", exclude={"expected_revision"})
    algorithm = finding.algorithm.upper()
    weak = algorithm in {"MD5", "SHA1", "SHA-1", "DES", "3DES", "RC4", "RSA", "DSA"}
    uncertainty = ["Context is a reviewed assertion; original observation and scanner policy evaluation remain unchanged."]
    if body.purpose == "CHECKSUM" and body.security_use is False:
        recommendation = "No cryptographic migration on a nonsecurity checksum alone; prevent reuse for authentication, signatures or adversarial integrity."
        importance = "NONSECURITY_CHECKSUM_REVIEW"
    elif body.purpose == "UNKNOWN" or body.security_use is None:
        recommendation = "Confirm security purpose and runtime applicability before choosing a migration; retain the observed algorithm as evidence."
        importance = "APPLICABILITY_UNRESOLVED"
        uncertainty.append("Security purpose is not established.")
    else:
        importance = "SECURITY_REVIEW" if weak else "PURPOSE_SPECIFIC_POLICY_REVIEW"
        recommendation = {
            "CERT_SIGNATURE": "Review certificate signature algorithm, issuer chain and certificate lifecycle; do not assume it is the negotiated key exchange.",
            "KEY_EXCHANGE": "Verify negotiated key establishment and peer compatibility; algorithm availability alone is not negotiation evidence.",
            "SYMMETRIC": "Review key size, mode, nonce handling and key lifecycle for the actual symmetric operation.",
            "SECURITY_HASH": "Review collision/preimage requirements and authenticated integrity; checksum use is not the same security purpose.",
        }.get(body.purpose, "Review security purpose and applicable policy before remediation.")
    if finding.is_hardcoded_key:
        recommendation += " Independently investigate the observed hardcoded-key evidence; test/checksum context does not dismiss secret exposure."
    if body.environment == "TEST":
        recommendation += " Test scope changes prioritization, not the recorded fact or possible production reuse."
    elif body.environment == "UNKNOWN":
        uncertainty.append("Production versus test deployment is unresolved.")
    if body.execution != "INVOKED":
        uncertainty.append("Packaged or named crypto is not proof of deployment or invocation.")
        recommendation += " Verify the deployed/invoked path before asserting runtime exposure."
    else:
        uncertainty.append("Invocation is customer-context declared, not independently verified by this assessment.")
    original_purpose = (finding.purpose or "").upper()
    if body.purpose == "CHECKSUM" and any(s in original_purpose for s in ("SIGN", "ENCRYPT", "AUTH", "EXCHANGE", "TLS")):
        importance = "CONTEXT_CONFLICT_REQUIRES_REVIEW"
        uncertainty.append("Checksum context conflicts with an original security-purpose observation; no automatic downgrade is justified.")
        recommendation = "Resolve the conflicting context with domain-owner evidence before changing security remediation. " + recommendation
    applicability = "NOT_EVALUATED"
    if body.advisory_id or body.pypi_affected_versions:
        applicability = "UNKNOWN"
        if body.sbom_binding_id and body.package_identity and body.pypi_affected_versions:
            binding = store.exact(db, ReleaseSbomBinding, owner, body.sbom_binding_id)
            identities = {c.get("package_identity") for c in binding.components}
            if body.package_identity not in identities or not body.package_identity.startswith("pkg:pypi/"):
                raise HTTPException(409, "Applicability requires an exact PyPI version resolved in the referenced SBOM")
            from .relationships import active
            if not active(binding):
                raise HTTPException(409, "Inactive SBOM binding cannot establish current version applicability")
            from packaging.specifiers import SpecifierSet, InvalidSpecifier
            from packaging.version import Version, InvalidVersion
            from urllib.parse import unquote
            try:
                version = unquote(body.package_identity.split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[1])
                applicability = "VERSION_IN_DECLARED_RANGE" if Version(version) in SpecifierSet(body.pypi_affected_versions) else "VERSION_OUTSIDE_DECLARED_RANGE"
            except (InvalidSpecifier, InvalidVersion, IndexError):
                raise HTTPException(422, "Only valid PyPI/PEP440 applicability ranges are implemented; other ecosystems remain unresolved") from None
            uncertainty.append("Version-range match uses a declared advisory range; reachability, vulnerable configuration and advisory authenticity are not established.")
        else:
            uncertainty.append("No exact versioned package/range evidence; a vulnerability name alone is not applicability.")
    certification = "NOT_EVALUATED"
    if body.certification_label:
        exact = (body.module_name and body.module_version and body.module_mode and body.certified_module
                 and body.certified_version and body.certified_modes)
        if not exact:
            certification = "INSUFFICIENT_EXACT_MODULE_VERSION_MODE"
        elif (body.module_name == body.certified_module and body.module_version == body.certified_version
              and body.module_mode in body.certified_modes):
            certification = "DECLARED_EXACT_MATCH_NOT_INDEPENDENTLY_VALIDATED"
        else:
            certification = "DECLARED_MODULE_VERSION_MODE_MISMATCH"
        uncertainty.append("A certification label and customer-supplied matching fields do not independently validate a certified module or operating mode.")
    observation = {"evidence_id": finding.id, "content_hash": finding.content_hash, "chain_hash": finding.chain_hash,
                   "algorithm": finding.algorithm, "purpose": finding.purpose, "key_size": finding.key_size,
                   "mode": finding.mode, "location": {"file": finding.file_path, "line": finding.line_number}}
    return store.append(db, owner, "finding_assessment", evidence_id, body.expected_revision,
        {"observation": observation, "context": context, "importance": importance, "uncertainty": uncertainty,
         "recommendation": recommendation, "recommendation_evidence": [finding.id, body.evidence_ref],
         "vulnerability_applicability": applicability, "certification": certification,
         "posture_acceptable": None, "assessment_engine": "purpose-context/v1"}, actor)
