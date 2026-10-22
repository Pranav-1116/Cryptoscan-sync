# 3.4 — Six-BOM evidence paths, not invented joins

The implementation extends existing `System`, `SoftwareArtifact`,
`ReleaseSbomBinding`, `SoftwareDeployment`, `EvidenceRecord`, hardware and vendor
identities. It does not create another application identity model or equate an
SBOM document digest with an executable/image digest.

## Each BOM has a different evidence burden

| Layer | Supported evidence path in this increment | What is deliberately not inferred |
|---|---|---|
| **SBOM** | Existing exact artifact digest → content-hashed stored SBOM → exact versioned package identity; nested components remain bounded by the existing normalizer | A package name/reference without a resolved version; packaged → deployed/invoked |
| **NBOM** | Exact approved endpoint/SSH phase receipt, freshness and explicit reviewed endpoint→system assertion; offline exports distinguish endpoint/protocol from optional declared service reference | An open port/host key means a particular application/service identity |
| **CBOM** | Existing immutable algorithm/key-size/mode/purpose/location evidence; explicit package→crypto assertion; purpose-aware contextual assessment and typed offline crypto facts | Algorithm name/import/reference means security use, reachable invocation or acceptable posture |
| **TechBOM** | Existing exact system→deployment→artifact relation and separately reviewed service/deployment assertion | Matching names mean dependency or independent runtime deployment verification |
| **HBOM** | Existing hardware identity can be referenced by an explicit reviewed assertion; bounded offline hardware facts separately carry product/version, firmware, hardware-backed state and operating mode | Model/product string determines firmware/version, HSM/TPM use or operating mode |
| **VBOM** | Existing vendor identity can be referenced by a reviewed product assertion; signed exact-customer/build/product/version exports preserve supplier attribution | A vendor declaration, trusted signer or certification label is independent supplier/product verification |

`/assurance/relationships` accepts only enumerated typed endpoint pairs:
PACKAGE_CRYPTO, ENDPOINT_SERVICE, SERVICE_DEPLOYMENT, HARDWARE_FIRMWARE,
SUPPLIER_PRODUCT. All identities and supporting evidence must exist in the exact
estate. Package edges require an exact versioned package in the named SBOM
binding; service/deployment edges must agree with the existing system ID. A failed
or refused endpoint probe cannot become an observed service edge. Relationships
require an observation/expiry window and explicit evidence references.

A proposal is not a usable reviewed edge. A different human must approve it.
Review records preserve who proposed/reviewed it and why. These are **customer
reviewed assertions**, not automatically independently verified facts. Hardware/
vendor assertions against general evidence still require customer domain-source
review; the API does not certify their firmware or supplier truth from a label.
No claim of live vendor, hardware-backed or proprietary-source qualification is
made without those sources and actual runs.

## Application → artifact → package → crypto

1. Register/measure a release using existing software-supply-chain APIs. Preserve
   whether the digest was actually measured or operator/supplier declared.
2. Store and bind an actual SBOM with its exact document SHA-256. Unresolved
   package versions remain unresolved.
3. Register the exact existing application/system and deployment key against the
   release artifact. This still says whether the deployment link is declared.
4. Propose PACKAGE_CRYPTO with the existing binding ID, exact package identity,
   actual crypto EvidenceRecord ID and supporting evidence IDs; supply the
   explicit source/package mapping rationale and validity window.
5. Obtain a different entitled human's review.
6. Read `GET /api/v1/assurance/applications/{system_id}/trace`.

Each returned path retains deployment assertion/evidence, artifact identity
source/digest, SBOM document hash, versioned package, crypto observation/location,
relationship hash and proof IDs. The response explicitly keeps
`deployed_verified=false`, `invocation_verified=false`, `runtime_verified=false`.
A reviewed source/package association is useful without laundering it into a
runtime assertion. Inactive/expired/retracted endpoints are not followed.

Example: a measured release contains `pkg:pypi/cryptography@42.0.0`, and an
approved source-file observation is explicitly mapped to that component. The
trace can identify the release/component/crypto evidence and the reviewer. It
cannot say that production invoked that library unless separately evidenced.
A different package version, same-name application or arbitrary BOM reference
cannot fill the path. Missing binding/package/crypto edges are returned under
`unresolved`; the endpoint never fabricates a clean/complete application.

The new bounded supplier export lane emits typed facts for all six layers but
**never automatically materializes identity joins**. Actual proprietary/vendor
formats, runtime logs and independent deployment/firmware/supplier verification
remain profile-specific acceptance work. See [3.7](52-qualified-adapters-and-supplier-quarantine.md).


## Quality correction: unresolved version labels stay unknown

The [second quality increment](../readiness-evidence/quality-package-identity-2026-10-22.md)
removes an exact-package false join. Known `${...}`, `$name`, `@NAME@` build
variables, wildcard version segments and interval ranges do not become resolved
versions because they appear inside a version-bearing PURL. Percent encoding does
not change that rule. CycloneDX/SPDX imports retain raw version/PURL metadata and
count those components unresolved; the correction does not guess actual versions.

Current review/trace paths re-evaluate legacy derived identities. A pre-upgrade
reviewed assertion cannot resolve an unknown coordinate; an old proposal refuses
new approval with 409. Current cascade projections correct derived package identity
and unresolved counts without editing the captured snapshot or prior run result.
Explicit artifact/deployment relations stay available with their declared/measured
basis and existing runtime limitations. Historical SBOM/review records remain
unchanged; use actual resolved build evidence rather than patching old rows.

The existing offline supplier package validator also applies the rule. A valid
signature over an unresolved package fact stays origin-verified but quarantined,
not independently true. Old engine-bound offline qualifications require actual
re-exercise after this helper change. No live supplier adapter, new collector,
schema migration or whole-bank qualification is introduced.
