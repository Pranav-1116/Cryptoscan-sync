# Open-source and software supply-chain policy

**Status:** security/release/legal review required
**Owner:** `[RELEASE OWNER]`

## 1. Purpose

This policy governs third-party and open-source components, source-to-artifact
traceability, dependency risk, licences, releases, images, SBOMs, provenance,
signing, and emergency updates.

## 2. Component inventory

For every release, retain:

- Python and frontend lockfiles;
- direct and transitive dependencies;
- container base images;
- first-party services;
- licence and notice files;
- SBOM in approved format;
- vulnerability/advisory result and feed date;
- source commit and build environment;
- image digests;
- signatures and provenance;
- release approval; and
- deployment digest/admission record.

## 3. Approval rules

Review before introduction or material upgrade:

- licence compatibility and obligations;
- maintainer and provenance risk;
- vulnerability history and support;
- cryptographic relevance;
- transitive dependency exposure;
- package integrity and signing;
- export/control restrictions; and
- replacement or rollback plan.

## 4. Release controls

A release package should include:

1. immutable version and source commit;
2. repeatable build instructions;
3. dependency lockfiles;
4. SBOM;
5. vulnerability report and exceptions;
6. container image digests;
7. signed release lock and provenance;
8. migration compatibility and rollback;
9. deployment admission verification;
10. security and product approval; and
11. retained source-to-deployment mapping.

Reference tools: `scripts/generate_own_sbom.py`,
`scripts/pin_release_images.py`, `scripts/verify_release_attestation.py`, and
`scripts/release_check.py`.

## 5. Vulnerability response

Triage advisories by exploitability, affected scope, exposure, cryptographic
impact, and available fix. Record compensating controls and expiry for an
exception. A clean scan is not proof that an advisory feed was complete or
current.

## 6. Licence and notice delivery

Customer receives required notices and licence information for the contracted
release. Do not represent third-party components as Vendor-owned. Legal reviews
copyleft, patent, export, and attribution issues.

## 7. Emergency changes and rollback

The release owner must define:

- emergency severity;
- approval authority;
- signed update source;
- anti-rollback rule;
- customer notice;
- migration rollback;
- evidence retention; and
- post-change review.

## 8. Evidence boundary

Repository tools show that a release control exists. They do not prove a
specific registry, production deployment, protected branch, customer approval,
or provider enforcement unless the corresponding operational record is
retained.
