# 5.3 — One payments application, one valuable evidence-to-remediation loop

## Purpose and honest acceptance boundary

Prove a useful bounded outcome before expanding coverage: for **one payments
application**, identify a known deployed release, its source/SBOM evidence,
approved TLS and SSH endpoints, hardware metadata and signed supplier evidence;
then show a finding/change, accountable owner, separate approval, reported action
and a later independently collected exact-condition proof. The supported pilot
workflow is `PAYMENTS_RELEASE_REMEDIATION_V1`.

The Launch readiness Preview console and API retain this manifest and compute
current evidence gates. They do **not** discover an entire bank, reconcile all
runtime dependencies, obtain production scan permission, run an external
assessment, guarantee accuracy or execute a real customer pilot. No customer
acceptance is pre-populated. The initial empty deployment remains blocked until
real evidence, operating records and independent reports are supplied.

## Agree the pilot charter before collecting anything

The bank sponsor and technical owner agree, in writing:

- Business value: e.g. demonstrate safe replacement of one certificate or one
  known insecure source condition without losing the supporting evidence chain.
- One application identity and one known release/deployment; environment, source
  root/commit, artifact digest and separate SBOM document checksum. Document how
  the bank knows this artifact was deployed and how source relates to the build.
- Approved TLS endpoint including port and SNI/STARTTLS context; approved SSH
  endpoint/host-key method; exact permissions, network windows and stop contacts.
  Intake of an old receipt is not fresh authorization to send packets.
- Required hardware manufacturer/model and firmware or cryptographic metadata;
  named vendor and current customer-approved signed supplier evidence for the
  release. Explicitly identify what is supplier assertion versus direct observation.
- A finite expected-target register owned independently of scanner output. Include
  SOURCE target by exact source location, ENDPOINT targets by exact endpoint,
  DEPLOYMENT target by deployment ID, HARDWARE target by hardware ID and SUPPLIER
  target by supplier-evidence ID, all linked to this application.
- Success criteria, evidence freshness, completion/review dates, support window,
  customer and technical owner IDs, exclusions and the decision authority.

Typical exclusions: other payments applications, mainframe/proprietary exports,
other branches/releases, runtime reachability, HSM certification validation,
all load-balancer nodes/client paths, certificate chain trust/revocation, vendor
internal controls, whole-bank denominator completeness, contractual availability,
financial/compliance assurance and commercial rollout beyond this charter.

## Six BOMs are complementary, not interchangeable

| Evidence path | Pilot use | Do not claim |
|---|---|---|
| **SBOM** | Exact document binding to release artifact; resolved packages and unresolved count remain visible. | An SBOM hash is the deployed binary hash, every package is crypto-relevant, or source/build provenance is independently proven. |
| **CBOM** | Observed source crypto conditions with purpose, file/site and retained parser receipts; use a later exact-site proof for source remediation. | All crypto use or runtime execution was observed; UNKNOWN purpose is a confirmed insecure use. |
| **NBOM** | Approved TLS/SSH endpoint receipts with identity, phase success and observation times. | An open port identifies a service, a renewed inventory row proves deployment, or one node proves all paths. |
| **TechBOM** | Explicit application, deployment and package relationships; registered target denominator independent of discoveries. | Matching names infer runtime dependency or whole-bank impact. |
| **HBOM** | Exact hardware identity plus manufacturer/model and firmware/crypto metadata, with provenance disclosed. | An operator/supplier declaration is a fresh attestation or product certification. |
| **VBOM** | Existing vendor identity plus approved signed supplier payload for this release; signature trust/freshness rechecked. | Supplier assertion proves independent factual truth or qualifies a live vendor adapter. |

The pilot manifest's source/build evidence blob and deployment/endpoint/hardware
associations are **explicit customer assertions**. They are not a reproducible
build, signed provenance chain or automatically verified runtime placement.
The API exposes that limitation even when every pilot gate is satisfied.

## Preparation and API sequence

Paths are relative to `/api/v1/assurance/launch`; use existing source, SBOM,
software-supply-chain, estate-register, supplier-quarantine and condition-proof
APIs to prepare the actual evidence. Existing controlled `local-source/v1`
restrictions remain unchanged: this page does not re-enable legacy live network
collection. Import only admitted durable receipts from an appropriately qualified
collector/deployment; unsupported live collection remains an external blocker.

1. Create or select the exact application, source scan with parsed-file receipts,
   artifact, SBOM binding and deployment. Confirm SBOM/deployment both reference
   that artifact and deployment references the application.
2. Obtain separately approved completed TLS collector/job evidence for the exact
   endpoint and a successful SSH `host_keys` phase receipt with integrity hash
   and completed durable job. Empty key lists, failed phases and open ports do
   not satisfy the pilot. The declared permission references must match those
   exact application endpoints in the expected-target register. This checks
   retained permission assertions, not a new live execution permit.
3. Register hardware with meaningful metadata and the vendor. Complete signed
   supplier intake and different-human approval; wrong release, stale/revoked
   signer, quarantine or mismatched vendor identity is blocked.
4. Complete [5.1 independent security records](56-independent-security-assurance.md)
   for this release and [5.2 operational ownership/exercises](57-operational-ownership-and-demonstrated-service.md).
   These are external delivery requirements, not automatically satisfied by
   internal unit tests.
5. Demonstrate the [condition-level remediation loop](54-independent-remediation-verification.md).
   A SOURCE_SITE change must have this source scan as its baseline; a TLS change
   must address this exact endpoint. A current VERIFIED condition proof must bind
   the exact current change revision and still be within its approved freshness.
6. `POST /pilots`: retain business value, success criteria, explicit exclusions,
   distinct active customer/technical owner User IDs, expiry and all exact evidence
   IDs. Default endpoint observation age is 3,600 seconds; configurable from 60 to
   604,800 seconds. This is **PROPOSED**, not accepted.
7. `GET /pilots/{id}/status`: inspect all blockers and uncovered register targets.
   Fix evidence gaps, obtain fresh observations, complete missing reviews and
   re-propose changed scope rather than editing retained evidence in place.
8. Designated technical owner calls `POST /pilots/{id}/technical-review` with current
   pilot revision, evidence reference and rationale. All evidence/operating/security
   gates must already be clear. This pins their review to the exact gate snapshot.
9. A different designated customer owner, who did not propose the pilot, calls
   `POST /pilots/{id}/accept` after reviewing success criteria, limitations and
   retained evidence. The customer also needs review authority; assignment does
   not grant a role. Acceptance state is `CUSTOMER_ACCEPTED_BOUNDED`, not whole-bank
   rollout approval or an SLA. No automatic authority is given to a business title.

`PUT /pilots/{id}` creates a replacement manifest revision and resets both reviews.
All writes use `expected_revision`; stale concurrent submissions return 409.
History remains available through the exact-estate assurance records API.

## Dynamic readiness and deliberate coverage gaps

Readiness rechecks active users/identities, exact release and deployment bindings,
register revision, source-build evidence digest, endpoint receipts and freshness,
supplier approval/signature/freshness, independent security records, all nine
operating duties and the current remediation proof. Source and SSH registered
coverage must be current SQL receipt-backed observations. The source observation
must bind the selected pilot source scan, and the SSH coverage job must be the
job that produced the selected phase receipt.

TLS is validated directly against the retained TLS run/job. Existing generic
register coverage does **not** implement qualified external-export receipts for
TLS inventory, deployment assertions, hardware declarations or supplier documents.
These register entries remain explicitly NOT_ATTEMPTED/unsupported as applicable;
`unresolved_targets` and coverage counts expose them. They are **not** silently
converted to OBSERVED because a pilot manifest mentions them. Bounded readiness
uses their separate typed evidence checks, not a fictitious 100% register score.

Technical review/acceptance bind an exact evidence gate fingerprint. A later
security report, exercise review, supplier evidence, register/receipt change or
condition proof requires fresh review; expiry, revocation, inactive ownership and
stale observations remove current acceptance even though the historical accepted
revision remains. `commercial_acceptance_current` is a scoped customer assertion,
not a global feature flag. `whole_bank_visibility` and `sla_authorized` remain false.

## Pilot demonstration and final handover

Present a small evidence pack: charter and exclusions; exact source/build/release
assertions; separate artifact/SBOM hashes; application/deployment register;
approved endpoint receipts and limitations; hardware/vendor evidence; independent
security scope, report, finding/retest history; operating owners and reviewed
exercises; original condition, approved change, reported completion and later
current proof. Include failed/blocked/UNKNOWN evidence and remaining gaps.

Have the customer reproduce the decision from retained records, not slides.
Record whether success criteria were met, what remains inconclusive, the useful
business outcome and whether to extend, repeat or stop the pilot. Expansion to
another application/release or commercial SLA needs a new explicit agreement and
representative site evidence. A feature demo alone is not commercial acceptance.

See [templates](../templates/launch/README.md) and
[launch handoff runbook](../runbooks/launch-assurance-handoff.md).
