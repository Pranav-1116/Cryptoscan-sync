# 34 — Worked example: a multi-country, multi-vendor bank assessment

[Guide index](README.md) · [Program](27-international-bank-scan-program.md) ·
[Coverage accounting](30-evidence-pipeline-identity-and-coverage.md) ·
[Rollout](33-international-bank-engineering-and-rollout.md)

**Everything in this scenario is illustrative.** No real bank/vendor system
was accessed and these figures are not a CryproScan benchmark or test result.
The regional architecture and enterprise ledger are proposed designs, not a
claim that this checkout automatically implements them.

## 1. Starting situation

Fictional **Example International Bank** operates in India, the UK, Germany and
Singapore. It wants crypto/security-configuration assurance for an international
payments service, not a general penetration test or live payment simulation.

It identifies seven supplier roles:

| Supplier | Role in this example | Permitted evidence |
|---|---|---|
| Vendor A | Bank-hosted core ledger software | Scoped source/configuration export and build-specific SBOM |
| Vendor B | Payment-switch product | Supplier release BOM, admitted binary/image and approved configuration |
| Vendor C | Managed HSM service | Bank-partition public metadata and sanitized operational assertions |
| Vendor D | Cloud infrastructure | Bank-account scoped control-plane reads |
| Vendor E | CDN/WAF | Bank-hostname edge observations and tenant configuration evidence |
| Vendor F | Clearing/SaaS interface | Contractual evidence and specifically approved bank-facing metadata |
| Vendor G | Outsourced DR operator | DR inventory/build/certificate metadata within its approved scope |

Their evidence rights differ. Vendor F does not allow inspection of its internal
servers. The bank records that boundary rather than attempting a wider internet
scan. Vendor C prohibits key/ceremony payloads. Bank applications and suppliers
can span countries; a country label on the vendor is not enough to locate data.

## 2. Agree scope and ownership

The payments owner creates scope revision `S17` with application IDs, registered
source/builds, bank accounts/regions, exact listener profiles, HSM partitions,
legacy subsystems, vendor evidence packages and DR surfaces.

Regional owners approve detailed evidence destinations and allowed summary
fields. A proposed global view receives approved target-status/gap information,
not automatically source code, hostnames, key labels or the full dependency graph.
The bank decides applicable legal/contractual rules; this scenario does not
prescribe universal residency laws.

A network operator authorizes one canary listener before broader collection.
Mainframe and HSM custodians approve only sanitized metadata exports. Each
supplier method has an owner, expiry, support contact and escalation route.

## 3. Collect in a safe order

1. **Offline first:** import approved supplier SBOMs and metadata into quarantine.
   Reject wrong-release documents and record unavailable internals.
2. **Source:** stage approved commits and use qualified isolated parsing. Keep
   test-code findings distinct from production assertions.
3. **Release:** measure admitted artifact bytes; keep supplier document digest
   separate from release digest. Bind artifacts to deployments explicitly.
4. **Cloud:** read selected accounts/regions with scoped identity. Require
   pagination/error receipts; an unqueried region stays unqueried.
5. **Network:** start at the canary, verify destination/SNI/vantage and load,
   then expand only within scope/rate/window. Persist failures as well as successes.
6. **Mainframe:** receive approved text/metadata extracts with source encoding
   and conversion provenance; execute no JCL or payment operation.
7. **HSM:** ingest only permitted public metadata for the actual bank partition.
   Do not retrieve private keys or complete wrapped key blocks.
8. **DR:** obtain approved dormant-system evidence; do not trigger failover to
   create a collection opportunity.

Each accepted result has an observation interval, source/method, omissions and
persistence reference. A refused collection is a blocked ledger outcome, not a
clean system.

## 4. What actually happened in the example

The snapshot contains **48 registered work targets**. These heterogeneous items
are not 48 equal units of security coverage. The following is an operational
work-accounting table, not a percentage of the bank discovered.

| Target class | Expected | Fresh accepted scope met | Stale | Partial | Failed | Blocked | Unsupported | Not yet | Excluded |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| TLS listener profiles | 12 | 9 | 0 | 1 | 0 | 1 | 0 | 1 | 0 |
| Source/artifact targets | 14 | 10 | 2 | 1 | 0 | 1 | 0 | 0 | 0 |
| Cloud collection slices | 6 | 3 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| Hardware/key-metadata targets | 6 | 4 | 0 | 1 | 0 | 1 | 0 | 0 | 0 |
| Legacy extract targets | 5 | 2 | 1 | 0 | 0 | 0 | 2 | 0 | 0 |
| Supplier package targets | 5 | 2 | 0 | 1 | 1 | 0 | 0 | 0 | 1 |
| **Operational totals** | **48** | **30** | **4** | **5** | **2** | **3** | **2** | **1** | **1** |

The target classes include several suppliers through different methods. Five
supplier-package targets do not mean the bank has only five supplier relationships.
Underlying attempt events may have multiple reasons; the table uses one primary
outcome per target at cut-off. An exclusion retains its risk/approval record.

For the homogeneous TLS set, report **9/12 declared listener contracts met**.
Do not extrapolate this to all internal paths, applications or vendor infrastructure.
Completeness of the bank's expected register is itself still under review.

## 5. Diagnose the gaps instead of smoothing them away

| Observation | Interpretation | Next action |
|---|---|---|
| One TLS profile needs client authentication | Required observation incomplete; not plaintext and not secure-by-default | Owner chooses approved workload identity/proxy or metadata alternative |
| One region's cloud API denies a resource listing | Partial scope; zero returned resources is not zero deployed resources | Fix approved minimal permission or document permanent limitation |
| HSM export lacks partition binding | Public metadata exists but application-to-partition mapping is unproven | Custodian supplies an authorized explicit mapping |
| Legacy source uses an unsupported proprietary dialect | Unsupported evidence surface | Obtain approved alternative export or qualify a parser; record residual risk |
| Supplier package fails intake validation | Failed/quarantined evidence, not a clean product | Supplier repairs delivery under the agreed contract |
| DR document is older than accepted freshness | Stale DR evidence | Operator schedules approved renewal; no automatic failover |
| SaaS backend is contractually excluded | Known blind spot | Assess supplier assurance and service risk; do not scan beyond permission |

No partial update removes old dependencies. No late document refreshes an old
observation merely because it arrived today.

## 6. Correlate six BOMs for the payment switch

The switch's supplier SBOM describes library **L**. Its document digest verifies
the supplied document, not the deployed software. The bank measures artifact
**A**, retains the supplier-to-artifact assertion, and obtains an authorized
mapping of A to deployment **P** for system **S**.

- **SBOM:** L belongs to the admitted release evidence, with extraction/declaration
  origin and omitted component classes retained.
- **CBOM:** crypto findings relate to source/configuration/runtime evidence as
  available; static presence is not proof of runtime invocation.
- **NBOM:** the observed gateway certificate/protocol is scoped to the actual
  edge listener and vantage. Backend TLS is separate or unknown.
- **TechBOM:** system S is connected through explicit registered technology and
  release relationships, not a guessed name match.
- **HBOM:** relevant HSM firmware/partition evidence is linked only after the
  custodian's mapping is accepted. A model catalog is supporting declaration.
- **VBOM:** supplier/product/customer scope, evidence age and contractual limits
  remain visible; a readiness declaration is not live bank attestation.

If the artifact-to-deployment mapping is missing, that gap blocks the corresponding
production applicability claim. Generating all six documents does not repair it.

## 7. Model the service impact without predicting an outage

Suppose the registered graph declares mobile channel -> gateway -> payment
switch -> ledger, plus a conditional switch -> HSM dependency for a specific
function. Review every edge's source, validity, relation and operational mode.

An algorithm or vendor concern can identify modeled direct exposure and reverse
consumers. Supporting providers remain context unless another valid path makes
them consumers too. A stale relationship can support an uncertain/potential
review path without becoming a current definitive dependency.

A declared alternative HSM does not establish independent capacity, routing,
key synchronization or tested switchover. A buffered queue does not prove how
long payments can continue. Those require separate bank/vendor operational tests.
The platform must not claim a measured outage, transaction failure count or
predicted financial loss from these annotations.

## 8. Handoff and corrective work

The assessment pack contains scope revision S17, collection outcomes, accepted
raw-evidence references, six BOM projections, identity mappings, modeled service
exposure, coverage qualifications and supplier/legacy gaps. Regional reviewers
approve the fields of any global summary.

Actions have named owners: vendor obtains corrected release evidence; network
owner approves the client-auth observation method; cloud owner reviews permission;
HSM custodian resolves partition mapping; legacy owner approves parser qualification;
DR operator renews stale evidence. Risk owners accept or reject residual gaps.

Changes follow normal bank approval. The platform does not rotate keys, upgrade
a mainframe, change a firewall or trigger DR. After changes, new evidence is
collected with compatible identity/scope; historical answers stay frozen. A
closed ticket alone does not count as verified remediation.

## 9. What the sponsor can and cannot conclude

**Can conclude:** a defined assessment lifecycle ran for named targets; supported
facts and gaps are traceable; accepted evidence supports specific modeled
exposure and prioritized follow-up.

**Cannot conclude:** all bank assets were discovered, all supplier internals were
inspected, no undiscovered vulnerabilities exist, every region is compliant,
PQC migration is complete, failover will work, or the bank cannot suffer an outage.

The next expansion is gated on the unresolved risks and controls in
[guide 33](33-international-bank-engineering-and-rollout.md), not on making every
box in a global dashboard appear green.
