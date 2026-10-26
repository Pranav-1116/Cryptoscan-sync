# 85 — Shared collection snapshots, metadata graph and evidence-aware drift

## What was built next

The repository already has target authorization/jobs, original host evidence, an OCI registry/job/intake path, typed collector candidates, identity helpers, six-BOM projections, host associations, a general dependency graph and crypto-specific drift. Replacing those with new scanners or a second inventory database would duplicate work.

This increment fills a narrower missing link: **one durable, source-revalidated snapshot format and metadata-drift path for committed host and OCI collection jobs**. It uses the existing assurance revision/audit store. It does not replace the existing operational dependency graph, legacy crypto drift, host association review or OCI truth review.

[API details](../api-reference/collection-snapshots.md) · [operator runbook](../runbooks/collection-snapshots.md) · [executed engineering evidence](../readiness-evidence/collection-snapshots-2026-10-26.md).

```text
authorized target → existing job → existing original evidence intake
                                  ↓ verify original closure
                             collection_snapshot
                            /        |          \
                  six BOM references | metadata-only graph
                                     ↓
                  two compatible committed snapshots
                                     ↓
                         collection_metadata_drift
```

There is no new collection service, scheduler, scanner, database migration or automatic baseline approval. Snapshot creation and drift comparison do not read a target filesystem, contact an endpoint or execute a collector. The HTTP source readers reopen retained evidence, not the original live target.

## Architecture audit: reuse versus this increment

| Requested phase | Existing implementation reused or inspected | Boundary / remaining integration |
|---|---|---|
| Foundation | `assurance/collection.py`, target revisions, explicit approval, jobs, original host intake, errors/coverage and domain references | No unrestricted discovery; collection production boundary remains closed |
| Linux | Inventory host/package/passive-runtime readers; scoped metadata-slot identities and host evidence validation | Metadata presence is not application cryptographic use |
| Windows | Existing certificate, image/module, CNG/TPM and bounded-metadata candidate modules in the published tree | Candidate code is not actual Windows/customer execution qualification; not every standalone intake is a collection job |
| Containers | Offline OCI reader, typed six-view projection, registry/jobs/intake and separate precommitted truth review | This bridge supports that specific OCI job path, not arbitrary container scanner results |
| Network | Existing bounded single-session TLS, selected-group and hybrid-evidence paths | Not a broad scan or automatic runtime/HSM dependency assertion; no network-job snapshot bridge added here |
| Cloud | Existing cloud scanners and resource identities | No cloud-to-this-snapshot adapter or new credential/provider access added |
| HSM / hardware | Existing hardware metadata, operation-evidence and qualification paths | Physical origin, key residence and operation use require their own evidence; no automatic `USES_HSM` |
| Vendor | Existing supplier/catalog/association paths and OCI label declarations | Image vendor label is declared context, not observed supplier assurance |
| Correlation | Existing asset/software identities, general graph, host association review and crypto drift | **Added here:** common collection snapshot, stable scoped metadata graph, exact fact-multiset drift for host/OCI jobs |
| Hardening | Existing tenancy/residency, current-human authority, hash-linked revisions, audit transaction and storage budgets | New tests cover these paths; no HA, uptime, performance SLA or bank production acceptance claimed |

Some previously published candidate modules are currently deleted/edited in the user's pending workspace. Those changes were not restored, overwritten or published as part of this increment. The publication candidate was tested separately against the published dependency tree plus only this change; a focused suite also ran against the current workspace. See the evidence report for exact scope.

**This is not completion of every phase.** Other collector families still need explicit common-snapshot adapters. Enterprise/physical identity correlation, approved operational relationships, downstream threat-intelligence UI integration and production qualification are not created by this metadata bridge. Existing scanner implementations must be audited before adding those adapters, rather than reimplemented because a catalog entry is stale.

## One source, six views

Each snapshot stores bounded input dispositions and observation references: original observation/evidence IDs, fact hash, source input, local basis and domain membership. Original typed fact values remain in the existing evidence endpoints. There is no second copy of raw files, package databases, certificate bodies or private keys.

- **SBOM:** package, binary and supported library metadata references.
- **CBOM:** certificate/configuration references; no promotion from configuration to negotiated use.
- **NBOM / HBOM:** references only when the admitted host source actually supplies supported metadata. Empty views are `UNKNOWN`.
- **VBOM:** OCI image vendor declarations are `DECLARED_ONLY`; they never become observed supplier relationships.
- **TechBOM:** references all retained snapshot observations, integrating these views without running another scan.

Every view has `complete=false`. There is no CycloneDX claim (`standard_document=false`). Use existing, separately schema-validated export paths when a standards document is required.

OCI config is pinned by the original image/config commitment. It is retained as a `PINNED_IMAGE_CONFIG` source for vendor context, **not counted as an extra approved metadata-file input**. For example, three selected OCI files still have an approved-input denominator of three, not four. No whole-image, host or estate coverage percentage is emitted.

## Stable identity without fabricated asset correlation

An **observation** belongs to a specific retained collection. A **metadata slot** identifies the same scoped record location across collections. Neither identifies an attested physical asset.

Host slots reuse the existing `metadata-slot/v1` identity: tenant scope, registered logical target, input kind/path, fact kind and software name or native identity key. OCI slots use a versioned namespace with tenant scope, registered logical target, kind/path, fact kind and software name. OCI manifest digest and software version are intentionally not slot keys: an updated image/package can be compared under the same logical target. Original source commitments and fact hashes still bind each observation to its exact version.

The fact commitment covers the complete typed fact, including any native interface commitment carried inside that fact. Interface-content churn can therefore produce record drift; operators must inspect it rather than infer an operational change.

A package name does **not** merge packages across targets, paths or collector families. Runtime PID/start/boot identities retain their existing instance boundaries. Multiple records sharing one slot are retained as a multiset, disclosed by `multiple_records_in_slot=true`, and never silently collapsed into a single installed component. Renamed package, changed path or changed native instance can create a different slot; this is not a global entity-resolution guarantee.

The metadata graph contains a scoped system node and metadata-slot nodes. Its only edge type is:

```text
SYSTEM_SCOPE —HAS_METADATA_REFERENCE→ METADATA_SLOT
```

Each edge has retained observation/evidence support, `provenance=IMPORTED` and `operational_use=UNKNOWN`. Edge IDs are stable across repeated collections of the same slot. No `USES`, `DEPENDS_ON`, `DEPLOYED_ON` or `USES_HSM` edge is inferred or written to the operational graph. Existing human-reviewed association workflows remain separate.

## Drift means record change, not an installation/removal verdict

Comparison requires the same family, logical registered target, system and environment. Candidate collection must start at or after baseline collection finishes. The baseline is an explicitly selected committed snapshot, **not an automatically approved business baseline**.

| Condition | Reported state | Meaning |
|---|---|---|
| Same slot and identical fact-hash multiset | Counted in `unchanged_slots` | Changing evidence IDs/timestamps alone does not create semantic drift |
| Same slot, changed fact or duplicate multiplicity | `CHANGED_METADATA_RECORD` | For example, package version changed in the selected package database |
| New slot, same input parsed in baseline | `NEW_METADATA_RECORD` | Newly reported metadata, not proof of a new installation |
| New slot, baseline source missing/failed | `NEWLY_OBSERVABLE_METADATA` | Visibility improved; do not label this a newly installed asset |
| Old slot missing; same candidate input parsed | `NOT_REOBSERVED_IN_PARSED_INPUT` | The previous metadata record was not returned from that parsed source |
| Old slot missing; candidate input failed/unavailable | `UNRESOLVED_COLLECTION_GAP` | Observation cannot establish continued presence or absence |
| Old slot's source no longer selected | `OUT_OF_COMPARISON_SCOPE` | Scope changed; no removal conclusion |

Every change retains baseline/candidate observation IDs and fact-hash counts. All changes have `asset_absence_proven=false` and `installation_or_removal_proven=false`. Input dispositions remain visible even when neither snapshot contains a positive fact for an input. Comparing two empty observations lists does not certify absence or coverage.

### Practical examples

1. **OCI package upgrade:** two separately authorized image captures under `payments-image` report `openssl 3.0.17` and `3.0.18` at the same package-database location. The slot is unchanged; the fact hash changes; drift is `CHANGED_METADATA_RECORD`. No runtime use is established.
2. **Later certificate read failure:** the baseline contains a certificate fact; the next approved capture cannot read that input. Drift is `UNRESOLVED_COLLECTION_GAP`, not certificate removal. The public synthetic witness exercises this through actual intake and HTTP endpoints.
3. **Narrowed OCI scope:** the next authorization selects OS metadata but not the old package input. Old software slots are `OUT_OF_COMPARISON_SCOPE`; their omission is not inventory cleanup.
4. **Identical recollection:** original observations/evidence IDs and collection timestamps change while fact hashes are unchanged. There is no semantic metadata change; the graph still records the candidate's exact evidence references.

## Durable integrity and boundaries

- Current selected-estate human authority is required for POST. Readonly/auditor users can inspect but cannot materialize records.
- Snapshot/drift revisions are write-once. Duplicate requests return 409; PostgreSQL uniqueness plus the audit transaction commits only one duplicate writer.
- Every snapshot GET and paginated listing rebuilds the snapshot/views from the original verified source closure. Drift GET reopens both snapshots and recomputes the comparison. Recomputed mismatch refuses with 409, including a view whose local record hash was maliciously resealed.
- Snapshot/drift creation and audit entries share one transaction. Audit failure leaves no partially committed materialization.
- Creating a historical snapshot after target revocation is permitted because it does not authorize new collection. Existing handoff/intake revocation controls are unchanged.
- Existing 1.5 MB assurance payload limits apply. Oversize records are refused, not truncated. Snapshot bounds are 101 source descriptors and 1,001 references, including the possible pinned config/vendor context. List pages are bounded to 20 summaries and verify each returned source.
- Hashes provide unsigned integrity and reproducibility, not authenticity, independent custody or physical truth. Coordinated rewriting of all sources/commitments is not defeated by an unsigned hash chain alone.
- Runtime use remains `UNKNOWN`; whole-asset coverage, source authenticity and production execution qualification remain false. Controlled-production admission is not enabled.

The next integration work should adapt the next existing collector family to the same retained-source closure and then connect approved domain/relationship consumers. Do not broaden this metadata edge into an operational-use claim to make a graph appear complete.
