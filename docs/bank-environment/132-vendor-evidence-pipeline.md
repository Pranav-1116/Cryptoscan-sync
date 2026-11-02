# The evidence pipeline: from a log line to a VBOM row

`cryptoscan.vendor-evidence-guide/3` · generated 2026-11-02T15:34:18.342445+00:00 · as of 2026-11-02 · **6 pass · 0 partial · 0 fail**

Guides 130 and 131 built an evidence model and then closed the gaps that model named against itself. What neither showed is the part a bank actually runs: **the logs it already keeps, joined to the register it already has, producing a row somebody can defend in a review.** That is this artifact.

| | what it adds |
|---|---|
| `log_readers` | Zeek `ssl.log`, a CSV export and an access log with `$ssl_cipher` appended become session records; a key-material column refuses the file and a file that yields nothing raises instead of reporting calm |
| `workload_attribution` | peers are joined to a register: one endpoint and one application is `ATTRIBUTED`, a shared appliance is `AMBIGUOUS` with both named, an unregistered peer is `UNATTRIBUTED`, and the remainder stays in the workload table |
| `sbom_sub_vendors` | a CycloneDX `supplier` becomes a sub-vendor edge cited to the component; a component with no supplier is listed, never inferred |
| `alias_overrides` | a bank may add spellings, may not redefine builtins, and gets an unfilled review stub for the names nobody recognises |
| `due_diligence_evidence` | the twenty-two-section check can say COMPLETE while the evidence audit says nothing is supported — both answers are printed |
| `end_to_end` | one log line, through decode, attribution, claim, VBOM row and coverage statement, with each hop asserted |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `log_readers` | can a session record come from a log the bank already keeps? | **PASS** | 7, 0 failing |
| `workload_attribution` | does an observed session say which application used the primitive? | **PASS** | 6, 0 failing |
| `sbom_sub_vendors` | does a sub-vendor edge come from the SBOM, or from folklore? | **PASS** | 6, 0 failing |
| `alias_overrides` | can a bank teach the reader its own spellings without weakening it? | **PASS** | 6, 0 failing |
| `due_diligence_evidence` | is a due-diligence section filled in, or supported? | **PASS** | 4, 0 failing |
| `end_to_end` | can one log line be followed all the way to a VBOM row somebody can defend? | **PASS** | 5, 0 failing |

## `log_readers` — PASS

*can a session record come from a log the bank already keeps?* (review item 6)

- **PASS** `a-zeek-log-becomes-session-records` — 12 of 13 row(s) used, 1 skipped: no cipher: the handshake did not finish
- **PASS** `the-log-carries-post-quantum-key-establishment` — 12 session(s) -> ['ML-KEM-768'] at HIGH confidence; the curve column is where it appears
- **PASS** `a-csv-is-mapped-and-its-unknown-columns-are-named` — 2 row(s) used, 1 skipped, columns not used: ['hostname']
- **PASS** `an-access-log-yields-protocol-cipher-and-curve` — one line decoded (TLS_AES_256_GCM_SHA384), one skipped with 'no timestamp or no cipher at the end of the line: th…'
- **PASS** `a-key-material-column-refuses-the-file` — the CSV is refused rather than partially read: column 'premaster_secret' looks like key material or payload; this reader takes metadata o
- **PASS** `a-file-that-yields-nothing-raises-instead-of-reporting-calm` — 1 row(s) were read and none carried a session: no timestamp or no cipher at the end of the line: this virtual 
- **PASS** `an-unrecognised-file-is-named-not-guessed` — detected None and refused: the log is not in a shape this reader knows (zeek_ssl_log, csv, nginx_access); d

## `workload_attribution` — PASS

*does an observed session say which application used the primitive?* (review item 11/12)

- **PASS** `one-endpoint-one-application-is-attributed-with-its-citation` — 12 session(s) -> ['Payments API'] on ['HSM-001'], backed by VE-215c15a655cc
- **PASS** `a-shared-appliance-is-ambiguous-and-names-both` — AMBIGUOUS: Payments API, Reporting — the endpoint hosts 2 applications; a session on a shared appliance cannot say which one used the primitive
- **PASS** `an-unregistered-peer-is-not-assigned-to-the-nearest-appliance` — 10.9.9.9:443 -> UNATTRIBUTED with no application; the collector's asset is kept and the workload is not guessed
- **PASS** `an-endpoint-with-no-application-is-partial` — PARTIAL: the asset is known and the workload is not — the endpoint is known and names no application, so the asset is identified and the workload is not
- **PASS** `the-workload-table-keeps-the-remainder` — {'Payments API': 12} covers 66.7% of sessions; the other 6 are an unknown workload, not a rounding difference
- **PASS** `every-half-answer-reaches-a-ledger` — 3 ledger entr(ies): 10.0.0.7:443=AMBIGUOUS, 10.0.0.8:443=PARTIAL, 10.9.9.9:443=UNATTRIBUTED

## `sbom_sub_vendors` — PASS

*does a sub-vendor edge come from the SBOM, or from folklore?* (review item 12)

- **PASS** `a-supplier-field-becomes-an-edge-with-a-citation` — Vendor-Z openssl-wrapper 1.0.3 from field supplier, cited as sbom:urn:uuid:9f2c#c1 (VE-127cfef8ba9a)
- **PASS** `a-component-with-no-supplier-is-listed-not-inferred` — libfoo names no supplier, so no vendor is invented for it: the component carries no supplier, publisher or group; a component nam…
- **PASS** `the-parents-own-component-is-not-a-sub-vendor` — vendor-x-core is published by Vendor-X, so it is a self edge and not a dependency
- **PASS** `the-edge-reaches-the-estate-through-the-embedded-vendor` — direct ['HSM-001'], inherited ['APP-07'] via ['Vendor-Z']; Vendor-X: 1 appliance(s) bought directly, 1 more reached through 1 sub-vendor(s); 2 system(s) in total, of which 1 critical
- **PASS** `a-document-that-is-not-a-cyclonedx-bom-is-refused` — not a CycloneDX BOM: bomFormat='SPDX'
- **PASS** `an-empty-bom-is-called-a-metadata-gap` — 0 component(s) read for Vendor-X and no sub-vendor edge follows: that is a gap in the SBOM's supplier metadata, not evidence that nothing is embedded

## `alias_overrides` — PASS

*can a bank teach the reader its own spellings without weakening it?* (review item 15)

- **PASS** `a-bank-spelling-resolves-through-the-supplied-table` — AESGCM256 -> AES-256-GCM and RSA-3K -> RSA-3072; the builtin table is unchanged
- **PASS** `an-override-cannot-redefine-a-builtin` — 'AES256' is already a builtin spelling of AES-256; a bank table may add spellings, not redefine known ones
- **PASS** `an-alias-cannot-point-at-a-name-nobody-knows` — 'X99' points at 'NOPE-1', which this table does not know; add the family to the builtin table deliberately rather than aliasing into a name nobody can interpret
- **PASS** `the-review-stub-is-emitted-unfilled` — one unknown name queued with an empty target: {'Weird-99-xyz': ''}
- **PASS** `an-unfilled-stub-cannot-be-loaded-as-no-aliases` — 1 alias(es) have no target yet (Weird-99-xyz); the stub is meant to be filled in and reviewed, not l
- **PASS** `a-filled-stub-loads-and-normalises` — MYCIPHER-1 -> AES-128, and ZZZ is still in the review queue

## `due_diligence_evidence` — PASS

*is a due-diligence section filled in, or supported?* (review item 9)

- **PASS** `a-record-can-be-complete-and-support-nothing` — the completeness check says COMPLETE and the evidence audit says 0 of 22 sections are supported
- **PASS** `citations-that-resolve-are-support` — 22 section(s) supported against an evidence index of 20 record(s)
- **PASS** `a-citation-that-does-not-resolve-is-not-support` — fips_claims cites VD-missing, which is not in the evidence index, so the section is UNRESOLVED rather than supported
- **PASS** `every-uncited-section-is-a-listed-partial` — 22 partial(s) enumerated, none dropped, none renderable as a pass

## `end_to_end` — PASS

*can one log line be followed all the way to a VBOM row somebody can defend?* (review item 6/11/13)

- **PASS** `a-log-line-becomes-a-vbom-row` — ML-KEM-768 in the vendor block from 12 session citation(s), status RUNTIME_OBSERVED_ONLY
- **PASS** `the-row-traces-back-to-a-named-session` — every citation names a session id from the log (session:C0, …) rather than a document that restates the conclusion
- **PASS** `the-coverage-statement-says-which-tick-is-backed` — 1 post-quantum tick, 1 evidence-backed (['ML-KEM-768']) and 0 resting on a declaration
- **PASS** `the-workload-behind-the-tick-is-named-or-not-claimed` — 12 of 12 session(s) are attributed to a single application; 0 peer(s) are ambiguous, 0 name an asset but no application and 0 are unknown workloads — so the row can say which workload, or say that it cannot
- **PASS** `the-document-carries-the-verdict-not-just-the-algorithm` — 3449 bytes of VBOM document carrying the algorithm, the verification status and an evidence id

## What this does not prove

- the logs are fixtures written by this file. The readers are graded against the column names, separators and absent-value conventions those formats use, not against a bank's own parser quirks
- attribution matches host and port exactly after normalisation. A NAT, a proxy or a load balancer between the session and the appliance will produce UNATTRIBUTED peers, which is the honest answer and not a defect to work around
- a shared appliance hosting several applications is reported AMBIGUOUS. Splitting that further needs an application-level audit trail this module does not have
- sub-vendor edges come from CycloneDX supplier metadata. A supplier field that is wrong makes the edge wrong; the citation is there so the claim can be checked against the vendor's own SBOM
- the alias table is validated but its content is a judgement: a bank that aliases MYCIPHER-1 to AES-128 has asserted that, and the audit trail is the reviewed file
- a due-diligence citation is checked for resolution only when the caller supplies an evidence index; without one, SUPPORTED means 'cites something', not 'cites something that exists'

## What is still missing

1. **A live collector.** The readers take text. Something has to ship the log — a file drop, a syslog forwarder, a read-only mount — and that deployment is where the metadata-only rule is enforced a third time (after the reader and the decoder).
2. **Application-level attribution on shared appliances.** Splitting an `AMBIGUOUS` peer needs a per-application audit trail (a PKCS#11 log with a process id, a mTLS client certificate per workload), which is a connector, not a matcher.
3. **Transitive sub-vendor discovery.** Edges come from one SBOM's supplier fields. Following a vendor's own SBOM to its suppliers is the next hop, and it needs the vendor to publish one.
4. **A signed alias table.** The file is reviewed and validated; it is not signed, so its provenance is a process rather than a proof.
5. **Prose answers.** A questionnaire that answers in paragraphs, rather than `Label: value` lines or a table, is still read only where a label is recognisable.

## How to run it

```bash
python scripts/vendor_evidence_pipeline.py --as-of 2026-11-02 \
--json docs/bank-environment/132-vendor-evidence-pipeline.json \
--md docs/bank-environment/132-vendor-evidence-pipeline.md
python scripts/vendor_evidence_pipeline.py --check   # non-zero on FAIL or PARTIAL
```

