# Four questions the last guide could not answer

`cryptoscan.sbom-availability-guide/1` · generated 2026-11-02T17:08:05.961167+00:00 · as of 2026-11-02 · **5 pass · 0 partial · 0 fail** · 68 probes

Guide 135 ended with a list of what it had not proven. Four of those entries were not footnotes but missing capability, and this artifact is where each one is measured:

1. **Failure domains.** An object store in the same region as the primary is not a backup. `storage_topology` refuses a pair that shares a required axis — and refuses one that never declared the axis, because an unknown domain is not a second one.
2. **Replicated writes.** `ReplicatedStore` writes every object to every site, reads each write back and compares digests, and only acknowledges on a verified quorum. The artifact manifest now carries both the placement verdict and which sites verified the bytes.
3. **Archive intake.** `archive_guard` refuses traversal, device nodes, fifos and links out of the root *before* expansion, and `binary_scan` never parses a refused member. A hostile archive is a refusal, not a budget.
4. **Obligations and deployment.** `license_obligations` turns a licence plus a distribution model into cited duties, and `deployment_collectors` turns a pod listing and a CMDB register into observations that stop the moment the runtime only offers a tag.

The decision tables behind these probes are 4 placement cases, 9 archive cases and 13 licence-model cases.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `storage_failure_domains` | can the platform tell a replica from a second copy in the same room? | **PASS** | 9, 0 failing |
| `replicated_writes` | is a copy a copy, or only a write that returned 200? | **PASS** | 10, 0 failing |
| `archive_intake` | may this archive's members be expanded at all? | **PASS** | 19, 0 failing |
| `licence_obligations` | what does shipping this component make the bank do? | **PASS** | 20, 0 failing |
| `deployment_evidence` | is this component in the SBOM, or in production? | **PASS** | 10, 0 failing |

## `storage_failure_domains` — PASS

*can the platform tell a replica from a second copy in the same room?* (review item 8)

- **PASS** `placement-same-region,-other-zone` — REFUSE — REFUSED: primary and replica share region, so one event removes both copies
- **PASS** `placement-other-region` — ALLOW — 2 site(s), separated on region
- **PASS** `placement-other-provider,-same-region` — REFUSE — REFUSED: primary and replica share region, so one event removes both copies
- **PASS** `placement-other-region,-same-provider` — ALLOW — 2 site(s), separated on region
- **PASS** `one-site-is-not-redundant` — REFUSED: 1 site(s) declared; at least 2 are required for a replica to survive the loss of the first
- **PASS** `an-undeclared-axis-is-not-separation` — REFUSED: a and b do not both declare zone, so separation on it cannot be shown
- **PASS** `undeclared-topology-is-a-state-not-a-pass` — UNDECLARED: no SBOM_STORAGE_SITES topology is configured
- **PASS** `invalid-topology-is-refused` — INVALID: the declared topology cannot be read
- **PASS** `a-declared-cross-region-pair-passes` — 2 site(s), separated on region

## `replicated_writes` — PASS

*is a copy a copy, or only a write that returned 200?* (review item 8)

- **PASS** `every-site-verifies-its-own-copy` — verified on dr, primary; quorum 2
- **PASS** `health-is-reported-per-site` — 2 site(s), quorum 2, no write failures
- **PASS** `a-corrupted-read-back-is-a-failed-site` — write refused below quorum; 1 site(s) have failed a write: dr
- **PASS** `a-quorum-survives-one-dead-site-and-says-so` — quorum 2 of 3 sites; 1 site(s) have failed a write: cold
- **PASS** `one-copy-out-of-two-is-not-a-quorum` — two-site write with one dead site raises instead of acknowledging
- **PASS** `the-manifest-records-the-placement-verdict` — 2 site(s), separated on region
- **PASS** `the-manifest-records-which-sites-verified-the-object` — 2 object(s) verified on 2 site(s)
- **PASS** `the-object-really-exists-at-the-second-site` — 2 object(s) written to the replica root
- **PASS** `a-same-region-replica-is-refused-on-the-manifest` — REFUSED: primary and dr share region, so one event removes both copies
- **PASS** `an-undeclared-replica-domain-is-not-called-separate` — UNDECLARED: 1 replica target(s) are configured but dr is not in SBOM_STORAGE_SITES

## `archive_intake` — PASS

*may this archive's members be expanded at all?* (review item 17)

- **PASS** `guard-traversal` — REFUSE — REFUSED: the member name traverses upward ('../../etc/passwd') (1 member(s) refused)
- **PASS** `guard-nested-traversal` — REFUSE — REFUSED: the member name traverses upward ('app/../../../etc/shadow') (1 member(s) refused)
- **PASS** `guard-absolute-path` — REFUSE — REFUSED: the member name is absolute ('/etc/passwd') (1 member(s) refused)
- **PASS** `guard-windows-drive` — REFUSE — REFUSED: the member name carries a Windows drive letter ('C:\\windows\\system32\\x.dll') (1 member(s) refused)
- **PASS** `guard-backslash-traversal` — REFUSE — REFUSED: the member name uses backslashes, which some extractors read as separators ('app\\..\\..\\win.ini') (1 member(s) refused)
- **PASS** `guard-overlong-name` — REFUSE — REFUSED: the member name is longer than 1024 bytes (1 member(s) refused)
- **PASS** `guard-escape-sequence` — REFUSE — REFUSED: the member name contains a control character (1 member(s) refused)
- **PASS** `guard-ordinary-member` — ALLOW — 2 member(s), 9 declared bytes, nothing outside the root
- **PASS** `guard-nested-member` — ALLOW — 2 member(s), 9 declared bytes, nothing outside the root
- **PASS** `a-nul-in-a-member-name-is-refused` — REFUSED: the member name contains a NUL byte, which truncates in C libraries (1 member(s) refused)
- **PASS** `a-symlink-out-of-the-root-is-refused` — REFUSED: 'app/link' links outside the archive root ('../../etc/shadow' resolves to '../etc/shadow') (1 member(s) refused)
- **PASS** `a-device-node-is-refused` — REFUSED: 'dev/mem' is a device node; expanding it would create one on the host (1 member(s) refused)
- **PASS** `a-fifo-is-refused` — REFUSED: 'run/pipe' is a fifo/socket; an archive has no business making one (1 member(s) refused)
- **PASS** `a-compression-bomb-ratio-is-refused` — REFUSED: the archive declares 10000000 bytes from a 100-byte declared compressed size (100000× compression), over the 200× ratio limit
- **PASS** `a-duplicate-member-is-refused` — REFUSED: 1 member name(s) appear more than once: a/index — a later entry silently replaces the earlier one
- **PASS** `a-clean-archive-passes` — 1 member(s), 68 declared bytes, nothing outside the root
- **PASS** `an-unrecognised-format-is-not-assumed-fine` — REFUSED: the format is not recognised, so its members cannot be checked
- **PASS** `the-scanner-never-parses-a-refused-member` — archive_guard=REFUSE; REFUSED: the member name traverses upward ('../../etc/passwd') (1 member(s) refused)
- **PASS** `a-clean-container-carries-an-allowing-guard` — 1 member(s), 68 declared bytes, nothing outside the root

## `licence_obligations` — PASS

*what does shipping this component make the bank do?* (review item 12)

- **PASS** `duties-MIT-INTERNAL` — ['PATENT_GRANT'] — MIT (PERMISSIVE) under INTERNAL: 1 duty to check — PATENT_GRANT — a checklist for counsel, not a legal opinion
- **PASS** `duties-MIT-BINARY_SHIPPED` — ['ATTRIBUTION', 'NOTICE_FILE', 'NOTICE_PRESERVATION', 'PATENT_GRANT'] — MIT (PERMISSIVE) under BINARY_SHIPPED: 4 duties to check — ATTRIBUTION, NOTICE_FILE, NOTICE_PRESERVATION, PATENT_GRANT — a checklist for counsel, not a legal opinion
- **PASS** `duties-Apache-2.0-BINARY_SHIPPED` — ['ATTRIBUTION', 'NOTICE_FILE', 'NOTICE_PRESERVATION', 'PATENT_GRANT'] — Apache-2.0 (PERMISSIVE) under BINARY_SHIPPED: 4 duties to check — ATTRIBUTION, NOTICE_FILE, NOTICE_PRESERVATION, PATENT_GRANT — a checklist for counsel, not a legal opinion
- **PASS** `duties-Apache-2.0-BINARY_SHIPPED-modified` — ['ATTRIBUTION', 'MODIFICATION_DISCLOSURE', 'NOTICE_FILE', 'NOTICE_PRESERVATION', 'PATENT_GRANT'] — Apache-2.0 (PERMISSIVE) under BINARY_SHIPPED: 5 duties to check — ATTRIBUTION, MODIFICATION_DISCLOSURE, NOTICE_FILE, NOTICE_PRESERVATION — a checklist for counsel, not a legal opinion
- **PASS** `duties-GPL-3.0-only-INTERNAL` — [] — GPL-3.0-only (STRONG_COPYLEFT) under INTERNAL: no duties identified — a checklist for counsel, not a legal opinion
- **PASS** `duties-GPL-3.0-only-BINARY_SHIPPED` — ['ATTRIBUTION', 'DERIVATIVE_SCOPE', 'NOTICE_FILE', 'SOURCE_DISCLOSURE'] — GPL-3.0-only (STRONG_COPYLEFT) under BINARY_SHIPPED: 4 duties to check — ATTRIBUTION, DERIVATIVE_SCOPE, NOTICE_FILE, SOURCE_DISCLOSURE — a checklist for counsel, not a legal opinion
- **PASS** `duties-GPL-3.0-only-BINARY_SHIPPED-modified` — ['ATTRIBUTION', 'DERIVATIVE_SCOPE', 'MODIFICATION_DISCLOSURE', 'NOTICE_FILE', 'SOURCE_DISCLOSURE'] — GPL-3.0-only (STRONG_COPYLEFT) under BINARY_SHIPPED: 5 duties to check — ATTRIBUTION, DERIVATIVE_SCOPE, MODIFICATION_DISCLOSURE, NOTICE_FILE — a checklist for counsel, not a legal opinion
- **PASS** `duties-GPL-3.0-only-SAAS` — ['DERIVATIVE_SCOPE'] — GPL-3.0-only (STRONG_COPYLEFT) under SAAS: 1 duty to check — DERIVATIVE_SCOPE — a checklist for counsel, not a legal opinion
- **PASS** `duties-AGPL-3.0-only-SAAS` — ['DERIVATIVE_SCOPE', 'NETWORK_SOURCE_OFFER'] — AGPL-3.0-only (NETWORK_COPYLEFT) under SAAS: 2 duties to check — DERIVATIVE_SCOPE, NETWORK_SOURCE_OFFER — a checklist for counsel, not a legal opinion
- **PASS** `duties-AGPL-3.0-only-INTERNAL` — ['DERIVATIVE_SCOPE'] — AGPL-3.0-only (NETWORK_COPYLEFT) under INTERNAL: 1 duty to check — DERIVATIVE_SCOPE — a checklist for counsel, not a legal opinion
- **PASS** `duties-LGPL-2.1-only-BINARY_SHIPPED-modified` — ['ATTRIBUTION', 'DERIVATIVE_SCOPE', 'MODIFICATION_DISCLOSURE', 'NOTICE_FILE', 'RELINKING', 'SOURCE_DISCLOSURE'] — LGPL-2.1-only (WEAK_COPYLEFT) under BINARY_SHIPPED: 6 duties to check — ATTRIBUTION, DERIVATIVE_SCOPE, MODIFICATION_DISCLOSURE, NOTICE_FILE — a checklist for counsel, not a legal opinion
- **PASS** `duties-MPL-2.0-BINARY_SHIPPED-modified` — ['ATTRIBUTION', 'DERIVATIVE_SCOPE', 'MODIFICATION_DISCLOSURE', 'NOTICE_FILE', 'RELINKING', 'SOURCE_DISCLOSURE'] — MPL-2.0 (WEAK_COPYLEFT) under BINARY_SHIPPED: 6 duties to check — ATTRIBUTION, DERIVATIVE_SCOPE, MODIFICATION_DISCLOSURE, NOTICE_FILE — a checklist for counsel, not a legal opinion
- **PASS** `duties-CC0-1.0-BINARY_SHIPPED` — ['NO_OBLIGATION'] — CC0-1.0 (PUBLIC_DOMAIN) under BINARY_SHIPPED: 1 duty to check — NO_OBLIGATION — a checklist for counsel, not a legal opinion
- **PASS** `an-unidentified-licence-needs-legal` — unknown licence (UNKNOWN) under INTERNAL: 1 duty to check — TERMS_UNKNOWN — a checklist for counsel, not a legal opinion
- **PASS** `a-non-commercial-licence-is-flagged-in-every-model` — CC-BY-NC-4.0 (NON_COMMERCIAL) under BINARY_SHIPPED: 1 duty to check — NC_USE_RESTRICTION — a checklist for counsel, not a legal opinion
- **PASS** `a-proprietary-licence-is-not-answered-by-this-table` — LicenseRef-Acme-EULA (PROPRIETARY) under BINARY_SHIPPED: 1 duty to check — COMMERCIAL_TERMS — a checklist for counsel, not a legal opinion
- **PASS** `the-engine-never-returns-compliant` — NEEDS_LEGAL, NO_ACTION, REVIEW
- **PASS** `every-duty-cites-a-clause` — 13 duties, each with a title and a cite
- **PASS** `a-portfolio-groups-duties-across-components` — 4 component(s) under BINARY_SHIPPED: 8 distinct duties, 1 component(s) with no identified licence — a checklist for counsel, not a legal opinion
- **PASS** `the-api-exposes-obligations-beside-the-licence-inventory` — /sbom/obligations answers what the model obliges; /sbom/license answers what is in the document

## `deployment_evidence` — PASS

*is this component in the SBOM, or in production?* (review item 6)

- **PASS** `a-running-container-becomes-an-observation` — 1 observation(s) from 1 workload(s)
- **PASS** `a-tag-only-image-yields-no-observation` — 0 observation(s) from 1 workload(s); 1 refused for carrying no digest
- **PASS** `a-crashlooping-container-is-not-deployed` — 0 observation(s) from 1 workload(s); 1 skipped as not running
- **PASS** `a-configmap-is-not-a-workload` — 0 observation(s) from 1 workload(s); 1 skipped as not running
- **PASS** `the-register-attributes-a-workload-to-a-business-system` — 1 application(s) covering 1 workload(s)
- **PASS** `a-workload-claimed-twice-is-a-conflict` — 2 application(s) covering 1 workload(s); 1 workload(s) claimed by more than one application
- **PASS** `a-matching-digest-is-present-in-deployment` — PRESENT_IN_DEPLOYMENT; 1 of 1 component answer(s) resolve to a running system; 0 stop at the artifact or the document
- **PASS** `an-unobserved-digest-stops-at-the-artifact` — PRESENT_IN_ARTIFACT
- **PASS** `an-unbound-document-is-never-called-deployed` — PRESENT_IN_SBOM_ONLY
- **PASS** `a-conflicted-workload-is-attributed-to-neither-application` — 1 of 1 component answer(s) resolve to a running system; 0 stop at the artifact or the document; 1 run without a single owning application

## What this does not prove

- the topology check compares what an operator *declared*. It cannot see that two providers' control planes share a fibre path or one IAM administrator, so 'separate on region' is a statement about the declared axes and nothing more
- the replicated writer verifies bytes, not availability: a write that reached a quorum says the copies exist now, not that a site will answer during an incident
- archive_guard judges the member list before expansion. It refuses what it can recognise as hostile; an archive format it does not model is reported as unrecognised rather than declared safe
- licence obligations are a checklist with clause citations, not legal advice. Derivative-work questions, linking questions and the acceptability of a licence are counsel's call, which is why the verdict tops out at NEEDS_LEGAL
- the deployment collector needs a truth source it is given. Without a cluster listing or a CMDB export it observes nothing, and 'no observation' is not 'not deployed' — it is 'nobody looked'
- correlation matches artifact digests. A workload running an image the registry has no SBOM for produces no rows at all, which is a gap in the inventory, not a clean result
