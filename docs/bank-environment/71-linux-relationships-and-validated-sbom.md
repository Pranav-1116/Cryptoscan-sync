# 71. Phase 2 — Linux relationships and validated CycloneDX SBOM

## Built, not merely planned

This follows [guide 70](70-linux-software-evidence-phase-two.md). The intermediate software endpoint is unchanged. There are now **two additional working outputs** over the same completed, verified intake:

```http
GET /api/v1/collection/jobs/{job-id}/relationships/linux
GET /api/v1/collection/jobs/{job-id}/software/linux/cyclonedx-1.6
```

The first returns a typed evidence graph. The second returns a **CycloneDX 1.6 JSON software BOM, validated before return against the pinned official schema and referenced schemas**. It is no longer necessary to relabel intermediate JSON as a standard document. The standard export explicitly declares its composition incomplete: schema conformance is not inventory completeness or production qualification.

Neither endpoint registers targets, runs collectors, opens host interfaces, executes package tools or scans again. Original v1 intake/fact/envelope fields and defaults remain unchanged. Existing estate authorization, historical approved-target binding, evidence reconciliation, limits and read rate controls apply. Foreign estate/unselected administrator returns 404; uncompleted or corrupted intake/non-Linux scope returns 409. Official-schema validation failure returns 503 with **no export**. Private responses are not cacheable.

## Linux evidence-to-node and relationship rules

Every original observation is retained as a separate graph node: OS, packages, binary metadata, processes, mapped paths, services, listeners, certificates, TLS configuration and hardware metadata. Nodes retain their scoped metadata slot, source path/input/content digest, original local basis, fact digest, evidence ID and IMPORTED transport basis. No physical asset identity or fresh observation is manufactured.

Only these joins are supported:

| Derived edge | Required evidence | Meaning / limit |
|---|---|---|
| `PROCESS_HAS_MAPPED_PATH` | Exactly one process observation matching the mapped-path observation's **boot ID + PID + process start ticks** in the same job | A deterministic metadata join for the same reported process incarnation, not proof of a function call, crypto operation or continuous/simultaneous activity |
| `PROCESS_REPORTS_SERVICE_UNIT` | Process fact records a service-unit name; exactly one approved service observation has that exact name | Relates a reported cgroup unit marker to captured unit metadata; does not prove service health, current ownership or causal execution |

Edges are explicitly **INFERRED deterministic metadata joins**, not new OBSERVED facts or AI-manufactured evidence. Each edge names its two endpoint observations and their evidence IDs. The typed graph recomputes allowed joins and refuses fabricated endpoints, proof references, edge identities, missing/extra joins and promoted completeness/use flags. Join IDs bind job, relation and both endpoint observations.

Missing or multiple candidates remain unresolved. A PID match with a different boot/start time never joins. The output includes the actual candidate count, at most 20 candidate IDs, and an explicit truncation flag; there is no all-pairs graph expansion or silent winner. No matching evidence does not mean no matching asset.

These relationships remain explicitly **unsupported by captured fields**, not guessed:

- service MainPID → process incarnation (MainPID alone is insufficient);
- listener → process (no socket ownership evidence);
- configuration → service (same host/path proximity is insufficient);
- certificate → listener (file presence/listening is not negotiated TLS);
- hardware/HSM → application or key (metadata presence is not application/key use);
- package → binary or mapped library (path/name similarity is not package ownership).

## Standard software export profile

The response media type is `application/vnd.cyclonedx+json`, with an attachment filename and the server's validation-basis header. The exported document contains only standard CycloneDX fields plus namespaced properties.

| Evidence | Export treatment |
|---|---|
| Single unambiguous package record | Component name and known version; no version field when unknown |
| Package component type | CycloneDX's documented **`application` fallback when a more specific software classification cannot be determined**; explicit `component_type_basis=CYCLONEDX_SPEC_DEFAULT_NOT_OBSERVED_CLASSIFICATION`, not a claim that the package is an observed application |
| Multiple unresolved records in one metadata slot | Group omitted from components; omission count and slot references retained in metadata; never pick a version |
| Binary file presence | `file` component named by approved source path; not package ownership or execution |
| Mapped-library path | Not upgraded to an artifact component; excluded count disclosed in metadata and original observations retained in the evidence endpoints |
| Dependencies | Entire `dependencies` field omitted; no invented inventory root, empty-leaf declarations or conversion of metadata joins into dependency edges |
| Licenses/purl/artifact hashes | Not invented or emitted as native claims. Evidence digests stay clearly named provenance properties, not package artifact hashes |
| Completeness | Native `compositions: [{"aggregate":"incomplete"}]`; additional properties say inventory/dependencies/use/attestation/production are unproven or unknown |

Each emitted component retains original evidence/observation IDs, source kind/path/content digest, fact digest, local basis and IMPORTED transport. Metadata binds job, historical target revision/hash and original envelope hash, includes approved/failed package-input counts and original failure statuses/reasons, and discloses ambiguous/mapped-path omissions. A failed package input can coexist with a valid standard file-only BOM without becoming a complete package inventory.

Export references and serial number are deterministic for the same evidence. A package metadata-slot reference is scoped, not a globally attested package identity. Export timestamp is the intake's operator-supplied finish time, explicitly not attested UTC. Standard conformance does not authenticate imported facts.

### Official schema integrity

Reuses the existing offline validator in `services/cbom/cbom/cyclonedx16.py`, with official CycloneDX tag 1.6 commit `55343ba19dee1785acf1ce9191540d5fd7b590db`, pinned SHA-256 commitments for the BOM/SPDX/JSF schemas and local-only reference resolution. No network schema retrieval. Missing/changed schemas, illegal fields/types, dangling dependencies or duplicate component references refuse validation. See the vendored schema provenance/license files; no new schema fork or weakened validator was introduced.

## Existing interface

Inspect a completed job in the existing collection coverage section, then:

- **Read Linux evidence relationships**: explicit read, 20-second bounded wait, no retry/rescan; shows counts, proof references, unresolved joins and unsupported patterns. Rendering is limited to 50 joins / 50 unresolved rows, disclosed separately from full API retention.
- **Download Linux CycloneDX 1.6 SBOM**: existing authenticated download control; tenant/session headers, private-context/body guards, abort on context/route changes and temporary object-URL cleanup. Never an unauthenticated anchor navigation. The existing download helper has a 30-second abort guard; a non-cooperative body reader can still remain pending, but cannot release stale-context bytes.

Tenant/auth/storage/resume/history/job changes discard stale graph results. Downloads already saved by an authorized user have separate custody: logout cannot revoke their local files.

## Phase 2 acceptance position

| Engineering gate | Position after this increment |
|---|---|
| Authorized bounded Linux input adapters | Existing explicit profiles retained; no broad host discovery or remote execution admission |
| OS/package/service/library/certificate/config/listener/hardware evidence | Existing typed facts reused; approved-input failures and unrequested surfaces remain visible |
| Per-node/per-edge evidence | Implemented, with exact supported joins and explicit unsupported patterns |
| Standard software export | Implemented and pinned-official-schema validated; intentionally incomplete inventory |
| Existing public-certificate/config CBOM | Existing separate validated host CBOM remains available; no cross-file operational relationship inferred |
| All six BOM namespaces | Existing SBOM/CBOM/NBOM/HBOM/VBOM/TechBOM evidence projections retained; not a promise of six complete standard documents |
| Independent source/host truth and real bank acceptance | **Pending external operator/reviewer evidence**; cannot be created by code or local tests |

See [local readiness evidence](../readiness-evidence/linux-projections-2026-10-25.md) for exact completed checks. This closes the identified local graph/export implementation gaps, not every possible Linux discovery capability or real-host qualification. Do not advance Phase 3 qualification by inventing human returns. Operators must run the existing assigned packet against the approved release/scope; no credentials/private keys are requested here.
