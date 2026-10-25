# 70. Phase 2 — Linux software evidence

**Follow-up:** [guide 71](71-linux-relationships-and-validated-sbom.md) implements a separate officially validated CycloneDX export and evidence-backed Linux relationship view. This guide still describes the unchanged intermediate endpoint.

## Delivered increment, not a completed phase

Continue the ordered build in [guide 69](69-phasewise-universal-collection-build.md): foundation first, then Linux, then Windows, containers, network, cloud, hardware/HSM, vendor, correlation and production hardening. This increment implements a usable Linux software evidence view and hardens Debian input parsing. It does **not** qualify all Linux surfaces, finish all ten phases or admit new remote execution.

Collectors still emit facts, not BOM documents. One authorized collection session supplies all six existing projection namespaces: **SBOM, CBOM, NBOM, HBOM, VBOM, TechBOM**. A namespace with no evidence is not a complete BOM or an absence conclusion.

## What changed

1. Debian status input now parses bounded literal Deb822 records rather than collapsing matching lines into a dictionary. Duplicate fields, identity continuations, malformed status triples and duplicate package names refuse the entire input. Because the current fact contract has no architecture, multiarch records with the same name refuse instead of silently merging.
2. A record with current state `installed` is retained even when selection is `hold`, `deinstall` or `purge`. Selection is not current installation state. A `reinstreq` installed record is not a claim of a healthy installation. Missing version stays `null`; an explicitly empty version refuses.
3. A deterministic typed intermediate inventory groups original package observations by existing scoped metadata slot. Multiple records remain unresolved with no selected winning version. The slot is **not** an attested physical asset identity.
4. A read-only API and a button inside the existing CBOM host-evidence coverage drilldown expose the inventory. Neither registers targets nor starts collection. No new service, table or dashboard.

Existing APK and bounded RPM metadata facts can enter the same view. This increment does not add package-manager commands, scripts, dependency resolution, network retrieval or broad filesystem discovery. Version-1 raw fact/envelope defaults are unchanged: old evidence is not reparsed into new facts on read. New source code does require a new approved source lock for a future operator run.

## Three evidence classes that must not be merged

| Evidence | Meaning | Does not establish |
|---|---|---|
| `packages` | Exact original package-database observations, grouped by scoped metadata slot; manager/name/known version | Artifact contents, complete installed inventory, architecture, license, dependency graph or invocation |
| `binary_presence` | Original approved binary metadata observations | Package ownership, installed version, loaded executable or crypto use |
| `mapped_library_paths` | Original process-map shared-object-path observations | Package identity/version, call execution, specific key use or production traffic |

Every package group retains original observations, including evidence ID, observation ID, fact digest, source input ID/path/content digest and local evidence basis. `IMPORTED` describes transport; it does not upgrade local `DECLARED` to `OBSERVED`. The original stored intake snapshot contains emitted metadata and digests, **not a retained copy of every source file's raw bytes**. Hash agreement establishes consistency, not worker honesty, host attestation or authenticity.

## Practical read

After the existing registry/authorization/handoff/intake/completion workflow, use an already authenticated, estate-assigned session:

```http
GET /api/v1/collection/jobs/{completed-job-id}/software/linux
```

The response schema is `cryptoscan.linux-software-inventory/v1`. It contains:

- `coverage`: the exact original approved-input surface coverage, historical target revision and envelope digest;
- `package_inputs`: **only package-database inputs**, including original failure outcomes/reasons; binary inputs are not substituted into this denominator;
- `packages`, `binary_presence`, `mapped_library_paths` as separate bounded lists;
- explicit `standard_document: false`, incomplete inventory/dependency flags, and false host-attestation/production-qualification flags.

Example interpretation: an `openssl` database record with version `3.0.13` says that the approved metadata contained that version. Its source-content hash is **not** a package artifact digest. Architecture/licenses/dependencies/runtime/cryptographic use remain `UNKNOWN`; purl and package-artifact digest remain `null`. The package name does not prove that a bank application negotiates RSA, uses a particular certificate or invokes an HSM key.

This is **not a CycloneDX SBOM**. No standard schema validation or complete SBOM claim is made for this response. The existing separately validated CBOM export does not make this new profile standard-compliant.

### Interface

Within the existing collection coverage section, inspect a completed job, then explicitly select **Read Linux software evidence**. The view displays package outcomes, separate record counts and up to 50 package groups / five evidence records per group. It discloses truncation; the authorized API retains the full bounded result. Reads use tenant/session headers, a 20-second timeout, no automatic retry, and clear data on job, tenant, auth, storage, resume and history changes. A browser abort is not a collection cancellation—but this operation performs no collection at all.

### Refusals and gaps

- Cross-estate or unselected platform-admin access: `404`, using the existing estate boundary.
- Uncompleted job, altered original evidence, mismatched target/digests or a non-Linux scope: `409`, no replacement inventory.
- A failed package input can coexist with valid binary evidence. It remains a visible gap, never `NO_ASSET` or an empty-complete package inventory.
- No approved package inputs: empty `package_inputs`, no package denominator. The software surface may still contain approved binary metadata.
- Noninstalled-only Debian input retains the conservative unsupported/no-facts outcome; it is not proof that the host has no software.

## Validation and deployment boundary

See [the local readiness record](../readiness-evidence/linux-software-2026-10-25.md) for exact completed checks and limitations. Tests use owned synthetic fixtures and disposable local PostgreSQL, not bank hosts. Target labels such as `prod` in fixtures do not constitute production execution.

Do not reuse a previous signed collector source lock after these parser/model changes. The existing source-lock builder includes inventory/shared-model sources and will detect the difference. Rebuild and independently approve the release/source lock and rerun the assigned operator packet. No operator signature, approval, credential, private key or bank qualification is manufactured here.

## Next ordered work

Phase 2 stays open: reconcile remaining Linux evidence-to-asset/edge mappings across services, libraries, certificates, configuration, listeners and hardware, with explicit unsupported scope and per-edge evidence. A standard SBOM requires its own justified component identities, ambiguity handling, pinned official schema validation and negative tests—not relabeling this metadata response. Proceed to Phase 3 qualification only after the Linux acceptance gates and real operator/reviewer returns are satisfied. Windows and later adapters already present in the repository are candidates, not evidence that those phases are complete.
