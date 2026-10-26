# Offline OCI image candidate — engineering evidence, 2026-10-25

## Decision and scope

**LOCAL ENGINEERING VALIDATION ONLY.** The offline OCI candidate and pure six-view materializer ran against owned synthetic image bytes. This is not a real customer image assessment, complete image/estate SBOM, container execution test, native Windows/ARM qualification, physical-HSM proof, independent acceptance or production release.

See [Guide 68](../bank-environment/68-offline-oci-image-collection.md), [operator runbook](../runbooks/offline-oci-image-evidence.md) and [contracts](../api-reference/offline-oci-image-evidence.md).

The user selected the current working tree as the authoritative baseline. It contains substantial pending unrelated edits and untracked foundation code. This increment adds isolated files; it does not replace that baseline, stage/publish its contents, edit workflows or dispatch CI. It has **not been pushed as a standalone working release**, since its existing foundation dependencies are themselves untracked in this checkout. The repository workspace, not a hypothetical new commit, is the tested source of truth.

## Executed validation

| Gate | Result |
|---|---|
| New OCI runtime/CLI/negative cases | **87 passed**, included in affected gate |
| New target/schema contract cases | **17 passed**, included in affected and shared-model gates |
| OCI + existing host/Linux/Windows/RPM affected regression | **231 passed / 3 skipped**, 6.32 seconds |
| All current shared-model tests | **779 passed**, 4.11 seconds; overlaps the contract cases above |
| Original CLI target/evidence/view returns | Typed model + Draft 2020-12 validation PASS |
| Three published schemas | Exact model-schema equality and Draft 2020-12 structure PASS |
| Ruff lint / format | Six new Python files PASS |
| Environment dependency consistency | `pip check` PASS |
| Existing tracked diff preservation | Before/after SHA256 of the full tracked diff identical |

The three skips explicitly require a genuine Windows user/session: native local-file/reparse handling, SCM service receipts, and OS registry collection. Skips are **not Windows qualification**. No frontend/API/database code changed for this increment; frontend, PostgreSQL, HTTP integration, production performance and full-repository gates were not rerun or claimed.

An initial exploratory shared-model run used an incomplete import path and minimal environment and encountered dependency/import errors. The final 779-pass gate used all repository service/shared import roots and installed local test dependencies (`pydantic-settings`, `networkx`); no dependency manifests were changed. New OCI code itself uses the existing host/crypto/model support plus Python standard library. Final affected tests ran with the repository's timeout and socket-blocking test plugins installed.

## Actual owned witness

[Retained artifacts](offline-oci-image-2026-10-25/) include the actual CLI [target](offline-oci-image-2026-10-25/target.json), [original evidence](offline-oci-image-2026-10-25/evidence.json) and [six views](offline-oci-image-2026-10-25/views.json), plus test logs/JUnit and [integrity manifest](offline-oci-image-2026-10-25/evidence-manifest.json).

The CLI witness used a gzip OCI layer with exactly known fixture records:

- Debian package-database `openssl` record version `3.0.17` — metadata, not execution;
- OS declaration `debian` / `12`;
- a tiny **synthetic ELF-magic byte file**, not a real cryptographic library;
- declared `443/tcp` and `Fixture Vendor`, not a real listener/vendor verification;
- deliberately irrelevant environment, command and label strings, absent from output.

All three selected inputs parsed: scoped receipt coverage **3/3**, not image completeness. SBOM has two metadata references; TechBOM reuses all three. CBOM/NBOM/HBOM are `UNKNOWN`; VBOM is `DECLARED_ONLY`. No algorithm capability/use is inferred from `openssl`/`libcrypto` names. `authenticity_verified`, `full_image_software_complete`, `production_execution_qualified`, `image_executed`, `base_image_verified`, `live_listeners_observed`, `cyclonedx_export` and `graph_persisted` remain false where applicable.

The target contains an ephemeral owned test directory and a completed test approval window; **do not reuse it as a bank target**. Original fixture bytes are reproducible from the test helper, not retained as binary images in Git. Public metadata and hashes are retained; no private keys, credentials, raw image environment/config payloads or executable artifacts are retained.

## Negative controls actually exercised

- Changed approval target or wrong commitment refuses before image I/O.
- Expired scope and elevated execution refuse.
- Manifest media/schema, foreign URLs, unsupported compression/platform, wrong descriptor sizes/digests and wrong uncompressed diff IDs refuse.
- Traversal/absolute/noncanonical tar paths, duplicate paths, invalid whiteouts, PAX extension and trailing tar payload refuse.
- Symlinks/hardlinks/FIFOs and non-directory ancestors are never resolved; symlinked filesystem ancestors and hardlinked/symlinked blobs refuse.
- Ordinary whiteouts, root/directory opaque whiteouts, same-layer recreation and replacement-directory child removal are verified with known expected records.
- Selected-file, fact, tar-entry, raw-layer and total-blob budgets are exercised. Budget failures never become absence or success.
- Empty/invalid/ambiguous package inputs and private-key certificate inputs retain gaps without facts/raw private bytes.
- Exposed ports never create observed NBOM endpoints; packages never create crypto-use/HSM claims.
- Materialization rejects changed evidence digests and invalid/mutated typed returns; it is deterministic over the same retained evidence.
- Tests forbid subprocess execution, directory discovery, network connection and tar extraction calls during collection.
- CLI refuses duplicate JSON keys, unsafe output parents/links and overwriting; partial evidence is retained with exit 2 and wrong approval creates no output.

These tests demonstrate selected engineering controls, **not universal malicious-parser resistance, trusted producer custody, image authenticity or a hostile-code sandbox**.

## Retention and reproducibility

Run from the current approved workspace with all service/shared roots on `PYTHONPATH`:

```bash
python -m pytest services/inventory/tests/test_oci_evidence.py \
  shared/shared_models/tests/test_oci_collection_contract.py \
  services/inventory/tests/test_host.py \
  services/inventory/tests/test_host_windows.py \
  services/inventory/tests/test_collection_linux.py \
  services/inventory/tests/test_linux_runtime.py \
  services/inventory/tests/test_windows_runtime.py \
  services/inventory/tests/test_rpm_metadata.py -q
python -m pytest shared/shared_models/tests -q
```

`CRYPTOSCAN_OCI_WITNESS_DIR` optionally retains the three public JSON CLI witness files from the owned test. Use an owned output directory. That is a test-artifact facility, not customer qualification or an evidence signer.

The integrity manifest binds this increment's sources, generated schemas/docs and retained artifacts, plus relevant existing parser/contract/bootstrap dependencies. SHA256 checks integrity relative to this manifest; it is unsigned and does **not** prove authenticity, organizational approval, device origin or protected retention.

## Remaining integration and acceptance

1. Tenant-scoped OCI target/job authorization and durable evidence intake, including revoke/expiry/replay and database tests; the existing HTTP host contract remains unchanged.
2. Independent expected truth for actual authorized bank image formats and source coverage; no general complete-image claim from a selected metadata denominator.
3. Independent malicious-image/parser assessment and approved resource isolation before considering broader admission.
4. Evidence-backed deployment/vendor/operational relationships through existing reviewed graph paths, not automatic label/name correlation.
5. Real Windows/container runtime/customer/HSM qualification and bank production acceptance remain separate external gates.
