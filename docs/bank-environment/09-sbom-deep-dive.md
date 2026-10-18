# 09 — SBOM: software discovery, artifacts and supply-chain review

[Guide index](README.md) · [All six BOMs](04-six-boms.md) ·
[Bank release example](10-six-bom-bank-release-example.md)

## 1. What the bank buys an SBOM capability for

**SBOM means Software Bill of Materials.** It answers which software components
and versions are represented in a defined source/build/image scope, and which
relationships and provenance the available evidence supports.

A bank can use this to investigate a newly announced vulnerable dependency,
review software entering a payment zone, compare two supplier deliveries,
identify unpinned dependencies and retain an auditable release inventory. It is
not, on its own, malware detection, exploitability proof, license legal advice,
runtime execution monitoring or a cryptographic usage inventory.

A useful SBOM record can include package name, version, ecosystem/package URL,
component type, supplier/license/hash metadata where available, dependency edges,
input location and artifact identity. Missing values must not be replaced with
invented versions, licenses or publisher attestations.

## 2. Four levels of software evidence

| Level | Bank example | What it supports | What it does not prove |
|---|---|---|---|
| Declared | `package.json` says `jose: ^5.0.0` | A dependency was declared with that range | The exact version installed or shipped |
| Resolved | A matching supported lockfile resolves a package/version graph | The recorded resolution, with transitive entries/edges where supported | Which packages were excluded during a production build |
| Artifact | An inspected container/root filesystem or binary supplies package/component evidence | Contents detected in that specific inspected artifact | Which image is actually running in the bank |
| Deployed/runtime | Bank deployment inventory identifies an image digest or approved runtime observation | A linkage between a reviewed artifact and the deployed release, if substantiated | That every component was executed or every code path is exploitable |

The source SBOM scanner does not build/install the application just to resolve
all dependencies online. In particular, parsing a lockfile does not execute
`npm install`, Maven, pip, Gradle or arbitrary project build scripts.

## 3. How the source SBOM is generated

The standalone workflow is `POST /api/v1/devsecops/sbom/scan` with `kind=source`.
It validates an executor-local path against authorized source roots, walks that
source tree, parses supported manifests and merges supported lockfiles by
default. It then renders the selected format and stores a generated artifact.
This route is synchronous and normally returns **201 with an artifact ID**;
it is not the queued `/scans/trigger` job contract.

The current implementation includes manifest readers for the exact `requirements.txt` filename,
`package.json`, `pom.xml`, `go.mod`, `Cargo.toml`, `Gemfile`, `composer.json` and
intended `.csproj` handling. The current `.csproj` filename dispatch does not
match the helper's lookup key; do not promise that source path works without
a representative test. The supported .NET lockfile parser is a separate path. Supported lockfile names include:

```text
package-lock.json   yarn.lock        poetry.lock       Pipfile.lock
Cargo.lock          composer.lock    Gemfile.lock      go.sum
packages.lock.json  gradle.lockfile
```

A recognized filename does not certify full compatibility with every format
revision or build tool feature. Inspect per-ecosystem parser behavior, returned
rows and a bank-approved representative input. For example, checksum lists do
not necessarily encode a complete dependency graph, and unresolved Maven build
properties are not exact package versions.

When merging declarations and resolutions, the implementation can preserve
`declared_spec`, report resolved versions and tag source rows with scope/direct
information where determinable. These are not the same as runtime/dev deployment
scope. Current npm direct classification can include dev/optional/peer inputs;
**do not describe every direct row as a production runtime dependency**.

The walker normally excludes installation trees/caches/build outputs such as
`node_modules`, `.venv` and `dist`. `include_vendored=true` relaxes the `vendor/`
exclusion, not every skip rule. Source scanning has file/depth/size limits
(currently 50,000 walked files, nesting checks, 1 MB manifest and 8 MB lockfile
limits in the relevant helpers). Some malformed/oversized inputs can yield no
parsed rows rather than a complete failure. Independently reconcile expected
manifests/lockfiles against the result before claiming completeness.

**Important access difference:** this source SBOM endpoint rejects remote Git
URLs. First obtain the approved checkout/export on the executor, then scan the
admitted local path. A browser-local folder is not implicitly uploaded.

## 4. Containers and binaries are different input contracts

For `kind=container`, the SBOM workflow uses the container scanner on a supported
filesystem, docker-save archive or approved registry image reference. Registry
pulls require approved connectivity/tools/credentials and the route's air-gap
control; archives can avoid a registry pull but still need supported extraction
and inspection tools. Pin images by actual digest in bank evidence rather than
assuming a mutable tag is immutable.

For `kind=binary`, bounded binary/firmware observations can produce software
components plus additional BOM sidecars. Stripping, compression, unsupported
formats and unavailable external tools limit what can be identified. A library
name/fingerprint candidate is not necessarily a build-system package record.

The binary bundle's NBOM candidates describe detected network capabilities,
not actual live listeners. Its hardware/vendor projections are not automatically
the independent persisted-estate HBOM or due-diligence VBOM. The product's six
BOM questions remain distinct even when one artifact produces multiple views.

A container stored through `/container-scans` has a separate container record.
`GET /api/v1/container/scans/{scan_id}/sbom` and `/spdx` render its stored result.
Use that result's real scan identity, not a UUID from the standalone SBOM
artifact store or a queued source job.

## 5. API example: approved local software input

Use the restricted working directory and `bank_api` helper from
[05](05-practical-bank-walkthrough.md). The following is illustrative; it must
point to a real admitted executor-local input with appropriate permissions.
Save as `source-sbom-request.json`:

```json
{
  "kind": "source",
  "target": "/bank-input/payments-api",
  "format": "cyclonedx",
  "include_vendored": false,
  "use_lockfiles": true
}
```

```bash
bank_api POST /api/v1/devsecops/sbom/scan \
  --data-binary @source-sbom-request.json > source-sbom-response.json
SBOM_ARTIFACT_ID=$(python3 -c 'import json; print(json.load(open("source-sbom-response.json"))["artifact_id"])')
bank_api GET "/api/v1/devsecops/sbom/$SBOM_ARTIFACT_ID/download" > source-sbom.cdx.json
bank_api GET "/api/v1/devsecops/sbom/$SBOM_ARTIFACT_ID/verify" > source-sbom-verification.json
bank_api GET "/api/v1/devsecops/sbom/$SBOM_ARTIFACT_ID/report?fmt=markdown" > source-sbom-report.md
```

Inspect the actual response/manifest fields: component, manifest and lockfile
counts; direct/transitive counts where determinable; dependency edges; pinning;
minimum-elements assessment; crypto relevance; `feed_supplied`; target and
artifact provenance. A response does not necessarily expose every parser skip.

The route requires a permitted SBOM operator role. Its current code performs
path/role checks, but **does not explicitly call the shared `admit_scan` function**
used by some queued/direct scanner routes. It also does not invoke the queued
crypto AST parser's isolated launcher. Do not promise identical stop/window/
isolation semantics: restrict and qualify this path separately before use.

For a supplier document, `POST /api/v1/devsecops/sbom/import` expects `doc`; it
normalizes components and returns analysis, rather than proving a scan occurred
or promising automatic insertion into the generated-artifact store. Validation
is a separate request with `doc` to `/sbom/validate`.

## 6. Generated artifacts: durability, signing and verification

The standalone path returns `artifact_id`, `manifest`, `bom`, download/report/
verification URLs and applicable BOM information. Its artifact store is not the
TechBOM system table. The storage helper uses `SBOM_STORAGE_DIR` (default
`/var/lib/cryptoscan/sboms`) and can fall back to a temporary directory if the
requested store is unavailable.

**Bank deployment action:** explicitly provision and test persistent storage,
permissions, API/worker shared visibility, backup/restore and artifact access.
The supplied Compose files do not by themselves provision an SBOM artifact
volume merely because PostgreSQL is persistent. An on-disk store can survive a
process restart but not necessarily a container replacement or lost host disk.
A temporary fallback is not acceptable evidence retention for a bank pilot.

The path records the blob's SHA-256 and can sign its manifest with HMAC-SHA256
when a signing secret is available. Verification rechecks stored bytes and the
manifest signature through its actual key resolver. Inspect each returned check
and verdict, including unsigned/key-change cases. A component's checksum from
a lockfile is different from the digest of the generated whole-SBOM artifact.

Signing configuration, at-rest encryption and independent verifier trust are
separate controls. Do not assume that every writer uses the same sealing path,
that an on-disk artifact is always encrypted, or that an HMAC provides public-key
non-repudiation. Test the selected path and recorded `at_rest`/signature metadata
with the deployed key lifecycle; never export secrets with the evidence.

## 7. Vulnerabilities, licenses, pinning, VEX and gates

| Review | What is available | Safe interpretation |
|---|---|---|
| Dependency pinning | Version/range/unresolved-variable and applicable digest checks | An exact version reduces ambiguity; it does not make a package safe |
| Minimum elements | Supplier/name/version/identifier/relationships/author/time checks | A quality/completeness check, not third-party schema certification or regulatory approval |
| Advisory matching | Optional supplied feed matched against discovered versions; other collector paths can differ | `feed_supplied=false` with zero vulnerabilities does not mean vulnerability-free |
| License analysis | Declared/detected identifiers and configured policy outcomes | Missing/ambiguous licenses need review; software output is not legal advice |
| VEX | Supported assessment document workflows | A supplied “not affected” assertion needs product/version and justification evidence |
| Artifact gate | Deterministic counts/metadata and selected policy thresholds | A gate decision is only as meaningful as input coverage/feed/key/policy context |

`POST /api/v1/devsecops/sbom/{artifact_id}/gate` evaluates a stored artifact.
Do not treat a `signed` presence check in a policy gate as cryptographic
verification; run the artifact verifier too. No single default gate establishes
bank acceptance of an application or satisfaction of all legal controls.

`POST /api/v1/devsecops/sbom/diff` can compare actual artifact IDs or supplied
documents. It reports supported added/removed/version/license/crypto changes.
`POST /api/v1/devsecops/sbom/{artifact_id}/rescan` reuses stored options with
supported overrides. A mutable target path/tag may now represent different
content; retain the release identity and actual input digest.

## 8. Where the bank sees SBOM in the UI

Open **Discovery → Applications** (`/dev-sec-ops`), choose **SBOM**, then:

- **Scan & generate:** select source/container input and supported options.
- **Artifacts:** retrieve a stored artifact, report, verification and gate result.
- **Diff:** compare two actual artifacts.
- **Validate:** inspect minimum-element gaps in a supplied document.
- **Licenses:** review available declared identifiers and policy results.
- **Index:** query available indexed component/advisory data; inspect indexing
  scope and persistence rather than assuming every artifact is indexed.
- **Import:** normalize a supplied CycloneDX/SPDX document.

There is no registered dedicated `/sbom` SPA route. TechBOM export
`layer=sbom` is supported but exports its registered-application projection,
not automatically the standalone package SBOM artifacts described here.

## 9. How SBOM relates to the other five BOMs

A software package can indicate crypto relevance, but a curated package-name
mapping only suggests capability. CBOM evidence must support an actual crypto
usage claim. A package may be present in an image without being used by the
application; a TLS gateway may use a different library outside that image.

Match release commit/build identity, image digest, ecosystem/version/package URL,
application ID, device identity, endpoint/SNI/certificate, supplier product and
observation times where there is evidence. Current stores do not automatically
create every one of these links. Preserve unknown links and distinguish supplied
relationships from measured ones. See [the detailed six-BOM example](10-six-bom-bank-release-example.md).

## 10. Representative output from a local documentation fixture

The example below is generated from a temporary, synthetic manifest/lockfile
fixture using the actual `scan_source` and `render_sbom` functions. No bank
files, registry, installation command, live collector or application database is
used. It illustrates an exact software inventory path, not a production result.

The fixture declares `jose: ^5.0.0`; its synthetic lockfile resolves `jose` to
`5.9.6` with a deliberately fictional `demo-helper` transitive relationship.
**This is not a claim about the real jose package dependency graph**, a current
recommended version or its vulnerability status. No packages are downloaded.

Partial actual rendered output (omits document identity, time and other fields):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "demo-helper",
      "bom-ref": "pkg:npm/demo-helper@1.0.0",
      "purl": "pkg:npm/demo-helper@1.0.0",
      "version": "1.0.0",
      "properties": [
        {
          "name": "cryptoscan:scope",
          "value": "resolved"
        },
        {
          "name": "cryptoscan:direct",
          "value": "false"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    },
    {
      "type": "library",
      "name": "jose",
      "bom-ref": "pkg:npm/jose@5.9.6",
      "purl": "pkg:npm/jose@5.9.6",
      "version": "5.9.6",
      "properties": [
        {
          "name": "cryptoscan:crypto-library",
          "value": "true"
        },
        {
          "name": "cryptoscan:vendor",
          "value": "py-jose"
        },
        {
          "name": "cryptoscan:deprecated",
          "value": "false"
        },
        {
          "name": "cryptoscan:algorithms",
          "value": "RSA, ECDSA, EdDSA"
        },
        {
          "name": "cryptoscan:scope",
          "value": "resolved"
        },
        {
          "name": "cryptoscan:direct",
          "value": "true"
        },
        {
          "name": "cryptoscan:declared-spec",
          "value": "5.0.0"
        }
      ],
      "supplier": {
        "name": "py-jose"
      },
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/jose@5.9.6",
      "dependsOn": [
        "pkg:npm/demo-helper@1.0.0"
      ]
    }
  ]
}
```

Interpretation:

- One parsed manifest and one parsed lockfile produced two package rows and
  one dependency edge. `direct=false` is resolution evidence, not runtime proof.
- The output preserves a normalized `declared-spec` value `5.0.0`; the input
  used `^5.0.0`. Retain the original manifest when exact range syntax matters.
- The current name-based crypto registry labels `jose` with `py-jose` vendor/
  supplier metadata. **This is a heuristic mapping, not verified publisher
  identity for the npm package.** Review ecosystem-specific attribution; do
  not promote this generated value into a substantiated supplier claim.
- Neither the fictional dependency edge nor the crypto capability labels prove
  actual production execution or an assessed vulnerability.

### Reproduce the local fixture

From the repository root with the project Python dependencies installed, run
this snippet. It creates temporary input, calls the real functions and prints
partial output. It does not use a bank path, API, database or package install.

```bash
PYTHONPATH="services/devsecops:services/container_scanner${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PY'
import json, tempfile
from pathlib import Path
from devsecops.sbom_scan import scan_source, render_sbom
with tempfile.TemporaryDirectory(prefix='bank-doc-sbom-') as d:
    root = Path(d)
    manifest = {'name': 'bank-doc-demo', 'dependencies': {'jose': '^5.0.0'}}
    lock = {'name': 'bank-doc-demo', 'lockfileVersion': 3, 'packages': {
        '': manifest,
        'node_modules/jose': {'version': '5.9.6', 'license': 'MIT', 'dependencies': {'demo-helper': '1.0.0'}},
        'node_modules/demo-helper': {'version': '1.0.0', 'license': 'MIT'}}}
    (root/'package.json').write_text(json.dumps(manifest))
    (root/'package-lock.json').write_text(json.dumps(lock))
    result = scan_source(d)
    bom = render_sbom(result, fmt='cyclonedx', created_by='documentation-fixture')
    spdx = render_sbom(result, fmt='spdx', created_by='documentation-fixture')
    assert result['manifest_count'] == result['lockfile_count'] == 1
    pkgs = {p['name']: p for p in result['packages']}
    assert pkgs['jose']['version'] == '5.9.6' and pkgs['jose']['direct'] is True
    assert pkgs['demo-helper']['direct'] is False
    assert bom['bomFormat'] == 'CycloneDX' and spdx['spdxVersion'] == 'SPDX-2.3'
    excerpt = {k: bom[k] for k in ('bomFormat', 'specVersion', 'components', 'dependencies') if k in bom}
    print(json.dumps(excerpt, indent=2))
    print(json.dumps({'manifest_count': result['manifest_count'], 'lockfile_count':result['lockfile_count'], 'packages': result['packages'], 'dependencies':result['dependencies']}, indent=2))
PY
```
