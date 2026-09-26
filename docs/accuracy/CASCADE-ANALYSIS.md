# Dependency & cascade analysis — beyond "which algorithm, which key size"

`services/scanner/scanner/analysis/cascade.py`, run automatically as the third hop of every `Scanner.scan`
(after per-file detection and cross-file constant resolution; opt out with `CRYPTOSCAN_CASCADE=0`).
Output: `cascade` object in the scan result JSON and three statistics (`cascade_providers`,
`cascade_shared_keys`, `cascade_weak_parameters`); the CLI prints a one-line summary plus the top providers.

## What a bank gets

| Section | Question it answers | How it is derived |
|---|---|---|
| **providers** | *Which files actually do crypto, and what breaks if I change each one?* | every file with a non-UNKNOWN finding; `direct_dependents` / `transitive_dependents` from the estate import graph; `depends_on_providers` for ordering; `rank` by blast radius |
| **migration_waves** | *In what order do we migrate?* | Kahn's algorithm over the provider-to-provider dependency graph, on strongly-connected components so monolith import cycles do not stall it: wave 1 = shared crypto utilities nobody upstream depends on (change first, keep the interface compatible), wave *n* = depends on wave *n-1* |
| **libraries** | *Which third-party crypto packages, which versions, declared but unused, used but undeclared?* | manifests (`pom.xml`, Gradle incl. `libs.versions.toml` catalogs, `package.json`, `requirements*.txt`/`pyproject`, `go.mod`, `Cargo.toml`, `Gemfile`, `composer.json`, NuGet `*.csproj`/`packages.config`, SwiftPM, CocoaPods, conan/vcpkg/CMake) matched against a crypto-library coordinate table, joined with `metadata.library` from findings |
| **shared_keys** | *Which keystores, certificate files, key aliases and secret environment variables are used from more than one place?* | identifiers (never values) extracted from every source file and finding snippet: `*.jks/.p12/.pem/.kdb…`, `getenv("…KEY…")`-style env reads, `KeyStore.getKey("alias")`, `-alias`, `LABEL(…)`; kept only when ≥ 2 files reference the same identifier |
| **weak_parameters** | *Where is the key size below the floor for its family?* | `crypto.key_size` vs `shared_models.algorithm_registry` (`RSA/DSA/DH < 2048`, `EC < 256`, `AES < 128`, …) |

## Business systems (`systems` section)

Drop a `cryptoscan-systems.yml` (or `.cryptoscan/systems.yml`, or `.json`) at the repo root:

```yaml
systems:
  - system: PAY-SWITCH-01        # CMDB id / application code
    paths: [payments/, mf/PAYPOST.cbl]
    criticality: critical
    owner: payments-platform
  - system: CORE-CRYPTO-LIB
    paths: [core/]
```

The cascade then reports, per system: files, crypto providers, algorithms, weak parameters, **which other
systems depend on its crypto** (`dependent_systems`), which systems' crypto it depends on
(`depends_on_systems`), and the earliest migration wave it participates in. That is the blast radius in
the vocabulary the bank's change board uses.

### Where it shows up in the product

* **Worker → DB.** Every completed scan stores a bounded copy of the report in `Scan.statistics.cascade`
  (`services/worker/worker/pipeline/pipeline_runner.py::_bounded_cascade`). No schema change.
* **API.** `GET /api/v1/scans/{id}/cascade` (`?section=providers|libraries|shared_keys|weak_parameters|migration_waves|systems`,
  `?system=<id>` to filter by a declared system's paths, `?limit=`). Scan list/detail carry `statistics.cascade_summary` only.
* **System graph.** `api/graph_builder.py::merge_code_cascade` joins the newest per-target rollup into the CMDB graph:
  a rollup `system` matching a CMDB system **id or name** annotates that node with `code_cascade`
  (`providers`, `algorithms`, `weak_parameters`, `earliest_wave`, `depends_on_systems`, `scan_id`); an unknown one becomes a
  `System` node with `source="cryptoscan-systems.yml"`, `environment="code"`; `depends_on_systems` become **`IMPORTS`** edges
  (kept distinct from CMDB `CALLS`). `GET /graph`, `/graph/blast-radius`, `/graph/dependents`, `/graph/path`, hotspots and
  cycles all see those nodes and edges. The Neo4j store carries the node and the edge but not the `code_cascade` map
  (in-memory engine and `/graph` payload do).
* **Migration order.** `GET /api/v1/graph/migration-waves` now also (1) admits code-declared systems that the CMDB lacks
  (wave = their code cascade wave, capped at 3), (2) shows each system's code cascade in the rationale, and (3) applies
  `IMPORTS` edges as ordering constraints: a system whose code calls crypto that lives in another system is held to at
  least that system's wave (`constrained_by`, `systems_delayed_by_imports`), before cycle constraints are applied.
  Shown in the "System migration order" panel on the Migration page.
* **CBOM.** `GET /api/v1/scans/{id}/cbom` emits real CycloneDX `dependencies[]` from the cascade: `file` components for
  crypto-provider files (→ the crypto assets found in them, → provider files they import crypto from), `application`
  components for business systems (→ their provider files, → systems whose crypto they import), root → systems. Every
  ref resolves to a component. Key-inventory records carry their export metadata as `cryptoscan:key:*` properties and
  `assetType related-crypto-material` / `certificate`.
* **UI.** Dependency Graph page: "Code-level cascade" panel (scan picker, system drill-down, providers by blast radius,
  waves, libraries, shared keys, weak sizes) and a "Code-level crypto" block in the node drawer.

Tests: `services/api/tests/unit/test_scan_cascade_api.py`, `services/worker/tests/unit/test_pipeline_stages.py`.

## The import graph

Edges are extracted per language without a build: Java/Kotlin/Scala `import` (wildcards narrowed to the
classes the file actually names; static imports resolved to the class, never the package), Python
`import` / `from … import` (module suffixes, so `from bank.hashing import h` matches `src/bank/hashing.py`),
JS/TS relative imports (`./x`, `../x/index`), Go import-path suffixes, C# `using`/`namespace`,
COBOL/PL/I `CALL 'PROG'` and `COPY BOOK` (PROGRAM-ID identity), C `#include "…"`, PHP `require`, Ruby
`require`, Rust `use crate::`. External packages produce no edge — they appear under *libraries* instead.

## First real-repo results (2026-09-25)

| Repo | Files in graph | Edges | Providers | Top provider (direct / transitive dependents) | Libraries from manifests | Shared keys | Weak | Waves | Added time |
|---|---|---|---|---|---|---|---|---|---|
| jPOS (payments switch) | 1 208 | 2 961 | 75 (49 with dependents) | `q2/Q2.java` DES+SHA-1 — 29 / 305; `IssuerApplicationData` 3DES — 11 / 11; `JCESecurityModule` 3DES/DES/RSA — 9 / 9 | BouncyCastle 1.85 / 1.85.2 from `gradle/libs.versions.toml` | `LICENSEE.asc` (PGP key) in 2 files | RSA 1024 in a test | 4 | ≈ 2 s |
| Apache Fineract (core banking) | 7 567 | 31 028 | 41 (14 with dependents) | test `Utils.java` CSPRNG — 313 / 440; `RandomPasswordGenerator` — 7 / 1 647; `DatabasePasswordEncryptor` AES+BCRYPT — 6 / 15 | BouncyCastle (Gradle, version in buildSrc) | — | — | 3 | ≈ 15 s |

Read the jPOS row the way a bank would: the DES/SHA-1 in `Q2.java` sits under 305 transitive dependents,
so it is a wave-2 change with the whole product as blast radius, whereas the 3DES in the EMV
`IssuerApplicationData` class has 11 dependents and can be migrated in isolation.

## Limits (state them in the report)

* Edges are import-level, not call-level: a file that imports a crypto utility but never calls the crypto
  method still counts as a dependent (over-approximation — safe for blast radius, pessimistic for effort).
* Dynamic loading (reflection, DI by name, JCL `EXEC PGM=`, CICS `LINK PROGRAM(var)`) is not followed.
* Transitive counts saturate in monoliths (everything reaches everything); use `direct_dependents` and the
  waves for prioritisation there.
* Manifest coverage is the table above; an unknown build system just yields an empty *libraries* list.
* Shared-key identifiers require the identifier to be literal; keys resolved from vaults at runtime appear
  only through their env-var / secret name.
