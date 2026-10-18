# 12 — How CryptoScan finds dependencies and records their evidence

[Guide index](README.md) · Next: [Cascade and blast-radius mechanics](13-cascade-and-blast-radius.md)

**Implementation-traced · 2026-10-18.** This document describes the current code,
not a completed bank deployment. Examples are fictional. Recommended controls
are explicitly distinguished from implemented mechanisms.

## 1. Start with the right definition

A dependency is a directed relationship whose meaning depends on its evidence:

```text
A -> B means A depends on, uses, imports or contains B,
according to the specific relationship and source.
```

Those meanings are not interchangeable. A source import, a software package
resolution, a declared production call and an observed service request are
four different facts. They can corroborate each other; none automatically
establishes all the others.

| Term | Meaning | Bank example |
|---|---|---|
| Dependency | One recorded relationship | Payments API calls Signing Service |
| Cascade | Following relationships across multiple steps | Mobile Banking depends on Gateway, which depends on Payments API |
| Blast radius | Objects implicated by a change/problem within modeled scope | Consumers that should be reviewed before a signing-key migration |
| Business impact | Operational interpretation with business context | Payment authorization may be interrupted |
| Confirmed failure | Independently observed operational outcome | Transactions fail after a production change |

The product can calculate a dependency exposure set. That is not proof that
every returned object fails, is exploitable or loses availability.

## 2. Source-code dependency extraction

The scanner's dependency analyzer reads supported files, extracts language-aware
import/include/call patterns, resolves local targets, and builds both directions:

```text
imports[file]    = files this file imports
dependents[file] = files that import this file
```

Patterns include Java/Python/JavaScript/Go imports, C includes, COBOL CALL/COPY,
and other supported language-specific forms. This helper is deliberately simpler
than a compiler-backed whole-program, data-flow-sensitive runtime call graph.

### Bank example: a shared crypto wrapper

```text
payments/handler.py -> payments/signing.py -> shared/crypto_provider.py
cards/authorize.py -----------------------> shared/crypto_provider.py
```

If supported findings identify crypto behavior in `crypto_provider.py`, the
scanner can enumerate direct/transitive source consumers and associate provider,
library, shared-key-reference and parameter observations with the scan result.

**Supported conclusion:** changing that source provider warrants reviewing these
files and their tests.

**Unsupported conclusion:** every transaction in every listed application
executes the provider or will fail after any change.

### Coverage limits

- Dynamic imports, reflection, plugins, generated code and runtime configuration
  can evade simple static resolution.
- An import can be unused, test-only, platform-specific or outside the shipped
  artifact. Static presence does not prove production execution.
- External packages may not have local source to resolve.
- Wildcard/module-name ambiguity can broaden candidate relationships.
- The helper's file reader has a 2 MB per-file bound; its transitive-dependent
  walk also has a limit (10,000 by default). Missing/skipped inputs remain gaps.
- Key aliases, filenames and environment-variable references are identifiers in
  source, not proof of the actual production key, key material or HSM session.

See [scanner cascade implementation](../../services/scanner/scanner/analysis/cascade.py)
and [its unit tests](../../services/scanner/tests/unit/test_cascade.py).

## 3. Software composition and package dependencies: SBOM

The standalone source SBOM reads supported manifests and, by default, supported
lockfiles. Resolved versions win supported merges; transitive rows and edges are
available where the parser provides them. An image inspection is a different
input scope from a source checkout.

| Evidence | What it supports | What it does not establish |
|---|---|---|
| Manifest | A package was declared | Exact installed/shipped version |
| Supported lockfile | A recorded version resolution and supported relationships | Production installation or runtime reachability |
| Inspected image | Detected components in that artifact | That this exact digest is deployed |
| Bank build/deployment record | A substantiated release/deployment mapping | That every bundled package executes |

A bank investigating a library advisory needs a chain like:

```text
advisory -> package ecosystem/name/version -> artifact digest
         -> deployed application -> consuming systems -> business process
```

**Current integration boundary:** unified cascade does not automatically ingest
and traverse every standalone SBOM artifact's complete package graph. Its library
path primarily uses library entries on twin crypto assets and their system links.
A package-only component can therefore be present in SBOM without being a valid
starting point for the same end-to-end business cascade.

TechBOM's `sbom` layer is a registered-application projection, not the complete
standalone software package graph. See [09 — SBOM detail](09-sbom-deep-dive.md).

## 4. Map files to the bank's named systems

Supported system-map filenames include `.cryptoscan/systems.yml` and
`cryptoscan-systems.yml` (with supported YAML/JSON variants). The map associates
paths with systems and can declare dependencies the code cannot reveal.

This fictional monorepo example is configuration, not discovered bank truth:

```yaml
systems:
  - system: Payments API
    paths: [payments/**]
    owner: Payments Engineering
    depends_on: [Signing Service, Ledger]
  - system: Signing Service
    paths: [signing/**]
    owner: Cryptographic Services
  - system: Ledger
    paths: [ledger/**]
    owner: Core Banking
```

The analyzer rolls supported provider/import observations and declared
`depends_on` entries into system-level results. A named dependency must resolve
to the intended declared system; path overlap/name mismatch needs review.

### Several routes into the system graph exist

1. The worker's declared-system synchronization can create/update system context,
   attach assets by path and persist relationships such as `contains` and
   `imports-crypto`.
2. The graph builder can merge scan-system rollups into its view, including
   code-cascade `IMPORTS` edges and code-declared nodes absent from the register.
3. The discovered-edge API proposes candidates from recent scans and the latest
   graph snapshot; an operator can explicitly adopt selected candidates.
4. Operators/integrations can register approved edges directly.

Do not say all edges need adoption, or that every displayed edge is automatically
persisted into every store. These paths have different behavior.

**Staleness limit:** the worker synchronization is additive/idempotent and does
not remove old systems or edges. Deleting an input declaration alone is not
proof that the old inventory relationship disappeared.

Sources: [worker synchronization](../../services/worker/worker/pipeline/pipeline_runner.py),
[graph builder](../../services/api/api/graph_builder.py),
[edge discovery/adoption API](../../services/api/api/routers/graph.py).

## 5. Registered system dependencies

`SystemDependency` stores directed `parent_id -> child_id` relationships. It
supports relation, source, creator, confidence and last-verification metadata.
For a CALLS dependency, the parent is the consumer and the child is the provider.

A settlement batch queue dependency may be declared even when a static scan
cannot observe the bank's actual scheduling and messaging topology.

The API accepts manual/discovered/imported sources. A manually registered edge
receives a timestamp; that timestamp is not independent runtime verification.
Optional confidence is not a calibrated outage probability. Do not turn a value
such as `0.8` into an “80% chance of transaction failure”.

The current discovered-edge candidate collector examines the latest 200 scans
and a latest graph snapshot, resolves names/IDs and excludes existing proposals.
Its candidate confidence values are implementation heuristics, not statistical
measurements. Adoption records an operator action; it does not run a production
transaction test.

See [dependency model](../../services/database/db/models/system_dependency.py).

## 6. Optional service-mesh telemetry

When `ISTIO_PROMETHEUS_URL` is configured, the graph builder can read Istio request
metrics, map workload names to systems where possible, and add CALLS edges.

```text
Observed workload request: gateway-workload -> payments-workload
Possible registered mapping: API Gateway -> Payments API
```

Prerequisites include reachable approved telemetry, meaningful workload labels,
correct identity mapping and actual traffic coverage. The current query reads
request totals, not an explicit recent rate window. Counter presence alone does
not prove a current hard dependency. An unavailable/invalid telemetry response
can yield no edges; reconcile telemetry health rather than interpreting absence
as “no calls”.

**Store boundary:** mesh edges added to a graph payload are not automatically
identical to the persisted `SystemDependency` set read by unified cascade.

See [Istio client](../../services/graph_engine/graph_engine/service_mesh/istio_client.py)
and [graph assembly](../../services/api/api/graph_builder.py).

## 7. Cross-domain identity links

| Link | Why a bank needs it |
|---|---|
| Evidence -> crypto asset -> system | Name the application associated with a crypto finding |
| Endpoint -> registered system | Name the owner of an observed listener |
| Certificate usage -> system | Identify recorded consumers beyond subject similarity |
| Crypto asset -> hardware | Name applications served by a declared HSM/device |
| System -> vendor | Represent a supplier dependency |
| System -> business process | Supply business context |
| Vendor -> vendor | Represent declared sub-tier supply-chain exposure |

Inventory co-presence is not linkage. An HSM row plus a Payments API row does
not prove that Payments API uses that HSM. Native HBOM inventory does not itself
create the separate crypto-to-hardware declaration.

The twin adapter reads these link stores for applicable cascades. Refer to
[13](13-cascade-and-blast-radius.md) for target-specific traversal and
[16](16-dependency-limitations-and-acceptance.md) for completeness limitations.

## 8. Recommended bank evidence worksheet

For every operationally important edge, retain the following as a bank-owned
control; not all fields are enforced by every product path:

```text
Canonical consumer/provider IDs and environment
Relationship meaning: runtime call / import / containment / declared dependency
Evidence source: code / telemetry / operator declaration / supplier material
Input revision, deployment digest or telemetry context where applicable
Owner, collector/operator, observation and review times
Confidence meaning, freshness deadline, unresolved identity conflicts
Approval/reconciliation history and known exclusions
```

Never replace an unknown relationship with an inferred “verified” link just to
complete the picture. A smaller, substantiated graph is more useful for a bank
than an apparently complete graph with hidden assumptions.
