# 08 — Implementation map, route differences and open boundaries

[Guide index](README.md) · Previous: [Operations](07-operations-and-acceptance.md)

**Source-inspected on 2026-10-18.** This map is deliberately more precise than a
feature checklist. “Implemented” means code exists for the described behavior;
it does not mean a real bank/provider/production deployment was qualified here.
No application or CI behavior was changed to write this guide.

## 1. Source-to-output map

All links below point into this repository. Tests provide implementation context,
not evidence that a customer system was scanned.

| Area | Implementation | Supporting test/example |
|---|---|---|
| Deployment/services | [Base Compose](../../docker-compose.yml), [production](../../docker-compose.prod.yml), [TLS](../../docker-compose.tls.yml) | [Production parser contract](../dev/scanner-isolation.md) explains deliberately missing runtime prerequisites |
| Source admission | [Trigger](../../services/api/api/routers/trigger.py), [scan admission](../../services/api/api/security/scan_admission.py), [target validation](../../services/api/api/security/target_validation.py) | [Scan admission tests](../../services/api/tests/unit/test_scan_admission.py) |
| Source request/job schemas | [Request fields and job status](../../services/api/api/schemas/job_schemas.py), [system registration/scan](../../services/api/api/routers/systems.py) | [System model](../../services/database/db/models/system.py) |
| Source execution | [Pipeline runner](../../services/worker/worker/pipeline/pipeline_runner.py), [progress stages](../../services/worker/worker/pipeline/progress.py), [clone/copy](../../services/worker/worker/workspace/repo_cloner.py) | [Isolated launcher tests](../../services/worker/tests/unit/test_static_scan_isolation.py) |
| Parser boundary | [Worker launcher](../../services/worker/worker/core/static_scan_isolation.py), [parser adapter](../../services/scanner/scanner/isolated.py) | [Adapter tests](../../services/scanner/tests/unit/test_isolated_adapter.py) |
| Cloud ingestion | [Cloud job](../../services/worker/worker/pipeline/cloud_job.py), [estate mapping](../../services/cloud_scanner/cloud_scanner/estate.py) | [Direct filesystem/cloud route](../../services/api/api/routers/cloud_scans.py) is a different path |
| NBOM | [Builder/mapping](../../services/cbom/cbom/nbom.py), [live/API gather](../../services/api/api/routers/cbom.py), [network execution](../../services/api/api/routers/network.py) | [NBOM tests](../../services/cbom/tests/test_nbom.py), [plaintext/unknown distinction](../../services/cbom/tests/test_nbom_plaintext.py) |
| Network persistence | [Run repository](../../services/database/db/repositories/scan_run_repository.py), [run model](../../services/database/db/models/network_scan_run.py) | [Real controlled TLS-to-NBOM test](../../services/network_scanner/tests/test_tls_cbom_end_to_end.py) is local test evidence, not bank evidence |
| CBOM | [Generator](../../services/cbom/cbom/generator.py), [API/pins](../../services/api/api/routers/cbom.py), [stored scan verification](../../services/api/api/routers/export.py) | [Generator tests](../../services/cbom/tests/test_generator.py) |
| TechBOM | [Materializer](../../services/cbom/cbom/technology_bom.py), [inventory gather/API](../../services/api/api/routers/techbom.py), [export service](../../services/cbom/cbom/export_service.py) | [Technology BOM tests](../../services/cbom/tests/unit/test_technology_bom.py) |
| Independent HBOM | [Persisted-estate generator](../../services/cbom/cbom/hbom.py), [estate API/pins/diffs](../../services/api/api/routers/hbom.py) | [HBOM tests](../../services/cbom/tests/test_hbom.py), [pin/diff tests](../../services/cbom/tests/test_hbom_diff.py) |
| Hardware observation ingestion | [Hardware API/persistence](../../services/api/api/routers/hardware.py), [event types](../../services/universal_vendor/universal_vendor/hardware/live/events.py) | [Live HBOM/firmware tests](../../services/universal_vendor/tests/hardware/test_live_hbom_firmware.py) |
| Independent VBOM | [Vendor BOM generator/assembler](../../services/vendor_intel/vendor_intel/vbom.py), [vendor/profile/import APIs](../../services/api/api/routers/business.py) | [VBOM tests](../../services/vendor_intel/tests/test_vbom.py) |
| Cross-BOM correlation | [Unified cascade](../../services/cbom/cbom/unified_cascade.py), [TechBOM/cascade API](../../services/api/api/routers/techbom.py) | [Cross-BOM user guide](../user-guide/cross-bom-cascade.md) |
| UI and refresh | [SPA routes](../../frontend/src/App.tsx), [sidebar](../../frontend/src/components/Layout.tsx), [API client](../../frontend/src/lib/api.ts), [events](../../services/api/api/routers/events.py) | [NBOM page](../../frontend/src/pages/Nbom.tsx), [HBOM page](../../frontend/src/pages/Hbom.tsx), [TechBOM page](../../frontend/src/pages/LiveAssetIntelligence.tsx) |

## 2. Network route differences

This is a source-inspection finding, not a newly fixed defect. Do not summarize
all network entry points as having uniform admission and BOM persistence.

| Route | Explicit active-scan admission in its function | Writes NBOM's `network_scan_runs` ledger in its function | Operational implication |
|---|---|---|---|
| `POST /api/v1/network/run-due` | Yes | Yes, when due targets exist | Used in the worked pilot after reviewing the entire due set; bank firewall/scope controls still apply |
| `POST /api/v1/network/scan` | No direct `admit_scan` call | Yes when `persist_run` is true; storage failure can be returned | Do not assume emergency-stop/window parity with admitted routes; inspect storage errors and do not use as a bypass |
| `POST /api/v1/network-scans` | Yes | No direct network-run-ledger write | Durable `ScanJob`/coverage and certificate persistence do not alone populate NBOM's probe ledger |
| `POST /api/v1/network/discover` | Yes, plus execution-time sweep authorization | No direct network-run-ledger write for its optional TLS phase | Discovery/certificates can be present while that phase has no corresponding NBOM run |

Authentication, target validation, role policy, persistence and admission are
different controls. A route being authenticated or validating syntax does not
prove that every scan-policy check ran. The table reports explicit route
behavior; it does not certify every downstream collector or every other alias.

Before production rollout, reconcile these paths, test expected safety/persistence
uniformity, and qualify failures. This documentation task does not change them.
The bank should restrict unreviewed routes and enforce approved network scope
outside the application as well.

## 3. Other limits that affect a bank demonstration

### Shared state is not automatically whole-estate coverage

`techbom._gather_inventory` applies per-collection limits, normally 2,000. The
live endpoint's maximum selectable limit is 5,000; snapshot and export paths
have their own default gathers. The NBOM gather also bounds recent runs.
CBOM portfolio has separate cap/truncation behavior. Large-estate acceptance
must reconcile scope and caps; a bounded response is not an exhaustive census.

The current TechBOM `sbom` projection starts from registered systems. It is not
a guarantee of complete transitive package/OS SBOM extraction for every app.
Likewise, its `vendor` projection is not identical to the independent rich VBOM.

### Relationships and physical truth

The independent HBOM deliberately does not invent hardware-to-system edges.
Any narrative cross-BOM architecture diagram must distinguish bank-supplied
relationships, measured facts and unknown links. A shared vendor or algorithm
name is not enough to prove that two records describe the same deployed asset.

Device/vendor capability declarations, parser findings and wire observations
have different evidentiary strength. None alone certifies the underlying bank
hardware, a regulatory control, or a successful migration.

### Live state and durability

The live hardware controller has process-local state; the independent `/hbom`
generator reads persistent estate rows. Other live-scan and TechBOM hardware
views are scoped projections. Restart behavior must be tested against the
specific authoritative store, not assumed from a “Live” badge.

Source queue acceptance, final source scan linkage, synchronous network runs and
hardware imports have different identifiers/commit boundaries. Event delivery
or HTTP success alone is not proof of all downstream writes. Some collectors
can return partial results or best-effort storage errors; retain those facts.

### Isolation, provider and runtime qualification

Production source parsing requires more than setting `ENVIRONMENT=production`.
The immutable image, approved runtime/CLI, correct shared staging, non-root and
resource/network policy must all be proven. The stock Compose topology leaves
these prerequisites deliberately unprovisioned. Other stages remain outside the
source-parser boundary.

SDK/vendor support in code is not proof of working bank credentials, a correct
least-privilege policy, all-region coverage or tested devices/firmware. Use a
supported, authorized pilot for each provider/collector and retain failures.

### Integrity, privacy and permissions

Verify actual signing settings, key distribution and canonical formats. A
helper's development fallback or populated signature field is not an assurance
claim. SHA-256 consistency does not prove completeness, trusted time or input
truth. CycloneDX-style labels are not universal schema/interoperability proof.

Do not assert that no sensitive source material is ever read/stored. Input
source can contain secrets, older evidence can need disposition, and public
projection is a separate control from storage/retention. Bank acceptance must
cover raw logs, source staging, APIs, exports, backups and support channels.

Single-customer deployment is the baseline for this guide. Existing tenant and
role code still needs bank-specific negative testing, including cached reads,
relationships, workers and imports. No shared multi-bank SaaS approval follows
from the existence of tenant columns.

## 4. Practical evidence versus documentation evidence

This guide was checked by reading implementation, checking documented routes,
request shapes, Markdown links and selected BOM tests. That supports a technical
explanation. It does not create bank data, a signed acceptance, production
Docker/provider proof or a completed scan of the bank's infrastructure.

The current [readiness gate](../../PRODUCTION-READINESS.md),
[bank pilot standard](../pilot-standard.md) and
[network control guide](../security/NETWORK-CONTROLS.md) remain relevant inputs.
Where older narrative documents imply uniform automation or stronger coverage,
use the specific source paths, explicit limits and retained measurements here
rather than repeating an unqualified feature claim.

### Checks performed for this documentation update

- **80 selected BOM tests passed** in 3.57s: NBOM/transport assessment, CBOM
  generation, independent HBOM/diff, Technology BOM and vendor BOM tests.
- All **5** practical request bodies validated against their actual Pydantic
  request models. This checks shapes, not authorization, mounted input, target
  reachability or deployed endpoint behavior.
- All **10 JSON blocks**, **13 Bash blocks** (syntax only), local file links and
  local heading anchors checked successfully across the **9 guide files**.
- **41 explicit API method/path references** matched router declarations and
  **21 positive console route references** matched the SPA. The absence of a
  standalone `/vbom` route was checked separately.
- Five partial output excerpts were generated from illustrative input with the
  pure builders, without collector execution or application database ingestion.
- Scoped whitespace/conflict checks passed. No full backend/frontend suite,
  CI execution, Docker/provider deployment or real bank scan is claimed here.

These are implementation/documentation checks, not new customer acceptance
evidence. Existing production readiness decisions remain unchanged.
