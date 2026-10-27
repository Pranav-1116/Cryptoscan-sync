# Six-BOM current-evidence correctness — 2026-10-23

## Scope and actual execution

Eleventh bounded increment from published baseline `c48f667e3dee70b0ffc48f338004382b6543f94f`,
on `arena/bb4b80dd-cryproscan`, PR34. Existing product only: no new collector,
service, dashboard, deployment profile or architecture. Migration remains **0106**.

The corrected **21-case** six-BOM matrix produced **13 expected failures / 8 passes**
against the published original relationship/coverage implementations. The current
implementation passes all21 within **248 passing relevant API/auth/SQL/worker
contract tests**, with no skips and four warnings. **19 native PostgreSQL tests**
also pass, including16 existing workflow contracts and three new measurement/
recovery/error-handling tests. Warnings and exact durations remain in the logs;
these are not a claim that every repository test or CI workflow was executed.

The initial test draft had invalid human-auth/serialization expectations. Those
were corrected before the retained baseline comparison. A BLOCKED200 response
is deliberately accepted as a safe negative; it is not confused with OBSERVED.

## Six distinct evidence meanings and negatives

| BOM | Exact identity and meaning | Executed negative/current boundary |
|---|---|---|
| **SBOM** | Package/version tied to the selected retained document, release binding and exact estate. Presence is not deployed runtime. | Tampered bytes, wrong manifest digest, wrong owner and deleted original document cannot supply a current reviewed path. Canonical components are reparsed from the original bytes, not trusted from a mutable SQL projection. Legacy unresolved versions stay unresolved. |
| **CBOM** | A particular crypto observation and its supporting evidence, with location/purpose; not proof of security use everywhere. | Withdrawing the finding removes its current trace while preserving observation/assertion history. Existing lifecycle tests also check supporting-evidence expiry/retraction. A completed remediation task still does not establish a condition proof. |
| **NBOM** | Exact estate, durable job, endpoint and host-key/KEX phase. It is not complete network/service coverage. | Success flag/payload/digest/endpoint/time/job mutations are exercised both before recording and on later current reads. Invalid evidence cannot become or remain OBSERVED. Refused/failed collection can remain a BLOCKED declaration, never fabricated success. |
| **TechBOM** | An explicit reviewed package→crypto→declared deployment path for one application/build. | A reviewed path remains `complete=false`, `runtime_verified=false`, `deployed_verified=false`, `invocation_verified=false`; another estate gets404. History survives current refusal. No dependency or runtime identity is inferred. |
| **HBOM** | Persisted hardware estate rows and declared provenance, not model-name attestation. | Model name/declared FIPS mode do not fill missing firmware or verification time; absent dependencies stay explicitly empty. This case verifies honest missing-value semantics, **not** a newly qualified hardware collector or hardware freshness policy. |
| **VBOM** | Exact customer/build, bounded signed supplier document and approved signer lifecycle. Signature is provenance, not truth. | Even signed hardware claims retain `independent_truth_verified=false`. Signer revocation blocks current original-byte retrieval with409 while reviewed history/hash remain retrievable. Native recovery replays a post-backup signer revocation before candidate cutover. |

All six are distinct. Missing findings are not a coverage denominator; empty or
incomplete collection receipts do not manufacture current complete coverage.
Original observations, reviewer assertions, historical verification and current
eligibility remain separate. The existing source/remediation/unknown-execution
contracts are part of the248-test retained regression run.

## Product changes and bounds

- Relationship intake/review/current trace re-read original retained SBOM bytes,
  owner and SHA256, bounded by the existing SBOM payload limit. Original content
  failure returns a generic409 without exposing storage details.
- SSH coverage rechecks completed job, exact endpoint/required phase set,
  successful nonempty observation, canonical SHA256 and ordered job/phase times.
  Later changes cannot reuse an old green coverage revision. Non-canonical
  observation data fails closed.
- After the measured N+1 bottleneck, trace supporting evidence is fetched in one
  exact-tenant batch per binding; canonical package identity is computed once per
  request/binding. Every link still checks current lifecycle and freshness.
  There is **no persistent cache**, no inferred cross-estate join and no repair of
  old assertion history. Existing deployment/binding/history/path bounds remain;
  a10000-current-evidence-identity budget fails closed rather than unbounded SQL.
- Native test databases explicitly use UTF8. The lab cluster inherited SQL_ASCII
  from `initdb --no-locale`, which rejected Unicode JSON in the first broader run.
  This was an environment/test-fixture correction, not a product encoding patch.

## Retained evidence and reproduction

[Results and input hashes](quality-six-bom-perf-recovery-results-2026-10-23.json),
[original-source negative log](quality-six-bom-perf-recovery-2026-10-23/published-baseline-negative.log),
[current248-test log](quality-six-bom-perf-recovery-2026-10-23/correctness.log),
[JUnit](quality-six-bom-perf-recovery-2026-10-23/correctness.xml),
[native19-test log](quality-six-bom-perf-recovery-2026-10-23/native.log) and
[native JUnit](quality-six-bom-perf-recovery-2026-10-23/native.xml).

Use the lock-constrained Python environment and monorepo import paths described
in the [measurement record](quality-trace-performance-2026-10-23.md). The opt-in
`quality_published_baseline` pytest plugin loads the exact published versions of
**only** the two changed assurance modules; working files are never replaced.
The original-source negative command is expected to exit nonzero:

```bash
python -m pytest services/api/tests/unit/test_six_bom_current_evidence.py \
  -p quality_published_baseline -q
python -m pytest services/api/tests/unit/test_{assurance*,relationship*,package*,ssh*,remediation*,execution*}.py \
  services/api/tests/unit/test_six_bom_current_evidence.py \
  services/api/tests/unit/test_backup_encryption.py -q
```

## Still not accepted

Synthetic cases cannot establish full-bank inventory, actual runtime/hardware
attestation, independent supplier truth or complete six-BOM collector coverage.
All-purpose current-state readers have not been universally qualified. Broader
performance, integrated recovery and different-person review remain open; see
[measured performance](quality-trace-performance-2026-10-23.md) and
[executed recovery/limits](quality-isolated-recovery-2026-10-23.md).
