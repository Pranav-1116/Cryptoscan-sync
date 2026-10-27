# Linux runtime gaps implemented; Windows Phase 3 candidate started

**2026-10-24 · development evidence, not production or bank acceptance**

Branch: `arena/bb4b80dd-cryproscan` · [PR #34](https://github.com/ZKChainForge/CryproScan/pull/34)

Baseline: `d0efc929d1552ca5bcc398bdf22fbfb7168281be`. Exact selected source/artifact
commitments are in the [bundle manifest](linux-runtime-windows-candidate-2026-10-24/manifest.json).
Earlier foundation logs are historical; they are not reused as runtime qualification.

## Delivered code and product behavior

### Phase 2 Linux

- Explicit approved **PID/process** metadata with boot/start-tick identity,
  name/cgroup membership and change checks; no PID discovery, environment,
  command-line or memory extraction.
- **Shared-object-named mapped paths** tied to that process identity, with deleted
  marker and an explicit suffix-only classification basis. Not verified ELF,
  `dlopen`, provider/algorithm invocation or package linkage.
- Passive current-netns **TCP/TCP6 LISTEN** address/port/inode metadata with
  native-endian decoding and repeat/netns checks. No packet transmission,
  process-owner inference or port-443→TLS claim.
- Fixed read-only **named systemd service** query with pinned trusted executable,
  sanitized environment, no shell, bounded output/deadline and child cleanup.
- Explicit **CPU topology, DMI and TPM-major-version** kernel metadata interfaces;
  no serials, TPM commands, keys, mechanisms or HSM operations.
- Additional bounded literal **Alpine installed-package** parser; existing dpkg,
  OS-release, public-certificate, config and header profiles retained.
- Separate strict runtime-fact union, interface/projection commitments, exact
  fact-to-resource/platform consistency, runtime subject identities and schema
  refreshes without adding defaults to historical `HostFact` objects.
- Existing API intake, evidence records, original references, job sealing,
  current authorization and six projection views reused. Listeners→NBOM,
  hardware→HBOM, mapped paths/packages→SBOM and runtime metadata→TechBOM.
  Existing actual certificate/config evidence can populate CBOM; VBOM stays
  UNKNOWN without vendor evidence. No new tables/scanner service or fabricated
  runtime relationships. Console displays metadata with UNKNOWN runtime use.

[Detailed Linux design, resources, operator example and limitations](../bank-environment/63-linux-collection-phase-two.md).

### Phase 3 Windows — candidate only

- `OfflineWindowsCollector`, explicit target-spec CLI `--windows-candidate` and
  a native named-local-service SCM status implementation.
- Connect/query-status access only; fixed 36-byte status layout, two bounded
  status queries, valid-state PID handling, source commitment and handle cleanup.
  No remote SCM, PowerShell, credential handling or service mutation.
- Portable state/layout/refusal contracts plus a native ordinary-user SCM test
  ready for a real Windows runner. **That native test skips here.**
- Registry Windows authorization remains blocked. Windows and production
  qualification flags remain false; native SCM cancellation/isolated execution
  and the rest of the Windows interface matrix remain open.

[Windows implementation and native gate checklist](../bank-environment/64-windows-collection-phase-three.md).

## Final gates on this implementation

| Gate | Result | Retained evidence |
|---|---|---|
| Python regression including inventory/evidence/CBOM/shared contracts, host/API/associations/foundation/migration controls | **1,618 passed, 2 skipped**, 12 warnings; 226.26 seconds | [log](linux-runtime-windows-candidate-2026-10-24/regression.txt), [JUnit](linux-runtime-windows-candidate-2026-10-24/regression.xml) |
| Owned PostgreSQL **16.2**, associations + universal foundation + native-runtime API witness | **82 passed**, 6 warnings; 145.85 seconds | [log](linux-runtime-windows-candidate-2026-10-24/postgres.txt), [JUnit](linux-runtime-windows-candidate-2026-10-24/postgres.xml) |
| Frontend | **620 passed in 58 files**, 166.71 seconds | [log](linux-runtime-windows-candidate-2026-10-24/frontend.txt) |
| TypeScript and production frontend build | **PASS**, build 2.69 seconds | Same frontend log |
| Changed Python Ruff, dependency consistency, whitespace | **PASS** | [quality](linux-runtime-windows-candidate-2026-10-24/quality.txt) |
| Supplemental synthetic positive DMI/TPM parser fixtures | **PASS; not native execution** | [script](linux-runtime-windows-candidate-2026-10-24/check-hardware-fixtures.py), [output](linux-runtime-windows-candidate-2026-10-24/hardware-fixtures.txt) |
| Owned backend cleanup and systemd timeout/overflow child reap | **PASS** | [cleanup](linux-runtime-windows-candidate-2026-10-24/cleanup.json) |

Counts overlap; do not sum them into unique bank coverage. The two skips are
native Windows file/reparse and SCM execution, not successful Windows tests.
Existing Pydantic/Starlette/Alembic warnings remain. PostgreSQL logs also retain
nonfatal third-party closed-capture-stream logging diagnostics during shutdown;
pytest exits zero, server stop and removal of owned resources are verified.
These elapsed test durations are not p95/p99 or the agreed bottleneck target.

### Broad gates caught and fixed a real integration error

The first broad Python run had **1 failed / 1,616 passed / 2 skipped**; the first
PostgreSQL run had **1 failed / 81 passed**. The new `INTERFACE_UNAVAILABLE`
receipt reason was accepted by collection but missing from the existing flat
`HostEvidenceRef` reason alias, causing intake to raise a validation error for
an unavailable systemd interface.

The fix unifies `HostReceipt.reason` with the existing shared `ReceiptReason`
vocabulary, includes the new reason in that vocabulary and adds a flat-reference
regression. Focused tests passed, then **both complete broad gates were rerun**
with the final success counts above. Initial failure counts are retained in
[initial regression XML](linux-runtime-windows-candidate-2026-10-24/initial-regression.xml)
and [initial PostgreSQL XML](linux-runtime-windows-candidate-2026-10-24/initial-postgres.xml),
not described as successes or delegated to the user.

## What the native Linux witness actually establishes

[Actual interface status/count capture](linux-runtime-windows-candidate-2026-10-24/native-profile.json):
ordinary user UID/EUID 1001, Linux x86_64, privilege guard not bypassed.

| Explicit surface | Actual outcome here | Interpretation |
|---|---|---|
| Collector self process | PARSED, 1 fact | Actual PID/start/boot interface observation, not authenticated asset |
| Self shared-object-named mappings | PARSED, 25 path facts in this standalone capture | Named mappings, not algorithm invocation; counts differ with loaded test modules |
| Current-netns TCP with owned live loopback listener | PARSED, 2 listener facts in capture; owned port independently asserted | LISTEN observation only; no process ownership/TLS/reachability inference |
| Explicit CPU0 topology | PARSED, 1 fact | Kernel-reported topology, not physical identity/capacity attestation |
| DMI | UNAVAILABLE/NOT_FOUND | No DMI-positive qualification; not proof of no underlying hardware |
| Explicit TPM0 and deliberately nonexistent TPM999 | UNAVAILABLE/NOT_FOUND | Approved interface gaps, not proof no TPM/HSM exists elsewhere |
| Named nonexistent witness service | UNAVAILABLE/INTERFACE_UNAVAILABLE | System bus unavailable here; no positive systemd execution qualification |
| Windows target CLI, with and without candidate opt-in on Linux | Exit 64, no output | Refusal; no Windows API emulation or native qualification |

The end-to-end API witness holds a real socket while collecting real process,
mapping and sysfs metadata, performs one intake and sealed completion, verifies
NBOM/HBOM/SBOM/TechBOM observations, distinct per-library identity slots, empty
unsupported CBOM/VBOM views, UNKNOWN errors, native schema-valid empty crypto
CBOM, exact-bank denial and intact audit chain. The same contract runs against
owned PostgreSQL. Other adversarial cases cover grammar, regular-file/kernel
filesystem distinction, symlink refusal, input changes/PID reuse, output/byte
limits, timeout cleanup, malformed state/table/package data and fact promotion.
Mocked failures and positive hardware fixtures test code paths, not native device
or permission-denial qualification.

## Not closed by these results

This fills the principal **Linux implementation** gaps and starts Windows
candidate development, **not** every Phase 2 estate/production acceptance gate:

1. Positive native systemd, DMI and TPM, actual denied native interfaces,
   independent fixture review and broader Linux architecture/distribution truth.
2. Native Alpine review, RPM/other package profiles, alternate systemd layouts,
   verified binary/provider identity and genuine algorithm/traffic attribution.
3. Signed collector release/identity and authenticated host/clock binding.
   Hashes protect local commitments; they are not authenticity, WORM or bank
   review. Runtime receipt byte counts are charged source/check/projection work,
   not single-file lengths or RPC traffic statistics.
4. Isolated production admission→queue→worker execution/cancellation, Windows
   native gates and remaining Windows OS/store/provider/module/listener/hardware
   implementations. Fixed native reads do not guarantee a global elapsed-time
   deadline; Windows SCM cancellation remains open.
5. HSM/KMS mechanisms/operation evidence, effective TLS/PQC use, deployment
   hardening/HA/monitoring, independent bank acceptance and performance targets.

No customer deployment, cloud account, bank host or Windows machine was changed.
No workflows edited, CI manually dispatched, PR merged or deployment performed.
Publication uses `[skip ci]` on the existing session branch/PR.

## Reproduce and review

[Bundle/replay instructions](linux-runtime-windows-candidate-2026-10-24/README.md) ·
[Phase 2 guide](../bank-environment/63-linux-collection-phase-two.md) ·
[Phase 3 candidate guide](../bank-environment/64-windows-collection-phase-three.md) ·
[Product acceptance ledger](../bank-environment/60-host-first-product-acceptance.md)
