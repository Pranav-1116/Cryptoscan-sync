# Engineering evidence — disposable Linux TBF target — 2026-10-26

[Guide 88](../bank-environment/88-disposable-linux-tbf-qualification.md) · [Runbook](../runbooks/disposable-tbf.md) · [Source/requirements](../../tools/disposable_tbf/README.md)

## Delivered scope

A separate diskless Linux **6.12.58** x86_64 VM with **TBF compiled in**, one TCG CPU, 256 MiB guest RAM, no modules/NIC/disks/host-directory sharing, and a mandatory ordinary-user Landlock/seccomp launcher. It generates bounded synthetic UDP **only on guest loopback**, measures two caps and recovery, and reboots/exits. The host's unsupported TBF kernel is not changed or used as a fallback.

This is an operator-run engineering fixture, not a new collector/service/dashboard, a bank device, a production adapter or promotion of the previous resource proposal/namespace-review authorization. Its local scope/receipts are unsigned and explicitly not independently approved production changes. Source authenticity, real-host change authorization and production execution qualification remain **false**.

## Actual final measurements — two fresh VM boots

| Actual run | Baseline received payload Mbps | 10 Mbps TBF | 5 Mbps TBF | After rollback Mbps | Verdict |
|---|---:|---:|---:|---:|---|
| 01 | 46.3214 | 9.6619 | 4.8293 | 47.4475 | VERIFIED_IN_DISPOSABLE_VM |
| 02 | 47.4463 | 9.6596 | 4.8295 | 46.5401 | VERIFIED_IN_DISPOSABLE_VM |

These are **actual received-byte counters from an actual guest Linux kernel**, not mocked command responses or bare-metal/physical NIC results. The CPU is emulated. Each phase has one warmup second and four monotonic receive-measurement seconds. TBF accounts packet overhead and bursts; application payload Mbps need not equal configured queue Mbps exactly.

Both runs passed the criteria declared before the final measurements: baseline ≥30 Mbps; each cap's received payload in 80–110% of its setting; exact stable owned handle/rate; advancing kernel byte/packet/overlimit counters covering received counts; each default-policy rollback read back; final receive throughput ≥30 Mbps and ≥80% of baseline; valid denominators, timing, unchanged parent context and unchanged boot/runtime hashes. No fatal socket/receive/payload error was waived. Expected shaping backpressure is recorded separately, and queue drops remain visible. No lossless delivery, latency, TCP behavior or production SLA is claimed.

- Run 01: [receipt](disposable-tbf-2026-10-26/run-01/result.json), [serial](disposable-tbf-2026-10-26/run-01/serial.log), [original scope](disposable-tbf-2026-10-26/scope-01.json), [CLI](disposable-tbf-2026-10-26/cli-01.txt), [offline check](disposable-tbf-2026-10-26/verify-01.txt).
- Run 02: [receipt](disposable-tbf-2026-10-26/run-02/result.json), [serial](disposable-tbf-2026-10-26/run-02/serial.log), [original scope](disposable-tbf-2026-10-26/scope-02.json), [CLI](disposable-tbf-2026-10-26/cli-02.txt), [offline check](disposable-tbf-2026-10-26/verify-02.txt).
- Canonical result commitments: `51c385534bd3683f73ab95f466a40db034c371bb53c432772f1351d8c1da5d0e` and `5352a4cf872570de6898b8211b6e8383290427b3ac3b8c43ddc6d85502735e49`.
- Parent sandbox `eth0` queue policy: [before](disposable-tbf-2026-10-26/parent-qdisc-before.json) and [after](disposable-tbf-2026-10-26/parent-qdisc-after.json) are **byte-identical**. Each receipt also records unchanged parent boot/network/mount context. No parent-interface traffic rule, host module load or privilege escalation occurred.

## Build provenance — integrity, not attestation

The final [fresh owned build record](disposable-tbf-2026-10-26/build-record.json) records exit 0 from `scripts/qualify_tbf.py build`. Linux and a private musl runtime were compiled from locked sources; QEMU is a **prebuilt**, hash-pinned npm artifact reporting version 11.0.2, not an emulator compiled/attested here. GNU bootstrap tools and elfutils headers are pinned too. The fixed-source catalogue is [assets.lock.json](../../tools/disposable_tbf/assets.lock.json).

Exact final bundle-manifest byte SHA-256:

`ff9e3756f80fbdf541c07ccbae313000301cdda75d725604c53de791253978c0`

The [bundle manifest](disposable-tbf-2026-10-26/bundle-manifest.json) records kernel/config/initramfs/emulator/launcher/runtime hashes, explicit guest runtime file inventory and source/profile bindings. [Compiled config](disposable-tbf-2026-10-26/kernel.config) contains built-in TBF and no loadable modules. Build tails: [m4](disposable-tbf-2026-10-26/m4-build-tail.txt), [bison](disposable-tbf-2026-10-26/bison-build-tail.txt), [flex](disposable-tbf-2026-10-26/flex-build-tail.txt), [kernel](disposable-tbf-2026-10-26/kernel-build-tail.txt), [musl](disposable-tbf-2026-10-26/musl-build-tail.txt). Complete build-log hashes/lengths are recorded; full build trees/binaries are intentionally outside Git in disposable cache/work directories. Rebuild them using the runbook. Compiler/system runtimes vary by host; general bit-for-bit reproducibility and upstream signature verification are **not** claimed.

Exploratory failures were not promoted to success: the prebuilt emulator lacks optional built-in sandbox support, so that attempted launch failed. The final path instead requires a separate pinned Landlock/seccomp launcher. An initially over-restrictive signal rule stalled the VM and the 180-second deadline terminated/reaped it. The private musl runtime was explicitly patched to use own-process `tgkill` for thread signals, preserving denial of legacy/cross-process signaling rather than removing the guard. A fresh locked rebuild and both final measured runs then passed. The first receiver probe also separated expected `ENOBUFS`/`EAGAIN` shaping backpressure from fatal send errors, retaining complete attempt/success/backpressure/error denominators; thresholds were not loosened.

## Executed engineering gates

| Gate | Result | Qualification limit |
|---|---|---|
| Exact additive candidate Python suites | **119 passed**, no skips | 55 new tests plus 64 source traffic/preflight/review/resource regressions; focused, not the whole repository |
| New host sandbox negative tests | **PASS** | Actual safe denial checks for content reads, writable opens, truncation, mode/timestamp/xattr mutation, sockets, process creation, namespace change and external exec; owned temporary files remained intact |
| C probe / launcher | **PASS** | GCC static compilation with `-Wall -Wextra -Werror`; actual guarded VM execution |
| Ruff / format / `pip check` | **PASS** | Owned Python files/environment; no new dependency installation or frontend/database changes |
| Three generated Draft 2020-12 contracts and retained artifact closure | **PASS** | Schema shape plus typed semantic/report/serial checks; hashes are not device/custody authentication |
| Locked fresh build | **PASS, exit 0** | Supported Debian-style builder/layout only; no security certification or all-platform claim |
| Two final native guest sequences / offline CLI verification | **PASS, exit 0** | Exact generated UDP guest-loopback workload, not production interfaces |

[Test log](disposable-tbf-2026-10-26/python-tests.txt) · [JUnit](disposable-tbf-2026-10-26/python-tests.xml) · [static checks](disposable-tbf-2026-10-26/static-checks.txt) · [environment](disposable-tbf-2026-10-26/test-environment.txt).

New negative contracts cover insufficient baseline headroom, bad/reordered rate denominators, too-fast cap measurements, missing/changed readback or rollback, non-advancing/insufficient kernel counters, impossible timing, invalid received-byte/attempt denominators, fatal errors, unshaped backpressure, duplicate/nonfinite JSON, nonce/sandbox/frame mismatch, changed/unlisted/traversing/symlinked boot inputs, archive escape/special nodes, host probe execution, timeout/output-budget termination, capability/root refusal, report/scope/context/production-flag tampering and exact private-runtime patch/schema drift. Positive **unit** traffic fixtures remain synthetic; the separate receipts above supply actual measured enforcement.

The exact additive candidate starts from parent `99913d75959071a72f8c794297bc484fcd0ec9cb` and adds only this increment's owned paths. **4,961 outside-owned fingerprints and all 499 unrelated tracked edits/deletions were preserved.** This increment does not modify existing application code, workflows, system packages or customer deployment configuration.

## Offline verification and remaining boundaries

```bash
.venv/bin/python docs/readiness-evidence/disposable-tbf-2026-10-26/verify-artifacts.py
```

The [verifier](disposable-tbf-2026-10-26/verify-artifacts.py) checks three schema definitions, strict captured receipts, scope/nonce/bundle/report/serial closure, two distinct nonces, source/profile hashes, unchanged recorded parent policy and all [evidence-manifest](disposable-tbf-2026-10-26/evidence-manifest.json) file hashes. Boot binary hashes are **recorded, not independently rehashed without the external bundle**; runtime did verify that actual bundle before/after execution. There is no protected-custody, independent-reviewer, hardware-attestation or real-device-authenticity claim. Public test nonces/UUIDs are not secrets. No credentials/private keys or customer packets are retained.

The launcher/profile is not independently security-certified or a complete host-metadata confidentiality boundary. The kernel is an intentionally minimal, pinned laboratory build, not a current production hardening/update baseline. Use a dedicated engineering environment. Before real host/network enforcement, device enrollment/authenticated adapters, existing class/filter/firewall ownership, complete management exclusions, separate approved change/online lease and withdrawal semantics, independent device/load qualification and out-of-band recovery remain mandatory. Offline scopes can be replayed within their window. No application performance-target improvement, six-BOM discovery completeness, production deployment, 24/7 monitoring or SLA follows from this test.
