# Runbook — Build and qualify the disposable TBF target

[Guide 88](../bank-environment/88-disposable-linux-tbf-qualification.md) · [Source/requirements](../../tools/disposable_tbf/README.md) · [Engineering evidence](../readiness-evidence/disposable-tbf-2026-10-26.md)

Use a dedicated, ordinary-user Debian-style x86_64 Linux engineering environment and the existing trusted repository Python environment. **No sudo, credentials/private keys, host module load or customer interface selection.** This does not use or extend the Guide 87 namespace-review authorization. It is a separate, explicit local disposable-target test.

## 1. Build the target from locked inputs

Ensure GCC/static libc development files, make/binutils, BusyBox with `bc`, system Python 3.11/standard library, fixed root-owned `/usr/bin/ip`, `/usr/sbin/tc`, `/usr/bin/ldd` and libelf runtime are present. The host must support unprivileged Landlock ABI ≥2 and seccomp to run. The builder never silently installs prerequisites; unsupported layouts must be resolved in an owned engineering environment, not by escalating the collector.

Choose **new** absolute work and bundle directories. Cache archives are checked against `tools/disposable_tbf/assets.lock.json`; corrupt cache entries refuse rather than being trusted or overwritten.

```bash
.venv/bin/python scripts/qualify_tbf.py build \
  --cache "$HOME/.cache/cryptoscan-tbf-assets" \
  --work "$HOME/.cache/cryptoscan-tbf-build-001" \
  --output "$HOME/.cache/cryptoscan-tbf-bundle-001"
```

Retain `BUNDLE_SHA256=…`. It is the SHA-256 of the exact `bundle.json` bytes. That manifest pins boot/runtime files, input sources, guest probe/controller and launcher/build/profile sources. Build logs remain in the new work directory. Rebuilding on another compiler/runtime can produce different bytes: no reproducible-build or upstream-signature attestation is claimed.

GNU bootstrap sources are patched explicitly for glibc compatibility; the private musl runtime uses process-scoped thread signaling so the launcher's signal restrictions remain in force. The emulator package's optional built-in sandbox is not assumed present; **the separate pinned Landlock/seccomp launcher is mandatory**. Missing support produces a refused/failed result, never an unsandboxed fallback.

Advanced `assemble --kernel … --config … --qemu-root … --loader … --output …` can package operator-supplied components. It pins resulting bytes but does not prove kernel/config correspondence. Prefer the locked-source `build` path and independently review any supplied artifacts. No generated kernel, rootfs, emulator or build tree belongs in Git.

## 2. Declare a short-lived named target scope

```bash
.venv/bin/python scripts/qualify_tbf.py scope \
  --bundle "$HOME/.cache/cryptoscan-tbf-bundle-001" \
  --expected-bundle-sha256 ACTUAL_BUNDLE_SHA256 \
  --target-label disposable-engineering-001 \
  --output "$HOME/.cache/tbf-scope-001.json"
```

Retain `SCOPE_SHA256=…` separately. This is the canonical typed scope hash, **not** the pretty-file byte hash. The scope lasts ten minutes and has fixed profile `DISKLESS_TCG_NO_NIC_V1`; it cannot name interfaces, ports, commands, alternate rates, accelerators or mounts. Production authorization and independently verified change approval remain false. The public nonce binds one result denominator, not an authenticated operator identity.

## 3. Run the explicit isolated test

```bash
.venv/bin/python scripts/qualify_tbf.py run \
  --bundle "$HOME/.cache/cryptoscan-tbf-bundle-001" \
  --scope "$HOME/.cache/tbf-scope-001.json" \
  --expected-scope-sha256 ACTUAL_SCOPE_SHA256 \
  --acknowledge-disposable-vm-only \
  --output "$HOME/.cache/tbf-run-001"
```

A full 180-second execution window must remain. The VM normally runs approximately 20 seconds of generated traffic plus boot/teardown. Each phase uses one warmup and four measured receive seconds. Baseline/caps/recovery thresholds are fixed in the source/Guide 88, not selected after viewing a result.

- **0** / `VERIFIED_IN_DISPOSABLE_VM`: all measurement, readback, rollback, timing, context and integrity gates passed for this exact guest-loopback workload.
- **2** / `INCONCLUSIVE_OR_FAILED`: retained VM failure, insufficient headroom, bad measurement/policy/counter/rollback, expired scope or changed inputs. Inspect blockers; do not relabel it verified or lower thresholds to hide a failure.
- **64**: refused inputs, output collision, unsupported builder/runtime or invalid receipt. No usable successful receipt is asserted.

The new output directory is mode 0700 and `scope.json`, `serial.log`, `result.json` are exclusive mode 0600 files. Original scope/bundle files are not rewritten. Keep the printed `RESULT_SHA256` (canonical receipt digest). The launcher uses one emulated CPU/256 MiB guest RAM, a 120-second host CPU-time limit, 3 GiB host virtual-address limit, FD/core limits and the outer wall deadline. Guest filesystem/queues exist only in VM memory; reboot exits the emulator. There is no retained disk or network listener.

The small sandbox is an engineering mitigation, not a certified boundary for hostile guests or a complete host-metadata confidentiality guarantee. It permits needed anonymous emulator threads and memory-backed runtime operations. Do not run it alongside customer secrets/workloads. Never remedy failure with host-interface TBF, a host module load, privileged Docker, a writable host mount, KVM/device passthrough or disabled sandboxing.

## 4. Verify and retain the result

```bash
.venv/bin/python scripts/qualify_tbf.py verify \
  --input "$HOME/.cache/tbf-run-001/result.json" \
  --expected-sha256 ACTUAL_RESULT_SHA256
```

Keep its sibling `serial.log`. Offline verification checks the typed scope/bundle/nonce/timing/context/report closure and exact serial bytes/frame. It works after scope expiry because it inspects historical evidence; it does not authorize another run, authenticate a device/reviewer or certify an external imported kernel. A caller can fabricate its own unsigned artifacts and hashes; only trusted, reviewed build/execution and independent custody would address authenticity.

For repetitions, issue a fresh scope and choose a new run directory; never overwrite an earlier receipt. Two clean VM boots are retained in this delivery's engineering evidence. No production acceptance, TCP/latency/packet-loss guarantee, 24/7 SLA or existing engineering performance target is inferred from these measurements.

## 5. Tests

```bash
.venv/bin/python -m pytest tools/disposable_tbf/test_qualification.py -q
.venv/bin/ruff check tools/disposable_tbf scripts/qualify_tbf.py
```

Tests include actual safe host-side denial checks for filesystem content reads/writes/truncation/mode/timestamp/xattr changes, socket creation, process creation and namespace changes, plus synthetic throughput/rollback/report negative contracts. An unsupported Landlock/seccomp test host produces an explicit skip/refusal, not a positive sandbox qualification. Native measured enforcement requires executing the VM sequence above; unit fixtures alone never qualify it.
